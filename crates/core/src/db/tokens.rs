use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::db::map_sqlx;
use crate::envelope::EnvelopeCipher;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{TokenRecord, TokenStore};

#[derive(Debug, Clone)]
pub struct SqlxTokenStore {
    pool: SqlitePool,
    cipher: Option<Arc<dyn EnvelopeCipher>>,
}

impl SqlxTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool, cipher: None }
    }

    pub fn sealed(pool: SqlitePool, cipher: Arc<dyn EnvelopeCipher>) -> Self {
        Self {
            pool,
            cipher: Some(cipher),
        }
    }

    fn seal_token(&self, token: &str) -> Result<String, StoreError> {
        let Some(cipher) = self.cipher.as_ref() else {
            return Ok(token.to_owned());
        };
        let sealed = cipher
            .seal(token.as_bytes())
            .map_err(|e| StoreError::Io(format!("seal proxy token: {e}")))?;
        String::from_utf8(sealed)
            .map_err(|_| StoreError::Malformed("sealed proxy token was not utf-8".into()))
    }

    fn open_token(&self, stored: &str) -> Result<String, StoreError> {
        // Backwards compatibility for rows minted before token sealing.
        if stored.starts_with("pt_") || stored.starts_with("it_") {
            return Ok(stored.to_owned());
        }
        let Some(cipher) = self.cipher.as_ref() else {
            return Err(StoreError::Malformed(
                "proxy token row is sealed but token store has no cipher".into(),
            ));
        };
        let plain = cipher
            .open(stored.as_bytes())
            .map_err(|e| StoreError::Malformed(format!("open proxy token: {e}")))?;
        String::from_utf8(plain)
            .map_err(|_| StoreError::Malformed("proxy token plaintext was not utf-8".into()))
    }
}

/// Provider string stamped on rows minted via `TokenStore::mint_ingest`.
/// The internal-ingest route filters resolved tokens by prefix (`it_`),
/// so the provider field is largely a documentation-and-grep handle for
/// operators inspecting the table directly.
pub const INGEST_PROVIDER: &str = "ingest";

impl SqlxTokenStore {
    /// Common mint path — the prefix and provider are the only knobs
    /// the public surfaces (`mint` / `mint_ingest`) flex.  Both paths
    /// share the same row layout in `proxy_tokens` so revoke and
    /// resolve work uniformly across token kinds.
    async fn mint_with_prefix(
        &self,
        prefix: &str,
        instance_id: &str,
        provider: &str,
    ) -> Result<String, StoreError> {
        let token = format!("{prefix}{}", Uuid::new_v4().simple());
        let stored_token = self.seal_token(&token)?;
        sqlx::query(
            "INSERT INTO proxy_tokens (token, instance_id, provider, created_at, revoked_at) \
             VALUES (?, ?, ?, ?, NULL)",
        )
        .bind(&stored_token)
        .bind(instance_id)
        .bind(provider)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(token)
    }
}

#[async_trait]
impl TokenStore for SqlxTokenStore {
    async fn mint(&self, instance_id: &str, provider: &str) -> Result<String, StoreError> {
        // `pt_` prefix lets operators grep proxy tokens out of access
        // logs without false matches against bare 32-hex strings (UUIDs,
        // OR key ids, etc).  128 bits of entropy still come from the
        // UUID body — the prefix is purely for log distinguishability.
        self.mint_with_prefix("pt_", instance_id, provider).await
    }

    async fn mint_ingest(&self, instance_id: &str) -> Result<String, StoreError> {
        // `it_` prefix marks ingest tokens (artefact push from dyson →
        // swarm).  Same row layout as `pt_` proxy tokens; the prefix +
        // `provider = "ingest"` let the internal-ingest route reject
        // chat-provider tokens at the door and let operators grep the
        // table apart.
        self.mint_with_prefix("it_", instance_id, INGEST_PROVIDER)
            .await
    }

    async fn resolve(&self, token: &str) -> Result<Option<TokenRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT token, instance_id, provider, created_at, revoked_at \
             FROM proxy_tokens WHERE revoked_at IS NULL",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        for row in rows {
            let stored: String = row.get("token");
            let plain = self.open_token(&stored)?;
            if bool::from(plain.as_bytes().ct_eq(token.as_bytes())) {
                return Ok(Some(TokenRecord {
                    token: plain,
                    instance_id: row.get("instance_id"),
                    provider: row.get("provider"),
                    created_at: row.get("created_at"),
                    revoked_at: row.get("revoked_at"),
                }));
            }
        }
        Ok(None)
    }

    async fn revoke_for_instance(&self, instance_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE proxy_tokens SET revoked_at = ? WHERE instance_id = ? AND revoked_at IS NULL",
        )
        .bind(now_secs())
        .bind(instance_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn revoke_token(&self, token: &str) -> Result<bool, StoreError> {
        // Targeted single-row revoke (B1).  Does NOT cascade to other
        // tokens on the same instance — that's `revoke_for_instance`'s
        // job, called by the destroy path.  Already-revoked rows
        // return `false` (no-op) rather than an error so a duplicate
        // revoke is idempotent at the API boundary.
        let rows = sqlx::query("SELECT token FROM proxy_tokens WHERE revoked_at IS NULL")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        for row in rows {
            let stored: String = row.get("token");
            let plain = self.open_token(&stored)?;
            if !bool::from(plain.as_bytes().ct_eq(token.as_bytes())) {
                continue;
            }
            let r = sqlx::query(
                "UPDATE proxy_tokens SET revoked_at = ? \
                 WHERE token = ? AND revoked_at IS NULL",
            )
            .bind(now_secs())
            .bind(stored)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
            return Ok(r.rows_affected() > 0);
        }
        Ok(false)
    }

    async fn lookup_by_instance(&self, instance_id: &str) -> Result<Option<String>, StoreError> {
        // Caller wants the chat-side proxy token specifically — pin
        // the provider filter to `SHARED_PROVIDER` so an ingest
        // token (`provider = "ingest"`) minted after the chat one
        // doesn't shadow it at the rotation paths that were written
        // before the ingest token existed.
        self.lookup_by_instance_for_provider(instance_id, crate::instance::SHARED_PROVIDER)
            .await
    }

    async fn lookup_by_instance_for_provider(
        &self,
        instance_id: &str,
        provider: &str,
    ) -> Result<Option<String>, StoreError> {
        // Multiple non-revoked rows for one instance + provider
        // shouldn't happen (mint is called once per create), but
        // order-by-created_at makes the choice deterministic if it
        // ever does.  LIMIT 1 keeps the query cheap regardless.
        let row = sqlx::query(
            "SELECT token FROM proxy_tokens \
             WHERE instance_id = ? AND provider = ? AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(instance_id)
        .bind(provider)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(|r| {
            let stored: String = r.get("token");
            self.open_token(&stored)
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::envelope::EnvelopeError;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

    #[derive(Debug)]
    struct TestCipher;

    impl EnvelopeCipher for TestCipher {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let mut out = b"sealed:".to_vec();
            out.extend_from_slice(plaintext);
            Ok(out)
        }

        fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            ciphertext
                .strip_prefix(b"sealed:")
                .map(|s| s.to_vec())
                .ok_or(EnvelopeError::Corrupt)
        }
    }

    async fn seed(pool: &SqlitePool, id: &str) {
        let store = SqlxInstanceStore::new(pool.clone());
        store
            .create(InstanceRow {
                id: id.into(),
                owner_id: "legacy".into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: None,
                template_id: "t".into(),
                status: InstanceStatus::Live,
                bearer_token: "b".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: None,
                rotated_to: None,
                network_policy: crate::network_policy::NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mint_resolve_revoke() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::new(pool);
        let tok = store.mint("i1", "anthropic").await.unwrap();
        assert!(tok.starts_with("pt_"));
        assert_eq!(tok.len(), 35);

        let resolved = store.resolve(&tok).await.unwrap().expect("present");
        assert_eq!(resolved.instance_id, "i1");
        assert_eq!(resolved.provider, "anthropic");
        assert!(resolved.revoked_at.is_none());

        store.revoke_for_instance("i1").await.unwrap();
        assert!(store.resolve(&tok).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unknown_token_resolves_none() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxTokenStore::new(pool);
        assert!(store.resolve("not-a-token").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_only_targets_one_instance() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        seed(&pool, "i2").await;
        let store = SqlxTokenStore::new(pool);
        let t1 = store.mint("i1", "openai").await.unwrap();
        let t2 = store.mint("i2", "openai").await.unwrap();
        store.revoke_for_instance("i1").await.unwrap();
        assert!(store.resolve(&t1).await.unwrap().is_none());
        assert!(store.resolve(&t2).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_token_targets_named_row_only() {
        // B1 regression: revoking a single leaked proxy_token must
        // NOT cascade to sibling tokens on the same instance.  We
        // mint two rows for one instance (a contrived shape — mint
        // is normally called once per create — but the SPA could
        // hand-issue), revoke one by value, and assert the other
        // remains live.
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::new(pool);
        let t1 = store.mint("i1", "openai").await.unwrap();
        let t2 = store.mint("i1", "anthropic").await.unwrap();

        let revoked = store.revoke_token(&t1).await.unwrap();
        assert!(revoked, "revoke_token returns true on first call");
        assert!(store.resolve(&t1).await.unwrap().is_none());
        // Sibling token on the same instance survives.
        let r2 = store.resolve(&t2).await.unwrap().expect("t2 still live");
        assert_eq!(r2.instance_id, "i1");
        assert!(r2.revoked_at.is_none());

        // Idempotent: revoking again returns false (already revoked).
        let again = store.revoke_token(&t1).await.unwrap();
        assert!(!again);

        // Unknown token: false, no error.
        let unknown = store.revoke_token("not-a-real-token").await.unwrap();
        assert!(!unknown);
    }

    #[tokio::test]
    async fn mint_ingest_uses_it_prefix_and_ingest_provider() {
        // Ingest tokens live in the same `proxy_tokens` table but the
        // wire-side route filters by prefix and the operator grep path
        // filters by provider.  Both must be set correctly on mint.
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::new(pool);
        let tok = store.mint_ingest("i1").await.unwrap();
        assert!(
            tok.starts_with("it_"),
            "ingest token must start with `it_`, got {tok:?}"
        );
        assert_eq!(tok.len(), 35, "it_ + 32 hex chars");

        let resolved = store.resolve(&tok).await.unwrap().expect("present");
        assert_eq!(resolved.instance_id, "i1");
        assert_eq!(resolved.provider, INGEST_PROVIDER);
        assert!(resolved.revoked_at.is_none());
    }

    #[tokio::test]
    async fn revoke_for_instance_cleans_up_ingest_alongside_chat_token() {
        // Instance destroy must take the ingest token down with it —
        // we don't want a destroyed instance's ingest URL accepting
        // pushes from a still-running cube the destroy didn't catch.
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::new(pool);
        let chat = store.mint("i1", "openai").await.unwrap();
        let ingest = store.mint_ingest("i1").await.unwrap();

        store.revoke_for_instance("i1").await.unwrap();
        assert!(
            store.resolve(&chat).await.unwrap().is_none(),
            "chat token revoked"
        );
        assert!(
            store.resolve(&ingest).await.unwrap().is_none(),
            "ingest token revoked"
        );
    }

    #[tokio::test]
    async fn ingest_and_chat_tokens_are_distinguishable_after_mint() {
        // Token-prefix discrimination at the route layer relies on the
        // `pt_` and `it_` prefixes never colliding.  Belt-and-braces
        // assertion that mint and mint_ingest produce disjoint shapes.
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::new(pool);
        let pt = store.mint("i1", "openai").await.unwrap();
        let it = store.mint_ingest("i1").await.unwrap();
        assert!(pt.starts_with("pt_"));
        assert!(it.starts_with("it_"));
        assert_ne!(pt, it);
    }

    #[tokio::test]
    async fn sealed_store_does_not_persist_plaintext_tokens() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlxTokenStore::sealed(pool.clone(), Arc::new(TestCipher));
        let tok = store
            .mint("i1", crate::instance::SHARED_PROVIDER)
            .await
            .unwrap();

        let row = sqlx::query("SELECT token FROM proxy_tokens WHERE instance_id = 'i1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let stored: String = row.get("token");
        assert_ne!(stored, tok);
        assert_eq!(stored, format!("sealed:{tok}"));

        let resolved = store
            .resolve(&tok)
            .await
            .unwrap()
            .expect("sealed token resolves");
        assert_eq!(resolved.token, tok);
        assert_eq!(
            store.lookup_by_instance("i1").await.unwrap(),
            Some(tok.clone())
        );

        assert!(store.revoke_token(&tok).await.unwrap());
        assert!(store.resolve(&tok).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sealed_store_still_reads_legacy_plaintext_rows() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let legacy = SqlxTokenStore::new(pool.clone());
        let tok = legacy.mint("i1", "openai").await.unwrap();

        let sealed = SqlxTokenStore::sealed(pool, Arc::new(TestCipher));
        let resolved = sealed
            .resolve(&tok)
            .await
            .unwrap()
            .expect("legacy plaintext token resolves");
        assert_eq!(resolved.token, tok);
    }
}
