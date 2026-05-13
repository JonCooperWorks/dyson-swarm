use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::db::pg::map_sqlx;
use crate::envelope::EnvelopeCipher;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{TokenRecord, TokenStore};

#[derive(Debug, Clone)]
pub struct PgTokenStore {
    pool: PgPool,
    cipher: Arc<dyn EnvelopeCipher>,
}

impl PgTokenStore {
    pub fn new(pool: PgPool, cipher: Arc<dyn EnvelopeCipher>) -> Self {
        Self { pool, cipher }
    }

    fn seal_token(&self, token: &str) -> Result<String, StoreError> {
        let sealed = self
            .cipher
            .seal(token.as_bytes())
            .map_err(|e| StoreError::Io(format!("seal proxy token: {e}")))?;
        String::from_utf8(sealed)
            .map_err(|_| StoreError::Malformed("sealed proxy token was not utf-8".into()))
    }

    fn open_token(&self, stored: &str) -> Result<String, StoreError> {
        let plain = self
            .cipher
            .open(stored.as_bytes())
            .map_err(|e| StoreError::Malformed(format!("open proxy token: {e}")))?;
        String::from_utf8(plain)
            .map_err(|_| StoreError::Malformed("proxy token plaintext was not utf-8".into()))
    }
}

pub(crate) fn token_lookup_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Provider string stamped on rows minted via `TokenStore::mint_ingest`.
/// The internal-ingest route filters resolved tokens by prefix (`it_`),
/// so the provider field is largely a documentation-and-grep handle for
/// operators inspecting the table directly.
pub const INGEST_PROVIDER: &str = "ingest";

/// Base provider namespace for state-sync tokens. Concrete tokens are
/// always scoped as `state_sync:<generation>` so only the current
/// sandbox generation can write durable swarm state.
pub const STATE_SYNC_PROVIDER: &str = "state_sync";

pub fn state_sync_provider(generation: &str) -> String {
    let generation = generation.trim();
    debug_assert!(!generation.is_empty(), "state generation is required");
    format!("{STATE_SYNC_PROVIDER}:{generation}")
}

pub fn state_sync_provider_matches(provider: &str, generation: &str) -> bool {
    let generation = generation.trim();
    if generation.is_empty() {
        return false;
    }
    provider == state_sync_provider(generation)
}

impl PgTokenStore {
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
        let lookup = token_lookup_key(&token);
        sqlx::query(
            "INSERT INTO proxy_tokens \
             (token, token_lookup, instance_id, provider, created_at, revoked_at, expected_src_ip) \
             VALUES ($1, $2, $3, $4, $5, NULL, NULL)",
        )
        .bind(&stored_token)
        .bind(&lookup)
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
impl TokenStore for PgTokenStore {
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

    async fn mint_state_sync_for_generation(
        &self,
        instance_id: &str,
        generation: &str,
    ) -> Result<String, StoreError> {
        self.mint_with_prefix("st_", instance_id, &state_sync_provider(generation))
            .await
    }

    async fn bind_expected_src_ip(
        &self,
        instance_id: &str,
        expected_src_ip: &str,
    ) -> Result<(), StoreError> {
        let expected_src_ip = expected_src_ip.trim();
        if expected_src_ip.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "UPDATE proxy_tokens SET expected_src_ip = $1 \
             WHERE instance_id = $2 AND revoked_at IS NULL",
        )
        .bind(expected_src_ip)
        .bind(instance_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn resolve(&self, token: &str) -> Result<Option<TokenRecord>, StoreError> {
        let lookup = token_lookup_key(token);
        let row = sqlx::query(
            "SELECT token, instance_id, provider, created_at, revoked_at, expected_src_ip \
             FROM proxy_tokens \
             WHERE token_lookup = $1 AND revoked_at IS NULL \
             LIMIT 1",
        )
        .bind(&lookup)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored: String = row.get("token");
        let plain = self.open_token(&stored)?;
        if !bool::from(plain.as_bytes().ct_eq(token.as_bytes())) {
            return Ok(None);
        }
        Ok(Some(TokenRecord {
            token: plain,
            instance_id: row.get("instance_id"),
            provider: row.get("provider"),
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
            expected_src_ip: row.get("expected_src_ip"),
        }))
    }

    async fn revoke_for_instance(&self, instance_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE proxy_tokens SET revoked_at = $1 WHERE instance_id = $2 AND revoked_at IS NULL",
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
        let lookup = token_lookup_key(token);
        let row = sqlx::query(
            "SELECT token FROM proxy_tokens WHERE token_lookup = $1 AND revoked_at IS NULL LIMIT 1",
        )
        .bind(&lookup)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let Some(row) = row else {
            return Ok(false);
        };
        let stored: String = row.get("token");
        let plain = self.open_token(&stored)?;
        if !bool::from(plain.as_bytes().ct_eq(token.as_bytes())) {
            return Ok(false);
        }
        let r = sqlx::query(
            "UPDATE proxy_tokens SET revoked_at = $1 \
             WHERE token_lookup = $2 AND token = $3 AND revoked_at IS NULL",
        )
        .bind(now_secs())
        .bind(&lookup)
        .bind(stored)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(r.rows_affected() > 0)
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
             WHERE instance_id = $1 AND provider = $2 AND revoked_at IS NULL \
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
