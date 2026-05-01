use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{TokenRecord, TokenStore};

#[derive(Debug, Clone)]
pub struct SqlxTokenStore {
    pool: SqlitePool,
}

impl SqlxTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenStore for SqlxTokenStore {
    async fn mint(&self, instance_id: &str, provider: &str) -> Result<String, StoreError> {
        // `pt_` prefix lets operators grep proxy tokens out of access
        // logs without false matches against bare 32-hex strings (UUIDs,
        // OR key ids, etc).  128 bits of entropy still come from the
        // UUID body — the prefix is purely for log distinguishability.
        let token = format!("pt_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO proxy_tokens (token, instance_id, provider, created_at, revoked_at) \
             VALUES (?, ?, ?, ?, NULL)",
        )
        .bind(&token)
        .bind(instance_id)
        .bind(provider)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(token)
    }

    async fn resolve(&self, token: &str) -> Result<Option<TokenRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT token, instance_id, provider, created_at, revoked_at \
             FROM proxy_tokens WHERE token = ? AND revoked_at IS NULL",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| TokenRecord {
            token: r.get("token"),
            instance_id: r.get("instance_id"),
            provider: r.get("provider"),
            created_at: r.get("created_at"),
            revoked_at: r.get("revoked_at"),
        }))
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
        let r = sqlx::query(
            "UPDATE proxy_tokens SET revoked_at = ? \
             WHERE token = ? AND revoked_at IS NULL",
        )
        .bind(now_secs())
        .bind(token)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(r.rows_affected() > 0)
    }

    async fn lookup_by_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<String>, StoreError> {
        // Multiple non-revoked rows for one instance shouldn't happen
        // (mint is called once per create), but order-by-created_at
        // makes the choice deterministic if it ever does.  LIMIT 1
        // keeps the query cheap regardless.
        let row = sqlx::query(
            "SELECT token FROM proxy_tokens \
             WHERE instance_id = ? AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.get::<String, _>("token")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

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
}
