use async_trait::async_trait;
use sqlx::{Row, PgPool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::traits::SessionStore;

#[cfg(feature = "postgres")]
use crate::traits::SessionRow;

#[cfg(feature = "postgres")]
#[derive(Debug, Clone)]
pub struct PgSessionStore {
    pool: PgPool,
}

#[cfg(feature = "postgres")]
impl PgSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl SessionStore for PgSessionStore {
    async fn insert(&self, row: &SessionRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, created_at, last_seen_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&row.id)
        .bind(&row.user_id)
        .bind(row.created_at)
        .bind(row.last_seen_at)
        .bind(row.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_active(&self, id: &str) -> Result<Option<SessionRow>, StoreError> {
        let r = sqlx::query(
            "SELECT id, user_id, created_at, last_seen_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(SessionRow {
                id: row.try_get("id").map_err(map_sqlx)?,
                user_id: row.try_get("user_id").map_err(map_sqlx)?,
                created_at: row.try_get("created_at").map_err(map_sqlx)?,
                last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
                revoked_at: row.try_get("revoked_at").map_err(map_sqlx)?,
            })),
            None => Ok(None),
        }
    }

    async fn touch(&self, id: &str, now: i64) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE sessions SET last_seen_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn revoke(&self, id: &str, now: i64) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

#[cfg(all(feature = "postgres", test))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let pool = super::super::test_pg_pool().await;
        let store = PgSessionStore::new(pool);
        let row = SessionRow {
            id: "s1".into(),
            user_id: "legacy".into(),
            created_at: 100,
            last_seen_at: 100,
            revoked_at: None,
        };
        store.insert(&row).await.unwrap();
        let got = store.get_active("s1").await.unwrap().unwrap();
        assert_eq!(got.id, "s1");
        assert_eq!(got.user_id, "legacy");
        assert!(got.revoked_at.is_none());

        store.touch("s1", 200).await.unwrap();
        let touched = store.get_active("s1").await.unwrap().unwrap();
        assert_eq!(touched.last_seen_at, 200);

        store.revoke("s1", 300).await.unwrap();
        let revoked = store.get_active("s1").await.unwrap().unwrap();
        assert_eq!(revoked.revoked_at, Some(300));
    }
}
