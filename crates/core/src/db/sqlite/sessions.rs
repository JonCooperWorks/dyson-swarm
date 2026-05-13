//! SQLite-backed SPA session store.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::sqlite::map_sqlx;
use crate::error::StoreError;
use crate::traits::{SessionRow, SessionStore};

#[derive(Debug, Clone)]
pub struct SqliteSessionStore {
    pool: SqlitePool,
}

impl SqliteSessionStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn row_to_session(row: sqlx::sqlite::SqliteRow) -> Result<SessionRow, StoreError> {
    Ok(SessionRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        user_id: row.try_get("user_id").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
        revoked_at: row.try_get("revoked_at").map_err(map_sqlx)?,
    })
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn insert(&self, row: &SessionRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, created_at, last_seen_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?)",
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
        let row = sqlx::query(
            "SELECT id, user_id, created_at, last_seen_at, revoked_at \
             FROM sessions WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_session).transpose()
    }

    async fn touch(&self, id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn revoke(&self, id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite::open_in_memory;

    #[tokio::test]
    async fn revoked_session_is_not_active() {
        let pool = open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, subject, email, display_name, status, created_at, activated_at) \
             VALUES ('u1', 'subject', NULL, NULL, 'active', 0, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = SqliteSessionStore::new(pool);
        let row = SessionRow {
            id: "ses_0123456789abcdef0123456789abcdef".into(),
            user_id: "u1".into(),
            created_at: 10,
            last_seen_at: 10,
            revoked_at: None,
        };
        store.insert(&row).await.unwrap();
        assert!(store.get_active(&row.id).await.unwrap().is_some());
        store.revoke(&row.id, 20).await.unwrap();
        assert!(store.get_active(&row.id).await.unwrap().is_none());
    }
}
