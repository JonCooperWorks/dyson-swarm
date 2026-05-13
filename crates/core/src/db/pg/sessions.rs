//! SQLite-backed SPA session store.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::traits::{SessionRow, SessionStore};

#[derive(Debug, Clone)]
pub struct PgSessionStore {
    pool: PgPool,
}

impl PgSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn row_to_session(row: sqlx::postgres::PgRow) -> Result<SessionRow, StoreError> {
    Ok(SessionRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        user_id: row.try_get("user_id").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
        revoked_at: row.try_get("revoked_at").map_err(map_sqlx)?,
    })
}

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
        let row = sqlx::query(
            "SELECT id, user_id, created_at, last_seen_at, revoked_at \
             FROM sessions WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_session).transpose()
    }

    async fn touch(&self, id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE sessions SET last_seen_at = $1 WHERE id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn revoke(&self, id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE sessions SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}
