//! Audit-row CRUD. Backs the [`AuditStore`] trait. The `subject` parameter
//! to `daily_tokens` is opaque — `instance_id` today, `owner_id` after
//! phase 6 — so the trait shape doesn't change when budgets become per-user.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::error::StoreError;
use crate::traits::{AuditEntry, AuditStore};

fn map_sqlx(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        other => StoreError::Io(other.to_string()),
    }
}

#[derive(Debug, Clone)]
pub struct SqliteAuditStore {
    pool: SqlitePool,
}

impl SqliteAuditStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn insert(&self, entry: &AuditEntry) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO llm_audit \
             (instance_id, provider, model, prompt_tokens, output_tokens, status_code, duration_ms, occurred_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.instance_id)
        .bind(&entry.provider)
        .bind(&entry.model)
        .bind(entry.prompt_tokens)
        .bind(entry.output_tokens)
        .bind(entry.status_code)
        .bind(entry.duration_ms)
        .bind(entry.occurred_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn daily_tokens(&self, subject: &str, now: i64) -> Result<u64, StoreError> {
        let since = now - 86_400;
        let row = sqlx::query(
            "SELECT COALESCE(SUM(COALESCE(prompt_tokens,0) + COALESCE(output_tokens,0)), 0) AS total \
             FROM llm_audit WHERE instance_id = ? AND occurred_at >= ?",
        )
        .bind(subject)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let total: i64 = row.try_get("total").map_err(map_sqlx)?;
        Ok(total.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn r(instance: &str, when: i64, prompt: i64, output: i64) -> AuditEntry {
        AuditEntry {
            instance_id: instance.into(),
            provider: "openai".into(),
            model: Some("gpt-4o".into()),
            prompt_tokens: Some(prompt),
            output_tokens: Some(output),
            status_code: 200,
            duration_ms: 100,
            occurred_at: when,
        }
    }

    #[tokio::test]
    async fn daily_tokens_sums_window() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        store.insert(&r("i1", now - 100, 100, 50)).await.unwrap();
        store.insert(&r("i1", now - 1000, 200, 100)).await.unwrap();
        store.insert(&r("i1", now - 86_500, 999, 999)).await.unwrap();
        store.insert(&r("i2", now - 100, 9999, 9999)).await.unwrap();

        let total = store.daily_tokens("i1", now).await.unwrap();
        assert_eq!(total, 100 + 50 + 200 + 100);
    }

    #[tokio::test]
    async fn daily_tokens_handles_null_columns() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        let mut row = r("i1", now - 10, 50, 25);
        row.prompt_tokens = None;
        store.insert(&row).await.unwrap();
        assert_eq!(store.daily_tokens("i1", now).await.unwrap(), 25);
    }

    #[tokio::test]
    async fn daily_tokens_zero_on_no_rows() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        assert_eq!(store.daily_tokens("i1", 1).await.unwrap(), 0);
    }
}
