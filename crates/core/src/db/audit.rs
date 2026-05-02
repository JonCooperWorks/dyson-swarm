//! Audit-row CRUD. Backs the [`AuditStore`] trait. The `subject` parameter
//! to `daily_tokens` is opaque — `instance_id` today, `owner_id` after
//! phase 6 — so the trait shape doesn't change when budgets become per-user.
//!
//! # Two-step write (D1)
//!
//! Streaming LLM calls are now logged in two phases:
//!   1. `insert` — runs before the upstream body is consumed; stamps
//!      `completed = false` and returns the row id.
//!   2. `update_completion` — runs after the upstream body has fully
//!      streamed; stamps `completed = true` and the final `output_tokens`.
//!
//! A crash mid-stream therefore leaves a forensic row marked
//! `completed = 0`, distinguishable from rows that finished cleanly.
//! Daily-token rollups sum both prompt and output regardless of the
//! `completed` flag — partial usage still counts toward the cap so a
//! crashing tenant can't run a token-exfil loop.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::traits::{AuditEntry, AuditStore};

#[derive(Debug, Clone)]
pub struct SqliteAuditStore {
    pool: SqlitePool,
}

impl SqliteAuditStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Pricing is intentionally not implemented. Kept as a well-typed
    /// entry point so a future pricing layer can land without re-plumbing
    /// every call site.
    #[allow(dead_code, clippy::unused_async)]
    pub async fn monthly_usd(&self, _owner_id: &str, _now: i64) -> Result<f64, StoreError> {
        Ok(0.0)
    }
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn insert(&self, entry: &AuditEntry) -> Result<i64, StoreError> {
        // SQLite's `INTEGER PRIMARY KEY AUTOINCREMENT` exposes the
        // newly-assigned id via `last_insert_rowid()`; we round-trip
        // it through a single `RETURNING id` for portability.
        let row = sqlx::query(
            "INSERT INTO llm_audit \
             (owner_id, instance_id, provider, model, prompt_tokens, output_tokens, status_code, duration_ms, occurred_at, key_source, completed) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             RETURNING id",
        )
        .bind(&entry.owner_id)
        .bind(&entry.instance_id)
        .bind(&entry.provider)
        .bind(&entry.model)
        .bind(entry.prompt_tokens)
        .bind(entry.output_tokens)
        .bind(entry.status_code)
        .bind(entry.duration_ms)
        .bind(entry.occurred_at)
        .bind(&entry.key_source)
        .bind(i64::from(entry.completed))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let id: i64 = row.try_get("id").map_err(map_sqlx)?;
        Ok(id)
    }

    /// Sums tokens *per-owner* over the past 24h. Per-user budgets hold
    /// across all of a tenant's instances. Both prompt and output
    /// tokens count — usage from a streamed-but-incomplete row still
    /// pushes toward the cap.
    async fn daily_tokens(&self, owner_id: &str, now: i64) -> Result<u64, StoreError> {
        let since = now - 86_400;
        let row = sqlx::query(
            "SELECT COALESCE(SUM(COALESCE(prompt_tokens,0) + COALESCE(output_tokens,0)), 0) AS total \
             FROM llm_audit WHERE owner_id = ? AND occurred_at >= ?",
        )
        .bind(owner_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let total: i64 = row.try_get("total").map_err(map_sqlx)?;
        Ok(u64::try_from(total.max(0)).unwrap_or(0))
    }

    async fn update_completion(
        &self,
        audit_id: i64,
        output_tokens: Option<i64>,
    ) -> Result<(), StoreError> {
        // Idempotent: a re-stamp matches the same row and writes the
        // same values.  No `revoked_at IS NULL`-style guard because
        // the row is keyed on its primary id and there's no harm in
        // overwriting with a more accurate token count if the proxy
        // happens to call us twice.
        sqlx::query("UPDATE llm_audit SET output_tokens = ?, completed = 1 WHERE id = ?")
            .bind(output_tokens)
            .bind(audit_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn r(owner: &str, instance: &str, when: i64, prompt: i64, output: i64) -> AuditEntry {
        AuditEntry {
            owner_id: owner.into(),
            instance_id: instance.into(),
            provider: "openai".into(),
            model: Some("gpt-4o".into()),
            prompt_tokens: Some(prompt),
            output_tokens: Some(output),
            status_code: 200,
            duration_ms: 100,
            occurred_at: when,
            key_source: "platform".into(),
            completed: true,
        }
    }

    #[tokio::test]
    async fn daily_tokens_sums_window_per_owner() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        // Owner u1, two different instances — both should count.
        store
            .insert(&r("u1", "i-a", now - 100, 100, 50))
            .await
            .unwrap();
        store
            .insert(&r("u1", "i-b", now - 1000, 200, 100))
            .await
            .unwrap();
        // Outside window.
        store
            .insert(&r("u1", "i-a", now - 86_500, 999, 999))
            .await
            .unwrap();
        // Different owner — not counted.
        store
            .insert(&r("u2", "i-c", now - 100, 9999, 9999))
            .await
            .unwrap();

        let total = store.daily_tokens("u1", now).await.unwrap();
        assert_eq!(total, 100 + 50 + 200 + 100);
    }

    #[tokio::test]
    async fn daily_tokens_handles_null_columns() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        let mut row = r("u1", "i1", now - 10, 50, 25);
        row.prompt_tokens = None;
        store.insert(&row).await.unwrap();
        assert_eq!(store.daily_tokens("u1", now).await.unwrap(), 25);
    }

    #[tokio::test]
    async fn daily_tokens_zero_on_no_rows() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        assert_eq!(store.daily_tokens("i1", 1).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn daily_tokens_sums_prompt_and_output_columns() {
        // Regression guard: the budget rollup must include *both*
        // `prompt_tokens` and `output_tokens`.  Earlier shape only
        // summed prompt; if the proxy ever logs a row with prompt=0
        // and output>0 the cap must still tick over.
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        // Only-output and only-prompt rows both contribute.
        let mut only_output = r("u1", "i1", now - 10, 0, 700);
        only_output.prompt_tokens = None;
        store.insert(&only_output).await.unwrap();
        let mut only_prompt = r("u1", "i1", now - 20, 300, 0);
        only_prompt.output_tokens = None;
        store.insert(&only_prompt).await.unwrap();

        assert_eq!(store.daily_tokens("u1", now).await.unwrap(), 700 + 300);
    }

    #[tokio::test]
    async fn update_completion_stamps_tokens_and_completed() {
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool.clone());
        let now = 1_000_000;
        // Insert as completed = false, output_tokens = None — the
        // proxy's up-front shape.
        let mut entry = r("u1", "i1", now - 5, 100, 0);
        entry.completed = false;
        entry.output_tokens = None;
        let id = store.insert(&entry).await.unwrap();

        // Pre-update: completed = 0, output_tokens IS NULL.
        let row = sqlx::query("SELECT completed, output_tokens FROM llm_audit WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let completed: i64 = row.try_get("completed").unwrap();
        let output: Option<i64> = row.try_get("output_tokens").unwrap();
        assert_eq!(completed, 0);
        assert!(output.is_none());

        // Stamp completion.
        store.update_completion(id, Some(450)).await.unwrap();

        let row = sqlx::query("SELECT completed, output_tokens FROM llm_audit WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let completed: i64 = row.try_get("completed").unwrap();
        let output: Option<i64> = row.try_get("output_tokens").unwrap();
        assert_eq!(completed, 1);
        assert_eq!(output, Some(450));

        // Daily-tokens now sees the updated output count.
        // prompt(100) + output(450) = 550.
        assert_eq!(store.daily_tokens("u1", now).await.unwrap(), 550);
    }

    #[tokio::test]
    async fn update_completion_idempotent() {
        // Re-stamping is harmless — same row, same values.
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        let now = 1_000_000;
        let mut entry = r("u1", "i1", now - 5, 50, 0);
        entry.completed = false;
        entry.output_tokens = None;
        let id = store.insert(&entry).await.unwrap();
        store.update_completion(id, Some(10)).await.unwrap();
        store.update_completion(id, Some(10)).await.unwrap();
        // No panic, no state divergence.
        assert_eq!(store.daily_tokens("u1", now).await.unwrap(), 50 + 10);
    }

    #[tokio::test]
    async fn monthly_usd_is_zero_pricing_disabled() {
        // Pricing is intentionally not implemented (demo deployment);
        // the entry point exists so a future pricing layer can land
        // without re-plumbing call sites.
        let pool = open_in_memory().await.unwrap();
        let store = SqliteAuditStore::new(pool);
        // float exact-compare is intentional: this is a hard-coded 0.0
        // and we want to catch any accidental change to the no-op return.
        let usd = store.monthly_usd("u1", 0).await.unwrap();
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(usd, 0.0);
        }
    }
}
