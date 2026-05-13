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
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::traits::{
    AdminAuditEntry, AdminAuditStore, AuditEntry, AuditStore, McpAuditEntry, McpAuditStore,
};

#[derive(Debug, Clone)]
pub struct PgAuditStore {
    pool: PgPool,
}

impl PgAuditStore {
    pub fn new(pool: PgPool) -> Self {
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

#[derive(Debug, Clone)]
pub struct PgMcpAuditStore {
    pool: PgPool,
}

impl PgMcpAuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone)]
pub struct PgAdminAuditStore {
    pool: PgPool,
}

impl PgAdminAuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NoopMcpAuditStore;

#[async_trait]
impl AuditStore for PgAuditStore {
    async fn insert(&self, entry: &AuditEntry) -> Result<i64, StoreError> {
        // SQLite's `INTEGER PRIMARY KEY AUTOINCREMENT` exposes the
        // newly-assigned id via `last_insert_rowid()`; we round-trip
        // it through a single `RETURNING id` for portability.
        let row = sqlx::query(
            "INSERT INTO llm_audit \
             (owner_id, instance_id, provider, model, prompt_tokens, output_tokens, status_code, duration_ms, occurred_at, key_source, completed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
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
             FROM llm_audit WHERE owner_id = $1 AND occurred_at >= $2",
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
        sqlx::query("UPDATE llm_audit SET output_tokens = $1, completed = 1 WHERE id = $2")
            .bind(output_tokens)
            .bind(audit_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait]
impl McpAuditStore for PgMcpAuditStore {
    async fn insert(&self, entry: &McpAuditEntry) -> Result<i64, StoreError> {
        let row = sqlx::query(
            "INSERT INTO mcp_audit \
             (owner_id, instance_id, server_name, tool, status, duration_ms, ts, completed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id",
        )
        .bind(&entry.owner_id)
        .bind(&entry.instance_id)
        .bind(&entry.server_name)
        .bind(&entry.tool)
        .bind(entry.status)
        .bind(entry.duration_ms)
        .bind(entry.ts)
        .bind(i64::from(entry.completed))
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let id: i64 = row.try_get("id").map_err(map_sqlx)?;
        Ok(id)
    }

    async fn update_status(
        &self,
        audit_id: i64,
        status: i64,
        duration_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE mcp_audit SET status = $1, duration_ms = $2, completed = 1 WHERE id = $3",
        )
        .bind(status)
        .bind(duration_ms)
        .bind(audit_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait]
impl McpAuditStore for NoopMcpAuditStore {
    async fn insert(&self, _entry: &McpAuditEntry) -> Result<i64, StoreError> {
        Ok(0)
    }

    async fn update_status(
        &self,
        _audit_id: i64,
        _status: i64,
        _duration_ms: i64,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

#[async_trait]
impl AdminAuditStore for PgAdminAuditStore {
    async fn insert(&self, entry: &AdminAuditEntry) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO admin_audit \
             (actor_subject, action, target_user, params_hash, ts) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&entry.actor_subject)
        .bind(&entry.action)
        .bind(&entry.target_user)
        .bind(&entry.params_hash)
        .bind(entry.ts)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}
