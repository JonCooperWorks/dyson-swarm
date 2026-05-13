//! SQLite-backed registry for skill marketplace sources.
//!
//! Source rows are operator-managed metadata only. Installed skills remain
//! per-instance Dyson workspace files and flow back through state sync.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::skill_marketplace::{SkillMarketplaceSourceConfig, validate_marketplace_source_config};
use crate::traits::{SkillMarketplaceSourceRow, SkillMarketplaceSourceStore};

#[derive(Debug, Clone)]
pub struct PgSkillMarketplaceSourceStore {
    pool: PgPool,
}

impl PgSkillMarketplaceSourceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn list_visible(
        &self,
        include_disabled: bool,
    ) -> Result<Vec<SkillMarketplaceSourceRow>, StoreError> {
        let mut query = String::from(
            "SELECT id, source_type, location, enabled, created_at, updated_at, last_fetch_at, last_success_at, last_error \
             FROM skill_marketplace_sources \
             WHERE deleted_at IS NULL AND source_type != 'inline_quarantined'",
        );
        if !include_disabled {
            query.push_str(" AND enabled = 1");
        }
        query.push_str(" ORDER BY enabled DESC, LOWER(id)");
        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_source).collect()
    }
}

#[async_trait]
impl SkillMarketplaceSourceStore for PgSkillMarketplaceSourceStore {
    async fn list(&self) -> Result<Vec<SkillMarketplaceSourceRow>, StoreError> {
        self.list_visible(true).await
    }

    async fn list_enabled(&self) -> Result<Vec<SkillMarketplaceSourceRow>, StoreError> {
        self.list_visible(false).await
    }

    async fn get(&self, id: &str) -> Result<Option<SkillMarketplaceSourceRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, source_type, location, enabled, created_at, updated_at, last_fetch_at, last_success_at, last_error \
             FROM skill_marketplace_sources \
             WHERE id = $1 AND deleted_at IS NULL AND source_type != 'inline_quarantined'",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_source).transpose()
    }

    async fn upsert(
        &self,
        source: &SkillMarketplaceSourceConfig,
        enabled: bool,
    ) -> Result<SkillMarketplaceSourceRow, StoreError> {
        validate_marketplace_source_config(source)
            .map_err(|err| StoreError::Malformed(err.to_string()))?;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO skill_marketplace_sources \
             (id, source_type, location, enabled, created_at, updated_at, deleted_at, last_fetch_at, last_success_at, last_error) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, NULL) \
             ON CONFLICT(id) DO UPDATE SET \
               source_type = excluded.source_type, \
               location = excluded.location, \
               enabled = excluded.enabled, \
               updated_at = excluded.updated_at, \
               deleted_at = NULL",
        )
        .bind(source.id())
        .bind(source.source_type())
        .bind(source.stored_location())
        .bind(enabled)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        self.get(source.id())
            .await?
            .ok_or_else(|| StoreError::Io("skill marketplace source vanished after upsert".into()))
    }

    async fn delete(&self, id: &str) -> Result<bool, StoreError> {
        let now = now_secs();
        let result = sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET deleted_at = $1, updated_at = $2 \
             WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    async fn record_fetch_success(&self, id: &str) -> Result<(), StoreError> {
        let now = now_secs();
        sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET last_fetch_at = $1, last_success_at = $2, last_error = NULL \
             WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn record_fetch_error(&self, id: &str, error: &str) -> Result<(), StoreError> {
        let now = now_secs();
        let mut msg = error.to_owned();
        msg.truncate(2048);
        sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET last_fetch_at = $1, last_error = $2 \
             WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(msg)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}

fn row_to_source(row: sqlx::postgres::PgRow) -> Result<SkillMarketplaceSourceRow, StoreError> {
    let id: String = row.try_get("id").map_err(map_sqlx)?;
    let source_type: String = row.try_get("source_type").map_err(map_sqlx)?;
    let location: String = row.try_get("location").map_err(map_sqlx)?;
    let source = source_from_parts(id, source_type.as_str(), location)?;
    validate_marketplace_source_config(&source)
        .map_err(|err| StoreError::Malformed(err.to_string()))?;
    let enabled: i64 = row.try_get("enabled").map_err(map_sqlx)?;
    Ok(SkillMarketplaceSourceRow {
        source,
        enabled: enabled != 0,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        updated_at: row.try_get("updated_at").map_err(map_sqlx)?,
        last_fetch_at: row.try_get("last_fetch_at").map_err(map_sqlx)?,
        last_success_at: row.try_get("last_success_at").map_err(map_sqlx)?,
        last_error: row.try_get("last_error").map_err(map_sqlx)?,
    })
}

fn source_from_parts(
    id: String,
    source_type: &str,
    location: String,
) -> Result<SkillMarketplaceSourceConfig, StoreError> {
    match source_type {
        "inline" => Ok(SkillMarketplaceSourceConfig::Inline {
            id,
            index_json: location,
        }),
        "http" => Ok(SkillMarketplaceSourceConfig::Http { id, url: location }),
        other => Err(StoreError::Malformed(format!(
            "unknown marketplace source_type {other:?}"
        ))),
    }
}
