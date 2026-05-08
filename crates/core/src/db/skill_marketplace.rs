//! SQLite-backed registry for skill marketplace sources.
//!
//! Source rows are operator-managed metadata only. Installed skills remain
//! per-instance Dyson workspace files and flow back through state sync.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::skill_marketplace::{SkillMarketplaceSourceConfig, validate_marketplace_source_config};

#[derive(Debug, Clone)]
pub struct SqlxSkillMarketplaceSourceStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillMarketplaceSourceRow {
    pub source: SkillMarketplaceSourceConfig,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_fetch_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
}

impl SqlxSkillMarketplaceSourceStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<SkillMarketplaceSourceRow>, StoreError> {
        self.list_visible(true).await
    }

    pub async fn list_enabled(&self) -> Result<Vec<SkillMarketplaceSourceRow>, StoreError> {
        self.list_visible(false).await
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
        query.push_str(" ORDER BY enabled DESC, id COLLATE NOCASE");
        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_source).collect()
    }

    pub async fn get(&self, id: &str) -> Result<Option<SkillMarketplaceSourceRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, source_type, location, enabled, created_at, updated_at, last_fetch_at, last_success_at, last_error \
             FROM skill_marketplace_sources \
             WHERE id = ? AND deleted_at IS NULL AND source_type != 'inline_quarantined'",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_source).transpose()
    }

    pub async fn upsert(
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
             VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL) \
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

    pub async fn delete(&self, id: &str) -> Result<bool, StoreError> {
        let now = now_secs();
        let result = sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET deleted_at = ?, updated_at = ? \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn record_fetch_success(&self, id: &str) -> Result<(), StoreError> {
        let now = now_secs();
        sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET last_fetch_at = ?, last_success_at = ?, last_error = NULL \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn record_fetch_error(&self, id: &str, error: &str) -> Result<(), StoreError> {
        let now = now_secs();
        let mut msg = error.to_owned();
        msg.truncate(2048);
        sqlx::query(
            "UPDATE skill_marketplace_sources \
             SET last_fetch_at = ?, last_error = ? \
             WHERE id = ? AND deleted_at IS NULL",
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

fn row_to_source(row: sqlx::sqlite::SqliteRow) -> Result<SkillMarketplaceSourceRow, StoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn inline_source(id: &str, index_json: &str) -> SkillMarketplaceSourceConfig {
        SkillMarketplaceSourceConfig::Inline {
            id: id.into(),
            index_json: index_json.into(),
        }
    }

    fn http_source(id: &str, url: &str) -> SkillMarketplaceSourceConfig {
        SkillMarketplaceSourceConfig::Http {
            id: id.into(),
            url: url.into(),
        }
    }

    #[tokio::test]
    async fn upsert_enable_disable_delete_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxSkillMarketplaceSourceStore::new(pool);
        let saved = store
            .upsert(
                &http_source("curated", "https://example.com/market.json"),
                true,
            )
            .await
            .unwrap();

        assert_eq!(saved.source.id(), "curated");
        assert!(saved.enabled);

        assert_eq!(store.list_enabled().await.unwrap().len(), 1);
        store
            .upsert(
                &http_source("curated", "https://example.com/market.json"),
                false,
            )
            .await
            .unwrap();
        assert!(store.list_enabled().await.unwrap().is_empty());
        assert_eq!(store.list().await.unwrap().len(), 1);

        assert!(store.delete("curated").await.unwrap());
        assert!(!store.delete("curated").await.unwrap());
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upsert_replaces_existing_source_without_resurrecting_deleted_rows_as_duplicates() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxSkillMarketplaceSourceStore::new(pool);
        store
            .upsert(
                &http_source("local", "https://example.com/marketplace-v1.json"),
                true,
            )
            .await
            .unwrap();
        store
            .upsert(
                &http_source("local", "https://example.com/marketplace-v2.json"),
                false,
            )
            .await
            .unwrap();

        let updated = store.get("local").await.unwrap().unwrap();
        assert_eq!(
            updated.source.location(),
            "https://example.com/marketplace-v2.json"
        );
        assert!(!updated.enabled);

        assert!(store.delete("local").await.unwrap());
        store
            .upsert(
                &http_source("local", "https://example.com/marketplace-v3.json"),
                true,
            )
            .await
            .unwrap();
        let restored = store.get("local").await.unwrap().unwrap();
        assert_eq!(
            restored.source.location(),
            "https://example.com/marketplace-v3.json"
        );
        assert!(restored.enabled);
    }

    #[tokio::test]
    async fn rejects_non_https_http_sources() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxSkillMarketplaceSourceStore::new(pool);
        let err = store
            .upsert(&http_source("bad", "http://example.com/market.json"), true)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Malformed(_)));
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn records_fetch_status_without_mutating_source_timestamp() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxSkillMarketplaceSourceStore::new(pool);
        store
            .upsert(
                &inline_source(
                    "local",
                    r#"{"schema_version":1,"marketplace":{"id":"local","name":"Local"},"skills":[]}"#,
                ),
                true,
            )
            .await
            .unwrap();
        let before = store.get("local").await.unwrap().unwrap().updated_at;

        store.record_fetch_error("local", "boom").await.unwrap();
        let errored = store.get("local").await.unwrap().unwrap();
        assert_eq!(errored.updated_at, before);
        assert_eq!(errored.last_error.as_deref(), Some("boom"));

        store.record_fetch_success("local").await.unwrap();
        let ok = store.get("local").await.unwrap().unwrap();
        assert_eq!(ok.updated_at, before);
        assert!(ok.last_success_at.is_some());
        assert!(ok.last_error.is_none());
    }
}
