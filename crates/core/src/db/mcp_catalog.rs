//! SQLite-backed store for admin-curated Docker MCP templates.
//!
//! The catalog contains templates and placeholder metadata only.  When a
//! user selects a template, the rendered MCP server is written into that
//! user's encrypted `user_secrets` row by the instance service.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::mcp_servers::{
    McpDockerCatalogServer, McpDockerCatalogStatus, McpDockerPlaceholderSpec,
    validate_docker_catalog_server,
};
use crate::now_secs;

#[derive(Debug, Clone)]
pub struct SqlxMcpDockerCatalogStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDockerCatalogRow {
    pub server: McpDockerCatalogServer,
    pub status: McpDockerCatalogStatus,
    pub source: String,
    pub requested_by_user_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

impl SqlxMcpDockerCatalogStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Seed TOML-managed entries into the DB.  Config-owned rows track
    /// config edits until an admin edits or deletes the row in the UI;
    /// deleted config rows stay tombstoned so a restart does not
    /// surprise-resurrect something the operator removed.
    pub async fn seed_config(&self, servers: &[McpDockerCatalogServer]) -> Result<(), StoreError> {
        for server in servers {
            validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
            let placeholders_json = placeholders_json(&server.placeholders)?;
            let now = now_secs();
            sqlx::query(
                "INSERT INTO mcp_docker_catalog \
                 (id, label, description, template, placeholders_json, source, status, requested_by_user_id, created_at, updated_at, deleted_at) \
                 VALUES (?, ?, ?, ?, ?, 'config', 'active', NULL, ?, ?, NULL) \
                 ON CONFLICT(id) DO UPDATE SET \
                   label = excluded.label, \
                   description = excluded.description, \
                   template = excluded.template, \
                   placeholders_json = excluded.placeholders_json, \
                   status = 'active', \
                   updated_at = excluded.updated_at \
                 WHERE mcp_docker_catalog.source = 'config' \
                   AND mcp_docker_catalog.deleted_at IS NULL",
            )
            .bind(&server.id)
            .bind(&server.label)
            .bind(&server.description)
            .bind(&server.template)
            .bind(&placeholders_json)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        self.list_visible(None).await
    }

    pub async fn list_active(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        self.list_visible(Some(McpDockerCatalogStatus::Active))
            .await
    }

    async fn list_visible(
        &self,
        status: Option<McpDockerCatalogStatus>,
    ) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        let mut query = String::from(
            "SELECT id, label, description, template, placeholders_json, status, source, requested_by_user_id, created_at, updated_at, deleted_at \
             FROM mcp_docker_catalog \
             WHERE deleted_at IS NULL",
        );
        if status.is_some() {
            query.push_str(" AND status = ?");
        }
        query
            .push_str(" ORDER BY status = 'pending' DESC, label COLLATE NOCASE, id COLLATE NOCASE");
        let mut q = sqlx::query(&query);
        if let Some(status) = status {
            q = q.bind(status.as_str());
        }
        let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter().map(row_to_catalog).collect()
    }

    pub async fn get(&self, id: &str) -> Result<Option<McpDockerCatalogRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, label, description, template, placeholders_json, status, source, requested_by_user_id, created_at, updated_at, deleted_at \
             FROM mcp_docker_catalog \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.map(row_to_catalog).transpose()
    }

    pub async fn get_active(&self, id: &str) -> Result<Option<McpDockerCatalogRow>, StoreError> {
        Ok(self
            .get(id)
            .await?
            .filter(|row| row.status == McpDockerCatalogStatus::Active))
    }

    pub async fn upsert_admin(
        &self,
        server: &McpDockerCatalogServer,
    ) -> Result<McpDockerCatalogRow, StoreError> {
        validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
        let placeholders_json = placeholders_json(&server.placeholders)?;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO mcp_docker_catalog \
             (id, label, description, template, placeholders_json, source, status, requested_by_user_id, created_at, updated_at, deleted_at) \
             VALUES (?, ?, ?, ?, ?, 'admin', 'active', NULL, ?, ?, NULL) \
             ON CONFLICT(id) DO UPDATE SET \
               label = excluded.label, \
               description = excluded.description, \
               template = excluded.template, \
               placeholders_json = excluded.placeholders_json, \
               source = 'admin', \
               status = 'active', \
               updated_at = excluded.updated_at, \
               deleted_at = NULL",
        )
        .bind(&server.id)
        .bind(&server.label)
        .bind(&server.description)
        .bind(&server.template)
        .bind(&placeholders_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        self.get(&server.id)
            .await?
            .ok_or_else(|| StoreError::Io("mcp catalog row vanished after upsert".into()))
    }

    pub async fn request_user(
        &self,
        server: &McpDockerCatalogServer,
        user_id: &str,
    ) -> Result<McpDockerCatalogRow, StoreError> {
        validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
        if let Some(existing) = self.get(&server.id).await? {
            if existing.status == McpDockerCatalogStatus::Active {
                return Err(StoreError::Constraint(format!(
                    "mcp docker catalog entry `{}` is already active",
                    server.id
                )));
            }
            if existing.requested_by_user_id.as_deref() != Some(user_id) {
                return Err(StoreError::Constraint(format!(
                    "mcp docker catalog entry `{}` already has a pending request",
                    server.id
                )));
            }
        }
        let placeholders_json = placeholders_json(&server.placeholders)?;
        let now = now_secs();
        let result = sqlx::query(
            "INSERT INTO mcp_docker_catalog \
             (id, label, description, template, placeholders_json, source, status, requested_by_user_id, created_at, updated_at, deleted_at) \
             VALUES (?, ?, ?, ?, ?, 'user', 'pending', ?, ?, ?, NULL) \
             ON CONFLICT(id) DO UPDATE SET \
               label = excluded.label, \
               description = excluded.description, \
               template = excluded.template, \
               placeholders_json = excluded.placeholders_json, \
               source = 'user', \
               status = 'pending', \
               requested_by_user_id = excluded.requested_by_user_id, \
               updated_at = excluded.updated_at, \
               deleted_at = NULL \
             WHERE mcp_docker_catalog.status = 'pending' \
               AND mcp_docker_catalog.requested_by_user_id = excluded.requested_by_user_id",
        )
        .bind(&server.id)
        .bind(&server.label)
        .bind(&server.description)
        .bind(&server.template)
        .bind(&placeholders_json)
        .bind(user_id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::Constraint(format!(
                "mcp docker catalog entry `{}` cannot be requested",
                server.id
            )));
        }
        self.get(&server.id)
            .await?
            .ok_or_else(|| StoreError::Io("mcp catalog pending row vanished after request".into()))
    }

    pub async fn delete(&self, id: &str) -> Result<bool, StoreError> {
        let now = now_secs();
        let result = sqlx::query(
            "UPDATE mcp_docker_catalog \
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
}

fn placeholders_json(placeholders: &[McpDockerPlaceholderSpec]) -> Result<String, StoreError> {
    serde_json::to_string(placeholders)
        .map_err(|err| StoreError::Io(format!("mcp catalog placeholders encode: {err}")))
}

fn row_to_catalog(row: sqlx::sqlite::SqliteRow) -> Result<McpDockerCatalogRow, StoreError> {
    let placeholders_json: String = row.try_get("placeholders_json").map_err(map_sqlx)?;
    let placeholders: Vec<McpDockerPlaceholderSpec> = serde_json::from_str(&placeholders_json)
        .map_err(|err| StoreError::Malformed(format!("mcp catalog placeholders_json: {err}")))?;
    Ok(McpDockerCatalogRow {
        server: McpDockerCatalogServer {
            id: row.try_get("id").map_err(map_sqlx)?,
            label: row.try_get("label").map_err(map_sqlx)?,
            description: row.try_get("description").map_err(map_sqlx)?,
            template: row.try_get("template").map_err(map_sqlx)?,
            placeholders,
        },
        status: McpDockerCatalogStatus::from_db(
            row.try_get::<String, _>("status")
                .map_err(map_sqlx)?
                .as_str(),
        )
        .map_err(StoreError::Malformed)?,
        source: row.try_get("source").map_err(map_sqlx)?,
        requested_by_user_id: row.try_get("requested_by_user_id").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        updated_at: row.try_get("updated_at").map_err(map_sqlx)?,
        deleted_at: row.try_get("deleted_at").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn catalog(id: &str, image: &str, placeholder_id: Option<&str>) -> McpDockerCatalogServer {
        let mut server = serde_json::json!({
            "type": "stdio",
            "command": "docker",
            "args": ["run", "--rm", "-i", image],
            "env": {}
        });
        if let Some(id) = placeholder_id {
            server["env"] = serde_json::json!({ "API_KEY": format!("{{{{placeholder.{id}}}}}") });
        }
        let mut servers = serde_json::Map::new();
        servers.insert(id.into(), server);
        let placeholders = placeholder_id
            .map(|id| {
                vec![McpDockerPlaceholderSpec {
                    id: id.into(),
                    label: "API key".into(),
                    description: None,
                    required: true,
                    secret: true,
                    placeholder: Some("key_...".into()),
                }]
            })
            .unwrap_or_default();
        McpDockerCatalogServer {
            id: id.into(),
            label: id.into(),
            description: None,
            template: serde_json::json!({ "servers": servers }).to_string(),
            placeholders,
        }
    }

    #[tokio::test]
    async fn admin_upsert_list_get_and_delete_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxMcpDockerCatalogStore::new(pool);
        let saved = store
            .upsert_admin(&catalog(
                "github",
                "ghcr.io/example/github-mcp",
                Some("token"),
            ))
            .await
            .unwrap();

        assert_eq!(saved.server.id, "github");
        assert_eq!(saved.source, "admin");
        assert_eq!(saved.status, McpDockerCatalogStatus::Active);
        assert_eq!(saved.server.placeholders[0].id, "token");

        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].server.id, "github");
        assert!(store.get("github").await.unwrap().is_some());

        assert!(store.delete("github").await.unwrap());
        assert!(!store.delete("github").await.unwrap());
        assert!(store.get("github").await.unwrap().is_none());
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn config_seed_updates_config_rows_but_not_admin_or_tombstones() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxMcpDockerCatalogStore::new(pool);
        store
            .seed_config(&[catalog("github", "ghcr.io/example/v1", Some("token"))])
            .await
            .unwrap();
        store
            .seed_config(&[catalog("github", "ghcr.io/example/v2", Some("token"))])
            .await
            .unwrap();
        let seeded = store.get("github").await.unwrap().unwrap();
        assert!(seeded.server.template.contains("ghcr.io/example/v2"));
        assert_eq!(seeded.source, "config");
        assert_eq!(seeded.status, McpDockerCatalogStatus::Active);

        store
            .upsert_admin(&catalog("github", "ghcr.io/example/admin", Some("token")))
            .await
            .unwrap();
        store
            .seed_config(&[catalog("github", "ghcr.io/example/v3", Some("token"))])
            .await
            .unwrap();
        let admin = store.get("github").await.unwrap().unwrap();
        assert!(admin.server.template.contains("ghcr.io/example/admin"));
        assert_eq!(admin.source, "admin");

        store
            .seed_config(&[catalog("linear", "ghcr.io/example/linear", None)])
            .await
            .unwrap();
        assert!(store.delete("linear").await.unwrap());
        store
            .seed_config(&[catalog("linear", "ghcr.io/example/linear2", None)])
            .await
            .unwrap();
        assert!(store.get("linear").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn user_requests_are_pending_until_admin_saves() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxMcpDockerCatalogStore::new(pool);
        let pending = store
            .request_user(
                &catalog("brave", "ghcr.io/example/brave", Some("token")),
                "u1",
            )
            .await
            .unwrap();

        assert_eq!(pending.status, McpDockerCatalogStatus::Pending);
        assert_eq!(pending.source, "user");
        assert_eq!(pending.requested_by_user_id.as_deref(), Some("u1"));
        assert!(store.get_active("brave").await.unwrap().is_none());
        assert!(store.list_active().await.unwrap().is_empty());

        let active = store
            .upsert_admin(&catalog("brave", "ghcr.io/example/brave", Some("token")))
            .await
            .unwrap();
        assert_eq!(active.status, McpDockerCatalogStatus::Active);
        assert!(store.get_active("brave").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn user_request_cannot_replace_active_catalog_entry() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxMcpDockerCatalogStore::new(pool);
        store
            .upsert_admin(&catalog("github", "ghcr.io/example/github", None))
            .await
            .unwrap();

        let err = store
            .request_user(&catalog("github", "ghcr.io/example/other", None), "u1")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Constraint(_)));
    }

    #[tokio::test]
    async fn rejects_invalid_templates_before_persisting() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxMcpDockerCatalogStore::new(pool);
        let mut bad = catalog("bad", "ghcr.io/example/bad", None);
        bad.template = "{}".into();

        let err = store.upsert_admin(&bad).await.unwrap_err();
        assert!(matches!(err, StoreError::Malformed(_)));
        assert!(store.list().await.unwrap().is_empty());
    }
}
