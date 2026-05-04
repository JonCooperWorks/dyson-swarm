//! SQLite-backed store for admin-curated Docker MCP templates.
//!
//! The catalog contains templates and placeholder metadata only.  When a
//! user selects a template, the rendered MCP server is written into that
//! user's encrypted `user_secrets` row by the instance service.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::mcp_servers::{
    McpDockerCatalogServer, McpDockerCredentialSpec, validate_docker_catalog_server,
};
use crate::now_secs;

#[derive(Debug, Clone)]
pub struct SqlxMcpDockerCatalogStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDockerCatalogRow {
    pub server: McpDockerCatalogServer,
    pub source: String,
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
            let credentials_json = credentials_json(&server.credentials)?;
            let now = now_secs();
            sqlx::query(
                "INSERT INTO mcp_docker_catalog \
                 (id, label, description, template, credentials_json, source, created_at, updated_at, deleted_at) \
                 VALUES (?, ?, ?, ?, ?, 'config', ?, ?, NULL) \
                 ON CONFLICT(id) DO UPDATE SET \
                   label = excluded.label, \
                   description = excluded.description, \
                   template = excluded.template, \
                   credentials_json = excluded.credentials_json, \
                   updated_at = excluded.updated_at \
                 WHERE mcp_docker_catalog.source = 'config' \
                   AND mcp_docker_catalog.deleted_at IS NULL",
            )
            .bind(&server.id)
            .bind(&server.label)
            .bind(&server.description)
            .bind(&server.template)
            .bind(&credentials_json)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, label, description, template, credentials_json, source, created_at, updated_at, deleted_at \
             FROM mcp_docker_catalog \
             WHERE deleted_at IS NULL \
             ORDER BY label COLLATE NOCASE, id COLLATE NOCASE",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_catalog).collect()
    }

    pub async fn get(&self, id: &str) -> Result<Option<McpDockerCatalogRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, label, description, template, credentials_json, source, created_at, updated_at, deleted_at \
             FROM mcp_docker_catalog \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_catalog).transpose()
    }

    pub async fn upsert_admin(
        &self,
        server: &McpDockerCatalogServer,
    ) -> Result<McpDockerCatalogRow, StoreError> {
        validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
        let credentials_json = credentials_json(&server.credentials)?;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO mcp_docker_catalog \
             (id, label, description, template, credentials_json, source, created_at, updated_at, deleted_at) \
             VALUES (?, ?, ?, ?, ?, 'admin', ?, ?, NULL) \
             ON CONFLICT(id) DO UPDATE SET \
               label = excluded.label, \
               description = excluded.description, \
               template = excluded.template, \
               credentials_json = excluded.credentials_json, \
               source = 'admin', \
               updated_at = excluded.updated_at, \
               deleted_at = NULL",
        )
        .bind(&server.id)
        .bind(&server.label)
        .bind(&server.description)
        .bind(&server.template)
        .bind(&credentials_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        self.get(&server.id)
            .await?
            .ok_or_else(|| StoreError::Io("mcp catalog row vanished after upsert".into()))
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

fn credentials_json(credentials: &[McpDockerCredentialSpec]) -> Result<String, StoreError> {
    serde_json::to_string(credentials)
        .map_err(|err| StoreError::Io(format!("mcp catalog credentials encode: {err}")))
}

fn row_to_catalog(row: sqlx::sqlite::SqliteRow) -> Result<McpDockerCatalogRow, StoreError> {
    let credentials_json: String = row.try_get("credentials_json").map_err(map_sqlx)?;
    let credentials: Vec<McpDockerCredentialSpec> = serde_json::from_str(&credentials_json)
        .map_err(|err| StoreError::Malformed(format!("mcp catalog credentials_json: {err}")))?;
    Ok(McpDockerCatalogRow {
        server: McpDockerCatalogServer {
            id: row.try_get("id").map_err(map_sqlx)?,
            label: row.try_get("label").map_err(map_sqlx)?,
            description: row.try_get("description").map_err(map_sqlx)?,
            template: row.try_get("template").map_err(map_sqlx)?,
            credentials,
        },
        source: row.try_get("source").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        updated_at: row.try_get("updated_at").map_err(map_sqlx)?,
        deleted_at: row.try_get("deleted_at").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn catalog(id: &str, image: &str, credential_id: Option<&str>) -> McpDockerCatalogServer {
        let mut server = serde_json::json!({
            "type": "stdio",
            "command": "docker",
            "args": ["run", "--rm", "-i", image],
            "env": {}
        });
        if let Some(id) = credential_id {
            server["env"] = serde_json::json!({ "API_KEY": format!("{{{{placeholder.{id}}}}}") });
        }
        let mut servers = serde_json::Map::new();
        servers.insert(id.into(), server);
        let credentials = credential_id
            .map(|id| {
                vec![McpDockerCredentialSpec {
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
            credentials,
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
        assert_eq!(saved.server.credentials[0].id, "token");

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
