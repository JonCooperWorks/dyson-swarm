//! SQLite-backed store for admin-curated Docker MCP templates.
//!
//! The catalog contains templates and placeholder metadata only.  When a
//! user selects a template, the rendered MCP server is written into that
//! user's encrypted `user_secrets` row by the instance service.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::mcp_servers::{
    McpDockerCatalogServer, McpDockerCatalogStatus, McpDockerPlaceholderSpec,
    validate_docker_catalog_server,
};
use crate::now_secs;
use crate::traits::{McpDockerCatalogRow, McpDockerCatalogStore};

#[derive(Debug, Clone)]
pub struct PgMcpDockerCatalogStore {
    pool: PgPool,
}

impl PgMcpDockerCatalogStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
            query.push_str(" AND status = $1");
        }
        query.push_str(" ORDER BY status = 'pending' DESC, LOWER(label), LOWER(id)");
        let mut q = sqlx::query(&query);
        if let Some(status) = status {
            q = q.bind(status.as_str());
        }
        let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter().map(row_to_catalog).collect()
    }
}

#[async_trait]
impl McpDockerCatalogStore for PgMcpDockerCatalogStore {
    /// Seed TOML-managed entries into the DB.  Config-owned rows track
    /// config edits until an admin edits or deletes the row in the UI;
    /// deleted config rows stay tombstoned so a restart does not
    /// surprise-resurrect something the operator removed.
    async fn seed_config(&self, servers: &[McpDockerCatalogServer]) -> Result<(), StoreError> {
        for server in servers {
            validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
            let placeholders_json = placeholders_json(&server.placeholders)?;
            let now = now_secs();
            sqlx::query(
                "INSERT INTO mcp_docker_catalog \
                 (id, label, description, template, placeholders_json, source, status, requested_by_user_id, created_at, updated_at, deleted_at) \
                 VALUES ($1, $2, $3, $4, $5, 'config', 'active', NULL, $6, $7, NULL) \
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

    async fn list(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        self.list_visible(None).await
    }

    async fn list_active(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        self.list_visible(Some(McpDockerCatalogStatus::Active))
            .await
    }

    async fn get(&self, id: &str) -> Result<Option<McpDockerCatalogRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, label, description, template, placeholders_json, status, source, requested_by_user_id, created_at, updated_at, deleted_at \
             FROM mcp_docker_catalog \
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.map(row_to_catalog).transpose()
    }

    async fn get_active(&self, id: &str) -> Result<Option<McpDockerCatalogRow>, StoreError> {
        Ok(self
            .get(id)
            .await?
            .filter(|row| row.status == McpDockerCatalogStatus::Active))
    }

    async fn upsert_admin(
        &self,
        server: &McpDockerCatalogServer,
    ) -> Result<McpDockerCatalogRow, StoreError> {
        validate_docker_catalog_server(server).map_err(StoreError::Malformed)?;
        let placeholders_json = placeholders_json(&server.placeholders)?;
        let now = now_secs();
        sqlx::query(
            "INSERT INTO mcp_docker_catalog \
             (id, label, description, template, placeholders_json, source, status, requested_by_user_id, created_at, updated_at, deleted_at) \
             VALUES ($1, $2, $3, $4, $5, 'admin', 'active', NULL, $6, $7, NULL) \
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

    async fn request_user(
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
             VALUES ($1, $2, $3, $4, $5, 'user', 'pending', $6, $7, $8, NULL) \
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

    async fn delete(&self, id: &str) -> Result<bool, StoreError> {
        let now = now_secs();
        let result = sqlx::query(
            "UPDATE mcp_docker_catalog \
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
}

fn placeholders_json(placeholders: &[McpDockerPlaceholderSpec]) -> Result<String, StoreError> {
    serde_json::to_string(placeholders)
        .map_err(|err| StoreError::Io(format!("mcp catalog placeholders encode: {err}")))
}

fn row_to_catalog(row: sqlx::postgres::PgRow) -> Result<McpDockerCatalogRow, StoreError> {
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
