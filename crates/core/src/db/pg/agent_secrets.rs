use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{AgentSecretMetadata, AgentSecretRow, AgentSecretStore};

#[derive(Debug, Clone)]
pub struct PgAgentSecretStore {
    pool: PgPool,
}

impl PgAgentSecretStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AgentSecretStore for PgAgentSecretStore {
    async fn put(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
        ciphertext: &str,
    ) -> Result<AgentSecretMetadata, StoreError> {
        let now = now_secs();
        sqlx::query(
            "INSERT INTO agent_secrets \
             (owner_user_id, instance_id, name, ciphertext, created_at, updated_at, last_read_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL) \
             ON CONFLICT(owner_user_id, instance_id, name) DO UPDATE SET \
                ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
        )
        .bind(owner_user_id)
        .bind(instance_id)
        .bind(name)
        .bind(ciphertext)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        self.get(owner_user_id, instance_id, name)
            .await?
            .map(metadata_from_row)
            .ok_or(StoreError::NotFound)
    }

    async fn get(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<Option<AgentSecretRow>, StoreError> {
        let row = sqlx::query(
            "SELECT owner_user_id, instance_id, name, ciphertext, created_at, updated_at, last_read_at \
             FROM agent_secrets \
             WHERE owner_user_id = $1 AND instance_id = $2 AND name = $3",
        )
        .bind(owner_user_id)
        .bind(instance_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(row_to_agent_secret).transpose()
    }

    async fn list_metadata(
        &self,
        owner_user_id: &str,
        instance_id: &str,
    ) -> Result<Vec<AgentSecretMetadata>, StoreError> {
        let rows = sqlx::query(
            "SELECT owner_user_id, instance_id, name, created_at, updated_at, last_read_at \
             FROM agent_secrets \
             WHERE owner_user_id = $1 AND instance_id = $2 \
             ORDER BY name",
        )
        .bind(owner_user_id)
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_metadata).collect()
    }

    async fn touch_last_read(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE agent_secrets SET last_read_at = $1 \
             WHERE owner_user_id = $2 AND instance_id = $3 AND name = $4",
        )
        .bind(now_secs())
        .bind(owner_user_id)
        .bind(instance_id)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete(
        &self,
        owner_user_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM agent_secrets \
             WHERE owner_user_id = $1 AND instance_id = $2 AND name = $3",
        )
        .bind(owner_user_id)
        .bind(instance_id)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_for_instance(&self, instance_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM agent_secrets WHERE instance_id = $1")
            .bind(instance_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

fn row_to_agent_secret(row: sqlx::postgres::PgRow) -> Result<AgentSecretRow, StoreError> {
    Ok(AgentSecretRow {
        owner_user_id: row.try_get("owner_user_id").map_err(map_sqlx)?,
        instance_id: row.try_get("instance_id").map_err(map_sqlx)?,
        name: row.try_get("name").map_err(map_sqlx)?,
        ciphertext: row.try_get("ciphertext").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        updated_at: row.try_get("updated_at").map_err(map_sqlx)?,
        last_read_at: row.try_get("last_read_at").map_err(map_sqlx)?,
    })
}

fn row_to_metadata(row: sqlx::postgres::PgRow) -> Result<AgentSecretMetadata, StoreError> {
    Ok(AgentSecretMetadata {
        owner_user_id: row.try_get("owner_user_id").map_err(map_sqlx)?,
        instance_id: row.try_get("instance_id").map_err(map_sqlx)?,
        name: row.try_get("name").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        updated_at: row.try_get("updated_at").map_err(map_sqlx)?,
        last_read_at: row.try_get("last_read_at").map_err(map_sqlx)?,
    })
}

fn metadata_from_row(row: AgentSecretRow) -> AgentSecretMetadata {
    AgentSecretMetadata {
        owner_user_id: row.owner_user_id,
        instance_id: row.instance_id,
        name: row.name,
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_read_at: row.last_read_at,
    }
}
