use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::sqlite::map_sqlx;
use crate::error::StoreError;
use crate::traits::{ChannelDeliveryRow, InstanceChannelRow, InstanceChannelStore};

#[derive(Debug, Clone)]
pub struct SqlxInstanceChannelStore {
    pool: SqlitePool,
}

impl SqlxInstanceChannelStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn channel_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<InstanceChannelRow, StoreError> {
    let allowed_senders_json: String = row.try_get("allowed_senders").map_err(map_sqlx)?;
    let allowed_senders = serde_json::from_str(&allowed_senders_json)
        .map_err(|e| StoreError::Malformed(format!("allowed_senders: {e}")))?;
    Ok(InstanceChannelRow {
        id: row.try_get::<i64, _>("id").map_err(map_sqlx)?,
        instance_id: row.try_get::<String, _>("instance_id").map_err(map_sqlx)?,
        kind: row.try_get::<String, _>("kind").map_err(map_sqlx)?,
        handle: row.try_get::<String, _>("handle").map_err(map_sqlx)?,
        secret_name: row.try_get::<String, _>("secret_name").map_err(map_sqlx)?,
        webhook_secret_name: row
            .try_get::<String, _>("webhook_secret_name")
            .map_err(map_sqlx)?,
        enabled: row.try_get::<i64, _>("enabled").map_err(map_sqlx)? != 0,
        allowed_senders,
        last_inbound_at: row
            .try_get::<Option<i64>, _>("last_inbound_at")
            .map_err(map_sqlx)?,
        created_at: row.try_get::<i64, _>("created_at").map_err(map_sqlx)?,
    })
}

fn delivery_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ChannelDeliveryRow, StoreError> {
    Ok(ChannelDeliveryRow {
        id: row.try_get::<i64, _>("id").map_err(map_sqlx)?,
        instance_id: row.try_get::<String, _>("instance_id").map_err(map_sqlx)?,
        kind: row.try_get::<String, _>("kind").map_err(map_sqlx)?,
        received_at: row.try_get::<i64, _>("received_at").map_err(map_sqlx)?,
        status: row.try_get::<i32, _>("status").map_err(map_sqlx)?,
        preview: row.try_get::<String, _>("preview").map_err(map_sqlx)?,
    })
}

#[async_trait]
impl InstanceChannelStore for SqlxInstanceChannelStore {
    async fn insert(&self, row: InstanceChannelRow) -> Result<InstanceChannelRow, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO instance_channels
             (instance_id, kind, handle, secret_name, webhook_secret_name, enabled, allowed_senders, last_inbound_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING id, instance_id, kind, handle, secret_name, webhook_secret_name,
                       enabled, allowed_senders, last_inbound_at, created_at",
        )
        .bind(row.instance_id)
        .bind(row.kind)
        .bind(row.handle)
        .bind(row.secret_name)
        .bind(row.webhook_secret_name)
        .bind(i64::from(row.enabled))
        .bind(
            serde_json::to_string(&row.allowed_senders)
                .map_err(|e| StoreError::Malformed(format!("allowed_senders: {e}")))?,
        )
        .bind(row.last_inbound_at)
        .bind(row.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        channel_from_row(&inserted)
    }

    async fn get(
        &self,
        instance_id: &str,
        kind: &str,
    ) -> Result<Option<InstanceChannelRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, instance_id, kind, handle, secret_name, webhook_secret_name,
                    enabled, allowed_senders, last_inbound_at, created_at
             FROM instance_channels
             WHERE instance_id = ? AND kind = ?",
        )
        .bind(instance_id)
        .bind(kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.as_ref().map(channel_from_row).transpose()
    }

    async fn list_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<InstanceChannelRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, instance_id, kind, handle, secret_name, webhook_secret_name,
                    enabled, allowed_senders, last_inbound_at, created_at
             FROM instance_channels
             WHERE instance_id = ?
             ORDER BY kind",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter().map(channel_from_row).collect()
    }

    async fn delete(&self, instance_id: &str, kind: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM instance_channels WHERE instance_id = ? AND kind = ?")
            .bind(instance_id)
            .bind(kind)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_enabled(
        &self,
        instance_id: &str,
        kind: &str,
        enabled: bool,
    ) -> Result<Option<InstanceChannelRow>, StoreError> {
        let row = sqlx::query(
            "UPDATE instance_channels
             SET enabled = ?
             WHERE instance_id = ? AND kind = ?
             RETURNING id, instance_id, kind, handle, secret_name, webhook_secret_name,
                       enabled, allowed_senders, last_inbound_at, created_at",
        )
        .bind(i64::from(enabled))
        .bind(instance_id)
        .bind(kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.as_ref().map(channel_from_row).transpose()
    }

    async fn set_settings(
        &self,
        instance_id: &str,
        kind: &str,
        enabled: Option<bool>,
        allowed_senders: Option<&[String]>,
    ) -> Result<Option<InstanceChannelRow>, StoreError> {
        let enabled_value = enabled.map(i64::from);
        let allowed_senders_json = allowed_senders
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Malformed(format!("allowed_senders: {e}")))?;
        let row = sqlx::query(
            "UPDATE instance_channels
             SET enabled = COALESCE(?, enabled),
                 allowed_senders = COALESCE(?, allowed_senders)
             WHERE instance_id = ? AND kind = ?
             RETURNING id, instance_id, kind, handle, secret_name, webhook_secret_name,
                       enabled, allowed_senders, last_inbound_at, created_at",
        )
        .bind(enabled_value)
        .bind(allowed_senders_json)
        .bind(instance_id)
        .bind(kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.as_ref().map(channel_from_row).transpose()
    }

    async fn update_last_inbound_at(
        &self,
        instance_id: &str,
        kind: &str,
        at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE instance_channels SET last_inbound_at = ? WHERE instance_id = ? AND kind = ?",
        )
        .bind(at)
        .bind(instance_id)
        .bind(kind)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn record_delivery(
        &self,
        instance_id: &str,
        kind: &str,
        received_at: i64,
        status: i32,
        preview: &str,
    ) -> Result<ChannelDeliveryRow, StoreError> {
        let row = sqlx::query(
            "INSERT INTO instance_channel_deliveries
             (instance_id, kind, received_at, status, preview)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, instance_id, kind, received_at, status, preview",
        )
        .bind(instance_id)
        .bind(kind)
        .bind(received_at)
        .bind(status)
        .bind(preview)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        delivery_from_row(&row)
    }

    async fn recent_deliveries(
        &self,
        instance_id: &str,
        kind: &str,
        limit: i64,
    ) -> Result<Vec<ChannelDeliveryRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, instance_id, kind, received_at, status, preview
             FROM instance_channel_deliveries
             WHERE instance_id = ? AND kind = ?
             ORDER BY received_at DESC, id DESC
             LIMIT ?",
        )
        .bind(instance_id)
        .bind(kind)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter().map(delivery_from_row).collect()
    }
}
