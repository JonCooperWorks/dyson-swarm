//! Snapshot CRUD. Plain functions historically; now also exposed as
//! [`PgSnapshotStore`] implementing [`SnapshotStore`] so services hold a
//! trait object instead of a `PgPool` and a Postgres impl can slot in
//! without touching the service layer.
//!
//! # Content hash (A3)
//!
//! Each row carries a nullable `content_hash` column for tamper
//! detection.  The snapshot service computes a SHA-256 over the
//! on-disk archive (or per-file digest set, depending on the
//! sink) and stamps it via [`SnapshotStore::update_content_hash`]
//! once the bytes are flushed.  Restore-time verification is the
//! caller's responsibility — this layer only persists the value.
//! Pre-A3 rows are migrated as `NULL` (see
//! migrations/sqlite/0013_snapshot_hash.sql) and treated as
//! "unverified" until rehashed.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::traits::{SnapshotKind, SnapshotRow, SnapshotStore};

fn row_to_snapshot(row: &sqlx::postgres::PgRow) -> Result<SnapshotRow, StoreError> {
    let kind_text: String = row.try_get("kind").map_err(map_sqlx)?;
    let kind = SnapshotKind::parse(&kind_text)
        .ok_or_else(|| StoreError::Malformed(format!("kind={kind_text}")))?;
    Ok(SnapshotRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        owner_id: row.try_get("owner_id").map_err(map_sqlx)?,
        source_instance_id: row.try_get("source_instance_id").map_err(map_sqlx)?,
        parent_snapshot_id: row.try_get("parent_snapshot_id").map_err(map_sqlx)?,
        kind,
        path: row.try_get("path").map_err(map_sqlx)?,
        host_ip: row.try_get("host_ip").map_err(map_sqlx)?,
        remote_uri: row.try_get("remote_uri").map_err(map_sqlx)?,
        size_bytes: row.try_get("size_bytes").map_err(map_sqlx)?,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        deleted_at: row.try_get("deleted_at").map_err(map_sqlx)?,
        content_hash: row.try_get("content_hash").map_err(map_sqlx)?,
    })
}

#[derive(Debug, Clone)]
pub struct PgSnapshotStore {
    pool: PgPool,
}

impl PgSnapshotStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SnapshotStore for PgSnapshotStore {
    async fn insert(&self, row: &SnapshotRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO snapshots \
             (id, owner_id, source_instance_id, parent_snapshot_id, kind, path, host_ip, remote_uri, size_bytes, created_at, deleted_at, content_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&row.id)
        .bind(&row.owner_id)
        .bind(&row.source_instance_id)
        .bind(&row.parent_snapshot_id)
        .bind(row.kind.as_str())
        .bind(&row.path)
        .bind(&row.host_ip)
        .bind(&row.remote_uri)
        .bind(row.size_bytes)
        .bind(row.created_at)
        .bind(row.deleted_at)
        .bind(&row.content_hash)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<SnapshotRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_snapshot(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_for_instance(&self, instance_id: &str) -> Result<Vec<SnapshotRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM snapshots WHERE source_instance_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter().map(row_to_snapshot).collect()
    }

    async fn update_remote_uri(&self, id: &str, uri: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE snapshots SET remote_uri = $1 WHERE id = $2")
            .bind(uri)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update_path(&self, id: &str, path: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE snapshots SET path = $1 WHERE id = $2")
            .bind(path)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn mark_deleted(&self, id: &str, when: i64) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE snapshots SET deleted_at = $1 WHERE id = $2")
            .bind(when)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update_content_hash(&self, id: &str, hash: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE snapshots SET content_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn count_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<u64, StoreError> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM snapshots \
             WHERE owner_id = $1 AND source_instance_id = $2 AND deleted_at IS NULL",
        )
        .bind(owner_id)
        .bind(instance_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let cnt: i64 = row.try_get("cnt").map_err(map_sqlx)?;
        Ok(u64::try_from(cnt.max(0)).unwrap_or(0))
    }
}
