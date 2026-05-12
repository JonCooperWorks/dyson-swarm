//! SQLite metadata store for swarm-side instance state files.
//!
//! File bodies are sealed before they enter the store. This module owns
//! both the encrypted body bytes and row bookkeeping so workspace state
//! is replayable from the swarm store without node-local cache affinity.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::traits::StateFileStore;

pub use crate::traits::{StateFileRow, StateFileUpsertSpec as UpsertSpec};

#[derive(Clone)]
pub struct SqlxStateFileStore {
    pool: SqlitePool,
}

impl SqlxStateFileStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl StateFileStore for SqlxStateFileStore {
    async fn upsert(&self, spec: UpsertSpec<'_>) -> Result<StateFileRow, StoreError> {
        upsert(&self.pool, spec).await
    }

    async fn tombstone(
        &self,
        instance_id: &str,
        owner_id: &str,
        namespace: &str,
        path: &str,
        updated_at: i64,
        synced_at: i64,
    ) -> Result<StateFileRow, StoreError> {
        tombstone(
            &self.pool,
            instance_id,
            owner_id,
            namespace,
            path,
            updated_at,
            synced_at,
        )
        .await
    }

    async fn find(
        &self,
        instance_id: &str,
        namespace: &str,
        path: &str,
    ) -> Result<Option<StateFileRow>, StoreError> {
        find(&self.pool, instance_id, namespace, path).await
    }

    async fn list_for_instance(&self, instance_id: &str) -> Result<Vec<StateFileRow>, StoreError> {
        list_for_instance(&self.pool, instance_id).await
    }
}

pub async fn upsert(pool: &SqlitePool, spec: UpsertSpec<'_>) -> Result<StateFileRow, StoreError> {
    sqlx::query(
        "INSERT INTO instance_state_files \
         (instance_id, owner_id, namespace, path, mime, bytes, body_ciphertext, updated_at, synced_at, deleted_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) \
         ON CONFLICT(instance_id, namespace, path) DO UPDATE SET \
           owner_id = excluded.owner_id, \
           mime = excluded.mime, \
           bytes = excluded.bytes, \
           body_ciphertext = excluded.body_ciphertext, \
           updated_at = excluded.updated_at, \
           synced_at = excluded.synced_at, \
           deleted_at = NULL",
    )
    .bind(spec.instance_id)
    .bind(spec.owner_id)
    .bind(spec.namespace)
    .bind(spec.path)
    .bind(spec.mime)
    .bind(spec.bytes)
    .bind(spec.body_ciphertext)
    .bind(spec.updated_at)
    .bind(spec.synced_at)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;

    find(pool, spec.instance_id, spec.namespace, spec.path)
        .await?
        .ok_or_else(|| StoreError::Io("state file row vanished after upsert".into()))
}

pub async fn tombstone(
    pool: &SqlitePool,
    instance_id: &str,
    owner_id: &str,
    namespace: &str,
    path: &str,
    updated_at: i64,
    synced_at: i64,
) -> Result<StateFileRow, StoreError> {
    sqlx::query(
        "INSERT INTO instance_state_files \
         (instance_id, owner_id, namespace, path, mime, bytes, body_ciphertext, updated_at, synced_at, deleted_at) \
         VALUES (?, ?, ?, ?, NULL, 0, NULL, ?, ?, ?) \
         ON CONFLICT(instance_id, namespace, path) DO UPDATE SET \
           owner_id = excluded.owner_id, \
           mime = NULL, \
           bytes = 0, \
           body_ciphertext = NULL, \
           updated_at = excluded.updated_at, \
           synced_at = excluded.synced_at, \
           deleted_at = excluded.deleted_at",
    )
    .bind(instance_id)
    .bind(owner_id)
    .bind(namespace)
    .bind(path)
    .bind(updated_at)
    .bind(synced_at)
    .bind(synced_at)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;

    find(pool, instance_id, namespace, path)
        .await?
        .ok_or_else(|| StoreError::Io("state file row vanished after tombstone".into()))
}

pub async fn find(
    pool: &SqlitePool,
    instance_id: &str,
    namespace: &str,
    path: &str,
) -> Result<Option<StateFileRow>, StoreError> {
    let row = sqlx::query(
        "SELECT id, instance_id, owner_id, namespace, path, mime, bytes, body_ciphertext, updated_at, synced_at, deleted_at \
         FROM instance_state_files \
         WHERE instance_id = ? AND namespace = ? AND path = ?",
    )
    .bind(instance_id)
    .bind(namespace)
    .bind(path)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(row.map(row_to_state_file))
}

pub async fn list_for_instance(
    pool: &SqlitePool,
    instance_id: &str,
) -> Result<Vec<StateFileRow>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, namespace, path, mime, bytes, body_ciphertext, updated_at, synced_at, deleted_at \
         FROM instance_state_files \
         WHERE instance_id = ? \
         ORDER BY namespace, path",
    )
    .bind(instance_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(rows.into_iter().map(row_to_state_file).collect())
}

fn row_to_state_file(row: sqlx::sqlite::SqliteRow) -> StateFileRow {
    StateFileRow {
        id: row.get("id"),
        instance_id: row.get("instance_id"),
        owner_id: row.get("owner_id"),
        namespace: row.get("namespace"),
        path: row.get("path"),
        mime: row.get("mime"),
        bytes: row.get("bytes"),
        body_ciphertext: row.get("body_ciphertext"),
        updated_at: row.get("updated_at"),
        synced_at: row.get("synced_at"),
        deleted_at: row.get("deleted_at"),
    }
}
