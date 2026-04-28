//! Snapshot CRUD. Plain functions historically; now also exposed as
//! [`SqliteSnapshotStore`] implementing [`SnapshotStore`] so services hold a
//! trait object instead of a `SqlitePool` and a Postgres impl can slot in
//! without touching the service layer.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::traits::{SnapshotKind, SnapshotRow, SnapshotStore};

fn row_to_snapshot(row: &sqlx::sqlite::SqliteRow) -> Result<SnapshotRow, StoreError> {
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
    })
}

#[derive(Debug, Clone)]
pub struct SqliteSnapshotStore {
    pool: SqlitePool,
}

impl SqliteSnapshotStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SnapshotStore for SqliteSnapshotStore {
    async fn insert(&self, row: &SnapshotRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO snapshots \
             (id, owner_id, source_instance_id, parent_snapshot_id, kind, path, host_ip, remote_uri, size_bytes, created_at, deleted_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<SnapshotRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE id = ?")
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
            "SELECT * FROM snapshots WHERE source_instance_id = ? AND deleted_at IS NULL ORDER BY created_at DESC",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter().map(row_to_snapshot).collect()
    }

    async fn update_remote_uri(&self, id: &str, uri: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE snapshots SET remote_uri = ? WHERE id = ?")
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
        let r = sqlx::query("UPDATE snapshots SET path = ? WHERE id = ?")
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
        let r = sqlx::query("UPDATE snapshots SET deleted_at = ? WHERE id = ?")
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

    async fn seed(pool: &SqlitePool, id: &str) {
        let store = SqlxInstanceStore::new(pool.clone());
        store
            .create(InstanceRow {
                id: id.into(),
                owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
                cube_sandbox_id: None,
                template_id: "t".into(),
                status: InstanceStatus::Live,
                bearer_token: "b".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: None,
            })
            .await
            .unwrap();
    }

    fn snap(id: &str, parent: Option<&str>, source: &str) -> SnapshotRow {
        SnapshotRow {
            id: id.into(),
            owner_id: "legacy".into(),
            source_instance_id: source.into(),
            parent_snapshot_id: parent.map(String::from),
            kind: SnapshotKind::Manual,
            path: format!("/var/snaps/{id}"),
            host_ip: "10.0.0.1".into(),
            remote_uri: None,
            size_bytes: Some(1234),
            created_at: 100,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn insert_get_with_parent_and_remote_uri() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqliteSnapshotStore::new(pool);
        store.insert(&snap("s1", None, "i1")).await.unwrap();
        store.insert(&snap("s2", Some("s1"), "i1")).await.unwrap();
        store.update_remote_uri("s2", "s3://bucket/key/s2/").await.unwrap();
        let g = store.get("s2").await.unwrap().unwrap();
        assert_eq!(g.parent_snapshot_id.as_deref(), Some("s1"));
        assert_eq!(g.remote_uri.as_deref(), Some("s3://bucket/key/s2/"));
        assert_eq!(g.kind, SnapshotKind::Manual);
    }

    #[tokio::test]
    async fn list_excludes_deleted() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqliteSnapshotStore::new(pool);
        store.insert(&snap("s1", None, "i1")).await.unwrap();
        store.insert(&snap("s2", None, "i1")).await.unwrap();
        store.mark_deleted("s1", 200).await.unwrap();
        let listed = store.list_for_instance("i1").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "s2");
    }

    #[tokio::test]
    async fn update_path_after_pull() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqliteSnapshotStore::new(pool);
        store.insert(&snap("s1", None, "i1")).await.unwrap();
        store.update_path("s1", "/var/cache/s1").await.unwrap();
        let g = store.get("s1").await.unwrap().unwrap();
        assert_eq!(g.path, "/var/cache/s1");
    }

    #[tokio::test]
    async fn kind_round_trip() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqliteSnapshotStore::new(pool);
        let mut s = snap("s1", None, "i1");
        s.kind = SnapshotKind::Backup;
        store.insert(&s).await.unwrap();
        let g = store.get("s1").await.unwrap().unwrap();
        assert_eq!(g.kind, SnapshotKind::Backup);
    }
}
