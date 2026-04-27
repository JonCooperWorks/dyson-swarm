//! Snapshot orchestration: wraps `CubeClient::snapshot_sandbox`, writes the
//! resulting row into the `snapshots` table tagged with the right `kind`,
//! and (for backups) hands the row to a `BackupSink::promote`.
//!
//! Cube owns the snapshot id; warden uses Cube's `snapshotID` verbatim as
//! the row PK so there is no second namespace to translate between.

use std::sync::Arc;

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::snapshots as snap_db;
use crate::error::WardenError;
use crate::instance::{CreatedInstance, InstanceService, RestoreRequest};
use crate::traits::{BackupSink, CubeClient, InstanceStore, SnapshotKind, SnapshotRow};

#[derive(Clone)]
pub struct SnapshotService {
    cube: Arc<dyn CubeClient>,
    instances: Arc<dyn InstanceStore>,
    backup: Arc<dyn BackupSink>,
    instance_svc: Arc<InstanceService>,
    pool: SqlitePool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotView {
    pub id: String,
    pub source_instance_id: String,
    pub parent_snapshot_id: Option<String>,
    pub kind: String,
    pub path: String,
    pub host_ip: String,
    pub remote_uri: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: i64,
}

impl From<SnapshotRow> for SnapshotView {
    fn from(r: SnapshotRow) -> Self {
        Self {
            id: r.id,
            source_instance_id: r.source_instance_id,
            parent_snapshot_id: r.parent_snapshot_id,
            kind: r.kind.as_str().into(),
            path: r.path,
            host_ip: r.host_ip,
            remote_uri: r.remote_uri,
            size_bytes: r.size_bytes,
            created_at: r.created_at,
        }
    }
}

impl SnapshotService {
    pub fn new(
        cube: Arc<dyn CubeClient>,
        instances: Arc<dyn InstanceStore>,
        backup: Arc<dyn BackupSink>,
        instance_svc: Arc<InstanceService>,
        pool: SqlitePool,
    ) -> Self {
        Self {
            cube,
            instances,
            backup,
            instance_svc,
            pool,
        }
    }

    /// Take a snapshot of the given instance. `kind=manual`.
    pub async fn snapshot(&self, instance_id: &str) -> Result<SnapshotRow, WardenError> {
        self.snapshot_with_kind(instance_id, SnapshotKind::Manual, None)
            .await
    }

    /// Take a snapshot then `BackupSink::promote` it. `kind=backup`. If the
    /// sink returns a remote URI, the row is updated with it before return.
    pub async fn backup(&self, instance_id: &str) -> Result<SnapshotRow, WardenError> {
        let mut row = self
            .snapshot_with_kind(instance_id, SnapshotKind::Backup, None)
            .await?;
        if let Some(uri) = self.backup.promote(&row).await? {
            snap_db::update_remote_uri(&self.pool, &row.id, &uri).await?;
            row.remote_uri = Some(uri);
        }
        Ok(row)
    }

    /// Manual rehydration: ask the backup sink to download the snapshot
    /// bundle to its local cache, persist the new path on the row, and
    /// return the updated row. Idempotent — a sink whose `pull` is a no-op
    /// (the local sink) will simply return the row unchanged.
    pub async fn pull(&self, snapshot_id: &str) -> Result<SnapshotRow, WardenError> {
        let mut row = snap_db::get(&self.pool, snapshot_id)
            .await?
            .ok_or(WardenError::NotFound)?;
        let new_path = self.backup.pull(&row).await?;
        let new_path_str = new_path.display().to_string();
        if new_path_str != row.path {
            snap_db::update_path(&self.pool, &row.id, &new_path_str).await?;
            row.path = new_path_str;
        }
        Ok(row)
    }

    /// Restore from a previously-taken snapshot. Returns a brand-new
    /// instance (with its own id, bearer, proxy_token). The row's `path`
    /// must be present locally on the Cube host; if it isn't and the row
    /// has a `remote_uri`, the sink's `pull` is invoked first.
    pub async fn restore(
        &self,
        snapshot_id: &str,
        ttl_seconds: Option<i64>,
        env: std::collections::BTreeMap<String, String>,
    ) -> Result<CreatedInstance, WardenError> {
        let mut row = snap_db::get(&self.pool, snapshot_id)
            .await?
            .ok_or(WardenError::NotFound)?;

        // If the local path is missing and we have a remote URI, ask the
        // sink to rehydrate. The sink updates the row's `path` to wherever
        // it dropped the bytes; persist that.
        let needs_pull = !std::path::Path::new(&row.path).exists() && row.remote_uri.is_some();
        if needs_pull {
            let new_path = self.backup.pull(&row).await?;
            let new_path_str = new_path.display().to_string();
            snap_db::update_path(&self.pool, &row.id, &new_path_str).await?;
            row.path = new_path_str;
        }

        let source = self
            .instances
            .get(&row.source_instance_id)
            .await?
            .ok_or(WardenError::NotFound)?;

        self.instance_svc
            .restore(RestoreRequest {
                template_id: source.template_id,
                snapshot_path: row.path.into(),
                source_instance_id: Some(row.source_instance_id),
                env,
                ttl_seconds,
            })
            .await
    }

    async fn snapshot_with_kind(
        &self,
        instance_id: &str,
        kind: SnapshotKind,
        parent: Option<String>,
    ) -> Result<SnapshotRow, WardenError> {
        let inst = self
            .instances
            .get(instance_id)
            .await?
            .ok_or(WardenError::NotFound)?;
        let sandbox = inst
            .cube_sandbox_id
            .as_deref()
            .ok_or(WardenError::NotFound)?;
        let snap_name = format!("ckpt-{}", uuid::Uuid::new_v4().simple());
        let info = self.cube.snapshot_sandbox(sandbox, &snap_name).await?;

        let row = SnapshotRow {
            id: info.snapshot_id,
            source_instance_id: instance_id.into(),
            parent_snapshot_id: parent,
            kind,
            path: info.path,
            host_ip: info.host_ip,
            remote_uri: None,
            size_bytes: None,
            created_at: now_secs(),
            deleted_at: None,
        };
        snap_db::insert(&self.pool, &row).await?;
        Ok(row)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::error::CubeError;
    use crate::instance::CreateRequest;
    use crate::traits::{
        CreateSandboxArgs, InstanceStore, SandboxInfo, SecretStore, SnapshotInfo, TokenStore,
    };

    struct MockCube {
        next: Mutex<u32>,
        deleted: Mutex<Vec<(String, String)>>,
    }

    impl MockCube {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next: Mutex::new(0),
                deleted: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl CubeClient for MockCube {
        async fn create_sandbox(
            &self,
            _: CreateSandboxArgs,
        ) -> Result<SandboxInfo, CubeError> {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            let sid = format!("sb-{}", *n);
            Ok(SandboxInfo {
                sandbox_id: sid.clone(),
                host_ip: "10.0.0.5".into(),
                url: format!("https://{sid}.cube.test"),
            })
        }
        async fn destroy_sandbox(&self, _: &str) -> Result<(), CubeError> {
            Ok(())
        }
        async fn snapshot_sandbox(
            &self,
            sandbox_id: &str,
            _name: &str,
        ) -> Result<SnapshotInfo, CubeError> {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            let id = format!("snap-{}-{}", sandbox_id, *n);
            Ok(SnapshotInfo {
                snapshot_id: id.clone(),
                path: format!("/var/snaps/{id}"),
                host_ip: "10.0.0.5".into(),
            })
        }
        async fn delete_snapshot(&self, id: &str, host_ip: &str) -> Result<(), CubeError> {
            self.deleted
                .lock()
                .unwrap()
                .push((id.into(), host_ip.into()));
            Ok(())
        }
    }

    async fn build() -> (
        SnapshotService,
        Arc<InstanceService>,
        Arc<MockCube>,
        Arc<dyn SecretStore>,
        Arc<dyn InstanceStore>,
        SqlitePool,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
        let isvc = Arc::new(InstanceService::new(
            cube.clone(),
            instances.clone(),
            secrets.clone(),
            tokens,
            "http://t/llm",
            3600,
        ));
        let sink: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let svc = SnapshotService::new(cube.clone(), instances.clone(), sink, isvc.clone(), pool.clone());
        (svc, isvc, cube, secrets, instances, pool)
    }

    #[tokio::test]
    async fn snapshot_writes_manual_row_with_cube_id() {
        let (svc, isvc, _cube, _secrets, _instances, pool) = build().await;
        let created = isvc
            .create(CreateRequest {
                template_id: "t".into(),
                env: BTreeMap::new(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        let snap = svc.snapshot(&created.id).await.unwrap();
        assert!(snap.id.starts_with("snap-sb-1-"));
        assert_eq!(snap.kind, SnapshotKind::Manual);
        assert_eq!(snap.source_instance_id, created.id);
        let from_db = snap_db::get(&pool, &snap.id).await.unwrap().unwrap();
        assert_eq!(from_db.kind, SnapshotKind::Manual);
        assert_eq!(from_db.path, snap.path);
    }

    #[tokio::test]
    async fn backup_writes_backup_row_local_sink_no_remote_uri() {
        let (svc, isvc, _cube, _secrets, _instances, pool) = build().await;
        let created = isvc
            .create(CreateRequest {
                template_id: "t".into(),
                env: BTreeMap::new(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        let snap = svc.backup(&created.id).await.unwrap();
        assert_eq!(snap.kind, SnapshotKind::Backup);
        // Local sink: promote returns None, so no remote_uri.
        assert!(snap.remote_uri.is_none());
        let from_db = snap_db::get(&pool, &snap.id).await.unwrap().unwrap();
        assert_eq!(from_db.kind, SnapshotKind::Backup);
        assert!(from_db.remote_uri.is_none());
    }

    #[tokio::test]
    async fn restore_creates_new_instance_with_carried_secrets() {
        let (svc, isvc, _cube, secrets, _instances, _pool) = build().await;
        let src = isvc
            .create(CreateRequest {
                template_id: "t".into(),
                env: BTreeMap::new(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        secrets.put(&src.id, "K", "carry").await.unwrap();
        // Snapshot path won't exist on disk in the test, but it also has no
        // remote_uri, so the restore proceeds without calling pull.
        let snap = svc.snapshot(&src.id).await.unwrap();

        let new_inst = svc.restore(&snap.id, Some(60), BTreeMap::new()).await.unwrap();
        assert_ne!(new_inst.id, src.id);
        let copied = secrets.list(&new_inst.id).await.unwrap();
        assert_eq!(copied, vec![("K".into(), "carry".into())]);
    }
}
