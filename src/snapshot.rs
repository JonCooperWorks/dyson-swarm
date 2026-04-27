//! Snapshot orchestration: wraps `CubeClient::snapshot_sandbox`, writes the
//! resulting row into the `snapshots` table tagged with the right `kind`,
//! and (for backups) hands the row to a `BackupSink::promote`.
//!
//! Cube owns the snapshot id; warden uses Cube's `snapshotID` verbatim as
//! the row PK so there is no second namespace to translate between.

use std::sync::Arc;

use serde::Serialize;

use crate::error::WardenError;
use crate::instance::{CreatedInstance, InstanceService, RestoreRequest};
use crate::traits::{
    BackupSink, CubeClient, InstanceStore, SnapshotKind, SnapshotRow, SnapshotStore,
};

#[derive(Clone)]
pub struct SnapshotService {
    cube: Arc<dyn CubeClient>,
    instances: Arc<dyn InstanceStore>,
    snapshots: Arc<dyn SnapshotStore>,
    backup: Arc<dyn BackupSink>,
    instance_svc: Arc<InstanceService>,
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
        snapshots: Arc<dyn SnapshotStore>,
        backup: Arc<dyn BackupSink>,
        instance_svc: Arc<InstanceService>,
    ) -> Self {
        Self {
            cube,
            instances,
            snapshots,
            backup,
            instance_svc,
        }
    }

    /// Take a snapshot of the given instance. `kind=manual`.
    pub async fn snapshot(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<SnapshotRow, WardenError> {
        self.snapshot_with_kind(owner_id, instance_id, SnapshotKind::Manual, None)
            .await
    }

    /// Take a snapshot then `BackupSink::promote` it. `kind=backup`. If the
    /// sink returns a remote URI, the row is updated with it before return.
    pub async fn backup(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<SnapshotRow, WardenError> {
        let mut row = self
            .snapshot_with_kind(owner_id, instance_id, SnapshotKind::Backup, None)
            .await?;
        if let Some(uri) = self.backup.promote(&row).await? {
            self.snapshots.update_remote_uri(&row.id, &uri).await?;
            row.remote_uri = Some(uri);
        }
        Ok(row)
    }

    /// Owner-scoped list of snapshots for a single instance. The caller's
    /// `owner_id` must own the instance (or be the system sentinel `"*"`);
    /// otherwise we return `NotFound` so the existence of someone else's
    /// instance isn't an oracle. Snapshots whose `owner_id` doesn't match
    /// are filtered out — the store-level `list_for_instance` doesn't gate
    /// on ownership and we don't want to leak rows that share an
    /// `instance_id` after a restore-then-destroy.
    pub async fn list_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<Vec<SnapshotRow>, WardenError> {
        // Confirm ownership of the instance up front. `get_for_owner`
        // returns `None` either when the row doesn't exist or when it
        // belongs to someone else — both surface as `NotFound`, which is
        // what we want (no oracle for cross-tenant existence).
        self.instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(WardenError::NotFound)?;
        let rows = self.snapshots.list_for_instance(instance_id).await?;
        Ok(rows
            .into_iter()
            .filter(|r| owner_id == "*" || r.owner_id == owner_id)
            .collect())
    }

    /// Manual rehydration: ask the backup sink to download the snapshot
    /// bundle to its local cache, persist the new path on the row, and
    /// return the updated row. Idempotent — a sink whose `pull` is a no-op
    /// (the local sink) will simply return the row unchanged.
    pub async fn pull(
        &self,
        owner_id: &str,
        snapshot_id: &str,
    ) -> Result<SnapshotRow, WardenError> {
        let mut row = self
            .snapshots
            .get(snapshot_id)
            .await?
            .ok_or(WardenError::NotFound)?;
        require_owner(&row.owner_id, owner_id)?;
        let new_path = self.backup.pull(&row).await?;
        let new_path_str = new_path.display().to_string();
        if new_path_str != row.path {
            self.snapshots.update_path(&row.id, &new_path_str).await?;
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
        owner_id: &str,
        snapshot_id: &str,
        ttl_seconds: Option<i64>,
        env: std::collections::BTreeMap<String, String>,
    ) -> Result<CreatedInstance, WardenError> {
        let mut row = self
            .snapshots
            .get(snapshot_id)
            .await?
            .ok_or(WardenError::NotFound)?;
        require_owner(&row.owner_id, owner_id)?;

        // If the local path is missing and we have a remote URI, ask the
        // sink to rehydrate. The sink updates the row's `path` to wherever
        // it dropped the bytes; persist that.
        let needs_pull = !std::path::Path::new(&row.path).exists() && row.remote_uri.is_some();
        if needs_pull {
            let new_path = self.backup.pull(&row).await?;
            let new_path_str = new_path.display().to_string();
            self.snapshots.update_path(&row.id, &new_path_str).await?;
            row.path = new_path_str;
        }

        let source = self
            .instances
            .get(&row.source_instance_id)
            .await?
            .ok_or(WardenError::NotFound)?;

        self.instance_svc
            .restore(
                owner_id,
                RestoreRequest {
                    template_id: source.template_id,
                    snapshot_path: row.path.into(),
                    source_instance_id: Some(row.source_instance_id),
                    // Carry employee identity across the snapshot/restore
                    // boundary — same person, fresh sandbox.
                    name: Some(source.name),
                    task: Some(source.task),
                    env,
                    ttl_seconds,
                },
            )
            .await
    }

    async fn snapshot_with_kind(
        &self,
        owner_id: &str,
        instance_id: &str,
        kind: SnapshotKind,
        parent: Option<String>,
    ) -> Result<SnapshotRow, WardenError> {
        let inst = self
            .instances
            .get_for_owner(owner_id, instance_id)
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
            owner_id: inst.owner_id.clone(),
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
        self.snapshots.insert(&row).await?;
        Ok(row)
    }
}

fn require_owner(row_owner: &str, caller_owner: &str) -> Result<(), WardenError> {
    if caller_owner == "*" || row_owner == caller_owner {
        Ok(())
    } else {
        Err(WardenError::NotFound)
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
    use crate::db::snapshots::SqliteSnapshotStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::error::CubeError;
    use crate::instance::{CreateRequest, ENV_MODEL};
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
        Arc<dyn SnapshotStore>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let isvc = Arc::new(InstanceService::new(
            cube.clone(),
            instances.clone(),
            secrets.clone(),
            tokens,
            "http://t/llm",
            3600,
        ));
        let sink: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let svc = SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps.clone(),
            sink,
            isvc.clone(),
        );
        (svc, isvc, cube, secrets, instances, snaps)
    }

    fn env_with_model() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(ENV_MODEL.into(), "anthropic/claude-sonnet-4-5".into());
        m
    }

    #[tokio::test]
    async fn snapshot_writes_manual_row_with_cube_id() {
        let (svc, isvc, _cube, _secrets, _instances, snaps) = build().await;
        let created = isvc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        let snap = svc.snapshot("legacy", &created.id).await.unwrap();
        assert!(snap.id.starts_with("snap-sb-1-"));
        assert_eq!(snap.kind, SnapshotKind::Manual);
        assert_eq!(snap.source_instance_id, created.id);
        let from_db = snaps.get(&snap.id).await.unwrap().unwrap();
        assert_eq!(from_db.kind, SnapshotKind::Manual);
        assert_eq!(from_db.path, snap.path);
    }

    #[tokio::test]
    async fn backup_writes_backup_row_local_sink_no_remote_uri() {
        let (svc, isvc, _cube, _secrets, _instances, snaps) = build().await;
        let created = isvc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        let snap = svc.backup("legacy", &created.id).await.unwrap();
        assert_eq!(snap.kind, SnapshotKind::Backup);
        // Local sink: promote returns None, so no remote_uri.
        assert!(snap.remote_uri.is_none());
        let from_db = snaps.get(&snap.id).await.unwrap().unwrap();
        assert_eq!(from_db.kind, SnapshotKind::Backup);
        assert!(from_db.remote_uri.is_none());
    }

    #[tokio::test]
    async fn list_for_instance_returns_only_owners_rows() {
        // Owner-isolation: tenant "alice" creates an instance and snaps it;
        // tenant "bob" must 404 on the same instance id.  Both users have
        // to exist in `users` for the FK on instances.owner_id; the
        // legacy seeded user wouldn't suffice here because we need two.
        use crate::traits::{UserRow, UserStatus};
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn crate::traits::UserStore> =
            Arc::new(crate::db::users::SqlxUserStore::new(pool.clone()));
        for sub in ["alice", "bob"] {
            users
                .create(UserRow {
                    id: sub.into(),
                    subject: sub.into(),
                    email: Some(format!("{sub}@test")),
                    display_name: Some(sub.into()),
                    status: UserStatus::Active,
                    created_at: 0,
                    activated_at: Some(0),
                    last_seen_at: None,
                    openrouter_key_id: None,
                    openrouter_key_limit_usd: 10.0,
                })
                .await
                .unwrap();
        }

        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
        let snaps_store: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let isvc = Arc::new(InstanceService::new(
            cube.clone(), instances.clone(), secrets, tokens, "http://t/llm", 3600,
        ));
        let sink: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let svc = SnapshotService::new(
            cube, instances, snaps_store, sink, isvc.clone(),
        );

        let alice_inst = isvc
            .create("alice", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        let _alice_snap = svc.snapshot("alice", &alice_inst.id).await.unwrap();

        let err = svc.list_for_instance("bob", &alice_inst.id).await.unwrap_err();
        assert!(matches!(err, WardenError::NotFound));

        let visible = svc.list_for_instance("alice", &alice_inst.id).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].owner_id, "alice");
    }

    #[tokio::test]
    async fn restore_creates_new_instance_with_carried_secrets() {
        let (svc, isvc, _cube, secrets, _instances, _snaps) = build().await;
        let src = isvc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        secrets.put(&src.id, "K", "carry").await.unwrap();
        // Snapshot path won't exist on disk in the test, but it also has no
        // remote_uri, so the restore proceeds without calling pull.
        let snap = svc.snapshot("legacy", &src.id).await.unwrap();

        let new_inst = svc.restore("legacy", &snap.id, Some(60), BTreeMap::new()).await.unwrap();
        assert_ne!(new_inst.id, src.id);
        let copied = secrets.list(&new_inst.id).await.unwrap();
        assert_eq!(copied, vec![("K".into(), "carry".into())]);
    }
}
