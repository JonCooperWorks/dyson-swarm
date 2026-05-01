//! `LocalDiskBackupSink` — backups stay on the Cube host's filesystem.
//!
//! - `promote`: no-op (returns `Ok(None)` — there is no remote URI).
//! - `pull`: no-op (returns the row's existing `path`; idempotent).
//! - `delete`: forwards to `CubeClient::delete_snapshot`. The brief calls
//!   for best-effort local-cache cleanup as well, but for the local sink
//!   the snapshot bytes live inside Cube's snapshot store, not in our
//!   `local_cache_dir` — Cube's delete is the only side effect.
//! - `list`: pulls from the orchestrator DB, not from the sink. The
//!   in-memory listing surface here is a deliberate no-op so the trait
//!   stays uniform with the S3 sink (step 9), which also defers listing
//!   to the DB.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::BackupError;
use crate::traits::{BackupSink, CubeClient, SnapshotRow};

#[derive(Clone)]
pub struct LocalDiskBackupSink {
    cube: Arc<dyn CubeClient>,
}

impl LocalDiskBackupSink {
    pub fn new(cube: Arc<dyn CubeClient>) -> Self {
        Self { cube }
    }
}

#[async_trait]
impl BackupSink for LocalDiskBackupSink {
    async fn promote(&self, _: &SnapshotRow) -> Result<Option<String>, BackupError> {
        Ok(None)
    }

    async fn pull(&self, snap: &SnapshotRow) -> Result<PathBuf, BackupError> {
        Ok(PathBuf::from(&snap.path))
    }

    async fn list(&self, _instance_id: &str) -> Result<Vec<SnapshotRow>, BackupError> {
        Ok(Vec::new())
    }

    async fn delete(&self, snap: &SnapshotRow) -> Result<(), BackupError> {
        self.cube
            .delete_snapshot(&snap.id, &snap.host_ip)
            .await
            .map_err(|e| BackupError::Sink(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::error::CubeError;
    use crate::traits::{CreateSandboxArgs, SandboxInfo, SnapshotInfo, SnapshotKind};

    #[derive(Default)]
    struct StubCube {
        deleted: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl CubeClient for StubCube {
        async fn create_sandbox(&self, _: CreateSandboxArgs) -> Result<SandboxInfo, CubeError> {
            unreachable!()
        }
        async fn destroy_sandbox(&self, _: &str) -> Result<(), CubeError> {
            unreachable!()
        }
        async fn snapshot_sandbox(&self, _: &str, _: &str) -> Result<SnapshotInfo, CubeError> {
            unreachable!()
        }
        async fn delete_snapshot(&self, id: &str, host_ip: &str) -> Result<(), CubeError> {
            self.deleted
                .lock()
                .unwrap()
                .push((id.to_owned(), host_ip.to_owned()));
            Ok(())
        }
    }

    fn snap() -> SnapshotRow {
        SnapshotRow {
            id: "snap-1".into(),
            owner_id: "legacy".into(),
            source_instance_id: "i".into(),
            parent_snapshot_id: None,
            kind: SnapshotKind::Manual,
            path: "/var/snaps/snap-1".into(),
            host_ip: "10.0.0.5".into(),
            remote_uri: None,
            size_bytes: None,
            created_at: 0,
            deleted_at: None,
            content_hash: None,
        }
    }

    #[tokio::test]
    async fn promote_returns_none_for_local() {
        let sink = LocalDiskBackupSink::new(Arc::new(StubCube::default()));
        assert!(sink.promote(&snap()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pull_is_passthrough() {
        let sink = LocalDiskBackupSink::new(Arc::new(StubCube::default()));
        let p = sink.pull(&snap()).await.unwrap();
        assert_eq!(p, PathBuf::from("/var/snaps/snap-1"));
    }

    #[tokio::test]
    async fn delete_forwards_to_cube() {
        let cube = Arc::new(StubCube::default());
        let sink = LocalDiskBackupSink::new(cube.clone());
        sink.delete(&snap()).await.unwrap();
        let calls = cube.deleted.lock().unwrap();
        assert_eq!(calls.as_slice(), [("snap-1".into(), "10.0.0.5".into())]);
    }
}
