//! Snapshot orchestration: wraps `CubeClient::snapshot_sandbox`, writes the
//! resulting row into the `snapshots` table tagged with the right `kind`,
//! and (for backups) hands the row to a `BackupSink::promote`.
//!
//! Cube owns the snapshot id; swarm uses Cube's `snapshotID` verbatim as
//! the row PK so there is no second namespace to translate between.

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;

use crate::error::SwarmError;
use crate::instance::{CreatedInstance, InstanceService, RestoreRequest};
use crate::now_secs;
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
    pub content_hash: Option<String>,
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
            content_hash: r.content_hash,
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

    /// Count of live (non-deleted) snapshots owned by `owner_id` for
    /// `instance_id`.  Used by the per-instance snapshot quota check
    /// in http/snapshots.rs (A6).
    pub async fn count_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<u64, SwarmError> {
        Ok(self.snapshots.count_for_instance(owner_id, instance_id).await?)
    }

    /// Take a snapshot of the given instance. `kind=manual`.
    pub async fn snapshot(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<SnapshotRow, SwarmError> {
        self.snapshot_with_kind(owner_id, instance_id, SnapshotKind::Manual, None)
            .await
    }

    /// Take a snapshot then `BackupSink::promote` it. `kind=backup`. If the
    /// sink returns a remote URI, the row is updated with it before return.
    pub async fn backup(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<SnapshotRow, SwarmError> {
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
    ) -> Result<Vec<SnapshotRow>, SwarmError> {
        // Confirm ownership of the instance up front. `get_for_owner`
        // returns `None` either when the row doesn't exist or when it
        // belongs to someone else — both surface as `NotFound`, which is
        // what we want (no oracle for cross-tenant existence).
        self.instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
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
    ) -> Result<SnapshotRow, SwarmError> {
        let mut row = self
            .snapshots
            .get(snapshot_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
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
    ) -> Result<CreatedInstance, SwarmError> {
        let mut row = self
            .snapshots
            .get(snapshot_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
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

        // A3: verify the on-disk bundle hashes to what we recorded at
        // snapshot-time.  Skip with a warn for legacy rows (NULL
        // content_hash, written before migration 0013) — those still
        // restore so existing backups don't bork mid-fleet.
        if let Some(expected) = row.content_hash.as_ref() {
            match hash_bundle(Path::new(&row.path)).await {
                Ok(actual) if &actual == expected => {
                    // Match — proceed.
                }
                Ok(actual) => {
                    tracing::error!(
                        snapshot_id = %row.id,
                        path = %row.path,
                        expected = %expected,
                        actual = %actual,
                        "snapshot content hash mismatch — refusing restore",
                    );
                    return Err(SwarmError::SnapshotCorrupt(row.id));
                }
                Err(e) => {
                    // Hashing failed (path moved, IO error etc.).
                    // Conservative: refuse restore — better a clear
                    // error than restoring un-verified bytes.
                    tracing::error!(
                        snapshot_id = %row.id,
                        path = %row.path,
                        error = %e,
                        "snapshot hash compute failed at restore — refusing",
                    );
                    return Err(SwarmError::SnapshotCorrupt(row.id));
                }
            }
        } else {
            tracing::warn!(
                snapshot_id = %row.id,
                "legacy snapshot, no integrity check",
            );
        }

        let source = self
            .instances
            .get(&row.source_instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;

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
                    // Carry the source's network profile through too —
                    // a snapshot+restore must not silently widen egress.
                    network_policy: source.network_policy,
                    // Same for the model list: the restored employee
                    // keeps its primary + failover models so the
                    // first /api/admin/configure push after restore
                    // matches what the source dyson was running.
                    models: source.models,
                    // Same for the tool include list — restore must
                    // not silently widen the toolbox.
                    tools: source.tools,
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
    ) -> Result<SnapshotRow, SwarmError> {
        let inst = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let sandbox = inst
            .cube_sandbox_id
            .as_deref()
            .ok_or(SwarmError::NotFound)?;
        let snap_name = format!("ckpt-{}", uuid::Uuid::new_v4().simple());
        let info = self.cube.snapshot_sandbox(sandbox, &snap_name).await?;

        // A3: compute a SHA-256 over the bundle directory (deterministic
        // walk + path-binding framing) for tamper detection at restore.
        // Best-effort: if the path doesn't exist on this host yet (some
        // CubeAPI deployments stage bytes elsewhere) we leave the hash
        // None and the restore-side check skips with a warn.  This keeps
        // legacy / non-local-cube setups working while still hardening
        // the common case.
        let content_hash = match hash_bundle(Path::new(&info.path)).await {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!(
                    snapshot_id = %info.snapshot_id,
                    path = %info.path,
                    error = %e,
                    "snapshot hash computation failed; row will carry content_hash=None",
                );
                None
            }
        };

        let mut row = SnapshotRow {
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
            content_hash: content_hash.clone(),
        };
        self.snapshots.insert(&row).await?;
        // Keep the row's `content_hash` consistent with what we just
        // persisted — callers occasionally re-read the row after this
        // returns.
        row.content_hash = content_hash;
        Ok(row)
    }
}

/// Hash a snapshot bundle at `dir`.  Walks every regular file under
/// `dir` in sorted-by-path order and feeds:
///
///   `len(path) || path || len(bytes) || bytes`
///
/// (each length as a 64-bit little-endian) into a SHA-256 hasher so
/// the digest binds the directory layout, not just the bytes.  Returns
/// the hex-encoded digest.
///
/// Errors out if `dir` doesn't exist or if any file read fails — the
/// caller catches the error and stores `content_hash=None`, matching
/// the legacy-row semantics.
async fn hash_bundle(dir: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};

    if !tokio::fs::metadata(dir).await?.is_dir() {
        return Err(std::io::Error::other("snapshot path is not a directory"));
    }
    // Walk recursively, collecting every regular file's path relative
    // to `dir`.  No external dep — std-only iter.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_files(dir, dir, &mut files).await?;
    files.sort();
    let mut hasher = Sha256::new();
    for rel in &files {
        let abs = dir.join(rel);
        let path_str = rel.to_string_lossy();
        let path_bytes = path_str.as_bytes();
        hasher.update((path_bytes.len() as u64).to_le_bytes());
        hasher.update(path_bytes);
        let bytes = tokio::fs::read(&abs).await?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    Ok(hex_lower(&digest))
}

/// Recursive directory walk into `out` (relative-to-`base` paths).
/// Skips symlinks (they're not part of the snapshot's "real" content
/// surface) and any non-regular files.
fn collect_files<'a>(
    base: &'a Path,
    cur: &'a Path,
    out: &'a mut Vec<std::path::PathBuf>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = tokio::fs::read_dir(cur).await?;
        while let Some(entry) = entries.next_entry().await? {
            let ft = entry.file_type().await?;
            let path = entry.path();
            if ft.is_dir() {
                collect_files(base, &path, out).await?;
            } else if ft.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                out.push(rel);
            }
            // Symlinks and special files are deliberately skipped.
        }
        Ok(())
    })
}

fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &c in b {
        s.push(HEX[(c >> 4) as usize] as char);
        s.push(HEX[(c & 0x0f) as usize] as char);
    }
    s
}

fn require_owner(row_owner: &str, caller_owner: &str) -> Result<(), SwarmError> {
    if caller_owner == "*" || row_owner == caller_owner {
        Ok(())
    } else {
        Err(SwarmError::NotFound)
    }
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
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
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
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
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
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> = Arc::new(
            crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap(),
        );
        let users: Arc<dyn crate::traits::UserStore> = Arc::new(
            crate::db::users::SqlxUserStore::new(pool.clone(), cipher_dir),
        );
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
            cube.clone(), instances.clone(), secrets, tokens, "http://t/llm",
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
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            })
            .await
            .unwrap();
        let _alice_snap = svc.snapshot("alice", &alice_inst.id).await.unwrap();

        let err = svc.list_for_instance("bob", &alice_inst.id).await.unwrap_err();
        assert!(matches!(err, SwarmError::NotFound));

        let visible = svc.list_for_instance("alice", &alice_inst.id).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].owner_id, "alice");
    }

    #[tokio::test]
    async fn count_for_instance_reflects_live_snapshots() {
        // A6 quota: the http handler relies on this method returning
        // a monotonically-increasing count as snapshots are taken.
        // Pin the round-trip from a service-level test so a future
        // refactor that drops the SnapshotStore::count_for_instance
        // call doesn't silently re-open the runaway-snapshot DoS.
        let (svc, isvc, _cube, _secrets, _instances, _snaps) = build().await;
        let created = isvc
            .create("legacy", CreateRequest {
                template_id: "t".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(svc.count_for_instance("legacy", &created.id).await.unwrap(), 0);
        for expected in 1u64..=3 {
            svc.snapshot("legacy", &created.id).await.unwrap();
            assert_eq!(
                svc.count_for_instance("legacy", &created.id).await.unwrap(),
                expected,
            );
        }
    }

    #[tokio::test]
    async fn hash_bundle_is_deterministic_and_path_binding() {
        // Sanity-pin the hash function: same dir → same digest;
        // touching a single file's content (or its name) flips the
        // digest.  This is the property `restore` relies on to
        // detect tampering — A3 in the security review.
        let dir1 = tempfile::tempdir().unwrap();
        tokio::fs::write(dir1.path().join("a.txt"), b"hello").await.unwrap();
        tokio::fs::write(dir1.path().join("b.bin"), b"world").await.unwrap();
        let h1 = super::hash_bundle(dir1.path()).await.unwrap();

        // Re-hash same dir → same digest.
        let h1b = super::hash_bundle(dir1.path()).await.unwrap();
        assert_eq!(h1, h1b);

        // Different dir, same content, same paths → same digest.
        let dir2 = tempfile::tempdir().unwrap();
        tokio::fs::write(dir2.path().join("a.txt"), b"hello").await.unwrap();
        tokio::fs::write(dir2.path().join("b.bin"), b"world").await.unwrap();
        let h2 = super::hash_bundle(dir2.path()).await.unwrap();
        assert_eq!(h1, h2);

        // Same content, different path → different digest (path-
        // binding framing).
        let dir3 = tempfile::tempdir().unwrap();
        tokio::fs::write(dir3.path().join("a.txt"), b"hello").await.unwrap();
        tokio::fs::write(dir3.path().join("c.bin"), b"world").await.unwrap();
        let h3 = super::hash_bundle(dir3.path()).await.unwrap();
        assert_ne!(h1, h3);

        // Mutated bytes → different digest.
        let dir4 = tempfile::tempdir().unwrap();
        tokio::fs::write(dir4.path().join("a.txt"), b"hello").await.unwrap();
        tokio::fs::write(dir4.path().join("b.bin"), b"WORLD").await.unwrap();
        let h4 = super::hash_bundle(dir4.path()).await.unwrap();
        assert_ne!(h1, h4);
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
                network_policy: crate::network_policy::NetworkPolicy::default(),
                mcp_servers: Vec::new(),
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
