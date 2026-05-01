//! S3BackupSink integration test.
//!
//! Skipped silently unless `MINIO_URL` is set. To run locally:
//!
//! ```bash
//! docker run --rm -p 9000:9000 -p 9001:9001 \
//!   -e MINIO_ROOT_USER=minioadmin \
//!   -e MINIO_ROOT_PASSWORD=minioadmin \
//!   minio/minio server /data --console-address :9001
//! mc alias set local http://127.0.0.1:9000 minioadmin minioadmin
//! mc mb local/dyson-test
//! MINIO_URL=http://127.0.0.1:9000 \
//! MINIO_BUCKET=dyson-test \
//! MINIO_ACCESS_KEY=minioadmin \
//! MINIO_SECRET_KEY=minioadmin \
//!   cargo test --test backup_s3_minio -- --nocapture
//! ```
//!
//! Walks: promote (upload bundle) → delete local cache → pull
//! (download bundle) → byte-for-byte compare → delete (cleanup).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use dyson_swarm::backup::s3::S3BackupSink;
use dyson_swarm::config::S3Config;
use dyson_swarm::error::CubeError;
use dyson_swarm::traits::{
    BackupSink, CreateSandboxArgs, CubeClient, SandboxInfo, SnapshotInfo, SnapshotKind, SnapshotRow,
};

struct StubCube;

#[async_trait]
impl CubeClient for StubCube {
    async fn create_sandbox(&self, _: CreateSandboxArgs) -> Result<SandboxInfo, CubeError> {
        unimplemented!()
    }
    async fn destroy_sandbox(&self, _: &str) -> Result<(), CubeError> {
        unimplemented!()
    }
    async fn snapshot_sandbox(&self, _: &str, _: &str) -> Result<SnapshotInfo, CubeError> {
        unimplemented!()
    }
    async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), CubeError> {
        // Deliberately a no-op so the test can run against MinIO without a
        // real Cube reachable on the network.
        Ok(())
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

#[tokio::test]
async fn promote_pull_delete_round_trip_against_minio() {
    let Some(endpoint) = env("MINIO_URL") else {
        eprintln!("MINIO_URL unset; skipping");
        return;
    };
    let bucket = env("MINIO_BUCKET").unwrap_or_else(|| "dyson-test".into());
    let access_key = env("MINIO_ACCESS_KEY").unwrap_or_else(|| "minioadmin".into());
    let secret_key = env("MINIO_SECRET_KEY").unwrap_or_else(|| "minioadmin".into());
    let region = env("MINIO_REGION").unwrap_or_else(|| "us-east-1".into());

    let snap_id = format!("snap-test-{}", uuid::Uuid::new_v4().simple());
    let bundle = tempdir();
    let mut original: HashMap<String, Vec<u8>> = HashMap::new();
    for (name, payload) in [
        ("metadata.json", b"{\"version\":1}".to_vec()),
        ("memory.bin", (0u8..=255).cycle().take(64 * 1024).collect()),
        ("disk.qcow2.part0", b"hello world".to_vec()),
    ] {
        let p = bundle.join(name);
        tokio::fs::write(&p, &payload).await.unwrap();
        original.insert(name.to_string(), payload);
    }

    let cache = tempdir();
    let cfg = S3Config {
        endpoint,
        region,
        bucket,
        prefix: format!("swarm-it/{}/", uuid::Uuid::new_v4().simple()),
        access_key_id: access_key,
        secret_access_key: secret_key,
        path_style: true,
    };
    let sink = S3BackupSink::new(&cfg, cache.clone(), Arc::new(StubCube)).unwrap();

    let row = SnapshotRow {
        id: snap_id.clone(),
        owner_id: "legacy".into(),
        source_instance_id: "i".into(),
        parent_snapshot_id: None,
        kind: SnapshotKind::Backup,
        path: bundle.display().to_string(),
        host_ip: "127.0.0.1".into(),
        remote_uri: None,
        size_bytes: None,
        created_at: 0,
        deleted_at: None,
        content_hash: None,
    };

    // promote → uri returned
    let uri = sink.promote(&row).await.expect("promote");
    let uri = uri.expect("local sink returns None; s3 must return Some");
    assert!(uri.starts_with("s3://"));

    // wipe local cache (which doesn't exist yet anyway)
    let _ = tokio::fs::remove_dir_all(cache.join(&snap_id)).await;

    // pull → bytes appear in cache
    let pulled = sink.pull(&row).await.expect("pull");
    assert!(pulled.exists());
    for (name, payload) in &original {
        let got = tokio::fs::read(pulled.join(name))
            .await
            .expect("read pulled");
        assert_eq!(got.as_slice(), payload.as_slice(), "{name} mismatch");
    }

    // pull is idempotent
    let pulled_again = sink.pull(&row).await.expect("pull idempotent");
    assert_eq!(pulled, pulled_again);

    // delete → remote prefix empty, cache gone
    sink.delete(&row).await.expect("delete");
    let after_pull = sink.pull(&row).await;
    assert!(
        matches!(after_pull, Err(dyson_swarm::error::BackupError::Missing)),
        "expected Missing after delete, got {after_pull:?}"
    );
}

fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "swarm-s3-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
