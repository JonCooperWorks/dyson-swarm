//! `S3BackupSink` — S3-compatible storage via `rust-s3`.
//!
//! - `promote(snap)` walks `snap.path` (a directory of bundle files) and
//!   uploads each entry to `<prefix><snap.id>/<filename>` via
//!   `put_object_stream`, which auto-multiparts large objects. Returns the
//!   canonical `s3://<bucket>/<prefix><snap.id>/` URI.
//! - `pull(snap)` lists objects under that prefix and downloads each into
//!   `<local_cache_dir>/<snap.id>/`. Idempotent — if a non-empty cache
//!   directory already exists, it is returned as-is.
//! - `delete(snap)` removes every object under the prefix, best-effort
//!   removes the local cache dir, then forwards to
//!   `CubeClient::delete_snapshot` for the on-host bytes.
//! - `list` is intentionally a no-op; listings come from the `snapshots`
//!   table, not the sink.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

use crate::config::S3Config;
use crate::error::BackupError;
use crate::traits::{BackupSink, CubeClient, SnapshotRow};

#[derive(Clone)]
pub struct S3BackupSink {
    bucket: Box<Bucket>,
    prefix: String,
    cache_dir: PathBuf,
    cube: Arc<dyn CubeClient>,
}

impl S3BackupSink {
    pub fn new(
        cfg: &S3Config,
        cache_dir: PathBuf,
        cube: Arc<dyn CubeClient>,
    ) -> Result<Self, BackupError> {
        let region = Region::Custom {
            region: cfg.region.clone(),
            endpoint: cfg.endpoint.clone(),
        };
        let credentials = Credentials::new(
            Some(&cfg.access_key_id),
            Some(&cfg.secret_access_key),
            None,
            None,
            None,
        )
        .map_err(|e| BackupError::Sink(format!("aws-creds: {e}")))?;
        // rust-s3 0.37: `Bucket::new` returns `Box<Bucket>` directly.
        let mut bucket: Box<Bucket> = Bucket::new(&cfg.bucket, region, credentials)
            .map_err(|e| BackupError::Sink(format!("rust-s3: {e}")))?;
        if cfg.path_style {
            bucket = bucket.with_path_style();
        }
        Ok(Self {
            bucket,
            prefix: cfg.prefix.clone(),
            cache_dir,
            cube,
        })
    }

    fn key(&self, snapshot_id: &str, name: &str) -> String {
        format!("{}{}/{name}", self.prefix, snapshot_id)
    }

    fn snap_prefix(&self, snapshot_id: &str) -> String {
        format!("{}{}/", self.prefix, snapshot_id)
    }

    fn cache_path(&self, snapshot_id: &str) -> PathBuf {
        self.cache_dir.join(snapshot_id)
    }

    fn remote_uri(&self, snapshot_id: &str) -> String {
        format!(
            "s3://{}/{}{}/",
            self.bucket.name(),
            self.prefix,
            snapshot_id
        )
    }
}

fn map_io(e: std::io::Error) -> BackupError {
    BackupError::Io(e.to_string())
}

fn map_s3<E: std::fmt::Display>(e: E) -> BackupError {
    BackupError::Sink(e.to_string())
}

#[async_trait]
impl BackupSink for S3BackupSink {
    async fn promote(&self, snap: &SnapshotRow) -> Result<Option<String>, BackupError> {
        let local = PathBuf::from(&snap.path);
        let metadata = tokio::fs::metadata(&local).await.map_err(map_io)?;
        if !metadata.is_dir() {
            return Err(BackupError::Sink(format!(
                "snapshot path {} is not a directory",
                local.display()
            )));
        }
        let mut entries = tokio::fs::read_dir(&local).await.map_err(map_io)?;
        let mut uploaded = 0u32;
        while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
            let file_type = entry.file_type().await.map_err(map_io)?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|os| BackupError::Sink(format!("non-utf8 filename: {os:?}")))?;
            let key = self.key(&snap.id, &name);
            let mut file = tokio::fs::File::open(entry.path()).await.map_err(map_io)?;
            // A4: server-side encryption.  Always set
            // `x-amz-server-side-encryption: AES256` so even
            // misconfigured buckets (no default-encryption policy)
            // store the bytes encrypted at rest.  AES256 is the
            // SSE-S3 mode — keys managed by S3, no extra KMS round-
            // trip; the operator can swap to `aws:kms` via bucket
            // policy if they want managed keys.  rust-s3 0.37
            // exposes `put_object_stream_builder().with_header(...)`
            // for header injection; the request flows through the
            // same multipart code path as `put_object_stream`.
            let resp = self
                .bucket
                .put_object_stream_builder(&key)
                .with_content_type("application/octet-stream")
                .with_header(
                    http::HeaderName::from_static("x-amz-server-side-encryption"),
                    "AES256",
                )
                .map_err(map_s3)?
                .execute_stream(&mut file)
                .await
                .map_err(map_s3)?;
            if !(200..300).contains(&resp.status_code()) {
                return Err(BackupError::Sink(format!(
                    "put_object_stream {} returned {}",
                    key,
                    resp.status_code()
                )));
            }
            uploaded += 1;
        }
        if uploaded == 0 {
            return Err(BackupError::Sink(format!(
                "snapshot path {} contains no files",
                local.display()
            )));
        }
        Ok(Some(self.remote_uri(&snap.id)))
    }

    async fn pull(&self, snap: &SnapshotRow) -> Result<PathBuf, BackupError> {
        let dst = self.cache_path(&snap.id);
        if dst.exists() && cache_is_populated(&dst).await? {
            return Ok(dst);
        }
        tokio::fs::create_dir_all(&dst).await.map_err(map_io)?;
        let prefix = self.snap_prefix(&snap.id);
        let pages = self
            .bucket
            .list(prefix.clone(), None)
            .await
            .map_err(map_s3)?;
        let mut downloaded = 0u32;
        for page in pages {
            for obj in page.contents {
                let name = obj.key.strip_prefix(&prefix).unwrap_or(&obj.key);
                if name.is_empty() {
                    continue;
                }
                let dst_file = dst.join(name);
                if let Some(parent) = dst_file.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
                }
                let resp = self.bucket.get_object(&obj.key).await.map_err(map_s3)?;
                if !(200..300).contains(&resp.status_code()) {
                    return Err(BackupError::Sink(format!(
                        "get_object {} returned {}",
                        obj.key,
                        resp.status_code()
                    )));
                }
                tokio::fs::write(&dst_file, resp.as_slice())
                    .await
                    .map_err(map_io)?;
                downloaded += 1;
            }
        }
        if downloaded == 0 {
            return Err(BackupError::Missing);
        }
        Ok(dst)
    }

    async fn list(&self, _instance_id: &str) -> Result<Vec<SnapshotRow>, BackupError> {
        Ok(Vec::new())
    }

    async fn delete(&self, snap: &SnapshotRow) -> Result<(), BackupError> {
        let prefix = self.snap_prefix(&snap.id);
        let pages = self
            .bucket
            .list(prefix.clone(), None)
            .await
            .map_err(map_s3)?;
        for page in pages {
            for obj in page.contents {
                let _ = self.bucket.delete_object(&obj.key).await;
            }
        }
        let _ = tokio::fs::remove_dir_all(self.cache_path(&snap.id)).await;
        self.cube
            .delete_snapshot(&snap.id, &snap.host_ip)
            .await
            .map_err(|e| BackupError::Sink(e.to_string()))?;
        Ok(())
    }
}

async fn cache_is_populated(p: &std::path::Path) -> Result<bool, BackupError> {
    let mut entries = tokio::fs::read_dir(p).await.map_err(map_io)?;
    Ok(entries.next_entry().await.map_err(map_io)?.is_some())
}
