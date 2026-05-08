//! Sealed swarm-side mirror for selected Dyson state files.
//!
//! Dyson stays authoritative for its local workspace. In swarm mode it
//! can mirror selected file changes here via an internal endpoint; the
//! service validates the namespace/path, seals every body under the
//! owning user's age cipher, and stores only metadata in SQLite.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sqlx::SqlitePool;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::db::state_files::{self as store, StateFileRow};
use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::now_secs;
use crate::webhooks::AGE_ARMOR_PREFIX;

#[derive(Debug, thiserror::Error)]
pub enum StateFileError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("state file i/o: {0}")]
    Io(String),
    #[error("invalid state file: {0}")]
    Invalid(String),
}

impl From<std::io::Error> for StateFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Clone)]
pub struct StateFileService {
    pool: SqlitePool,
    root: PathBuf,
    ciphers: Arc<dyn CipherDirectory>,
}

#[derive(Debug, Clone)]
pub struct StateFileMeta<'a> {
    pub instance_id: &'a str,
    pub owner_id: &'a str,
    pub namespace: &'a str,
    pub path: &'a str,
    pub mime: Option<&'a str>,
    pub updated_at: i64,
}

impl StateFileService {
    pub fn new(pool: SqlitePool, root: PathBuf, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self {
            pool,
            root,
            ciphers,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn body_path_for(&self, row: &StateFileRow) -> PathBuf {
        self.root.join(&row.body_path)
    }

    pub async fn ingest(
        &self,
        meta: StateFileMeta<'_>,
        body: &[u8],
    ) -> Result<StateFileRow, StateFileError> {
        validate_namespace(meta.namespace)?;
        validate_relative_path(meta.path)?;
        validate_body(meta.namespace, meta.path, body)?;
        let body_path = relative_body_path(meta.instance_id, meta.namespace, meta.path)?;
        let cipher = self
            .ciphers
            .for_user(meta.owner_id)
            .map_err(|e| StateFileError::Io(format!("owner cipher: {e}")))?;
        let on_disk = cipher
            .seal(body)
            .map_err(|e| StateFileError::Io(format!("seal: {e}")))?;
        if !on_disk.starts_with(AGE_ARMOR_PREFIX) {
            return Err(StateFileError::Io("sealed body missing age armor".into()));
        }
        self.write_body(&body_path, &on_disk).await?;
        let bytes = i64::try_from(body.len()).unwrap_or(i64::MAX);
        Ok(store::upsert(
            &self.pool,
            store::UpsertSpec {
                instance_id: meta.instance_id,
                owner_id: meta.owner_id,
                namespace: meta.namespace,
                path: meta.path,
                mime: meta.mime,
                bytes,
                body_path: &body_path,
                updated_at: meta.updated_at,
                synced_at: now_secs(),
            },
        )
        .await?)
    }

    pub async fn tombstone(&self, meta: StateFileMeta<'_>) -> Result<StateFileRow, StateFileError> {
        validate_namespace(meta.namespace)?;
        validate_relative_path(meta.path)?;
        let body_path = relative_body_path(meta.instance_id, meta.namespace, meta.path)?;
        let _ = fs::remove_file(self.root.join(&body_path)).await;
        Ok(store::tombstone(
            &self.pool,
            meta.instance_id,
            meta.owner_id,
            meta.namespace,
            meta.path,
            &body_path,
            meta.updated_at,
            now_secs(),
        )
        .await?)
    }

    pub async fn find(
        &self,
        instance_id: &str,
        namespace: &str,
        path: &str,
    ) -> Result<Option<StateFileRow>, StateFileError> {
        Ok(store::find(&self.pool, instance_id, namespace, path).await?)
    }

    pub async fn list_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<StateFileRow>, StateFileError> {
        Ok(store::list_for_instance(&self.pool, instance_id).await?)
    }

    pub async fn read_body(&self, row: &StateFileRow) -> Result<Option<Vec<u8>>, StateFileError> {
        if row.deleted_at.is_some() {
            return Ok(None);
        }
        let path = self.body_path_for(row);
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !bytes.starts_with(AGE_ARMOR_PREFIX) {
            tracing::warn!(
                instance = %row.instance_id,
                namespace = %row.namespace,
                path = %row.path,
                "state file cache: refusing unsealed body",
            );
            return Ok(None);
        }
        let cipher = self
            .ciphers
            .for_user(&row.owner_id)
            .map_err(|e| StateFileError::Io(format!("owner cipher: {e}")))?;
        let plain = cipher
            .open(&bytes)
            .map_err(|e| StateFileError::Io(format!("open: {e}")))?;
        Ok(Some(plain))
    }

    pub async fn read_body_for_replay(
        &self,
        row: &StateFileRow,
    ) -> Result<Option<Vec<u8>>, StateFileError> {
        if row.deleted_at.is_some() {
            return Ok(None);
        }
        let path = self.body_path_for(row);
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let cipher = self
            .ciphers
            .for_user(&row.owner_id)
            .map_err(|e| StateFileError::Io(format!("owner cipher: {e}")))?;
        if bytes.starts_with(AGE_ARMOR_PREFIX) {
            let plain = cipher
                .open(&bytes)
                .map_err(|e| StateFileError::Io(format!("open: {e}")))?;
            return Ok(Some(plain));
        }

        tracing::warn!(
            instance = %row.instance_id,
            namespace = %row.namespace,
            path = %row.path,
            "state file cache: replaying legacy unsealed body and re-sealing it",
        );
        let sealed = cipher
            .seal(&bytes)
            .map_err(|e| StateFileError::Io(format!("seal legacy body: {e}")))?;
        if !sealed.starts_with(AGE_ARMOR_PREFIX) {
            return Err(StateFileError::Io(
                "sealed legacy body missing age armor".into(),
            ));
        }
        self.write_body(&row.body_path, &sealed).await?;
        Ok(Some(bytes))
    }

    async fn write_body(&self, rel_path: &str, bytes: &[u8]) -> Result<(), StateFileError> {
        let abs = self.root.join(rel_path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).await?;
        }
        let tmp = abs.with_extension("body.tmp");
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp, &abs).await?;
        Ok(())
    }
}

fn validate_namespace(namespace: &str) -> Result<(), StateFileError> {
    match namespace {
        "workspace" | "chats" => Ok(()),
        _ => Err(StateFileError::Invalid(format!(
            "unsupported namespace {namespace:?}"
        ))),
    }
}

fn validate_relative_path(path: &str) -> Result<(), StateFileError> {
    if path.is_empty() || path.len() > 2048 || path.contains('\0') {
        return Err(StateFileError::Invalid(
            "bad path length or nul byte".into(),
        ));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(StateFileError::Invalid(
            "absolute paths are not accepted".into(),
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {}
            _ => {
                return Err(StateFileError::Invalid(
                    "paths must be clean relative paths".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn is_zero_byte_chat_transcript(namespace: &str, path: &str, body: &[u8]) -> bool {
    namespace == "chats" && path.ends_with("/transcript.json") && body.is_empty()
}

fn validate_body(namespace: &str, path: &str, body: &[u8]) -> Result<(), StateFileError> {
    if is_zero_byte_chat_transcript(namespace, path, body) {
        return Err(StateFileError::Invalid(
            "zero-byte chat transcript rejected".into(),
        ));
    }
    Ok(())
}

fn relative_body_path(
    instance_id: &str,
    namespace: &str,
    path: &str,
) -> Result<String, StateFileError> {
    if instance_id.is_empty()
        || instance_id.contains('/')
        || instance_id.contains('\\')
        || instance_id.contains("..")
    {
        return Err(StateFileError::Invalid("bad instance id".into()));
    }
    validate_namespace(namespace)?;
    validate_relative_path(path)?;
    let encoded = URL_SAFE_NO_PAD.encode(path.as_bytes());
    Ok(format!("state/{instance_id}/{namespace}/{encoded}.body"))
}

pub type StateFiles = Arc<StateFileService>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn svc() -> (StateFileService, tempfile::TempDir, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let ciphers: Arc<dyn CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        (
            StateFileService::new(pool, dir.path().to_path_buf(), ciphers),
            dir,
            keys,
        )
    }

    fn meta<'a>(path: &'a str) -> StateFileMeta<'a> {
        StateFileMeta {
            instance_id: "inst-a",
            owner_id: ALICE,
            namespace: "workspace",
            path,
            mime: Some("text/markdown"),
            updated_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn ingest_seals_even_empty_bodies() {
        let (svc, _tmp, _keys) = svc().await;
        let row = svc.ingest(meta("MEMORY.md"), b"").await.unwrap();
        let stored = fs::read(svc.body_path_for(&row)).await.unwrap();
        assert!(stored.starts_with(AGE_ARMOR_PREFIX));
        assert_eq!(svc.read_body(&row).await.unwrap().unwrap(), b"");
        assert_eq!(row.bytes, 0);
    }

    #[tokio::test]
    async fn rejects_zero_byte_chat_transcripts() {
        let (svc, _tmp, _keys) = svc().await;
        let mut chat_meta = meta("c-1/transcript.json");
        chat_meta.namespace = "chats";
        chat_meta.mime = Some("application/json");

        let err = svc.ingest(chat_meta, b"").await.unwrap_err();

        assert!(matches!(err, StateFileError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let (svc, _tmp, _keys) = svc().await;
        let err = svc.ingest(meta("../MEMORY.md"), b"nope").await.unwrap_err();
        assert!(matches!(err, StateFileError::Invalid(_)));
    }

    #[tokio::test]
    async fn tombstone_marks_row_and_removes_body() {
        let (svc, _tmp, _keys) = svc().await;
        let row = svc.ingest(meta("MEMORY.md"), b"hello").await.unwrap();
        assert!(svc.body_path_for(&row).exists());
        let row = svc.tombstone(meta("MEMORY.md")).await.unwrap();
        assert!(row.deleted_at.is_some());
        assert!(svc.read_body(&row).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_for_instance_returns_workspace_and_chats() {
        let (svc, _tmp, _keys) = svc().await;
        svc.ingest(meta("memory/SOUL.md"), b"remember")
            .await
            .unwrap();
        let mut chat_meta = meta("c-1/transcript.json");
        chat_meta.namespace = "chats";
        chat_meta.mime = Some("application/json");
        svc.ingest(chat_meta, b"[]").await.unwrap();

        let rows = svc.list_for_instance("inst-a").await.unwrap();
        let keys: Vec<_> = rows
            .iter()
            .map(|r| format!("{}:{}", r.namespace, r.path))
            .collect();
        assert_eq!(
            keys,
            vec![
                "chats:c-1/transcript.json".to_string(),
                "workspace:memory/SOUL.md".to_string(),
            ]
        );
    }
}
