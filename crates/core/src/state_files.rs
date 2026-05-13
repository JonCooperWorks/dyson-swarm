//! Sealed swarm-side mirror for selected Dyson state files.
//!
//! In swarm mode Dyson keeps local workspace and chat files as a
//! hot-cache projection and mirrors selected durable file changes here
//! via an internal endpoint. The service validates namespace/path, seals
//! every body under the owning user's age cipher, and stores the sealed
//! body in the swarm store so replay is not pinned to a particular server.
//! Swarm is the durable source of truth for these mirrored files.

use std::path::{Component, Path};
use std::sync::Arc;

use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{StateFileRow, StateFileStore, StateFileUpsertSpec};
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
    store: Arc<dyn StateFileStore>,
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
    pub fn new(store: Arc<dyn StateFileStore>, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self { store, ciphers }
    }

    pub async fn ingest(
        &self,
        meta: StateFileMeta<'_>,
        body: &[u8],
    ) -> Result<StateFileRow, StateFileError> {
        validate_instance_id(meta.instance_id)?;
        validate_state_file_path(meta.namespace, meta.path)?;
        validate_body(meta.namespace, meta.path, body)?;
        if let Some(existing) = self.preserve_existing_chat_row(&meta, body).await? {
            return Ok(existing);
        }
        let cipher = self
            .ciphers
            .for_user(meta.owner_id)
            .map_err(|e| StateFileError::Io(format!("owner cipher: {e}")))?;
        let sealed_body = cipher
            .seal(body)
            .map_err(|e| StateFileError::Io(format!("seal: {e}")))?;
        if !sealed_body.starts_with(AGE_ARMOR_PREFIX) {
            return Err(StateFileError::Io("sealed body missing age armor".into()));
        }
        let bytes = i64::try_from(body.len()).unwrap_or(i64::MAX);
        Ok(self
            .store
            .upsert(StateFileUpsertSpec {
                instance_id: meta.instance_id,
                owner_id: meta.owner_id,
                namespace: meta.namespace,
                path: meta.path,
                mime: meta.mime,
                bytes,
                body_ciphertext: &sealed_body,
                updated_at: meta.updated_at,
                synced_at: now_secs(),
            })
            .await?)
    }

    async fn preserve_existing_chat_row(
        &self,
        meta: &StateFileMeta<'_>,
        body: &[u8],
    ) -> Result<Option<StateFileRow>, StateFileError> {
        if !is_placeholder_chat_state(meta.namespace, meta.path, body) {
            return Ok(None);
        }
        let incoming_bytes = i64::try_from(body.len()).unwrap_or(i64::MAX);
        let Some(existing) = self
            .store
            .find(meta.instance_id, meta.namespace, meta.path)
            .await?
        else {
            return Ok(None);
        };
        if existing.deleted_at.is_none()
            && existing.body_ciphertext.is_some()
            && existing.bytes > incoming_bytes
        {
            tracing::info!(
                instance = %meta.instance_id,
                namespace = %meta.namespace,
                path = %meta.path,
                existing_bytes = existing.bytes,
                incoming_bytes,
                "state file store: ignored placeholder chat overwrite"
            );
            return Ok(Some(existing));
        }
        Ok(None)
    }

    pub async fn tombstone(&self, meta: StateFileMeta<'_>) -> Result<StateFileRow, StateFileError> {
        validate_instance_id(meta.instance_id)?;
        validate_state_file_path(meta.namespace, meta.path)?;
        Ok(self
            .store
            .tombstone(
                meta.instance_id,
                meta.owner_id,
                meta.namespace,
                meta.path,
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
        Ok(self.store.find(instance_id, namespace, path).await?)
    }

    pub async fn list_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<StateFileRow>, StateFileError> {
        Ok(self.store.list_for_instance(instance_id).await?)
    }

    pub fn read_body(&self, row: &StateFileRow) -> Result<Option<Vec<u8>>, StateFileError> {
        if row.deleted_at.is_some() {
            return Ok(None);
        }
        let bytes = match row.body_ciphertext.as_deref() {
            Some(bytes) => bytes,
            None => {
                tracing::warn!(
                    instance = %row.instance_id,
                    namespace = %row.namespace,
                    path = %row.path,
                    "state file store: missing sealed body",
                );
                return Ok(None);
            }
        };
        if !bytes.starts_with(AGE_ARMOR_PREFIX) {
            tracing::warn!(
                instance = %row.instance_id,
                namespace = %row.namespace,
                path = %row.path,
                "state file store: refusing unsealed body",
            );
            return Ok(None);
        }
        let cipher = self
            .ciphers
            .for_user(&row.owner_id)
            .map_err(|e| StateFileError::Io(format!("owner cipher: {e}")))?;
        let plain = cipher
            .open(bytes)
            .map_err(|e| StateFileError::Io(format!("open: {e}")))?;
        Ok(Some(plain))
    }
    pub fn read_body_for_replay(
        &self,
        row: &StateFileRow,
    ) -> Result<Option<Vec<u8>>, StateFileError> {
        self.read_body(row)
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

fn validate_state_file_path(namespace: &str, path: &str) -> Result<(), StateFileError> {
    validate_namespace(namespace)?;
    validate_relative_path(path)?;
    let rel = Path::new(path);
    if has_hidden_or_unclean_component(rel) {
        return Err(StateFileError::Invalid(
            "paths may not contain hidden or unclean components".into(),
        ));
    }
    match namespace {
        "chats" => Ok(()),
        "workspace" if should_mirror_workspace_path(rel) => Ok(()),
        "workspace" => Err(StateFileError::Invalid(format!(
            "workspace path is not durable state: {path}"
        ))),
        _ => unreachable!("namespace already validated"),
    }
}

pub fn is_durable_state_file_path(namespace: &str, path: &str) -> bool {
    validate_state_file_path(namespace, path).is_ok()
}

fn should_mirror_workspace_path(rel: &Path) -> bool {
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    match parts.as_slice() {
        [file] => has_extension(file, "md"),
        ["memory", ..] => rel.extension().and_then(|s| s.to_str()) == Some("md"),
        ["kb", ..] | ["skills", ..] => true,
        ["channels", _channel, rest @ ..] => should_mirror_channel_workspace(rest, rel),
        _ => false,
    }
}

fn should_mirror_channel_workspace(parts: &[&str], rel: &Path) -> bool {
    match parts {
        [file] => has_extension(file, "md") || *file == "_audit.jsonl",
        ["memory", ..] => rel.extension().and_then(|s| s.to_str()) == Some("md"),
        _ => false,
    }
}

fn has_extension(file_name: &str, expected: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}

fn has_hidden_or_unclean_component(path: &Path) -> bool {
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(s) = part.to_str() else {
                    return true;
                };
                if s.is_empty() || s.starts_with('.') {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}

pub fn is_zero_byte_chat_transcript(namespace: &str, path: &str, body: &[u8]) -> bool {
    namespace == "chats" && path.ends_with("/transcript.json") && body.is_empty()
}

fn is_placeholder_chat_state(namespace: &str, path: &str, body: &[u8]) -> bool {
    is_empty_chat_transcript(namespace, path, body)
        || is_placeholder_chat_title(namespace, path, body)
}

fn is_empty_chat_transcript(namespace: &str, path: &str, body: &[u8]) -> bool {
    namespace == "chats"
        && path.ends_with("/transcript.json")
        && trim_ascii_whitespace(body) == b"[]"
}

fn is_placeholder_chat_title(namespace: &str, path: &str, body: &[u8]) -> bool {
    namespace == "chats"
        && path.ends_with("/title.txt")
        && trim_ascii_whitespace(body) == b"New conversation"
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last() {
        if !last.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    bytes
}

fn validate_body(namespace: &str, path: &str, body: &[u8]) -> Result<(), StateFileError> {
    if is_zero_byte_chat_transcript(namespace, path, body) {
        return Err(StateFileError::Invalid(
            "zero-byte chat transcript rejected".into(),
        ));
    }
    Ok(())
}

fn validate_instance_id(instance_id: &str) -> Result<(), StateFileError> {
    if instance_id.is_empty()
        || instance_id.contains('/')
        || instance_id.contains('\\')
        || instance_id.contains("..")
    {
        return Err(StateFileError::Invalid("bad instance id".into()));
    }
    Ok(())
}

pub type StateFiles = Arc<StateFileService>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite::open_in_memory;

    const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn svc() -> (StateFileService, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let keys = tempfile::tempdir().unwrap();
        let ciphers: Arc<dyn CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        (
            StateFileService::new(crate::db::sqlite::state_file_store(pool), ciphers),
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
        let (svc, _keys) = svc().await;
        let row = svc.ingest(meta("MEMORY.md"), b"").await.unwrap();
        let stored = row.body_ciphertext.as_deref().expect("sealed body");
        assert!(stored.starts_with(AGE_ARMOR_PREFIX));
        assert_eq!(svc.read_body(&row).unwrap().unwrap(), b"");
        assert_eq!(row.bytes, 0);
    }

    #[tokio::test]
    async fn rejects_zero_byte_chat_transcripts() {
        let (svc, _keys) = svc().await;
        let mut chat_meta = meta("c-1/transcript.json");
        chat_meta.namespace = "chats";
        chat_meta.mime = Some("application/json");

        let err = svc.ingest(chat_meta, b"").await.unwrap_err();

        assert!(matches!(err, StateFileError::Invalid(_)));
    }

    #[tokio::test]
    async fn placeholder_chat_transcript_does_not_replace_existing_body() {
        let (svc, _keys) = svc().await;
        let mut chat_meta = meta("c-1/transcript.json");
        chat_meta.namespace = "chats";
        chat_meta.mime = Some("application/json");

        let row = svc
            .ingest(
                chat_meta.clone(),
                br#"[{"role":"assistant","content":"kept"}]"#,
            )
            .await
            .unwrap();
        assert!(row.bytes > 2);

        let row = svc.ingest(chat_meta, b"[]").await.unwrap();
        assert!(row.bytes > 2);
        assert_eq!(
            svc.read_body(&row).unwrap().unwrap(),
            br#"[{"role":"assistant","content":"kept"}]"#
        );
    }

    #[tokio::test]
    async fn placeholder_chat_title_does_not_replace_existing_title() {
        let (svc, _keys) = svc().await;
        let mut chat_meta = meta("c-1/title.txt");
        chat_meta.namespace = "chats";
        chat_meta.mime = Some("text/plain");

        let row = svc
            .ingest(chat_meta.clone(), b"Security review: programs")
            .await
            .unwrap();
        assert!(row.bytes > "New conversation".len() as i64);

        let row = svc.ingest(chat_meta, b"New conversation").await.unwrap();
        assert_eq!(row.bytes, "Security review: programs".len() as i64);
        assert_eq!(
            svc.read_body(&row).unwrap().unwrap(),
            b"Security review: programs"
        );
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let (svc, _keys) = svc().await;
        let err = svc.ingest(meta("../MEMORY.md"), b"nope").await.unwrap_err();
        assert!(matches!(err, StateFileError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_workspace_paths_that_are_vm_local_cache() {
        let (svc, _keys) = svc().await;

        for path in [
            "dyson.json",
            ".env",
            "memory.db",
            "channels/group-1/memory.db",
            "channels/group-1/.workspace_version",
        ] {
            let err = svc.ingest(meta(path), b"nope").await.unwrap_err();
            assert!(
                matches!(err, StateFileError::Invalid(_)),
                "{path} must not be accepted into the swarm mirror"
            );
        }
    }

    #[tokio::test]
    async fn accepts_public_channel_workspace_state() {
        let (svc, _keys) = svc().await;

        for path in [
            "channels/group-1/MEMORY.md",
            "channels/group-1/USER.md",
            "channels/group-1/memory/2026-05-09.md",
            "channels/group-1/_audit.jsonl",
        ] {
            svc.ingest(meta(path), b"hello").await.unwrap();
        }

        let rows = svc.list_for_instance("inst-a").await.unwrap();
        let paths: Vec<_> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "channels/group-1/MEMORY.md",
                "channels/group-1/USER.md",
                "channels/group-1/_audit.jsonl",
                "channels/group-1/memory/2026-05-09.md",
            ]
        );
    }

    #[tokio::test]
    async fn tombstone_marks_row_and_removes_body() {
        let (svc, _keys) = svc().await;
        let row = svc.ingest(meta("MEMORY.md"), b"hello").await.unwrap();
        assert!(row.body_ciphertext.is_some());
        let row = svc.tombstone(meta("MEMORY.md")).await.unwrap();
        assert!(row.deleted_at.is_some());
        assert!(row.body_ciphertext.is_none());
        assert!(svc.read_body(&row).unwrap().is_none());
    }

    #[tokio::test]
    async fn list_for_instance_returns_workspace_and_chats() {
        let (svc, _keys) = svc().await;
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

    #[test]
    fn chat_artefacts_and_files_are_durable_state() {
        // Dyson stores artefact metadata/bodies under each chat and
        // file bytes under the chat-history root.  These must stay in
        // the swarm mirror so binary rotations replay the artefact
        // chips and their backing file URLs onto the new cube.
        for path in [
            "c-1/artefacts/a1.body",
            "c-1/artefacts/a1.meta.json",
            "files/f1.bin",
            "files/f1.meta.json",
        ] {
            assert!(
                is_durable_state_file_path("chats", path),
                "{path} must be accepted as durable chat state"
            );
        }
    }
}
