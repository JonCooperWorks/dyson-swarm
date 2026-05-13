//! Swarm-side durable store for dyson artefacts.
//!
//! The cache backs two surfaces:
//!
//! - the public `share.<apex>` read path, where we want a shared
//!   artefact to keep working after its cube has been destroyed /
//!   reset (the original reason this exists), and
//! - the `/v1/instances/:id/artefacts` listings the swarm SPA shows,
//!   so a user can browse and (later) decide-to-share without each
//!   request fanning out to the still-live cube.
//!
//! Metadata and sealed bytes both live in `artefact_cache` (see
//! `db::artefacts`). The agent sandbox disk can keep scratch copies,
//! but the durable artefact source of truth is the swarm store.

use std::sync::Arc;

use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::traits::{ArtefactCacheStore, ArtefactUpsertSpec, CachedArtefact};
use crate::webhooks::AGE_ARMOR_PREFIX;

/// Errors surfaced by the artefact service. Distinguished from
/// `StoreError` so callers can react differently on invalid ids vs DB
/// or seal/open failure.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("invalid cache key: {0}")]
    Invalid(String),
    #[error("cache i/o: {0}")]
    Io(String),
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e.to_string())
    }
}

/// Service handle. Cheap to clone — the backing store and cipher
/// directory are both held behind `Arc`s.
///
/// Bodies are sealed under the row's `owner_id` cipher before they hit
/// the store, so DB snapshots without the per-user age keys do not
/// expose historical artefact contents.
#[derive(Clone)]
pub struct ArtefactCacheService {
    store: Arc<dyn ArtefactCacheStore>,
    ciphers: Arc<dyn CipherDirectory>,
}

/// Metadata supplied at ingest time.  Mirrors the shape of dyson's
/// `ArtefactDto` (see `crates/dyson/src/controller/http/wire.rs`)
/// minus the `bytes` field — bytes are passed separately so a
/// metadata-only refresh can avoid re-uploading the body.
#[derive(Debug, Clone)]
pub struct IngestMeta<'a> {
    pub instance_id: &'a str,
    pub owner_id: &'a str,
    pub chat_id: &'a str,
    pub artefact_id: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub mime: Option<&'a str>,
    pub created_at: i64,
    pub metadata_json: Option<&'a str>,
}

impl ArtefactCacheService {
    /// Wire the service to a durable artefact store and the per-user
    /// cipher directory used to seal bodies at rest.
    pub fn new(store: Arc<dyn ArtefactCacheStore>, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self { store, ciphers }
    }

    /// Fetch a cached row by identity tuple.  Misses return
    /// `Ok(None)` so the caller can fall through to upstream.
    pub async fn find(
        &self,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<Option<CachedArtefact>, CacheError> {
        Ok(self.store.find(instance_id, chat_id, artefact_id).await?)
    }

    /// Read the body bytes from the swarm store. Returns `Ok(None)` if
    /// the row is metadata-only or the sealed body cannot be opened.
    pub fn read_body(&self, row: &CachedArtefact) -> Result<Option<Vec<u8>>, CacheError> {
        let bytes = match row.body_ciphertext.as_deref() {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        if bytes.is_empty() {
            return Ok(Some(Vec::new()));
        }
        if !bytes.starts_with(AGE_ARMOR_PREFIX) {
            tracing::warn!(
                artefact = %row.artefact_id,
                owner = %row.owner_id,
                "artefact store: refusing unsealed body",
            );
            return Ok(None);
        }
        let cipher = match self.ciphers.for_user(&row.owner_id) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    artefact = %row.artefact_id,
                    owner = %row.owner_id,
                    error = %e,
                    "artefact cache: owner cipher unavailable — body suppressed",
                );
                return Ok(None);
            }
        };
        match cipher.open(bytes) {
            Ok(plain) => Ok(Some(plain)),
            Err(e) => {
                tracing::warn!(
                    artefact = %row.artefact_id,
                    owner = %row.owner_id,
                    error = %e,
                    "artefact cache: body decrypt failed (key rotated?) — surfacing as miss",
                );
                Ok(None)
            }
        }
    }

    /// Owner-scoped instance listing.
    pub async fn list_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<Vec<CachedArtefact>, CacheError> {
        Ok(self.store.list_for_instance(owner_id, instance_id).await?)
    }

    /// Owner-scoped instance page.  `limit` and `offset` are applied
    /// in the store so the SPA can walk large caches without pulling
    /// the entire instance history into memory.
    pub async fn list_for_instance_page(
        &self,
        owner_id: &str,
        instance_id: &str,
        chat_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<CachedArtefact>, CacheError> {
        Ok(self
            .store
            .list_for_instance_page(owner_id, instance_id, chat_id, limit, offset)
            .await?)
    }

    /// Owner-scoped global listing.
    pub async fn list_for_owner(
        &self,
        owner_id: &str,
        limit: u32,
    ) -> Result<Vec<CachedArtefact>, CacheError> {
        Ok(self.store.list_for_owner(owner_id, limit).await?)
    }

    /// Owner-scoped global page.
    pub async fn list_for_owner_page(
        &self,
        owner_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<CachedArtefact>, CacheError> {
        Ok(self
            .store
            .list_for_owner_page(owner_id, limit, offset)
            .await?)
    }

    /// Delete a cached row + its stored body. Owner-scoped: returns
    /// `Ok(false)` if the row didn't exist or wasn't theirs (no oracle
    /// for cross-tenant probing).
    pub async fn delete(
        &self,
        owner_id: &str,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<bool, CacheError> {
        Ok(self
            .store
            .delete(owner_id, instance_id, chat_id, artefact_id)
            .await?)
    }

    /// Upsert the metadata row and, when `body` is `Some`, seal and
    /// store the body bytes in the same swarm row. Idempotent: calling
    /// twice with the same args produces the same durable state.
    pub async fn ingest(
        &self,
        meta: IngestMeta<'_>,
        body: Option<&[u8]>,
    ) -> Result<CachedArtefact, CacheError> {
        validate_tuple(meta.instance_id, meta.chat_id, meta.artefact_id)?;
        let id = self
            .store
            .upsert_meta(ArtefactUpsertSpec {
                instance_id: meta.instance_id,
                owner_id: meta.owner_id,
                chat_id: meta.chat_id,
                artefact_id: meta.artefact_id,
                kind: meta.kind,
                title: meta.title,
                created_at: meta.created_at,
                metadata_json: meta.metadata_json,
            })
            .await?;

        if let Some(bytes) = body {
            // Seal under the owner's age cipher before store write.
            // `body_size` (the `bytes` field on the row) reflects the
            // *plaintext* length so listings stay meaningful without
            // decryption. Empty bodies are stored as a present empty
            // blob, distinct from metadata-only `NULL`.
            let plain_len = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
            let stored_body = if bytes.is_empty() {
                Vec::new()
            } else {
                let cipher = self
                    .ciphers
                    .for_user(meta.owner_id)
                    .map_err(|e| CacheError::Io(format!("owner cipher: {e}")))?;
                cipher
                    .seal(bytes)
                    .map_err(|e| CacheError::Io(format!("seal: {e}")))?
            };
            self.store
                .update_body(id, plain_len, meta.mime, &stored_body)
                .await?;
        }
        let row = self
            .store
            .find(meta.instance_id, meta.chat_id, meta.artefact_id)
            .await?
            .ok_or_else(|| CacheError::Io("ingested row vanished".into()))?;
        Ok(row)
    }
}

fn validate_tuple(instance_id: &str, chat_id: &str, artefact_id: &str) -> Result<(), CacheError> {
    for (label, value) in [
        ("instance_id", instance_id),
        ("chat_id", chat_id),
        ("artefact_id", artefact_id),
    ] {
        if !safe_component(value) {
            return Err(CacheError::Invalid(format!(
                "{label} must match [A-Za-z0-9_-] and be 1..=128 bytes"
            )));
        }
    }
    Ok(())
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Trait alias — every place that holds an `Arc<ArtefactCacheService>`.
/// Using `Arc` directly rather than a trait object keeps the call sites
/// concrete; a future swap to e.g. an S3-backed body store would change
/// the type here in one place.
pub type ArtefactCache = Arc<ArtefactCacheService>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite::open_in_memory;

    /// Build a service backed by an in-memory pool and an
    /// `AgeCipherDirectory` rooted in a tempdir.
    async fn svc() -> (ArtefactCacheService, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let keys = tempfile::tempdir().unwrap();
        let ciphers: Arc<dyn CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let svc = ArtefactCacheService::new(crate::db::sqlite::artefact_cache_store(pool), ciphers);
        (svc, keys)
    }

    /// `AgeCipherDirectory::for_user` requires a 32-hex user id (or the
    /// `system` sentinel).  Production owner ids are uuid-simple form;
    /// tests bake fixed hex stand-ins for "alice" and "bob" so failures
    /// against these reads are obviously about the wrong owner, not
    /// random hex.
    const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn meta<'a>(instance: &'a str, owner: &'a str, chat: &'a str, art: &'a str) -> IngestMeta<'a> {
        IngestMeta {
            instance_id: instance,
            owner_id: owner,
            chat_id: chat,
            artefact_id: art,
            kind: "security_review",
            title: "Test",
            mime: Some("text/markdown"),
            created_at: 1_700_000_000,
            metadata_json: None,
        }
    }

    #[tokio::test]
    async fn ingest_writes_body_and_metadata() {
        let (svc, _keys) = svc().await;
        let row = svc
            .ingest(meta("inst-a", ALICE, "c1", "a1"), Some(b"hello"))
            .await
            .unwrap();
        assert_eq!(row.bytes, 5);
        assert_eq!(row.mime.as_deref(), Some("text/markdown"));
        let bytes = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn ingest_metadata_only_does_not_clobber_body() {
        // The whole point of the cache is that "I just need to refresh
        // the title" doesn't blow away a still-good body.
        let (svc, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"original"))
            .await
            .unwrap();
        // Metadata-only refresh — pass `None` for body.
        let mut refreshed_meta = meta("i", ALICE, "c", "a");
        refreshed_meta.title = "Renamed";
        svc.ingest(refreshed_meta, None).await.unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.title, "Renamed");
        assert_eq!(row.bytes, 8); // "original".len()
        let bytes = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(bytes, b"original");
    }

    #[tokio::test]
    async fn ingest_replaces_body_atomically() {
        let (svc, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1"))
            .await
            .unwrap();
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v2-longer"))
            .await
            .unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.bytes, 9);
        let bytes = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(bytes, b"v2-longer");
    }

    #[tokio::test]
    async fn ingest_rejects_traversal_ids() {
        let (svc, _keys) = svc().await;
        let err = svc
            .ingest(meta("i", ALICE, "../../../outside", "a"), Some(b"pwn"))
            .await
            .expect_err("traversal chat id must be rejected");
        assert!(
            err.to_string().contains("invalid"),
            "unexpected error: {err}",
        );
    }

    #[tokio::test]
    async fn metadata_only_body_returns_none() {
        let (svc, _keys) = svc().await;
        let row = svc.ingest(meta("i", ALICE, "c", "a"), None).await.unwrap();
        let got = svc.read_body(&row).unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn list_for_owner_is_owner_scoped() {
        let (svc, _keys) = svc().await;
        svc.ingest(meta("i1", ALICE, "c", "a1"), Some(b""))
            .await
            .unwrap();
        svc.ingest(meta("i2", ALICE, "c", "a2"), Some(b""))
            .await
            .unwrap();
        svc.ingest(meta("ix", BOB, "c", "ax"), Some(b""))
            .await
            .unwrap();
        let alice = svc.list_for_owner(ALICE, 100).await.unwrap();
        assert_eq!(alice.len(), 2);
        let bob = svc.list_for_owner(BOB, 100).await.unwrap();
        assert_eq!(bob.len(), 1);
    }

    #[tokio::test]
    async fn ingest_seals_body_in_store() {
        let (svc, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"top-secret findings"))
            .await
            .unwrap();
        let stored = row.body_ciphertext.as_deref().expect("sealed body");
        assert!(
            stored.starts_with(AGE_ARMOR_PREFIX),
            "body must be sealed under age cipher, found prefix {:?}",
            std::str::from_utf8(&stored[..stored.len().min(40)]).unwrap_or("<binary>"),
        );
        assert!(
            !stored
                .windows(b"top-secret findings".len())
                .any(|w| w == b"top-secret findings"),
            "plaintext must not appear in the stored ciphertext",
        );
    }

    #[tokio::test]
    async fn read_body_decrypts_sealed_roundtrip() {
        let (svc, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"# Findings\n\n* a\n"))
            .await
            .unwrap();
        let plain = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(plain, b"# Findings\n\n* a\n");
        // bytes column reflects PLAINTEXT length, not ciphertext.
        assert_eq!(row.bytes, 16);
    }

    #[tokio::test]
    async fn read_body_rejects_unsealed_store_body() {
        let (svc, _keys) = svc().await;
        let mut row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"sealed first"))
            .await
            .unwrap();
        row.body_ciphertext = Some(b"old plaintext body".to_vec());
        let got = svc.read_body(&row).unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn read_body_decrypt_failure_returns_none() {
        // A sealed body whose ciphertext has been corrupted (or whose
        // owner key has been rotated and the new key can't open old
        // ciphertexts) must surface as a miss — NOT as ciphertext bytes
        // — so the read path falls back to the live cube.
        let (svc, _keys) = svc().await;
        let mut row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"sealed payload"))
            .await
            .unwrap();
        let mut ct = row.body_ciphertext.clone().expect("sealed body");
        let mid = ct.len() / 2;
        ct[mid] ^= 0x40;
        row.body_ciphertext = Some(ct);
        let got = svc.read_body(&row).unwrap();
        assert!(
            got.is_none(),
            "tampered ciphertext must surface as a miss, not ciphertext bytes"
        );
    }

    #[tokio::test]
    async fn ingest_seal_persists_across_metadata_only_refresh() {
        // Combination of "metadata refresh keeps the body" + the seal:
        // the still-good ciphertext in the store must still decrypt after a
        // metadata-only re-upsert.
        let (svc, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1 sealed"))
            .await
            .unwrap();
        let mut refreshed = meta("i", ALICE, "c", "a");
        refreshed.title = "Renamed";
        svc.ingest(refreshed, None).await.unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.title, "Renamed");
        let plain = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(plain, b"v1 sealed");
    }

    #[tokio::test]
    async fn ingest_replaces_sealed_body_atomically() {
        let (svc, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1"))
            .await
            .unwrap();
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v2-much-longer-body"))
            .await
            .unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.bytes, 19);
        let plain = svc.read_body(&row).unwrap().unwrap();
        assert_eq!(plain, b"v2-much-longer-body");
    }

    #[tokio::test]
    async fn empty_body_ingest_writes_present_empty_blob() {
        // Empty body skips the seal but still stores a present empty
        // blob and surfaces it back as empty bytes (NOT as a miss).
        // The existing share/sweep paths pass `None` for body when
        // they only refresh metadata, but `Some(&[])` is a separate
        // signal ("known-empty body") that we need to preserve.
        let (svc, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b""))
            .await
            .unwrap();
        assert!(
            row.body_ciphertext.as_deref().is_some_and(|b| b.is_empty()),
            "empty body should store a present empty blob"
        );
        let got = svc.read_body(&row).unwrap().unwrap();
        assert!(
            got.is_empty(),
            "empty body should round-trip as empty bytes"
        );
        assert_eq!(row.bytes, 0);
    }

    #[tokio::test]
    async fn cross_owner_cannot_decrypt_each_others_bodies() {
        // Same cipher directory, two owners.  Forging the row's owner_id
        // on read should not let bob open alice's ciphertext.  We model
        // the attack as: alice ingests, bob tries to read by hand-rolling
        // a row with bob's owner_id pointing at alice's stored body.
        let (svc, _keys) = svc().await;
        let alice_row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"alice secret"))
            .await
            .unwrap();
        // Forged row: same body, bob's owner_id.
        let forged = CachedArtefact {
            owner_id: BOB.to_owned(),
            ..alice_row.clone()
        };
        let got = svc.read_body(&forged).unwrap();
        assert!(
            got.is_none(),
            "wrong-owner read must surface as a miss, not plaintext"
        );
    }
}
