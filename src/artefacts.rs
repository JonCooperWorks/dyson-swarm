//! Swarm-side write-through cache for dyson artefacts.
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
//! Bytes live on the local filesystem under `<cache_root>/artefacts/`
//! to keep large bodies (PDFs, generated images) out of SQLite where
//! a 4 MiB BLOB cap would matter.  Metadata lives in `artefact_cache`
//! (see `db::artefacts`).  The two are kept in sync by the upsert →
//! write-bytes → update-body sequence in `ingest`: a partial failure
//! after the metadata insert leaves the row pointing at a `body_path`
//! we may or may not have created — the next ingest call will
//! overwrite the on-disk body and clear the inconsistency, and the
//! read paths fall back to the live cube on a missing-file miss.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::db::artefacts::{self as store, CachedArtefact};
use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::webhooks::AGE_ARMOR_PREFIX;

/// Errors surfaced by the cache service.  Distinguished from
/// `StoreError` so callers can react differently on disk failure
/// (degrade to "no cache, fall through to upstream") vs DB failure
/// (5xx).
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cache i/o: {0}")]
    Io(String),
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e.to_string())
    }
}

/// Service handle.  Cheap to clone — `pool` is an `Arc` inside, `root`
/// is a `PathBuf` we just clone on each call, and `ciphers` is an
/// `Arc` to a directory.
///
/// Bodies are sealed under the row's `owner_id` cipher before they hit
/// disk, so a stolen `local_cache_dir` alone doesn't expose historical
/// artefact contents — an attacker would also need the per-user age
/// keys (kept outside the cache root).  Pre-encryption rows on disk
/// (legacy, no age armor header) open as-is so existing caches stay
/// readable.  Same posture as `WebhookService::open_audit_body`.
#[derive(Clone)]
pub struct ArtefactCacheService {
    pool: SqlitePool,
    root: PathBuf,
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
    /// Wire the service to a pool, a root directory, and the per-user
    /// cipher directory used to seal bodies at rest.  The root is
    /// created on first ingest (lazy) — failing fast at startup would
    /// prevent the swarm from booting on a host where the cache dir
    /// is on a still-mounting volume, which we'd rather not.
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

    /// Filesystem path to a row's body.  Joins `root` with the row's
    /// stored relative `body_path`.  Useful for the few callers that
    /// want to mmap or stream the file rather than read it into
    /// memory through `read_body`.
    pub fn body_path_for(&self, row: &CachedArtefact) -> PathBuf {
        self.root.join(&row.body_path)
    }

    /// Fetch a cached row by identity tuple.  Misses return
    /// `Ok(None)` so the caller can fall through to upstream.
    pub async fn find(
        &self,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<Option<CachedArtefact>, CacheError> {
        Ok(store::find(&self.pool, instance_id, chat_id, artefact_id).await?)
    }

    /// Read the body bytes from disk.  Returns `Ok(None)` if the row
    /// exists but the on-disk body is gone (mid-write crash, manual
    /// cache wipe, etc.) — the read path treats this the same as a
    /// row miss and falls through to the live cube.
    ///
    /// Sealed bodies (age armor prefix) open via the row's owner
    /// cipher.  Legacy bodies (pre-encryption rows: no armor header)
    /// pass through unchanged so existing caches stay readable.  A
    /// sealed body that fails to decrypt (key rotated, file tampered)
    /// returns `Ok(None)` plus a warn log — same posture as
    /// `WebhookService::open_audit_body` — so the read path falls
    /// through to the live cube instead of returning ciphertext.
    pub async fn read_body(&self, row: &CachedArtefact) -> Result<Option<Vec<u8>>, CacheError> {
        let path = self.body_path_for(row);
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !bytes.starts_with(AGE_ARMOR_PREFIX) {
            // Legacy body written before encryption shipped — surface
            // as-is so historical caches stay readable.  Empty bodies
            // also land here (zero-length file → no armor prefix).
            return Ok(Some(bytes));
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
        match cipher.open(&bytes) {
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
        Ok(store::list_for_instance(&self.pool, owner_id, instance_id).await?)
    }

    /// Owner-scoped global listing.
    pub async fn list_for_owner(
        &self,
        owner_id: &str,
        limit: u32,
    ) -> Result<Vec<CachedArtefact>, CacheError> {
        Ok(store::list_for_owner(&self.pool, owner_id, limit).await?)
    }

    /// Delete a cached row + its on-disk body.  Owner-scoped: returns
    /// `Ok(false)` if the row didn't exist or wasn't theirs (no oracle
    /// for cross-tenant probing).  Body removal is best-effort — a
    /// stale file is harmless once the row is gone (the read paths
    /// look up by tuple).
    pub async fn delete(
        &self,
        owner_id: &str,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<bool, CacheError> {
        // Look up the body_path before deleting the row so we can
        // unlink the file regardless of which delete leg ran first.
        if let Some(row) = store::find(&self.pool, instance_id, chat_id, artefact_id).await?
            && row.owner_id == owner_id
        {
            let abs = self.root.join(&row.body_path);
            let _ = fs::remove_file(&abs).await;
        }
        Ok(store::delete(&self.pool, owner_id, instance_id, chat_id, artefact_id).await?)
    }

    /// Upsert the metadata row and (when `body` is `Some`) write the
    /// body bytes to disk under the row's `body_path`, then promote
    /// the row's bytes/mime fields to point at the freshly-written
    /// body.  Idempotent — calling twice with the same args produces
    /// the same on-disk state.
    ///
    /// Sequencing: metadata first so a body-write crash doesn't leave
    /// a parent dir without a row to point at; body next; row promoted
    /// last so a reader sees the new mime/bytes only after the file
    /// is fully landed.
    pub async fn ingest(
        &self,
        meta: IngestMeta<'_>,
        body: Option<&[u8]>,
    ) -> Result<CachedArtefact, CacheError> {
        let body_path = relative_body_path(meta.instance_id, meta.chat_id, meta.artefact_id);
        let (id, existing_path) = store::upsert_meta(
            &self.pool,
            store::UpsertSpec {
                instance_id: meta.instance_id,
                owner_id: meta.owner_id,
                chat_id: meta.chat_id,
                artefact_id: meta.artefact_id,
                kind: meta.kind,
                title: meta.title,
                created_at: meta.created_at,
                body_path_seed: &body_path,
                metadata_json: meta.metadata_json,
            },
        )
        .await?;
        // First-insert seeds the row with our path; subsequent calls
        // get back the previous body_path.  Either way `existing_path`
        // is what we should write the body under.
        let target_rel = existing_path;

        if let Some(bytes) = body {
            // Seal under the owner's age cipher before disk write.
            // `body_size` (the `bytes` field on the row) reflects the
            // *plaintext* length so listings stay meaningful without
            // decryption.  Empty bodies skip the seal — write a zero-
            // length file so the read path's "row exists, no body"
            // branch sees an empty body rather than a stale ciphertext.
            let plain_len = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
            let on_disk = if bytes.is_empty() {
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
            self.write_body(&target_rel, &on_disk).await?;
            store::update_body(&self.pool, id, &target_rel, plain_len, meta.mime).await?;
        }
        let row = store::find(&self.pool, meta.instance_id, meta.chat_id, meta.artefact_id)
            .await?
            .ok_or_else(|| CacheError::Io("ingested row vanished".into()))?;
        Ok(row)
    }

    async fn write_body(&self, rel_path: &str, bytes: &[u8]) -> Result<(), CacheError> {
        let abs = self.root.join(rel_path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).await?;
        }
        // Write to a sibling temp file then rename, so a reader that
        // opens the path mid-ingest either sees the old body or the
        // new one — never a torn write.
        let tmp = abs.with_extension("body.tmp");
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp, &abs).await?;
        Ok(())
    }
}

/// Build the relative body path for a (instance, chat, artefact)
/// tuple.  The shape is intentionally short and predictable so an
/// operator can `ls` a chat's bodies; we don't sharded-prefix yet
/// because the row count per chat stays small (< ~100) in practice.
///
/// All three components have already passed through the swarm's
/// `safe_store_id`-style validation upstream — they're constrained to
/// `[A-Za-z0-9_-]` — so plain joining is safe (no `..` traversal).
fn relative_body_path(instance_id: &str, chat_id: &str, artefact_id: &str) -> String {
    format!("artefacts/{instance_id}/{chat_id}/{artefact_id}.body")
}

/// Trait alias — every place that holds an `Arc<ArtefactCacheService>`.
/// Using `Arc` directly rather than a trait object keeps the call sites
/// concrete; a future swap to e.g. an S3-backed body store would change
/// the type here in one place.
pub type ArtefactCache = Arc<ArtefactCacheService>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    /// Build a service backed by an in-memory pool, a tempdir for
    /// bodies, and an `AgeCipherDirectory` rooted in another tempdir
    /// (so each test gets its own keyring).  The keys tempdir is held
    /// alongside the body tempdir — both must outlive the service.
    async fn svc() -> (ArtefactCacheService, tempfile::TempDir, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let ciphers: Arc<dyn CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let svc = ArtefactCacheService::new(pool, dir.path().to_path_buf(), ciphers);
        (svc, dir, keys)
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
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("inst-a", ALICE, "c1", "a1"), Some(b"hello"))
            .await
            .unwrap();
        assert_eq!(row.bytes, 5);
        assert_eq!(row.mime.as_deref(), Some("text/markdown"));
        let bytes = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn ingest_metadata_only_does_not_clobber_body() {
        // The whole point of the cache is that "I just need to refresh
        // the title" doesn't blow away a still-good body.
        let (svc, _tmp, _keys) = svc().await;
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
        let bytes = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(bytes, b"original");
    }

    #[tokio::test]
    async fn ingest_replaces_body_atomically() {
        let (svc, _tmp, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1"))
            .await
            .unwrap();
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v2-longer"))
            .await
            .unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.bytes, 9);
        let bytes = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(bytes, b"v2-longer");
    }

    #[tokio::test]
    async fn read_body_gone_returns_none() {
        // Manual cache wipe: row exists but file's been removed.
        // Read path needs to see this as a miss so it can fall back.
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"hi"))
            .await
            .unwrap();
        std::fs::remove_file(svc.body_path_for(&row)).unwrap();
        let got = svc.read_body(&row).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn list_for_owner_is_owner_scoped() {
        let (svc, _tmp, _keys) = svc().await;
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
    async fn ingest_seals_body_on_disk() {
        // The bytes a stolen `local_cache_dir` would expose: ASCII-armored
        // age ciphertext, NOT the plaintext.  This is the at-rest
        // posture the seal exists to provide.
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"top-secret findings"))
            .await
            .unwrap();
        let on_disk = std::fs::read(svc.body_path_for(&row)).unwrap();
        assert!(
            on_disk.starts_with(AGE_ARMOR_PREFIX),
            "body must be sealed under age cipher, found prefix {:?}",
            std::str::from_utf8(&on_disk[..on_disk.len().min(40)]).unwrap_or("<binary>"),
        );
        assert!(
            !on_disk
                .windows(b"top-secret findings".len())
                .any(|w| w == b"top-secret findings"),
            "plaintext must not appear in the on-disk ciphertext",
        );
    }

    #[tokio::test]
    async fn read_body_decrypts_sealed_roundtrip() {
        // The end-to-end contract: bytes in via ingest, plaintext out
        // via read_body, even though disk holds ciphertext.
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"# Findings\n\n* a\n"))
            .await
            .unwrap();
        let plain = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(plain, b"# Findings\n\n* a\n");
        // bytes column reflects PLAINTEXT length, not ciphertext.
        assert_eq!(row.bytes, 16);
    }

    #[tokio::test]
    async fn read_body_legacy_plaintext_passes_through() {
        // Pre-encryption rows on disk: no armor header, surface as-is
        // so historical caches stay readable after the seal lands.
        // We simulate the legacy posture by writing plaintext directly
        // to the row's body_path, bypassing the seal.
        let (svc, _tmp, _keys) = svc().await;
        // First ingest with empty body so the row exists with a path.
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b""))
            .await
            .unwrap();
        // Overwrite with plaintext to simulate a legacy on-disk body.
        std::fs::write(svc.body_path_for(&row), b"old plaintext body").unwrap();
        let got = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(got, b"old plaintext body");
    }

    #[tokio::test]
    async fn read_body_decrypt_failure_returns_none() {
        // A sealed body whose ciphertext has been corrupted (or whose
        // owner key has been rotated and the new key can't open old
        // ciphertexts) must surface as a miss — NOT as ciphertext bytes
        // — so the read path falls back to the live cube.
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"sealed payload"))
            .await
            .unwrap();
        // Tamper: read the ciphertext, flip a byte in the middle of
        // the armor body, write it back.  age's MAC catches this.
        let mut ct = std::fs::read(svc.body_path_for(&row)).unwrap();
        let mid = ct.len() / 2;
        ct[mid] ^= 0x40;
        std::fs::write(svc.body_path_for(&row), ct).unwrap();
        let got = svc.read_body(&row).await.unwrap();
        assert!(
            got.is_none(),
            "tampered ciphertext must surface as a miss, not ciphertext bytes"
        );
    }

    #[tokio::test]
    async fn ingest_seal_persists_across_metadata_only_refresh() {
        // Combination of "metadata refresh keeps the body" + the seal:
        // the still-good ciphertext on disk must still decrypt after a
        // metadata-only re-upsert.
        let (svc, _tmp, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1 sealed"))
            .await
            .unwrap();
        let mut refreshed = meta("i", ALICE, "c", "a");
        refreshed.title = "Renamed";
        svc.ingest(refreshed, None).await.unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.title, "Renamed");
        let plain = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(plain, b"v1 sealed");
    }

    #[tokio::test]
    async fn ingest_replaces_sealed_body_atomically() {
        // Re-ingesting with new bytes: the new ciphertext lands via
        // the same atomic-rename path, the row's `bytes` column tracks
        // the new plaintext length, and read_body decrypts to the new
        // plaintext.  Catches a regression where double-sealing or a
        // stale ciphertext leaks through.
        let (svc, _tmp, _keys) = svc().await;
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v1"))
            .await
            .unwrap();
        svc.ingest(meta("i", ALICE, "c", "a"), Some(b"v2-much-longer-body"))
            .await
            .unwrap();
        let row = svc.find("i", "c", "a").await.unwrap().unwrap();
        assert_eq!(row.bytes, 19);
        let plain = svc.read_body(&row).await.unwrap().unwrap();
        assert_eq!(plain, b"v2-much-longer-body");
    }

    #[tokio::test]
    async fn empty_body_ingest_writes_zero_length_file() {
        // Empty body skips the seal — write a zero-length file and
        // surface it back as empty bytes (NOT as a NotFound miss).
        // The existing share/sweep paths pass `None` for body when
        // they only refresh metadata, but `Some(&[])` is a separate
        // signal ("known-empty body") that we need to preserve.
        let (svc, _tmp, _keys) = svc().await;
        let row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b""))
            .await
            .unwrap();
        let on_disk = std::fs::read(svc.body_path_for(&row)).unwrap();
        assert!(
            on_disk.is_empty(),
            "empty body should write zero-length file"
        );
        let got = svc.read_body(&row).await.unwrap().unwrap();
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
        // a row with bob's owner_id pointing at alice's body_path.
        let (svc, _tmp, _keys) = svc().await;
        let alice_row = svc
            .ingest(meta("i", ALICE, "c", "a"), Some(b"alice secret"))
            .await
            .unwrap();
        // Forged row: same body_path, bob's owner_id.
        let forged = CachedArtefact {
            owner_id: BOB.to_owned(),
            ..alice_row.clone()
        };
        let got = svc.read_body(&forged).await.unwrap();
        assert!(
            got.is_none(),
            "wrong-owner read must surface as a miss, not plaintext"
        );
    }
}
