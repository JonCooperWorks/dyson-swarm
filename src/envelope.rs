//! Envelope encryption for secrets at rest.
//!
//! Every long-lived secret warden owns — provider API keys, per-user
//! OpenRouter keys, the per-user `api_keys` we mint for CLI access,
//! arbitrary per-user opaque blobs — passes through this module on
//! the way to and from sqlite.  The store sees only ciphertext; the
//! trait owns the only path to plaintext.
//!
//! ## Key model — one root key per user
//!
//! Each warden user owns an age X25519 root key.  That user's secrets
//! are encrypted to their key only; compromise of one user's key
//! doesn't reveal another user's plaintext.  System-scope secrets
//! (provider api_keys, OpenRouter provisioning key) live under the
//! sentinel user id [`SYSTEM_KEY_ID`] which gets the same treatment —
//! one keypair, separate from any human user.
//!
//! Layout on disk: `<keys_dir>/<user_id>.age`, file mode 0600 (owner
//! read+write, no group/world).  We chose 0600 over the stricter 0400
//! to allow in-place rotation without permission gymnastics — a
//! process that owns the file can `fchmod` it anyway, so the "no
//! write" property of 0400 is mostly theatrical.  Keys are created
//! lazily on first access via [`CipherDirectory::for_user`] so a
//! user's row exists before their key file does, and so destroyed
//! users leave no key behind.
//!
//! ## Why two traits
//!
//! [`EnvelopeCipher`] is the single-key seal/open primitive — useful
//! on its own in tests and for system-scope code that doesn't need
//! routing.  [`CipherDirectory`] sits one level up and answers "give
//! me the cipher for user X", lazy-instantiating + caching as it goes.
//! Keeping them separate means the OpenRouter Provisioning client
//! (system-scope) and the per-user secrets store (user-scope) both
//! depend on the smaller `EnvelopeCipher` rather than the directory —
//! easier mocks, narrower blast radius for refactors.
//!
//! ## Why a trait at all (vs. concrete `AgeCipher`)
//!
//! We start on a single box with `age` keypairs on disk.  Production
//! deployments will eventually want a real KMS (AWS, GCP, Vault) so
//! root keys never live in the application's filesystem.  The trait
//! is the seam: today there's one impl ([`AgeCipher`] +
//! [`AgeCipherDirectory`]); tomorrow you drop in `AwsKmsCipher` /
//! `AwsKmsDirectory` without touching any callsite.
//!
//! ## Threat model
//!
//! Defends against: stolen sqlite file alone (no key files → no
//! plaintext).
//!
//! Does NOT defend against: stolen sqlite file + stolen `keys_dir`.
//! On a single-host deployment those usually go together; a future
//! KMS swap-in closes that gap by moving the root keys out of the
//! host's filesystem entirely.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use age::{Decryptor, Encryptor};

/// Sentinel "user id" used for system-scope secrets — provider API
/// keys, the OpenRouter provisioning key, anything else not owned by
/// a real user.  Reserved: real user ids are 32-hex (sqlite uuid
/// simple form), so a non-hex sentinel can't collide.
pub const SYSTEM_KEY_ID: &str = "system";

/// Per-key seal/open primitive.  One instance encrypts to and
/// decrypts from exactly one root key; routing across keys is the
/// [`CipherDirectory`]'s job.
///
/// `Send + Sync + Debug` so impls can live behind `Arc` in shared
/// state and surface in `tracing` spans without leaking key material
/// (Debug renders the path, never the key bytes).
pub trait EnvelopeCipher: Send + Sync + std::fmt::Debug {
    /// Encrypt plaintext into a self-describing ciphertext suitable
    /// for storage.  No structure is implied — callers treat the
    /// returned bytes as opaque.  ASCII-armored for the age impl, so
    /// the result is safe to put in a `TEXT` column.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError>;

    /// Decrypt a ciphertext previously returned by [`seal`].  Returns
    /// [`EnvelopeError::Corrupt`] for ciphertexts produced by a
    /// different key (or tampered with).
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError>;
}

/// Routes `user_id → EnvelopeCipher`.  Lazy: a user's key file is
/// generated on first call to [`for_user`] and cached for subsequent
/// calls.  System secrets use [`SYSTEM_KEY_ID`].
///
/// Invariant: two calls with the same `user_id` return the same
/// underlying key (and therefore the same ciphertexts decrypt
/// identically).  The cipher returned is `Arc`-shared to keep the
/// directory cheap to query inside hot paths.
pub trait CipherDirectory: Send + Sync + std::fmt::Debug {
    /// Lazy-create + cache the cipher for `user_id`.  Implementations
    /// MUST treat [`SYSTEM_KEY_ID`] as a valid user id.
    fn for_user(&self, user_id: &str) -> Result<Arc<dyn EnvelopeCipher>, EnvelopeError>;

    /// Sugar for `for_user(SYSTEM_KEY_ID)`.  Provided as a default to
    /// keep impls tiny.
    fn system(&self) -> Result<Arc<dyn EnvelopeCipher>, EnvelopeError> {
        self.for_user(SYSTEM_KEY_ID)
    }

    /// Drop a user's key.  Used when an admin deletes a user — their
    /// ciphertexts become unrecoverable, which is the desired
    /// "right to be forgotten" semantics.  Idempotent: missing keys
    /// are not an error.
    fn forget_user(&self, user_id: &str) -> Result<(), EnvelopeError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// I/O failure reading or writing a key file.  The path is elided
    /// from the message so it doesn't leak into logs.
    #[error("envelope: key file i/o: {0}")]
    Io(#[source] std::io::Error),
    /// Key file exists but isn't a valid age identity.
    #[error("envelope: key file parse: {0}")]
    KeyParse(String),
    /// Ciphertext failed to decrypt — wrong key or corrupted bytes.
    #[error("envelope: ciphertext corrupt or wrong key")]
    Corrupt,
    /// Underlying age library failure that doesn't map cleanly to a
    /// caller-actionable variant (e.g. PRNG failure during seal).
    #[error("envelope: age operation failed: {0}")]
    Age(String),
    /// The supplied user id is not a shape we'll accept as a path
    /// component.  Defensive — real user ids come from sqlite as
    /// 32-char hex, so this only fires on programmer error.
    #[error("envelope: invalid user id (must be hex or `{SYSTEM_KEY_ID}`)")]
    BadUserId,
}

// ───────────────────────────────────────────────────────────────────
// AgeCipher — single-key seal/open backed by an on-disk identity.
// ───────────────────────────────────────────────────────────────────

/// `EnvelopeCipher` backed by an on-disk age X25519 identity.
///
/// We hold the concrete `age::x25519::Identity` and `Recipient` rather
/// than the `dyn Identity` / `dyn Recipient` trait objects.  Two
/// reasons: (a) the trait objects aren't `Send + Sync` (there's a
/// plugin path that holds non-Sync state), and (b) we explicitly
/// only support X25519 — plugin identities (YubiKey, etc.) need a
/// different code path and aren't in scope.
#[derive(Clone)]
pub struct AgeCipher {
    identity: age::x25519::Identity,
    recipient: age::x25519::Recipient,
    /// Kept for diagnostics in `Debug` only — never logged in plain.
    key_path: PathBuf,
}

impl std::fmt::Debug for AgeCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeCipher")
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

impl AgeCipher {
    /// Load an age identity from `path` and build a cipher around it.
    /// The file must be readable by the warden process and SHOULD be
    /// mode 0400 / 0600 (the operator's responsibility — we don't
    /// enforce here so tests can use temp files).
    pub fn from_key_file(path: impl Into<PathBuf>) -> Result<Self, EnvelopeError> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path).map_err(EnvelopeError::Io)?;
        Self::from_identity_text(&raw, path)
    }

    /// Lower-level constructor — accepts the file contents directly.
    /// Used by tests that don't want to touch the filesystem.
    pub fn from_identity_text(text: &str, key_path: PathBuf) -> Result<Self, EnvelopeError> {
        let identities = age::IdentityFile::from_buffer(text.as_bytes())
            .map_err(|e| EnvelopeError::KeyParse(e.to_string()))?
            .into_identities();
        if identities.is_empty() {
            return Err(EnvelopeError::KeyParse("no identities in key file".into()));
        }
        // Multi-identity files: take the first.  Single-identity is
        // the only shape we ever generate; multi is accepted for
        // operator-managed keys.  Plugin entries are rejected — only
        // X25519 is in scope.
        let identity = match identities.into_iter().next().expect("len > 0 above") {
            age::IdentityFileEntry::Native(i) => i,
        };
        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
            key_path,
        })
    }

    /// Generate a fresh age identity at `path` if no file exists
    /// there.  Returns `Ok(true)` when a new key was written,
    /// `Ok(false)` when the file already existed (left alone — keeps
    /// re-runs idempotent).  File mode is 0400 on success.
    pub fn generate_if_missing(path: &Path) -> Result<bool, EnvelopeError> {
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(EnvelopeError::Io)?;
        }
        let identity = age::x25519::Identity::generate();
        let pem = identity.to_string();
        std::fs::write(path, expose(&pem)).map_err(EnvelopeError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).map_err(EnvelopeError::Io)?.permissions();
            perms.set_mode(0o400);
            std::fs::set_permissions(path, perms).map_err(EnvelopeError::Io)?;
        }
        Ok(true)
    }
}

impl EnvelopeCipher for AgeCipher {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        use std::io::Write;
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(self.recipient.clone())];
        let encryptor = Encryptor::with_recipients(recipients)
            .ok_or_else(|| EnvelopeError::Age("no recipients".into()))?;
        let mut out = Vec::with_capacity(plaintext.len() + 256);
        let armored =
            age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
                .map_err(|e| EnvelopeError::Age(e.to_string()))?;
        let mut writer = encryptor
            .wrap_output(armored)
            .map_err(|e| EnvelopeError::Age(e.to_string()))?;
        writer
            .write_all(plaintext)
            .map_err(|e| EnvelopeError::Age(e.to_string()))?;
        let armored = writer
            .finish()
            .map_err(|e| EnvelopeError::Age(e.to_string()))?;
        armored
            .finish()
            .map_err(|e| EnvelopeError::Age(e.to_string()))?;
        Ok(out)
    }

    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        use std::io::Read;
        let armored = age::armor::ArmoredReader::new(ciphertext);
        let decryptor = match Decryptor::new(armored).map_err(|_| EnvelopeError::Corrupt)? {
            Decryptor::Recipients(d) => d,
            // Passphrase-encrypted ciphertext arriving here means
            // someone wrote it with a different code path; treat as
            // corrupt rather than half-supporting passphrase mode.
            Decryptor::Passphrase(_) => return Err(EnvelopeError::Corrupt),
        };
        let identities: [&dyn age::Identity; 1] = [&self.identity];
        let mut reader = decryptor
            .decrypt(identities.iter().copied())
            .map_err(|_| EnvelopeError::Corrupt)?;
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .map_err(|_| EnvelopeError::Corrupt)?;
        Ok(out)
    }
}

// ───────────────────────────────────────────────────────────────────
// AgeCipherDirectory — routes user_id → AgeCipher, lazy-creating.
// ───────────────────────────────────────────────────────────────────

/// `CipherDirectory` impl that materialises one age key per user under
/// `keys_dir`.  Keys are created lazily on first access; cached
/// behind a `Mutex<HashMap>` so subsequent lookups skip disk.
///
/// Concurrency: the cache lock is short — it brackets the hashmap
/// insert only.  Disk I/O for first-time key creation happens with
/// the lock held, which is fine: key creation is rare (once per user
/// per box), and serialising it avoids two concurrent calls racing to
/// create the same file.
pub struct AgeCipherDirectory {
    keys_dir: PathBuf,
    cache: Mutex<HashMap<String, Arc<dyn EnvelopeCipher>>>,
}

impl std::fmt::Debug for AgeCipherDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeCipherDirectory")
            .field("keys_dir", &self.keys_dir)
            .finish_non_exhaustive()
    }
}

impl AgeCipherDirectory {
    /// Bind the directory to `keys_dir`.  The directory is created
    /// (mode 0700 on unix) if it doesn't exist; existing directories
    /// are left alone.
    pub fn new(keys_dir: impl Into<PathBuf>) -> Result<Self, EnvelopeError> {
        let keys_dir = keys_dir.into();
        std::fs::create_dir_all(&keys_dir).map_err(EnvelopeError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            // Best-effort: if the directory already had different
            // perms (operator override), don't fight it.
            let _ = std::fs::set_permissions(&keys_dir, perms);
        }
        Ok(Self {
            keys_dir,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn key_path(&self, user_id: &str) -> Result<PathBuf, EnvelopeError> {
        validate_user_id(user_id)?;
        Ok(self.keys_dir.join(format!("{user_id}.age")))
    }
}

impl CipherDirectory for AgeCipherDirectory {
    fn for_user(&self, user_id: &str) -> Result<Arc<dyn EnvelopeCipher>, EnvelopeError> {
        let mut cache = self.cache.lock().expect("cipher cache poisoned");
        if let Some(c) = cache.get(user_id) {
            return Ok(Arc::clone(c));
        }
        let path = self.key_path(user_id)?;
        AgeCipher::generate_if_missing(&path)?;
        let cipher: Arc<dyn EnvelopeCipher> = Arc::new(AgeCipher::from_key_file(&path)?);
        cache.insert(user_id.to_owned(), Arc::clone(&cipher));
        Ok(cipher)
    }

    fn forget_user(&self, user_id: &str) -> Result<(), EnvelopeError> {
        let path = self.key_path(user_id)?;
        // Drop the cached cipher first so a re-create later this
        // process lifetime gets a freshly-loaded one.
        self.cache
            .lock()
            .expect("cipher cache poisoned")
            .remove(user_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(EnvelopeError::Io(e)),
        }
    }
}

/// Reject anything that isn't `SYSTEM_KEY_ID` or 32 hex chars.
/// Defends against path traversal in `key_path` and surfaces
/// programmer error early.
fn validate_user_id(id: &str) -> Result<(), EnvelopeError> {
    if id == SYSTEM_KEY_ID {
        return Ok(());
    }
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EnvelopeError::BadUserId);
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// Internals.
// ───────────────────────────────────────────────────────────────────

fn expose(s: &age::secrecy::SecretString) -> &str {
    age::secrecy::ExposeSecret::expose_secret(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir() -> (tempfile::TempDir, AgeCipherDirectory) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = AgeCipherDirectory::new(tmp.path()).unwrap();
        (tmp, dir)
    }

    fn user_id(seed: u8) -> String {
        // Deterministic 32-hex strings for tests.  Real ids come from
        // sqlite's uuid simple form — same shape.
        format!("{:032x}", u128::from(seed) | (u128::from(seed) << 64))
    }

    // ── AgeCipher (single-key) ───────────────────────────────────────

    #[test]
    fn round_trip_short() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k.age");
        AgeCipher::generate_if_missing(&path).unwrap();
        let c = AgeCipher::from_key_file(&path).unwrap();
        let plain = b"hello, world";
        let cipher = c.seal(plain).unwrap();
        assert_ne!(cipher.as_slice(), plain);
        // Armored output is ASCII; sanity-check we don't accidentally
        // ship binary into a TEXT column later.
        assert!(cipher.iter().all(|&b| b.is_ascii()));
        assert_eq!(c.open(&cipher).unwrap(), plain);
    }

    #[test]
    fn round_trip_long() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k.age");
        AgeCipher::generate_if_missing(&path).unwrap();
        let c = AgeCipher::from_key_file(&path).unwrap();
        let plain: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
        let cipher = c.seal(&plain).unwrap();
        assert_eq!(c.open(&cipher).unwrap(), plain);
    }

    #[test]
    fn wrong_key_fails_open() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let p1 = tmp1.path().join("k.age");
        let p2 = tmp2.path().join("k.age");
        AgeCipher::generate_if_missing(&p1).unwrap();
        AgeCipher::generate_if_missing(&p2).unwrap();
        let c1 = AgeCipher::from_key_file(&p1).unwrap();
        let c2 = AgeCipher::from_key_file(&p2).unwrap();
        let cipher = c1.seal(b"secret").unwrap();
        let err = c2.open(&cipher).unwrap_err();
        assert!(matches!(err, EnvelopeError::Corrupt), "got: {err:?}");
    }

    #[test]
    fn tampered_ciphertext_fails_open() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k.age");
        AgeCipher::generate_if_missing(&path).unwrap();
        let c = AgeCipher::from_key_file(&path).unwrap();
        let mut cipher = c.seal(b"secret").unwrap();
        let mid = cipher.len() / 2;
        cipher[mid] ^= 0x01;
        let err = c.open(&cipher).unwrap_err();
        assert!(matches!(err, EnvelopeError::Corrupt), "got: {err:?}");
    }

    #[test]
    fn generate_if_missing_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k.age");
        assert!(AgeCipher::generate_if_missing(&path).unwrap());
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(!AgeCipher::generate_if_missing(&path).unwrap());
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(original, after, "second call must not overwrite the key");
    }

    #[test]
    fn missing_key_file_yields_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("never.age");
        let err = AgeCipher::from_key_file(&path).unwrap_err();
        assert!(matches!(err, EnvelopeError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn malformed_key_yields_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("garbage.age");
        std::fs::write(&path, "not an age identity").unwrap();
        let err = AgeCipher::from_key_file(&path).unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyParse(_)), "got: {err:?}");
    }

    // ── AgeCipherDirectory (per-user routing) ────────────────────────

    #[test]
    fn directory_round_trips_per_user() {
        let (_tmp, dir) = fresh_dir();
        let alice = user_id(0xa1);
        let bob = user_id(0xb0);
        let alice_c = dir.for_user(&alice).unwrap();
        let bob_c = dir.for_user(&bob).unwrap();
        let secret = b"shared phrase";
        let a_cipher = alice_c.seal(secret).unwrap();
        let b_cipher = bob_c.seal(secret).unwrap();
        // Same plaintext under two keys → two distinct ciphertexts
        // (no cross-user deduplication leak).
        assert_ne!(a_cipher, b_cipher);
        // Each user can decrypt their own.
        assert_eq!(alice_c.open(&a_cipher).unwrap(), secret);
        assert_eq!(bob_c.open(&b_cipher).unwrap(), secret);
        // Cross-decrypt fails.  This is the headline property.
        assert!(matches!(
            bob_c.open(&a_cipher).unwrap_err(),
            EnvelopeError::Corrupt
        ));
        assert!(matches!(
            alice_c.open(&b_cipher).unwrap_err(),
            EnvelopeError::Corrupt
        ));
    }

    #[test]
    fn directory_caches_cipher_across_calls() {
        let (_tmp, dir) = fresh_dir();
        let alice = user_id(0x01);
        let c1 = dir.for_user(&alice).unwrap();
        let c2 = dir.for_user(&alice).unwrap();
        assert!(Arc::ptr_eq(&c1, &c2), "second lookup must hit cache");
    }

    #[test]
    fn directory_persists_keys_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        let alice = user_id(0xaa);
        let plain = b"persistent";
        let cipher_bytes;
        {
            let dir = AgeCipherDirectory::new(tmp.path()).unwrap();
            cipher_bytes = dir.for_user(&alice).unwrap().seal(plain).unwrap();
        }
        // Drop the directory; reload from the same dir; same key
        // should be on disk and decrypt the prior ciphertext.
        let dir2 = AgeCipherDirectory::new(tmp.path()).unwrap();
        let opened = dir2.for_user(&alice).unwrap().open(&cipher_bytes).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn forget_user_makes_ciphertexts_unrecoverable() {
        let (_tmp, dir) = fresh_dir();
        let u = user_id(0x42);
        let c_old = dir.for_user(&u).unwrap();
        let cipher = c_old.seal(b"will be lost").unwrap();
        assert_eq!(c_old.open(&cipher).unwrap(), b"will be lost");

        dir.forget_user(&u).unwrap();
        // Re-creating the user gets a fresh key — the old ciphertext
        // is now uneanable, which is the "right to be forgotten"
        // contract.
        let c_new = dir.for_user(&u).unwrap();
        assert!(matches!(
            c_new.open(&cipher).unwrap_err(),
            EnvelopeError::Corrupt
        ));
    }

    #[test]
    fn forget_user_is_idempotent_when_missing() {
        let (_tmp, dir) = fresh_dir();
        let u = user_id(0xff);
        // Never created → forget should still succeed.
        dir.forget_user(&u).unwrap();
        dir.forget_user(&u).unwrap();
    }

    #[test]
    fn system_key_routes_to_distinct_key() {
        let (_tmp, dir) = fresh_dir();
        let sys = dir.system().unwrap();
        let alice = dir.for_user(&user_id(0xa1)).unwrap();
        let cipher = sys.seal(b"system-only").unwrap();
        assert_eq!(sys.open(&cipher).unwrap(), b"system-only");
        assert!(matches!(
            alice.open(&cipher).unwrap_err(),
            EnvelopeError::Corrupt
        ));
    }

    #[test]
    fn invalid_user_id_rejected() {
        let (_tmp, dir) = fresh_dir();
        // Path-traversal attempt.
        assert!(matches!(
            dir.for_user("../etc/passwd").unwrap_err(),
            EnvelopeError::BadUserId
        ));
        // Wrong length.
        assert!(matches!(
            dir.for_user("deadbeef").unwrap_err(),
            EnvelopeError::BadUserId
        ));
        // Wrong charset (not hex).
        assert!(matches!(
            dir.for_user(&"z".repeat(32)).unwrap_err(),
            EnvelopeError::BadUserId
        ));
    }
}
