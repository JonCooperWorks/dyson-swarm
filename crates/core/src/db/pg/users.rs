//! SQLite-backed `UserStore`. The `subject` field is the OIDC `sub` claim
//! (or an admin-issued opaque label for non-OIDC api keys). Users start in
//! `inactive` status — JIT provisioning creates the row from a fresh OIDC
//! token but the auth middleware refuses requests until an admin flips the
//! status to `active`.
//!
//! # API-key envelope (Stage 4)
//!
//! Bearer tokens minted via `mint_api_key` are stored sealed: each row
//! holds the OWNER user's age-encrypted ciphertext alongside an
//! 8-hex-char plaintext `prefix` used as the lookup oracle.  The store
//! never persists the bearer's plaintext — it can only be reconstructed
//! by opening the ciphertext with the user's key.
//!
//! Token format: `dy_<32 hex>` (35 chars).  The `dy_` literal makes
//! swarm-issued tokens unmistakable in logs / dashboards and lets
//! `BearerAuthenticator` short-circuit obviously-not-ours bearers
//! before any DB hit.  The 32-hex random part gives 128 bits of
//! unguessable entropy.
//!
//! Resolve flow: prefix-match → for each candidate, open the
//! ciphertext with the row's user cipher → constant-time-compare against
//! the bearer.  Prefix collisions in a 32-bit space are statistically
//! negligible at human scales (a tenant minting 65k keys still has only
//! ~50% chance of any prefix collision), so the expected per-resolve
//! cost is exactly one age open.
//!
//! # Race-free JIT provisioning (G4)
//!
//! `create` uses `INSERT … ON CONFLICT(subject) DO NOTHING` so two
//! racing resolve-or-provision callers don't surface a constraint
//! error to the loser; the loser's `INSERT` becomes a no-op and the
//! caller's subsequent `get_by_subject` returns the canonical row
//! (the winner's id).  The previous check-then-insert flow flagged in
//! the security review (G4) could mint two distinct internal ids for
//! the same OIDC subject if two requests arrived in the same JIT
//! window.
//!
//! # Constant-cost api-key resolve (B6)
//!
//! `resolve_api_key` performs a dummy age-open against a fixed
//! sentinel ciphertext when the prefix lookup yields zero rows, so
//! the timing channel between "no-such-prefix" and
//! "prefix-exists-but-wrong-secret" is closed.  The sentinel cipher
//! is built once via `LazyLock` and uses an in-memory ephemeral age
//! identity — no key material lands on disk.  This pads the miss
//! path to roughly the same cost as a single-candidate hit.

use std::fmt::Write as _;
use std::sync::{Arc, LazyLock};

use age::secrecy::ExposeSecret;
use async_trait::async_trait;
use rand::RngCore;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::pg::map_sqlx;
use crate::envelope::{AgeCipher, CipherDirectory, EnvelopeCipher};
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{UserApiKey, UserRow, UserStatus, UserStore};

/// Literal prefix every swarm-issued bearer carries.  Public so
/// [`crate::auth::bearer::BearerAuthenticator`] can route by it.
pub const TOKEN_PREFIX: &str = "dy_";
/// Width (in chars) of the indexed plaintext lookup prefix.  8 hex
/// chars = 32 bits = collision-rare at any realistic tenant scale.
const LOOKUP_PREFIX_LEN: usize = 8;

/// Plaintext sentinel sealed once at startup.  Mismatches every
/// possible real bearer (a real bearer is `dy_<32 hex>`; this string
/// isn't).  Used by `resolve_api_key` to pad the miss path.
const SENTINEL_PLAINTEXT: &str = "sentinel.miss";

/// Lazy-initialised sentinel: an ephemeral in-memory age identity +
/// the ciphertext of [`SENTINEL_PLAINTEXT`] sealed with it.  On a
/// resolve miss we open `ciphertext` with `cipher` and ct_eq the
/// resulting plaintext against the bearer; the result is always
/// false (different content, different length) but the timing
/// matches a single-candidate hit on the success path.
static SENTINEL: LazyLock<(Arc<dyn EnvelopeCipher>, Vec<u8>)> = LazyLock::new(|| {
    let identity = age::x25519::Identity::generate();
    // `SecretString::expose_secret` hands back an `&str` view of the
    // PEM bytes; we feed it straight into the in-memory constructor
    // — the file path is only used by the `Debug` impl, never read.
    let pem = identity.to_string();
    let cipher = AgeCipher::from_identity_text(pem.expose_secret(), std::path::PathBuf::new())
        .expect("ephemeral age identity is well-formed");
    let ciphertext = cipher
        .seal(SENTINEL_PLAINTEXT.as_bytes())
        .expect("ephemeral age cipher seals deterministically");
    let cipher: Arc<dyn EnvelopeCipher> = Arc::new(cipher);
    (cipher, ciphertext)
});

/// Row decode that opens the per-user envelope on `email_ciphertext`
/// and falls back to the legacy plaintext `email` column when no
/// ciphertext is on file.  Cipher failures (missing key file, bad
/// ciphertext) collapse to `None` rather than erroring the read —
/// orphaned key material shouldn't 500 the admin list.
fn row_to_user(
    row: &sqlx::postgres::PgRow,
    ciphers: &dyn CipherDirectory,
) -> Result<UserRow, StoreError> {
    let status_text: String = row.try_get("status").map_err(map_sqlx)?;
    let status = UserStatus::parse(&status_text)
        .ok_or_else(|| StoreError::Malformed(format!("status={status_text}")))?;
    let id: String = row.try_get("id").map_err(map_sqlx)?;
    let ciphertext: Option<String> = row.try_get("email_ciphertext").map_err(map_sqlx)?;
    let legacy_email: Option<String> = row.try_get("email").map_err(map_sqlx)?;
    let email = match ciphertext.as_deref().filter(|s| !s.is_empty()) {
        Some(ct) => open_email_ciphertext(ciphers, &id, ct).or(legacy_email),
        None => legacy_email,
    };
    Ok(UserRow {
        id,
        subject: row.try_get("subject").map_err(map_sqlx)?,
        email,
        display_name: row.try_get("display_name").map_err(map_sqlx)?,
        status,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        activated_at: row.try_get("activated_at").map_err(map_sqlx)?,
        last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
        openrouter_key_id: row.try_get("openrouter_key_id").map_err(map_sqlx)?,
        openrouter_key_limit_usd: row.try_get("openrouter_key_limit_usd").map_err(map_sqlx)?,
    })
}

fn open_email_ciphertext(ciphers: &dyn CipherDirectory, user_id: &str, ct: &str) -> Option<String> {
    let cipher = ciphers.for_user(user_id).ok()?;
    let bytes = cipher.open(ct.as_bytes()).ok()?;
    String::from_utf8(bytes).ok()
}

fn seal_email_plaintext(
    ciphers: &dyn CipherDirectory,
    user_id: &str,
    plain: &str,
) -> Result<String, StoreError> {
    let cipher = ciphers
        .for_user(user_id)
        .map_err(|e| StoreError::Io(format!("envelope: {e}")))?;
    let ct = cipher
        .seal(plain.as_bytes())
        .map_err(|e| StoreError::Io(format!("envelope seal: {e}")))?;
    String::from_utf8(ct).map_err(|_| StoreError::Malformed("email ciphertext not ASCII".into()))
}

#[derive(Clone)]
pub struct PgUserStore {
    pool: PgPool,
    /// Routes `user_id → EnvelopeCipher` for sealing/opening api-key
    /// ciphertexts.  Held here so the store is self-sufficient — the
    /// auth path sees a plain `UserStore` trait object, no separate
    /// service to thread through.
    ciphers: Arc<dyn CipherDirectory>,
}

impl std::fmt::Debug for PgUserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUserStore").finish_non_exhaustive()
    }
}

impl PgUserStore {
    pub fn new(pool: PgPool, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self { pool, ciphers }
    }
}

/// Generate a fresh random api-key token: `dy_<32 hex>`.  Uses the
/// thread-local CSPRNG; failures are unrecoverable so we panic.
fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(TOKEN_PREFIX.len() + 32);
    s.push_str(TOKEN_PREFIX);
    for b in bytes {
        // `write!` formats straight into `s` — no per-byte heap alloc.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Extract the indexed lookup prefix from a token.  Returns `None`
/// for anything that isn't shaped like a swarm bearer (wrong literal
/// prefix, too short).  Used by both mint (to derive the row's
/// `prefix` column) and resolve (to compute the sqlite WHERE clause).
fn lookup_prefix(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    if rest.len() < LOOKUP_PREFIX_LEN {
        return None;
    }
    let p = &rest[..LOOKUP_PREFIX_LEN];
    if !p.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(p)
}

/// Constant-time bytewise equality for two ASCII bearers.  We're well
/// past the entropy needed to make timing leaks academic, but lookup
/// candidates do come from the DB so a non-CT comparison would, in
/// principle, leak prefix-bucket sizes.  Trivial to do right.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Open `ciphertext` under `user_id`'s envelope cipher and constant-time-
/// compare the plaintext against `token`. Used by both api-key resolve
/// and revoke to walk the prefix-bucket candidate list. Any failure to
/// load the cipher, decrypt, or interpret as UTF-8 is treated as a
/// non-match — a row whose key file is missing (orphaned by a
/// `forget_user`) shouldn't error a token lookup.
fn ciphertext_matches_token(
    ciphers: &dyn CipherDirectory,
    user_id: &str,
    ciphertext: &str,
    token: &str,
) -> bool {
    let Ok(cipher) = ciphers.for_user(user_id) else {
        return false;
    };
    let Ok(plaintext) = cipher.open(ciphertext.as_bytes()) else {
        return false;
    };
    let Ok(plaintext_str) = std::str::from_utf8(&plaintext) else {
        return false;
    };
    ct_eq(plaintext_str, token)
}

/// Constant-cost dummy decrypt for the no-prefix-match path (B6).
/// Opens the lazily-built sentinel ciphertext and ct_eqs the result
/// against `token`.  Always returns `false` (the sentinel plaintext
/// is fixed, length-distinct from any real bearer) but the work
/// performed matches a single real candidate decrypt, closing the
/// timing oracle between "no row in this prefix bucket" and "row
/// exists but ciphertext doesn't match".
fn dummy_decrypt_against_sentinel(token: &str) -> bool {
    let (cipher, ciphertext) = &*SENTINEL;
    let Ok(plaintext) = cipher.open(ciphertext) else {
        // Self-built sentinel — open failure would be a programmer
        // error, not a runtime hazard.  Treat as non-match.
        return false;
    };
    let Ok(plaintext_str) = std::str::from_utf8(&plaintext) else {
        return false;
    };
    ct_eq(plaintext_str, token)
}

#[async_trait]
impl UserStore for PgUserStore {
    /// Idempotent insert: race-free under concurrent JIT-provision
    /// calls (G4).  The conflict target is `subject` because that's
    /// the OIDC-side identity; if two callers race to provision the
    /// same subject, only one row materialises and the loser's call
    /// is a no-op.  Callers that need the canonical id MUST follow
    /// up with `get_by_subject` — the row id they constructed is
    /// authoritative only on the winner's path.
    async fn create(&self, row: UserRow) -> Result<(), StoreError> {
        // Seal the email under the user's per-row age cipher and write
        // it into `email_ciphertext`; leave the legacy plaintext column
        // NULL for sealed rows.  The cipher directory mints a fresh
        // key file for the user on first seal — same lazy pattern the
        // api-key envelope uses.
        //
        // Fallback: when the cipher refuses (e.g. legacy non-hex
        // user_ids, test fixtures, or the seeded `legacy` row) we
        // write the email to the plaintext `email` column instead.
        // Production user ids are uuid-simple (32 hex), so this path
        // only fires for synthetic ids that already lived outside
        // the envelope contract.
        let (ciphertext, plaintext): (Option<String>, Option<String>) =
            match row.email.as_deref().filter(|s| !s.is_empty()) {
                Some(plain) => match seal_email_plaintext(&*self.ciphers, &row.id, plain) {
                    Ok(ct) => (Some(ct), None),
                    Err(_) => (None, Some(plain.to_owned())),
                },
                None => (None, None),
            };
        sqlx::query(
            "INSERT INTO users \
             (id, subject, email, email_ciphertext, display_name, status, created_at, activated_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT(subject) DO NOTHING",
        )
        .bind(&row.id)
        .bind(&row.subject)
        .bind(&plaintext)
        .bind(&ciphertext)
        .bind(&row.display_name)
        .bind(row.status.as_str())
        .bind(row.created_at)
        .bind(row.activated_at)
        .bind(row.last_seen_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<UserRow>, StoreError> {
        let r = sqlx::query("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row, &*self.ciphers)?)),
            None => Ok(None),
        }
    }

    async fn get_by_subject(&self, subject: &str) -> Result<Option<UserRow>, StoreError> {
        let r = sqlx::query("SELECT * FROM users WHERE subject = $1")
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row, &*self.ciphers)?)),
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<UserRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.iter()
            .map(|r| row_to_user(r, &*self.ciphers))
            .collect()
    }

    async fn set_status(&self, id: &str, status: UserStatus) -> Result<(), StoreError> {
        let now = now_secs();
        let activated_at: Option<i64> = if matches!(status, UserStatus::Active) {
            Some(now)
        } else {
            None
        };
        let r = sqlx::query(
            "UPDATE users SET status = $1, \
                              activated_at = COALESCE($2, activated_at) \
             WHERE id = $3",
        )
        .bind(status.as_str())
        .bind(activated_at)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn touch_last_seen(&self, id: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET last_seen_at = $1 WHERE id = $2")
            .bind(now_secs())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn mint_api_key(&self, user_id: &str, label: Option<&str>) -> Result<String, StoreError> {
        let token = generate_token();
        let prefix =
            lookup_prefix(&token).expect("generate_token always produces a well-formed token");
        let cipher = self
            .ciphers
            .for_user(user_id)
            .map_err(|e| StoreError::Io(format!("envelope: {e}")))?;
        let ciphertext_bytes = cipher
            .seal(token.as_bytes())
            .map_err(|e| StoreError::Io(format!("envelope seal: {e}")))?;
        let ciphertext = String::from_utf8(ciphertext_bytes)
            .map_err(|_| StoreError::Malformed("envelope ciphertext not ASCII".into()))?;
        let id = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO user_api_keys (id, user_id, prefix, ciphertext, label, created_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(prefix)
        .bind(&ciphertext)
        .bind(label)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(token)
    }

    async fn resolve_api_key(&self, token: &str) -> Result<Option<UserApiKey>, StoreError> {
        let Some(prefix) = lookup_prefix(token) else {
            // Token not shaped like ours: short-circuit with a
            // sentinel decrypt anyway so the rejection cost matches
            // the prefix-miss cost.  Defends against an attacker
            // probing whether a candidate string is even our shape.
            let _ = dummy_decrypt_against_sentinel(token);
            return Ok(None);
        };
        // Pull every live row whose plaintext prefix matches.  At 32
        // bits of prefix entropy the candidate set is overwhelmingly
        // size-1; we still iterate so a rare collision doesn't break
        // resolution.
        let rows = sqlx::query(
            "SELECT user_id, ciphertext, label, created_at, revoked_at \
             FROM user_api_keys WHERE prefix = $1 AND revoked_at IS NULL",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if rows.is_empty() {
            // No candidates → pad with a sentinel decrypt so this
            // path costs about the same as a single-candidate hit.
            // Closes the timing oracle between "prefix bucket empty"
            // (cheap reject) and "prefix bucket has one row, wrong
            // secret" (one age open + ct_eq).
            let _ = dummy_decrypt_against_sentinel(token);
            return Ok(None);
        }
        for r in rows {
            let user_id: String = r.get("user_id");
            let ciphertext: String = r.get("ciphertext");
            if ciphertext_matches_token(&*self.ciphers, &user_id, &ciphertext, token) {
                return Ok(Some(UserApiKey {
                    token: token.to_owned(),
                    user_id,
                    label: r.get("label"),
                    created_at: r.get("created_at"),
                    revoked_at: r.get("revoked_at"),
                }));
            }
        }
        Ok(None)
    }

    async fn revoke_api_key(&self, token: &str) -> Result<(), StoreError> {
        // Same prefix-and-open flow as resolve, but we mark the row
        // by id (NOT by token, since the token isn't in the DB).
        let Some(prefix) = lookup_prefix(token) else {
            // Match resolve_api_key's miss-path padding: do one
            // sentinel decrypt so a "wrong shape" rejection costs
            // about the same as a "right shape, unknown key" miss.
            // This is admin-gated so the timing side-channel is
            // already small, but it's free to be consistent.
            let _ = dummy_decrypt_against_sentinel(token);
            return Err(StoreError::NotFound);
        };
        let rows = sqlx::query(
            "SELECT id, user_id, ciphertext FROM user_api_keys \
             WHERE prefix = $1 AND revoked_at IS NULL",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if rows.is_empty() {
            // Same padding as resolve_api_key when the prefix bucket
            // is empty: one sentinel decrypt so the cost matches the
            // single-candidate path.
            let _ = dummy_decrypt_against_sentinel(token);
            return Err(StoreError::NotFound);
        }
        for r in rows {
            let user_id: String = r.get("user_id");
            let ciphertext: String = r.get("ciphertext");
            if !ciphertext_matches_token(&*self.ciphers, &user_id, &ciphertext, token) {
                continue;
            }
            let id: String = r.get("id");
            let upd = sqlx::query(
                "UPDATE user_api_keys SET revoked_at = $1 \
                 WHERE id = $2 AND revoked_at IS NULL",
            )
            .bind(now_secs())
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
            if upd.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            return Ok(());
        }
        Err(StoreError::NotFound)
    }

    async fn set_openrouter_key_id(
        &self,
        user_id: &str,
        key_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET openrouter_key_id = $1 WHERE id = $2")
            .bind(key_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_openrouter_limit(&self, user_id: &str, limit_usd: f64) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET openrouter_key_limit_usd = $1 WHERE id = $2")
            .bind(limit_usd)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
