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
//! warden-issued tokens unmistakable in logs / dashboards and lets
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

use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngCore;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::db::map_sqlx;
use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{UserApiKey, UserRow, UserStatus, UserStore};

/// Literal prefix every warden-issued bearer carries.  Public so
/// [`crate::auth::bearer::BearerAuthenticator`] can route by it.
pub const TOKEN_PREFIX: &str = "dy_";
/// Width (in chars) of the indexed plaintext lookup prefix.  8 hex
/// chars = 32 bits = collision-rare at any realistic tenant scale.
const LOOKUP_PREFIX_LEN: usize = 8;

fn row_to_user(row: &sqlx::sqlite::SqliteRow) -> Result<UserRow, StoreError> {
    let status_text: String = row.try_get("status").map_err(map_sqlx)?;
    let status = UserStatus::parse(&status_text)
        .ok_or_else(|| StoreError::Malformed(format!("status={status_text}")))?;
    Ok(UserRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        subject: row.try_get("subject").map_err(map_sqlx)?,
        email: row.try_get("email").map_err(map_sqlx)?,
        display_name: row.try_get("display_name").map_err(map_sqlx)?,
        status,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        activated_at: row.try_get("activated_at").map_err(map_sqlx)?,
        last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
        openrouter_key_id: row.try_get("openrouter_key_id").map_err(map_sqlx)?,
        openrouter_key_limit_usd: row.try_get("openrouter_key_limit_usd").map_err(map_sqlx)?,
    })
}

#[derive(Clone)]
pub struct SqlxUserStore {
    pool: SqlitePool,
    /// Routes `user_id → EnvelopeCipher` for sealing/opening api-key
    /// ciphertexts.  Held here so the store is self-sufficient — the
    /// auth path sees a plain `UserStore` trait object, no separate
    /// service to thread through.
    ciphers: Arc<dyn CipherDirectory>,
}

impl std::fmt::Debug for SqlxUserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxUserStore").finish_non_exhaustive()
    }
}

impl SqlxUserStore {
    pub fn new(pool: SqlitePool, ciphers: Arc<dyn CipherDirectory>) -> Self {
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
/// for anything that isn't shaped like a warden bearer (wrong literal
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

#[async_trait]
impl UserStore for SqlxUserStore {
    async fn create(&self, row: UserRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO users \
             (id, subject, email, display_name, status, created_at, activated_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.subject)
        .bind(&row.email)
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
        let r = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn get_by_subject(&self, subject: &str) -> Result<Option<UserRow>, StoreError> {
        let r = sqlx::query("SELECT * FROM users WHERE subject = ?")
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<UserRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.iter().map(row_to_user).collect()
    }

    async fn set_status(&self, id: &str, status: UserStatus) -> Result<(), StoreError> {
        let now = now_secs();
        let activated_at: Option<i64> = if matches!(status, UserStatus::Active) {
            Some(now)
        } else {
            None
        };
        let r = sqlx::query(
            "UPDATE users SET status = ?1, \
                              activated_at = COALESCE(?2, activated_at) \
             WHERE id = ?3",
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
        let r = sqlx::query("UPDATE users SET last_seen_at = ? WHERE id = ?")
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

    async fn mint_api_key(
        &self,
        user_id: &str,
        label: Option<&str>,
    ) -> Result<String, StoreError> {
        let token = generate_token();
        let prefix = lookup_prefix(&token)
            .expect("generate_token always produces a well-formed token");
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
             VALUES (?, ?, ?, ?, ?, ?, NULL)",
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
            return Ok(None);
        };
        // Pull every live row whose plaintext prefix matches.  At 32
        // bits of prefix entropy the candidate set is overwhelmingly
        // size-1; we still iterate so a rare collision doesn't break
        // resolution.
        let rows = sqlx::query(
            "SELECT user_id, ciphertext, label, created_at, revoked_at \
             FROM user_api_keys WHERE prefix = ? AND revoked_at IS NULL",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
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
            return Err(StoreError::NotFound);
        };
        let rows = sqlx::query(
            "SELECT id, user_id, ciphertext FROM user_api_keys \
             WHERE prefix = ? AND revoked_at IS NULL",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        for r in rows {
            let user_id: String = r.get("user_id");
            let ciphertext: String = r.get("ciphertext");
            if !ciphertext_matches_token(&*self.ciphers, &user_id, &ciphertext, token) {
                continue;
            }
            let id: String = r.get("id");
            let upd = sqlx::query(
                "UPDATE user_api_keys SET revoked_at = ? \
                 WHERE id = ? AND revoked_at IS NULL",
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
        let r = sqlx::query("UPDATE users SET openrouter_key_id = ? WHERE id = ?")
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

    async fn set_openrouter_limit(
        &self,
        user_id: &str,
        limit_usd: f64,
    ) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET openrouter_key_limit_usd = ? WHERE id = ?")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::envelope::AgeCipherDirectory;

    /// User-id shape accepted by [`AgeCipherDirectory::validate_user_id`]:
    /// 32 hex chars.  Tests pre-stage-4 used `u-<subject>` which the
    /// envelope rejects, so test fixtures now mint conformant ids.
    fn fixed_id(seed: u8) -> String {
        format!("{:032x}", u128::from(seed) | (u128::from(seed) << 64))
    }

    fn sample(id: &str, subject: &str) -> UserRow {
        UserRow {
            id: id.to_owned(),
            subject: subject.into(),
            email: Some(format!("{subject}@example")),
            display_name: Some(subject.into()),
            status: UserStatus::Inactive,
            created_at: 100,
            activated_at: None,
            last_seen_at: None,
            openrouter_key_id: None,
            openrouter_key_limit_usd: 10.0,
        }
    }

    fn build_store() -> impl FnOnce(SqlitePool) -> (tempfile::TempDir, SqlxUserStore) {
        |pool| {
            let tmp = tempfile::tempdir().unwrap();
            let dir: Arc<dyn CipherDirectory> =
                Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
            (tmp, SqlxUserStore::new(pool, dir))
        }
    }

    #[tokio::test]
    async fn openrouter_key_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        let alice = fixed_id(0xa1);
        store.create(sample(&alice, "alice")).await.unwrap();

        let r0 = store.get(&alice).await.unwrap().unwrap();
        assert!(r0.openrouter_key_id.is_none());
        assert!((r0.openrouter_key_limit_usd - 10.0).abs() < 1e-9);

        store
            .set_openrouter_key_id(&alice, Some("or-key-abc"))
            .await
            .unwrap();
        store.set_openrouter_limit(&alice, 25.0).await.unwrap();

        let r1 = store.get(&alice).await.unwrap().unwrap();
        assert_eq!(r1.openrouter_key_id.as_deref(), Some("or-key-abc"));
        assert!((r1.openrouter_key_limit_usd - 25.0).abs() < 1e-9);

        store.set_openrouter_key_id(&alice, None).await.unwrap();
        let r2 = store.get(&alice).await.unwrap().unwrap();
        assert!(r2.openrouter_key_id.is_none());
    }

    #[tokio::test]
    async fn create_get_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        let alice = fixed_id(0xa1);
        store.create(sample(&alice, "alice")).await.unwrap();
        let got = store.get_by_subject("alice").await.unwrap().unwrap();
        assert_eq!(got.id, alice);
        assert_eq!(got.status, UserStatus::Inactive);
    }

    #[tokio::test]
    async fn activate_user_sets_activated_at() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        let alice = fixed_id(0xa1);
        store.create(sample(&alice, "alice")).await.unwrap();
        store
            .set_status(&alice, UserStatus::Active)
            .await
            .unwrap();
        let got = store.get(&alice).await.unwrap().unwrap();
        assert_eq!(got.status, UserStatus::Active);
        assert!(got.activated_at.is_some());
    }

    #[tokio::test]
    async fn api_key_mint_resolve_revoke() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        let alice = fixed_id(0xa1);
        store.create(sample(&alice, "alice")).await.unwrap();

        let tok = store.mint_api_key(&alice, Some("ci")).await.unwrap();
        assert!(tok.starts_with(TOKEN_PREFIX));
        assert_eq!(tok.len(), TOKEN_PREFIX.len() + 32);

        let resolved = store.resolve_api_key(&tok).await.unwrap().unwrap();
        assert_eq!(resolved.user_id, alice);
        assert_eq!(resolved.label.as_deref(), Some("ci"));

        store.revoke_api_key(&tok).await.unwrap();
        assert!(store.resolve_api_key(&tok).await.unwrap().is_none());

        // Revoking an already-revoked token returns NotFound.
        let err = store.revoke_api_key(&tok).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[tokio::test]
    async fn api_key_resolve_rejects_unprefixed_token() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        // No DB hit needed — short-circuits on token shape.
        assert!(store.resolve_api_key("not-ours").await.unwrap().is_none());
        assert!(store
            .resolve_api_key("dy_short")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn api_key_ciphertext_is_not_token_at_rest() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool.clone());
        let alice = fixed_id(0xa1);
        store.create(sample(&alice, "alice")).await.unwrap();
        let tok = store.mint_api_key(&alice, None).await.unwrap();

        // Read the row directly: ciphertext must not equal the token.
        let row = sqlx::query("SELECT ciphertext, prefix FROM user_api_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        let ct: String = row.get("ciphertext");
        let prefix: String = row.get("prefix");
        assert_ne!(ct, tok);
        // age-armored output starts with the literal `-----BEGIN AGE`.
        assert!(ct.starts_with("-----BEGIN AGE"), "got: {ct:.40}");
        // The prefix column is plaintext lookup oracle = first 8 hex
        // chars after the `dy_` literal.
        assert_eq!(prefix, &tok[TOKEN_PREFIX.len()..TOKEN_PREFIX.len() + 8]);
    }

    #[tokio::test]
    async fn api_key_resolve_handles_prefix_collision() {
        // Engineer a prefix collision so the lookup-by-prefix step
        // returns multiple candidate rows: the open-and-compare loop
        // must pick the row whose ciphertext actually decrypts to the
        // bearer.  Forced here by rewriting bob's row's prefix to
        // match alice's; we then resolve alice's token and assert
        // the loop didn't accidentally surface bob's row.
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool.clone());
        let alice = fixed_id(0xa1);
        let bob = fixed_id(0xb0);
        store.create(sample(&alice, "alice")).await.unwrap();
        store.create(sample(&bob, "bob")).await.unwrap();
        let alice_tok = store.mint_api_key(&alice, None).await.unwrap();
        let _bob_tok = store.mint_api_key(&bob, None).await.unwrap();

        let alice_prefix = lookup_prefix(&alice_tok).unwrap();
        sqlx::query("UPDATE user_api_keys SET prefix = ? WHERE user_id = ?")
            .bind(alice_prefix)
            .bind(&bob)
            .execute(&pool)
            .await
            .unwrap();

        // Two rows share the same plaintext prefix now; resolving
        // alice's token must still return alice's row (only alice's
        // ciphertext decrypts to alice's bearer).
        let r_alice = store.resolve_api_key(&alice_tok).await.unwrap().unwrap();
        assert_eq!(r_alice.user_id, alice);
    }

    #[tokio::test]
    async fn legacy_user_seeded_by_migration() {
        let pool = open_in_memory().await.unwrap();
        let (_tmp, store) = build_store()(pool);
        let legacy = store.get("legacy").await.unwrap().unwrap();
        assert_eq!(legacy.subject, "legacy");
        assert_eq!(legacy.status, UserStatus::Suspended);
    }
}
