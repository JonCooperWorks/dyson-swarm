//! OpenRouter Provisioning API client.
//!
//! Used by the swarm's Stage-6 per-user-key flow: each user gets their
//! own OpenRouter key minted at first use, with a configurable USD
//! budget cap (default $10).  When the user is suspended or admin-
//! deleted, the key is revoked upstream so a leaked plaintext stops
//! accruing charges.
//!
//! The "provisioning key" is a separate credential from a regular
//! OpenRouter API key — only it can mint/list/update/delete keys via
//! `/api/v1/keys`.  Keep it tightly scoped (swarm config / system
//! secrets); never hand it to a Dyson sandbox.
//!
//! API shape (excerpt from openrouter.ai/docs):
//!   POST   /api/v1/keys        body { name, label, limit }   → { data: { id, key, ... } }
//!   PATCH  /api/v1/keys/:id    body { limit }                → { data: { ... } }
//!   DELETE /api/v1/keys/:id                                   → 204
//!   GET    /api/v1/keys/:id                                   → { data: { ... } }
//!
//! `limit` is USD (a float); OpenRouter rejects negative or absurd
//! values upstream so we don't policy that here.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Live OpenRouter Provisioning client.
#[derive(Clone)]
pub struct OpenRouterProvisioning {
    upstream: String,
    provisioning_key: String,
    http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenRouterError {
    #[error("openrouter http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("openrouter status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("openrouter response missing field: {0}")]
    Missing(&'static str),
}

#[derive(Debug, Clone, Serialize)]
struct CreateKeyBody<'a> {
    /// User-visible label in the OpenRouter dashboard. We use the
    /// swarm user id (and email if known, joined) so an operator
    /// can match a key to a person.  Note: OR's API returns its
    /// own `label` field (the key preview, server-generated); the
    /// only operator-visible string is `name`, so we encode both
    /// pieces in there.
    name: &'a str,
    /// Hard USD spend cap on this key.  When exceeded, OR returns
    /// 402 on every subsequent call.
    limit: f64,
}

#[derive(Debug, Clone, Serialize)]
struct UpdateKeyBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
}

/// Fields returned by POST /keys.  `key` is the plaintext bearer the
/// user's instances will use; swarm seals it into the user's
/// envelope cipher and stores the ciphertext in `user_secrets`.
/// Subsequent calls (PATCH/GET) return only the metadata — never
/// the plaintext again.
///
/// OR's actual response shape is the somewhat irregular:
///     `{ "data": { "hash": "...", "name": "...", "label": "<preview>", "limit": ... }, "key": "<plaintext>" }`
/// where `hash` is the stable id and `key` is at the top level (not
/// inside `data`).  We deserialize via a private wire type and
/// project the relevant fields; that way an OR API change in
/// shape only breaks one place.
#[derive(Debug, Clone)]
pub struct MintedKey {
    /// Stable identifier — what we keep on `users.openrouter_key_id`.
    /// Maps to OR's `data.hash`.
    pub id: String,
    /// Plaintext OR key.  Sealed via [`crate::envelope::CipherDirectory`]
    /// and discarded after.
    pub key: String,
    pub name: Option<String>,
    pub label: Option<String>,
    pub limit: Option<f64>,
}

/// Wire shape of POST /api/v1/keys.  Kept private so the rest of the
/// crate sees the cleaned-up [`MintedKey`].
#[derive(Debug, Deserialize)]
struct MintWire {
    data: MintWireData,
    /// Plaintext key — sibling of `data`, never inside it.
    key: String,
}

#[derive(Debug, Deserialize)]
struct MintWireData {
    hash: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    limit: Option<f64>,
}

impl OpenRouterProvisioning {
    /// Build a client.  `upstream` is e.g. `"https://openrouter.ai/api"`
    /// (no trailing slash; matches the `[providers.openrouter]` value
    /// in swarm config).
    pub fn new(
        upstream: impl Into<String>,
        provisioning_key: impl Into<String>,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self {
            upstream: upstream.into(),
            provisioning_key: provisioning_key.into(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/keys{}", self.upstream.trim_end_matches('/'), path)
    }

    /// Mint a new key for `name` (we use the swarm user id, plus
    /// email if known, joined into one string since OR's API only
    /// has one operator-visible label field) with the given USD
    /// `limit_usd`.  Returns the plaintext key — the only chance to
    /// capture it.
    pub async fn mint(
        &self,
        name: &str,
        label: Option<&str>,
        limit_usd: f64,
    ) -> Result<MintedKey, OpenRouterError> {
        // OR's `name` is the only operator-visible string; fold the
        // email into it when present so the dashboard reads as
        // "alice@x · <user_id>".
        let combined = match label {
            Some(l) if !l.is_empty() => format!("{l} · {name}"),
            _ => name.to_string(),
        };
        let body = CreateKeyBody {
            name: &combined,
            limit: limit_usd,
        };
        let resp = self
            .http
            .post(self.url(""))
            .bearer_auth(&self.provisioning_key)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(OpenRouterError::Status {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        let wire: MintWire = resp.json().await?;
        if wire.key.is_empty() {
            return Err(OpenRouterError::Missing("key"));
        }
        Ok(MintedKey {
            id: wire.data.hash,
            key: wire.key,
            name: wire.data.name,
            label: wire.data.label,
            limit: wire.data.limit,
        })
    }

    /// Update the USD limit on an existing key.  No-op upstream if
    /// the new limit equals the current one — OR is idempotent here.
    pub async fn update_limit(&self, id: &str, limit_usd: f64) -> Result<(), OpenRouterError> {
        let body = UpdateKeyBody {
            limit: Some(limit_usd),
            disabled: None,
        };
        let resp = self
            .http
            .patch(self.url(&format!("/{id}")))
            .bearer_auth(&self.provisioning_key)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(OpenRouterError::Status {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Disable (revoke) a key upstream.  After this call, any inbound
    /// requests bearing the plaintext get 401 from OR.  We use this
    /// on user suspension and on hard-delete; swarm's local copy of
    /// the ciphertext is wiped separately.
    pub async fn delete(&self, id: &str) -> Result<(), OpenRouterError> {
        let resp = self
            .http
            .delete(self.url(&format!("/{id}")))
            .bearer_auth(&self.provisioning_key)
            .send()
            .await?;
        let status = resp.status();
        // 404 is fine — the key was already gone.  Treat as success
        // so suspend/delete idempotency works after a partial failure.
        if !status.is_success() && status.as_u16() != 404 {
            return Err(OpenRouterError::Status {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        Ok(())
    }
}

/// Trait wrapper so the proxy + admin paths can take a generic
/// provisioning client and tests can drop in a mock without spinning
/// up a hyper server.
#[async_trait::async_trait]
pub trait Provisioning: Send + Sync {
    async fn mint(
        &self,
        name: &str,
        label: Option<&str>,
        limit_usd: f64,
    ) -> Result<MintedKey, OpenRouterError>;
    async fn update_limit(&self, id: &str, limit_usd: f64) -> Result<(), OpenRouterError>;
    async fn delete(&self, id: &str) -> Result<(), OpenRouterError>;
}

#[async_trait::async_trait]
impl Provisioning for OpenRouterProvisioning {
    async fn mint(
        &self,
        name: &str,
        label: Option<&str>,
        limit_usd: f64,
    ) -> Result<MintedKey, OpenRouterError> {
        OpenRouterProvisioning::mint(self, name, label, limit_usd).await
    }
    async fn update_limit(&self, id: &str, limit_usd: f64) -> Result<(), OpenRouterError> {
        OpenRouterProvisioning::update_limit(self, id, limit_usd).await
    }
    async fn delete(&self, id: &str) -> Result<(), OpenRouterError> {
        OpenRouterProvisioning::delete(self, id).await
    }
}

/// Bridges the proxy's per-request "give me this user's OpenRouter
/// bearer" need with the lazy-mint policy: first call mints upstream,
/// stores `users.openrouter_key_id` + sealed plaintext in
/// `user_secrets`, and returns the plaintext.  Subsequent calls
/// decrypt the sealed plaintext.  Two consecutive misses (key id set
/// but plaintext gone) are treated as a re-mint trigger so a
/// half-deleted state self-heals.
pub struct UserOrKeyResolver {
    users: std::sync::Arc<dyn crate::traits::UserStore>,
    user_secrets: std::sync::Arc<crate::secrets::UserSecretsService>,
    provisioning: std::sync::Arc<dyn Provisioning>,
    /// Per-user mint serialiser.  Without this, two concurrent proxy
    /// requests for a user with no OR key both fall through to the mint
    /// branch, both mint upstream, and only the second `set_openrouter_key_id`
    /// survives — the first key is orphaned in OR and keeps counting
    /// against the operator's spend cap.  We dedupe with a per-user
    /// async mutex so the second call double-checks and reuses the
    /// first one's freshly-sealed plaintext.
    mint_locks:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("user gone")]
    UserGone,
    #[error("user store: {0}")]
    Store(#[from] crate::error::StoreError),
    #[error("secrets: {0}")]
    Secrets(#[from] crate::secrets::SecretsError),
    #[error("openrouter: {0}")]
    OpenRouter(#[from] OpenRouterError),
}

/// Name under which the per-user OR key plaintext lives in
/// `user_secrets`.  Stable string so manual recovery / migration
/// scripts can find it.
pub const USER_OR_KEY_SECRET_NAME: &str = "openrouter_key";

impl UserOrKeyResolver {
    pub fn new(
        users: std::sync::Arc<dyn crate::traits::UserStore>,
        user_secrets: std::sync::Arc<crate::secrets::UserSecretsService>,
        provisioning: std::sync::Arc<dyn Provisioning>,
    ) -> Self {
        Self {
            users,
            user_secrets,
            provisioning,
            mint_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Resolve `user_id` to the plaintext OpenRouter bearer, minting
    /// upstream + persisting if this user has never had a key.  Safe
    /// to call concurrently from multiple proxy requests: a per-user
    /// mutex serialises mint, so the second caller double-checks and
    /// reuses the first one's sealed plaintext instead of spawning a
    /// second OR key.
    pub async fn resolve_plaintext(&self, user_id: &str) -> Result<String, ResolveError> {
        // Fast path: existing key + plaintext, no lock needed.
        if let Some(plain) = self.try_existing(user_id).await? {
            return Ok(plain);
        }

        // Slow path: serialise on the per-user mint lock so two concurrent
        // requests don't both mint.  Drop the registry guard before
        // awaiting on the per-user mutex.
        let lock = {
            let mut map = self.mint_locks.lock().expect("mint_locks poisoned");
            map.entry(user_id.to_string())
                .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        // Re-check under the lock — a concurrent caller may have minted
        // already.  This is the bit that closes the double-mint race.
        if let Some(plain) = self.try_existing(user_id).await? {
            return Ok(plain);
        }

        // First minter wins.
        let user = self
            .users
            .get(user_id)
            .await?
            .ok_or(ResolveError::UserGone)?;
        let label = user.email.as_deref();
        let minted = self
            .provisioning
            .mint(&user.id, label, user.openrouter_key_limit_usd)
            .await?;
        self.user_secrets
            .put(user_id, USER_OR_KEY_SECRET_NAME, minted.key.as_bytes())
            .await?;
        self.users
            .set_openrouter_key_id(user_id, Some(&minted.id))
            .await?;
        Ok(minted.key)
    }

    /// Returns the existing per-user OR plaintext when both the key id
    /// and the sealed value are present.  Used for both the unlocked
    /// fast path and the under-lock recheck.
    async fn try_existing(&self, user_id: &str) -> Result<Option<String>, ResolveError> {
        let user = self
            .users
            .get(user_id)
            .await?
            .ok_or(ResolveError::UserGone)?;
        if user.openrouter_key_id.is_none() {
            return Ok(None);
        }
        let Some(plain) = self
            .user_secrets
            .get(user_id, USER_OR_KEY_SECRET_NAME)
            .await?
        else {
            return Ok(None);
        };
        let s = String::from_utf8(plain).map_err(|_| {
            ResolveError::Secrets(crate::secrets::SecretsError::Envelope(
                crate::envelope::EnvelopeError::Age("non-utf8 OR key plaintext".into()),
            ))
        })?;
        Ok(Some(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxUserSecretStore;
    use crate::db::users::SqlxUserStore;
    use crate::envelope::AgeCipherDirectory;
    use crate::secrets::UserSecretsService;
    use crate::traits::{UserRow, UserSecretStore, UserStatus, UserStore};

    #[test]
    fn url_builder_handles_trailing_slash() {
        let c = OpenRouterProvisioning::new("https://openrouter.ai/api/", "pk").unwrap();
        assert_eq!(c.url(""), "https://openrouter.ai/api/v1/keys");
        assert_eq!(c.url("/abc"), "https://openrouter.ai/api/v1/keys/abc");
    }

    /// Records every mint call so the test can assert at most one fired
    /// per user even under concurrent resolve_plaintext.
    #[derive(Clone, Default)]
    struct CountingProvisioning {
        mints: Arc<AtomicU32>,
    }
    #[async_trait::async_trait]
    impl Provisioning for CountingProvisioning {
        async fn mint(
            &self,
            name: &str,
            _label: Option<&str>,
            limit_usd: f64,
        ) -> Result<MintedKey, OpenRouterError> {
            // Slow the mint path so a parallel resolver call has time to
            // race in.  Without this the test passes even on the broken
            // implementation because each await is a microsecond.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let n = self.mints.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(MintedKey {
                id: format!("or-key-{n}"),
                key: format!("sk-or-mock-{name}-{n}"),
                name: Some(name.into()),
                label: None,
                limit: Some(limit_usd),
            })
        }
        async fn update_limit(&self, _: &str, _: f64) -> Result<(), OpenRouterError> {
            Ok(())
        }
        async fn delete(&self, _: &str) -> Result<(), OpenRouterError> {
            Ok(())
        }
    }

    /// Regression: when two proxy requests race past `try_existing` for
    /// a user with no OR key, only ONE mint upstream may fire.  The
    /// second caller must double-check under the lock and reuse the
    /// first call's sealed plaintext.
    #[tokio::test]
    async fn parallel_resolve_mints_at_most_once_per_user() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let users: Arc<dyn UserStore> =
            Arc::new(SqlxUserStore::new(pool.clone(), cipher_dir.clone()));
        let user_secret_store: Arc<dyn UserSecretStore> =
            Arc::new(SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(UserSecretsService::new(user_secret_store, cipher_dir));
        // Seed the user directly so users.get() returns a row without an
        // openrouter_key_id (forces the mint branch).  AgeCipherDirectory
        // requires user_id be 32 hex chars (path-traversal guard).
        let user_id = uuid::Uuid::new_v4().simple().to_string();
        users
            .create(UserRow {
                id: user_id.clone(),
                subject: "alice@idp".into(),
                email: Some("alice@example.com".into()),
                display_name: None,
                status: UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
            })
            .await
            .unwrap();

        let prov = Arc::new(CountingProvisioning::default());
        let resolver = Arc::new(UserOrKeyResolver::new(
            users.clone(),
            user_secrets.clone(),
            prov.clone() as Arc<dyn Provisioning>,
        ));

        // Fire 16 concurrent resolves; only one should mint.
        let mut handles = Vec::new();
        for _ in 0..16 {
            let r = resolver.clone();
            let uid = user_id.clone();
            handles.push(tokio::spawn(async move { r.resolve_plaintext(&uid).await }));
        }
        let mut keys: Vec<String> = Vec::new();
        for h in handles {
            keys.push(h.await.unwrap().unwrap());
        }
        assert_eq!(
            prov.mints.load(Ordering::SeqCst),
            1,
            "mint must fire exactly once"
        );
        // Every caller observes the same plaintext.
        let first = keys[0].clone();
        for k in &keys {
            assert_eq!(k, &first, "all parallel resolvers must see one plaintext");
        }
    }
}
