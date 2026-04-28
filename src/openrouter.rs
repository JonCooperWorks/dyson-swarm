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
    pub fn new(upstream: impl Into<String>, provisioning_key: impl Into<String>) -> Result<Self, reqwest::Error> {
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
        let body = CreateKeyBody { name: &combined, limit: limit_usd };
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
        let body = UpdateKeyBody { limit: Some(limit_usd), disabled: None };
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
        Self { users, user_secrets, provisioning }
    }

    /// Resolve `user_id` to the plaintext OpenRouter bearer, minting
    /// upstream + persisting if this user has never had a key.  Safe
    /// to call concurrently from multiple proxy requests — a duplicate
    /// mint just creates a second OR key, which the next admin
    /// suspend cleans up; we accept that race over taking a per-user
    /// mutex on the hot path.
    pub async fn resolve_plaintext(&self, user_id: &str) -> Result<String, ResolveError> {
        let user = self
            .users
            .get(user_id)
            .await?
            .ok_or(ResolveError::UserGone)?;

        // Happy path: key id set + plaintext present.
        if user.openrouter_key_id.is_some()
            && let Some(plain) = self
                .user_secrets
                .get(user_id, USER_OR_KEY_SECRET_NAME)
                .await?
        {
            return Ok(String::from_utf8(plain).map_err(|_| {
                ResolveError::Secrets(crate::secrets::SecretsError::Envelope(
                    crate::envelope::EnvelopeError::Age(
                        "non-utf8 OR key plaintext".into(),
                    ),
                ))
            })?);
        }

        // Otherwise lazy mint.  Use the email as the OR-side label so
        // an operator browsing the OR dashboard sees a human hint
        // alongside the swarm user id.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock that captures calls.  Used by every other module's tests
    /// so we don't bring up a hyper server for trivial happy-path
    /// stubs.
    #[derive(Clone, Default)]
    pub struct MockProvisioning {
        pub minted: std::sync::Arc<std::sync::Mutex<Vec<(String, Option<String>, f64)>>>,
        pub updated: std::sync::Arc<std::sync::Mutex<Vec<(String, f64)>>>,
        pub deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        pub next_key: std::sync::Arc<std::sync::Mutex<String>>,
    }

    #[async_trait::async_trait]
    impl Provisioning for MockProvisioning {
        async fn mint(
            &self,
            name: &str,
            label: Option<&str>,
            limit_usd: f64,
        ) -> Result<MintedKey, OpenRouterError> {
            self.minted
                .lock()
                .unwrap()
                .push((name.into(), label.map(String::from), limit_usd));
            let key = self.next_key.lock().unwrap().clone();
            Ok(MintedKey {
                id: format!("or-key-{name}"),
                key: if key.is_empty() { format!("sk-or-mock-{name}") } else { key },
                name: Some(name.into()),
                label: label.map(String::from),
                limit: Some(limit_usd),
            })
        }
        async fn update_limit(&self, id: &str, limit_usd: f64) -> Result<(), OpenRouterError> {
            self.updated.lock().unwrap().push((id.into(), limit_usd));
            Ok(())
        }
        async fn delete(&self, id: &str) -> Result<(), OpenRouterError> {
            self.deleted.lock().unwrap().push(id.into());
            Ok(())
        }
    }

    #[test]
    fn url_builder_handles_trailing_slash() {
        let c = OpenRouterProvisioning::new("https://openrouter.ai/api/", "pk").unwrap();
        assert_eq!(c.url(""), "https://openrouter.ai/api/v1/keys");
        assert_eq!(c.url("/abc"), "https://openrouter.ai/api/v1/keys/abc");
    }
}
