//! BYOK key resolution for the LLM proxy.
//!
//! Policy (see `byok.md`):
//!
//! - **OpenRouter is the only provider where the operator backstops
//!   spend.**  Its API is reseller-shaped (per-user keys + USD caps via
//!   the Provisioning API) so the operator can safely lazy-mint a
//!   capped key on first use.
//! - **Every other provider is BYOK-or-503.**  No platform fallback;
//!   if the user hasn't pasted a key, the call fails closed rather
//!   than silently spending against the operator's account on an API
//!   that has no per-user spending controls.
//!
//! Resolution chain:
//!
//! 1. **`byo`** — JSON blob under `byok_byo` carrying both upstream
//!    URL and key.  No fallback; missing → 503.
//! 2. **BYOK** — `byok_<provider>` row in `user_secrets`, sealed
//!    under the user's age key.  Wins for every provider (including
//!    `openrouter`).
//! 3. **OpenRouter lazy-mint** — legacy Stage-6 path.  Only fires
//!    when no `byok_openrouter` is set *and* swarm has a Provisioning
//!    client configured.  Mints a per-user OR key on first call and
//!    caches it under `user_secrets["openrouter_key"]`.
//! 4. **Anything else** → `NoKey`, mapped to 503.  The
//!    `[providers.<name>].api_key` TOML field is ignored for non-OR
//!    providers; it stays parseable for back-compat but never reaches
//!    an upstream.
//!
//! The resolver tags each result with [`KeySource`] so the audit row
//! can attribute spend correctly: BYOK pays the user, OrMinted pays
//! the operator (capped per-user via OR).

use serde::{Deserialize, Serialize};

use crate::proxy::ProxyService;

/// Where the real upstream key came from.  Recorded on every audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// User pasted their own key into `user_secrets`.
    Byok,
    /// OpenRouter Provisioning API minted a per-user key.
    OrMinted,
    /// Operator-configured `[providers.X].api_key` from TOML.
    Platform,
}

impl KeySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            KeySource::Byok => "byok",
            KeySource::OrMinted => "or_minted",
            KeySource::Platform => "platform",
        }
    }
}

/// Outcome of `resolve`.  `upstream_override` is `Some` only for `byo`,
/// where the user owns the URL too.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub key: String,
    pub upstream_override: Option<String>,
    pub source: KeySource,
}

/// JSON shape of the `byok_byo` blob.  The user's chosen upstream is
/// stored alongside the key so the proxy can route there without a TOML
/// edit per user.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ByoBlob {
    pub upstream: String,
    pub api_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("user secrets unavailable")]
    UserSecretsUnavailable,
    #[error("byo upstream not configured for this user")]
    NoByoConfigured,
    #[error("byo blob malformed: {0}")]
    MalformedByo(String),
    #[error("byok row stored non-utf8")]
    NonUtf8Byok,
    #[error("provider not configured: {0}")]
    UnknownProvider(String),
    #[error("no key available for provider")]
    NoKey,
    #[error("openrouter mint failed: {0}")]
    OrMint(String),
    #[error("user secret store error: {0}")]
    UserSecretStore(#[from] crate::secrets::SecretsError),
}

/// Build the secret name for a provider's BYOK row.
pub fn byok_name(provider: &str) -> String {
    format!("byok_{provider}")
}

/// Name reserved for the `byo` JSON blob.  Distinct from the
/// `byok_<provider>` plaintext convention.
pub const BYO_BLOB_NAME: &str = "byok_byo";

/// Run the layered lookup described in the module docstring.
pub async fn resolve(
    state: &ProxyService,
    provider: &str,
    owner_id: &str,
) -> Result<ResolvedKey, ResolveError> {
    // 1. byo: a JSON blob with upstream + key.  No platform fallback.
    if provider == "byo" {
        let user_secrets = state
            .user_secrets
            .as_ref()
            .ok_or(ResolveError::UserSecretsUnavailable)?;
        let blob_bytes = user_secrets
            .get(owner_id, BYO_BLOB_NAME)
            .await?
            .ok_or(ResolveError::NoByoConfigured)?;
        let blob: ByoBlob = serde_json::from_slice(&blob_bytes)
            .map_err(|e| ResolveError::MalformedByo(e.to_string()))?;
        return Ok(ResolvedKey {
            key: blob.api_key,
            upstream_override: Some(blob.upstream),
            source: KeySource::Byok,
        });
    }

    // 2. BYOK: user-pasted key for any other provider.  Wins over both
    //    OR lazy-mint and platform.
    if let Some(user_secrets) = state.user_secrets.as_ref() {
        if let Some(bytes) = user_secrets.get(owner_id, &byok_name(provider)).await? {
            let key = String::from_utf8(bytes).map_err(|_| ResolveError::NonUtf8Byok)?;
            return Ok(ResolvedKey {
                key,
                upstream_override: None,
                source: KeySource::Byok,
            });
        }
    }

    // 3. OpenRouter lazy-mint, only when no BYOK is set.  OR is the
    //    sole provider where the operator backstops spend, because
    //    its Provisioning API gives us per-user keys with USD caps.
    if provider == "openrouter" {
        if let Some(resolver) = state.user_or_keys.as_ref() {
            let key = resolver
                .resolve_plaintext(owner_id)
                .await
                .map_err(|e| ResolveError::OrMint(e.to_string()))?;
            return Ok(ResolvedKey {
                key,
                upstream_override: None,
                source: KeySource::OrMinted,
            });
        }
        // No resolver configured AND no BYOK set → fail closed.
        // OpenRouter never falls back to the global api_key (would
        // shift user spend onto the operator's plan and bypass per-
        // user caps); pin behaviour preserved from Stage 6.
        return Err(ResolveError::NoKey);
    }

    // 4. Every other provider: BYOK-only.  Their APIs aren't
    //    reseller-shaped — there's no per-user spend cap we can
    //    enforce without the user's own account, so silently using
    //    `[providers.<name>].api_key` would mean unbounded operator
    //    spend.  Fail closed and let the SPA prompt for BYOK.  The
    //    TOML field is still parseable (for back-compat with
    //    deployments mid-migration) but never reaches an upstream.
    if state.provider_config(provider).is_none() {
        return Err(ResolveError::UnknownProvider(provider.to_string()));
    }
    Err(ResolveError::NoKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_source_as_str() {
        assert_eq!(KeySource::Byok.as_str(), "byok");
        assert_eq!(KeySource::OrMinted.as_str(), "or_minted");
        assert_eq!(KeySource::Platform.as_str(), "platform");
    }

    #[test]
    fn byok_name_prepends_prefix() {
        assert_eq!(byok_name("openai"), "byok_openai");
        assert_eq!(byok_name("groq"), "byok_groq");
    }

    #[test]
    fn byo_blob_round_trips_json() {
        let b = ByoBlob {
            upstream: "https://my.example/v1".into(),
            api_key: "sk-x".into(),
        };
        let json = serde_json::to_vec(&b).unwrap();
        let back: ByoBlob = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.upstream, b.upstream);
        assert_eq!(back.api_key, b.api_key);
    }
}
