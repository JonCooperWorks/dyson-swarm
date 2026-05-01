//! Probe-on-paste validation for BYOK keys.
//!
//! When a user pastes a key into the SPA we hit the provider's cheapest
//! auth-checking endpoint with an 8s timeout.  This catches typos and
//! revoked keys at paste time so the first real chat call doesn't 401.
//!
//! - openai / openrouter / groq / deepseek / xai / ollama →
//!   `GET <upstream>/v1/models` with `Authorization: Bearer <key>`.
//!   Ollama here means Ollama Cloud (OpenAI-compatible); local
//!   `ollama serve` daemons go through the `byo` slot instead.
//! - gemini → `GET <upstream>/v1beta/models` with `x-goog-api-key`.
//! - anthropic → `POST <upstream>/v1/messages` with `x-api-key`,
//!   `max_tokens=1`, `model=claude-3-5-haiku-latest` (no public list-
//!   models endpoint).
//! - byo → `GET <user_upstream>/v1/models` with Bearer (assume OpenAI-
//!   compatible).

use std::time::Duration;

use crate::config::ProviderConfig;

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const ANTHROPIC_DEFAULT_VERSION: &str = "2023-06-01";

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    #[error("provider not supported by validator: {0}")]
    UnknownProvider(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("client init error: {0}")]
    Client(String),
}

/// Outcome of a validation probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateResult {
    /// Provider accepted the key (HTTP 2xx).
    Ok,
    /// Provider rejected the key (HTTP 401 / 403 / 422).
    Rejected,
}

/// Run a validation probe.  `upstream` is the provider's base URL — for
/// `byo`, that's the user-supplied URL; for everything else, the value
/// from `[providers.<name>].upstream`.  `version` is consumed only for
/// Anthropic.
pub async fn validate_key(
    provider: &str,
    key: &str,
    upstream: &str,
    version: Option<&str>,
) -> Result<ValidateResult, ValidateError> {
    let http = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ValidateError::Client(e.to_string()))?;
    let base = upstream.trim_end_matches('/');

    let resp = match provider {
        "openai" | "openrouter" | "groq" | "deepseek" | "xai" | "ollama" | "byo" => http
            .get(format!("{base}/v1/models"))
            .bearer_auth(key)
            .send()
            .await
            .map_err(|e| ValidateError::Network(e.to_string()))?,
        "gemini" => http
            .get(format!("{base}/v1beta/models"))
            .header("x-goog-api-key", key)
            .send()
            .await
            .map_err(|e| ValidateError::Network(e.to_string()))?,
        "anthropic" => http
            .post(format!("{base}/v1/messages"))
            .header("x-api-key", key)
            .header(
                "anthropic-version",
                version.unwrap_or(ANTHROPIC_DEFAULT_VERSION),
            )
            .json(&serde_json::json!({
                "model": "claude-3-5-haiku-latest",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "."}],
            }))
            .send()
            .await
            .map_err(|e| ValidateError::Network(e.to_string()))?,
        other => return Err(ValidateError::UnknownProvider(other.to_string())),
    };

    let status = resp.status();
    if status.is_success() {
        Ok(ValidateResult::Ok)
    } else if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    {
        Ok(ValidateResult::Rejected)
    } else {
        // Treat other non-2xx (5xx, 429, 404) as Rejected too — the
        // user's key clearly isn't usable against this upstream right
        // now, and we'd rather show "rejected" than persist a key the
        // first chat call will then fail on.  Network errors stay on
        // the Err path so the SPA can distinguish "we couldn't reach
        // them" from "they didn't like the key".
        Ok(ValidateResult::Rejected)
    }
}

/// Convenience: pull the upstream + version out of a `ProviderConfig`
/// when validating a non-`byo` key.
pub async fn validate_known_provider(
    provider: &str,
    key: &str,
    cfg: &ProviderConfig,
) -> Result<ValidateResult, ValidateError> {
    validate_key(
        provider,
        key,
        &cfg.upstream,
        cfg.anthropic_version.as_deref(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_provider_errors() {
        let err = validate_key("nope", "k", "http://x", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ValidateError::UnknownProvider(_)));
    }
}
