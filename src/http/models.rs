//! `GET /v1/models` — aggregated list of model ids across every
//! configured upstream the operator has wired up.  Used by the SPA's
//! create-form picker so the user sees the full catalogue without
//! the SPA hardcoding it or talking to providers directly.
//!
//! Resolution order, per provider in `[providers.*]` with a platform
//! `api_key`:
//!
//! - openrouter            → `GET /v1/models` (already returns prefixed
//!                            ids like `anthropic/claude-sonnet-4-5`,
//!                            so no extra prefixing on our side).
//! - openai/groq/deepseek/xai → `GET /v1/models` Bearer auth; bare ids,
//!                            we prefix with `<provider>/` so the
//!                            picker can disambiguate.
//! - anthropic             → `GET /v1/models` x-api-key + version;
//!                            ids prefixed.
//! - gemini                → `GET /v1beta/models?key=…`; names like
//!                            `models/gemini-1.5-pro`, we strip the
//!                            `models/` prefix and re-prefix with
//!                            `gemini/`.
//! - ollama / byo          → skipped (local; user-private).
//!
//! Results are merged in declaration order, deduped, and cached for 5
//! minutes per process.  A failure on one provider doesn't fail the
//! whole call: we log and skip that provider, so a flapping upstream
//! can't take the picker offline.
//!
//! Mounted on the tenant tier (OIDC users only); admin/bearer callers
//! don't need it because they don't drive the create form.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use tokio::sync::Mutex;

use super::AppState;
use crate::config::ProviderConfig;

/// 5 minutes — long enough to absorb burst opens of the create modal,
/// short enough that a brand-new model becomes pickable on the same
/// day it's listed upstream.
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Per-process cache.  Cloneable cheaply, lives in `AppState`.
#[derive(Clone, Default)]
pub struct ModelsCache {
    inner: Arc<Mutex<Option<CachedEntry>>>,
}

struct CachedEntry {
    fetched_at: Instant,
    ids: Vec<String>,
}

impl ModelsCache {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Serialize)]
struct ModelsResponse {
    /// Ordered list of upstream model ids
    /// (e.g. `"anthropic/claude-sonnet-4-5"`).  Order follows config
    /// declaration order with each provider's own ordering preserved.
    models: Vec<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/v1/models", get(handler)).with_state(state)
}

async fn handler(State(state): State<AppState>) -> Result<Json<ModelsResponse>, StatusCode> {
    {
        let guard = state.models_cache.inner.lock().await;
        if let Some(entry) = guard.as_ref()
            && entry.fetched_at.elapsed() < CACHE_TTL
        {
            return Ok(Json(ModelsResponse { models: entry.ids.clone() }));
        }
    }

    // Iterate every configured provider with a platform key.  ollama
    // and byo are skipped — the former is local with no public
    // catalogue, the latter is per-user and we don't have user
    // context here.  A provider with no api_key is also skipped.
    let mut all = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for name in state.providers.names() {
        if name == "ollama" || name == "byo" {
            continue;
        }
        let Some(cfg) = state.providers.get(name) else { continue };
        let Some(api_key) = cfg.api_key.as_deref() else { continue };
        if api_key.is_empty() {
            continue;
        }
        match fetch_provider_models(&state.dyson_http, name, cfg, api_key).await {
            Ok(ids) => {
                for id in ids {
                    if seen.insert(id.clone()) {
                        all.push(id);
                    }
                }
            }
            Err(err) => {
                // One bad provider must not take down the picker.
                // Log + skip so the rest still aggregate.
                tracing::warn!(provider = %name, error = %err, "list_models: provider fetch failed");
            }
        }
    }

    if all.is_empty() {
        // Mirror the legacy single-upstream behaviour: 503 when there's
        // nothing to show.  The SPA renders a "no upstream provider
        // configured" message off this status.
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    {
        let mut guard = state.models_cache.inner.lock().await;
        *guard = Some(CachedEntry {
            fetched_at: Instant::now(),
            ids: all.clone(),
        });
    }
    Ok(Json(ModelsResponse { models: all }))
}

/// Fetch a single provider's catalogue, normalising the model-id
/// format to `<provider>/<model>` everywhere except OpenRouter (which
/// already returns prefixed ids natively).  The id format is what the
/// dyson agent uses to route — its provider segment becomes the
/// `/llm/<provider>/...` URL component on outbound calls.
async fn fetch_provider_models(
    http: &reqwest::Client,
    provider: &str,
    cfg: &ProviderConfig,
    api_key: &str,
) -> Result<Vec<String>, FetchError> {
    let base = cfg.upstream.trim_end_matches('/');
    let req = match provider {
        "openrouter" | "openai" | "groq" | "deepseek" | "xai" => http
            .get(format!("{base}/v1/models"))
            .bearer_auth(api_key),
        "anthropic" => http
            .get(format!("{base}/v1/models"))
            .header("x-api-key", api_key)
            .header(
                "anthropic-version",
                cfg.anthropic_version
                    .as_deref()
                    .unwrap_or("2023-06-01"),
            ),
        "gemini" => http
            .get(format!("{base}/v1beta/models"))
            .query(&[("key", api_key)]),
        other => return Err(FetchError::Unsupported(other.to_string())),
    };

    let resp = req.send().await.map_err(FetchError::Network)?;
    if !resp.status().is_success() {
        return Err(FetchError::HttpStatus(resp.status().as_u16()));
    }
    let body: serde_json::Value = resp.json().await.map_err(FetchError::Network)?;

    let ids = match provider {
        "gemini" => parse_gemini(&body),
        _ => parse_openai_shape(&body),
    };

    let prefixed = match provider {
        // OpenRouter ids already carry the provider prefix natively.
        "openrouter" => ids,
        other => ids
            .into_iter()
            .map(|id| {
                // Some providers may already namespace; keep idempotent.
                if id.starts_with(&format!("{other}/")) {
                    id
                } else {
                    format!("{other}/{id}")
                }
            })
            .collect(),
    };
    Ok(prefixed)
}

/// `{ data: [{ id, ... }] }` — OpenAI-shaped catalogues.
fn parse_openai_shape(body: &serde_json::Value) -> Vec<String> {
    body.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("id").and_then(|s| s.as_str()).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `{ models: [{ name: "models/gemini-1.5-pro", ... }] }` — Gemini.
/// The `models/` prefix is uninteresting; strip it so the caller sees
/// just the model id.
fn parse_gemini(body: &serde_json::Value) -> Vec<String> {
    body.get("models")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("name").and_then(|s| s.as_str()))
                .map(|n| n.strip_prefix("models/").unwrap_or(n).to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("provider {0} not supported by /v1/models aggregator")]
    Unsupported(String),
    #[error("network: {0}")]
    Network(reqwest::Error),
    #[error("upstream returned HTTP {0}")]
    HttpStatus(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_openai_shape_extracts_ids() {
        let body = json!({
            "data": [
                {"id": "gpt-4o"},
                {"id": "gpt-4o-mini"},
                {"id": null},
            ]
        });
        let ids = parse_openai_shape(&body);
        assert_eq!(ids, vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string()]);
    }

    #[test]
    fn parse_gemini_strips_models_prefix() {
        let body = json!({
            "models": [
                {"name": "models/gemini-1.5-pro"},
                {"name": "models/gemini-1.5-flash"},
                {"name": "weird-no-prefix"},
            ]
        });
        let ids = parse_gemini(&body);
        assert_eq!(
            ids,
            vec![
                "gemini-1.5-pro".to_string(),
                "gemini-1.5-flash".to_string(),
                "weird-no-prefix".to_string(),
            ],
        );
    }

    #[test]
    fn parse_handles_missing_keys_gracefully() {
        assert!(parse_openai_shape(&json!({})).is_empty());
        assert!(parse_gemini(&json!({})).is_empty());
    }
}
