//! `GET /v1/models` — list of model ids exposed by OpenRouter, the
//! single platform-managed default provider.  Used by the SPA's
//! create-form picker so the user sees the full catalogue without
//! the SPA hardcoding it or talking to OR directly.
//!
//! Why OR-only: the BYOK policy is "OpenRouter is the default,
//! everything else is BYOK-or-503" — see `proxy::byok` for the
//! resolver that enforces this.  Non-OR providers don't have a
//! platform-managed key the operator backstops, so there's no
//! global catalogue to surface from them; per-user catalogues live
//! behind the BYOK rows and aren't exposed here.  OR's catalogue
//! already returns prefixed ids (`anthropic/claude-sonnet-4-5`,
//! `openai/gpt-4o`, …) so it's effectively a multi-provider list
//! anyway.
//!
//! No api_key required: OR's `/v1/models` is publicly readable.  We
//! send the platform-managed key as a Bearer when one is configured
//! (fewer rate-limit hiccups), and call the endpoint unauthenticated
//! when the operator runs in Stage 6 / per-user-mint mode where only
//! a Provisioning key is on file.
//!
//! Mounted on the tenant tier (OIDC users only); admin/bearer
//! callers don't need it because they don't drive the create form.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;
use tokio::sync::Mutex;

use super::AppState;

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
    Router::new()
        .route("/v1/models", get(handler))
        .with_state(state)
}

async fn handler(State(state): State<AppState>) -> Result<Json<ModelsResponse>, StatusCode> {
    {
        let guard = state.models_cache.inner.lock().await;
        if let Some(entry) = guard.as_ref()
            && entry.fetched_at.elapsed() < CACHE_TTL
        {
            return Ok(Json(ModelsResponse {
                models: entry.ids.clone(),
            }));
        }
    }

    // OR is the only platform-managed provider; without it we have
    // nothing to show.  503 the BYOK-only deployments — the SPA
    // renders a "no upstream provider configured" message off the
    // status and the picker stays a free-text input.
    //
    // OR's `/v1/models` catalogue is publicly readable, so we fetch
    // it without auth when no static api_key is on file.  A platform-
    // managed key is optional (operators on a Stage 6 / per-user-mint
    // deployment have only a Provisioning key), but we send it as a
    // Bearer when present — fewer rate-limit hiccups under burst.
    let Some(cfg) = state.providers.get("openrouter") else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let upstream = cfg.upstream.trim_end_matches('/');

    let url = format!("{upstream}/v1/models");
    let mut req = state.dyson_http.get(&url);
    if let Some(key) = cfg.api_key.as_deref()
        && !key.is_empty()
    {
        req = req.bearer_auth(key);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, url = %url, "list_models: openrouter fetch failed");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), url = %url, "list_models: non-2xx upstream");
        return Err(StatusCode::BAD_GATEWAY);
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "list_models: openrouter body not JSON");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    // OR returns OpenAI-shaped `{ data: [{ id, ... }] }` with model
    // ids already prefixed (`anthropic/claude-…`, `openai/gpt-…`),
    // so nothing to renormalise.
    let ids: Vec<String> = parse_openai_shape(&body);

    {
        let mut guard = state.models_cache.inner.lock().await;
        *guard = Some(CachedEntry {
            fetched_at: Instant::now(),
            ids: ids.clone(),
        });
    }
    Ok(Json(ModelsResponse { models: ids }))
}

/// `{ data: [{ id, ... }] }` — OpenAI-shaped catalogues, which OR
/// emits unchanged from upstream.
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
    fn parse_handles_missing_keys_gracefully() {
        assert!(parse_openai_shape(&json!({})).is_empty());
    }
}
