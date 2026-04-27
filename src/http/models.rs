//! `GET /v1/models` — list of model ids the configured upstream LLM
//! provider exposes.  Used by the SPA's create-form picker so the user
//! sees the full upstream catalogue without the SPA hardcoding it or
//! talking to openrouter.ai directly.
//!
//! The handler proxies through to `<upstream>/v1/models` (OpenRouter,
//! OpenAI, etc. all return the same `{ data: [{ id, ... }] }` shape).
//! The result is cached per-process for 5 minutes — `[providers.*]`
//! catalogues update slowly (new models are weekly news at most), and
//! the SPA hits this on every modal open.
//!
//! Mounted on the tenant tier (OIDC users only); admin/bearer callers
//! don't need it because they don't drive the create form.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
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
    /// Ordered list of upstream model ids (e.g. `"anthropic/claude-sonnet-4-5"`).
    /// Order follows the upstream's response — OpenRouter sorts by
    /// recency so newest entries show up first in the SPA picker.
    models: Vec<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/v1/models", get(handler)).with_state(state)
}

async fn handler(State(state): State<AppState>) -> Result<Json<ModelsResponse>, StatusCode> {
    let upstream = state
        .models_upstream
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    {
        let guard = state.models_cache.inner.lock().await;
        if let Some(entry) = guard.as_ref()
            && entry.fetched_at.elapsed() < CACHE_TTL
        {
            return Ok(Json(ModelsResponse { models: entry.ids.clone() }));
        }
    }

    let url = format!("{}/v1/models", upstream.trim_end_matches('/'));
    let resp = match state.dyson_http.get(&url).send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, url = %url, "list_models: upstream fetch failed");
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
            tracing::warn!(error = %err, "list_models: upstream body not JSON");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let ids: Vec<String> = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("id").and_then(|s| s.as_str()).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    {
        let mut guard = state.models_cache.inner.lock().await;
        *guard = Some(CachedEntry {
            fetched_at: Instant::now(),
            ids: ids.clone(),
        });
    }
    Ok(Json(ModelsResponse { models: ids }))
}
