//! User-scoped artefact list / fetch / sweep endpoints on swarm.
//!
//! The cube already exposes its own per-conversation artefact endpoints
//! (`/api/conversations/:chat/artefacts`, `/api/artefacts/:id`).  These
//! swarm-side mirrors exist for two reasons:
//!
//! 1. The cube is ephemeral.  Once we've cached an artefact via the
//!    share read path or a deliberate `sweep`, the swarm copy persists
//!    across cube reset / template rotation / OOM.
//! 2. Swarm-side listing lets the SPA show "all my artefacts across
//!    all my instances" without N round trips to N cubes.
//!
//! Auth: same `user_middleware` chain as the rest of `/v1/`.  Owner
//! scoping is enforced at the cache layer (the row carries
//! `owner_id`).
//!
//! We deliberately do not 404 on cache miss for `GET /v1/instances/.../
//! artefacts/:id` — instead, fall through to a live cube fetch and
//! write through to the cache, so the SPA has a single endpoint to
//! call and gets persistence "for free".

use axum::body::Body;
use axum::extract::{Extension, Path, State};
use axum::http::{header, Response, StatusCode, Uri};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CallerIdentity;
use crate::error::SwarmError;
use crate::http::AppState;

fn parse_query(s: &str) -> std::collections::HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/instances/:id/artefacts",
            get(list_for_instance),
        )
        .route(
            "/v1/instances/:id/artefacts/sweep",
            post(sweep_instance),
        )
        .route(
            "/v1/instances/:id/artefacts/:art_id",
            get(get_artefact_meta).delete(delete_artefact),
        )
        .route(
            "/v1/instances/:id/artefacts/:art_id/raw",
            get(get_artefact_raw),
        )
        .route("/v1/artefacts", get(list_for_owner))
        .with_state(state)
}

/// Wire shape for a single cached artefact, mirrors dyson's
/// `ArtefactDto` plus the swarm-only `cached_at` timestamp.
#[derive(Debug, Serialize)]
pub struct ArtefactView {
    pub id: String,
    pub instance_id: String,
    pub chat_id: String,
    pub kind: String,
    pub title: String,
    pub mime: Option<String>,
    pub bytes: i64,
    pub created_at: i64,
    pub cached_at: i64,
}

impl ArtefactView {
    fn from_row(r: crate::db::artefacts::CachedArtefact) -> Self {
        Self {
            id: r.artefact_id,
            instance_id: r.instance_id,
            chat_id: r.chat_id,
            kind: r.kind,
            title: r.title,
            mime: r.mime,
            bytes: r.bytes,
            created_at: r.created_at,
            cached_at: r.cached_at,
        }
    }
}

async fn list_for_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
    uri: Uri,
) -> Result<Json<Vec<ArtefactView>>, StatusCode> {
    // Ownership probe — same shape the shares routes use.
    state
        .instances
        .get(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_to_status)?;
    let q = parse_query(uri.query().unwrap_or(""));
    let chat = q.get("chat_id").cloned();
    let mut rows = state
        .artefact_cache
        .list_for_instance(&caller.user_id, &instance_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(chat) = chat.as_deref() {
        rows.retain(|r| r.chat_id == chat);
    }
    Ok(Json(rows.into_iter().map(ArtefactView::from_row).collect()))
}

async fn list_for_owner(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    uri: Uri,
) -> Result<Json<Vec<ArtefactView>>, StatusCode> {
    let q = parse_query(uri.query().unwrap_or(""));
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(500)
        .min(1000);
    let rows = state
        .artefact_cache
        .list_for_owner(&caller.user_id, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows.into_iter().map(ArtefactView::from_row).collect()))
}

async fn get_artefact_meta(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((instance_id, art_id)): Path<(String, String)>,
) -> Result<Json<ArtefactView>, StatusCode> {
    state
        .instances
        .get(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_to_status)?;
    // Cache-only lookup: meta endpoint is for "is this artefact known
    // to swarm?" answers; for "fetch the body even if cold", use /raw.
    // Search across all chats this user owns under this instance.  The
    // by-tuple lookup is O(1) — but we don't know the chat — so we do
    // the per-instance scan and find the matching id.  In practice
    // each instance has < 100 artefacts so the scan is cheap.
    let rows = state
        .artefact_cache
        .list_for_instance(&caller.user_id, &instance_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row = rows
        .into_iter()
        .find(|r| r.artefact_id == art_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ArtefactView::from_row(row)))
}

async fn get_artefact_raw(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((instance_id, art_id)): Path<(String, String)>,
) -> Result<Response<Body>, StatusCode> {
    let instance = state
        .instances
        .get(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_to_status)?;

    // 1. Cache hit + body present?
    let cached_row = state
        .artefact_cache
        .list_for_instance(&caller.user_id, &instance_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .find(|r| r.artefact_id == art_id);
    if let Some(row) = &cached_row
        && let Ok(Some(bytes)) = state.artefact_cache.read_body(row).await
    {
        return Ok(body_response(bytes, row.mime.as_deref(), &row.title));
    }

    // 2. Cache miss → fall through to the live cube and write through.
    let resp = crate::instance_client::fetch_artefact(
        &state.dyson_http,
        &state.sandbox_domain,
        &instance,
        &format!("/api/artefacts/{art_id}"),
    )
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !resp.status().is_success() {
        return Err(StatusCode::NOT_FOUND);
    }
    let mime = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Surface the chat id back so the cache can be populated.  The
    // cube stamps `X-Dyson-Chat-Id` on artefact responses.
    let chat_id = resp
        .headers()
        .get("x-dyson-chat-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let title = cached_row
        .as_ref()
        .map(|r| r.title.clone())
        .unwrap_or_else(|| art_id.clone());
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .to_vec();
    if !chat_id.is_empty() {
        let _ = state
            .artefact_cache
            .ingest(
                crate::artefacts::IngestMeta {
                    instance_id: &instance_id,
                    owner_id: &caller.user_id,
                    chat_id: &chat_id,
                    artefact_id: &art_id,
                    kind: cached_row.as_ref().map(|r| r.kind.as_str()).unwrap_or("other"),
                    title: &title,
                    mime: mime.as_deref(),
                    created_at: crate::now_secs(),
                    metadata_json: None,
                },
                Some(&bytes),
            )
            .await;
    }
    Ok(body_response(bytes, mime.as_deref(), &title))
}

/// Aggressively populate the cache for an instance — pulls the full
/// artefact list off the cube and ingests metadata for every entry.
/// Bodies are NOT pulled here (a chat with hundreds of multi-MB
/// artefacts would otherwise spike memory); the SPA can hit `/raw`
/// individually for bodies the user actually opens, OR the user can
/// pre-cache by clicking "share" (the share read path also write-
/// throughs the body).  Returns the list of artefacts now known to
/// swarm.
async fn sweep_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
    Json(body): Json<SweepBody>,
) -> Result<Json<Vec<ArtefactView>>, StatusCode> {
    let instance = state
        .instances
        .get(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_to_status)?;
    let chat_id = body.chat_id;
    if chat_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let resp = crate::instance_client::fetch_artefact(
        &state.dyson_http,
        &state.sandbox_domain,
        &instance,
        &format!("/api/conversations/{chat_id}/artefacts"),
    )
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let raw = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let arr: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let items = arr.as_array().cloned().unwrap_or_default();
    for item in &items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("other");
        let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("Artefact");
        let created_at = item.get("created_at").and_then(|v| v.as_i64()).unwrap_or(0);
        let metadata_json = item.get("metadata").map(|v| v.to_string());
        let _ = state
            .artefact_cache
            .ingest(
                crate::artefacts::IngestMeta {
                    instance_id: &instance_id,
                    owner_id: &caller.user_id,
                    chat_id: &chat_id,
                    artefact_id: id,
                    kind,
                    title,
                    mime: None,
                    created_at,
                    metadata_json: metadata_json.as_deref(),
                },
                None,
            )
            .await;
    }
    let rows = state
        .artefact_cache
        .list_for_instance(&caller.user_id, &instance_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let filtered: Vec<_> = rows
        .into_iter()
        .filter(|r| r.chat_id == chat_id)
        .map(ArtefactView::from_row)
        .collect();
    Ok(Json(filtered))
}

#[derive(Debug, Deserialize)]
struct SweepBody {
    chat_id: String,
}

async fn delete_artefact(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((instance_id, art_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    state
        .instances
        .get(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_to_status)?;
    // We don't know the chat_id from the URL alone — find it via
    // the per-instance listing, then call the owner-scoped delete.
    let rows = state
        .artefact_cache
        .list_for_instance(&caller.user_id, &instance_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(row) = rows.into_iter().find(|r| r.artefact_id == art_id) else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let _ = state
        .artefact_cache
        .delete(&caller.user_id, &row.instance_id, &row.chat_id, &row.artefact_id)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

fn body_response(bytes: Vec<u8>, mime: Option<&str>, title: &str) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "private, no-store");
    if let Some(ct) = mime {
        builder = builder.header(header::CONTENT_TYPE, format!("{ct}; charset=utf-8"));
    }
    let safe_title = sanitize_title(title);
    builder = builder.header(
        header::CONTENT_DISPOSITION,
        format!("inline; filename=\"{safe_title}\""),
    );
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn sanitize_title(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .take(80)
        .collect()
}

fn swarm_to_status(e: SwarmError) -> StatusCode {
    match e {
        SwarmError::NotFound => StatusCode::NOT_FOUND,
        SwarmError::BadRequest(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
