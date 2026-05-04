//! Admin CRUD for anonymous artefact shares.  Mounted under the
//! tenant tier (`/v1/...`) — every request runs through
//! `user_middleware` first, so handlers see a stamped `CallerIdentity`.
//!
//! Public read (the `share.<apex>/v1/...` endpoint) lives in a
//! sibling module — `share_public` — because it dispatches off the
//! Host header and bypasses `user_middleware` by design.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CallerIdentity;
use crate::db::shares::{ShareAccessRow, ShareRow};
use crate::http::AppState;
use crate::shares::ShareTtl;
use crate::shares::service::{MintedShare, ShareServiceError};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/instances/:id/artifacts/:artefact_id/shares",
            post(mint_share),
        )
        .route(
            "/v1/instances/:id/artefacts/:artefact_id/shares",
            post(mint_share),
        )
        .route("/v1/instances/:id/shares", get(list_shares))
        .route("/v1/shares/:jti", delete(revoke_share))
        .route("/v1/shares/:jti/url", get(get_share_url))
        .route("/v1/shares/:jti/accesses", get(list_accesses))
        .route("/v1/shares/:jti/reissue", post(reissue_share))
        .route("/v1/shares/rotate-key", post(rotate_key))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct ShareView {
    pub jti: String,
    pub instance_id: String,
    pub chat_id: String,
    pub artifact_id: String,
    pub artifact_title: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub label: Option<String>,
    /// Whether the share is currently usable from the SPA's
    /// perspective — not revoked AND not past expiry.  The public
    /// verifier double-checks both at read time, so this is purely
    /// a UI affordance.
    pub active: bool,
}

impl ShareView {
    fn from_row(r: ShareRow) -> Self {
        let now = crate::now_secs();
        let active = r.revoked_at.is_none() && r.expires_at > now;
        Self {
            jti: r.jti,
            instance_id: r.instance_id,
            chat_id: r.chat_id,
            artifact_id: r.artefact_id,
            artifact_title: r.artefact_title,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            label: r.label,
            active,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ShareAccessView {
    pub id: i64,
    pub accessed_at: i64,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub status: i32,
}

impl ShareAccessView {
    fn from_row(r: ShareAccessRow) -> Self {
        Self {
            id: r.id,
            accessed_at: r.accessed_at,
            remote_addr: r.remote_addr,
            user_agent: r.user_agent,
            status: r.status,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MintBody {
    /// dyson identifies artefacts by id alone but we record the
    /// owning chat_id on the share row so the SPA can list shares per
    /// conversation and so a destroyed-conversation cleanup can sweep
    /// orphans without parsing every URL.  Required.
    pub chat_id: String,
    /// `1d`, `7d`, or `30d`.
    pub ttl: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReissueBody {
    pub ttl: String,
}

fn err_to_status(e: &ShareServiceError) -> StatusCode {
    match e {
        ShareServiceError::NotFound => StatusCode::NOT_FOUND,
        ShareServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ShareServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ShareServiceError::Upstream(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn parse_ttl(s: &str) -> Result<ShareTtl, StatusCode> {
    ShareTtl::parse(s).ok_or(StatusCode::BAD_REQUEST)
}

async fn mint_share(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((instance_id, artefact_id)): Path<(String, String)>,
    Json(body): Json<MintBody>,
) -> Result<(StatusCode, Json<MintedShare>), StatusCode> {
    let ttl = parse_ttl(&body.ttl)?;
    if body.chat_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let label = body.label.filter(|s| !s.trim().is_empty());
    let minted = state
        .shares
        .mint(
            &caller.user_id,
            &instance_id,
            &body.chat_id,
            &artefact_id,
            ttl,
            label,
        )
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok((StatusCode::CREATED, Json(minted)))
}

async fn list_shares(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
) -> Result<Json<Vec<ShareView>>, StatusCode> {
    let rows = state
        .shares
        .list(&caller.user_id, &instance_id)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(rows.into_iter().map(ShareView::from_row).collect()))
}

async fn revoke_share(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(jti): Path<String>,
) -> impl IntoResponse {
    match state.shares.revoke(&caller.user_id, &jti).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => err_to_status(&e),
    }
}

/// Re-derive the URL for a still-active share owned by the caller.
/// Returns `{ url }` on success, 410 Gone when the row is revoked or
/// past expiry (the SPA distinguishes that from "not yours" so the
/// copy button can render disabled).
async fn get_share_url(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(jti): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.shares.url_for(&caller.user_id, &jti).await {
        Ok(Some(url)) => Ok(Json(serde_json::json!({ "url": url }))),
        Ok(None) => Err(StatusCode::GONE),
        Err(e) => Err(err_to_status(&e)),
    }
}

async fn list_accesses(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(jti): Path<String>,
) -> Result<Json<Vec<ShareAccessView>>, StatusCode> {
    let rows = state
        .shares
        .list_accesses(&caller.user_id, &jti, 200)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(
        rows.into_iter().map(ShareAccessView::from_row).collect(),
    ))
}

async fn reissue_share(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(jti): Path<String>,
    Json(body): Json<ReissueBody>,
) -> Result<(StatusCode, Json<MintedShare>), StatusCode> {
    let ttl = parse_ttl(&body.ttl)?;
    let minted = state
        .shares
        .reissue(&caller.user_id, &jti, ttl)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok((StatusCode::CREATED, Json(minted)))
}

async fn rotate_key(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<StatusCode, StatusCode> {
    state
        .shares
        .rotate_key(&caller.user_id)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_view_serializes_artifact_spelling() {
        let view = ShareView::from_row(ShareRow {
            jti: "jti-1".to_string(),
            instance_id: "inst-1".to_string(),
            chat_id: "chat-1".to_string(),
            artefact_id: "art-1".to_string(),
            artefact_title: Some("report.md".to_string()),
            created_by: "user-1".to_string(),
            created_at: 1,
            expires_at: crate::now_secs() + 60,
            revoked_at: None,
            label: None,
        });

        let value = serde_json::to_value(view).unwrap();
        assert_eq!(value["artifact_id"], "art-1");
        assert_eq!(value["artifact_title"], "report.md");
        assert!(value.get("artefact_id").is_none());
        assert!(value.get("artefact_title").is_none());
    }
}
