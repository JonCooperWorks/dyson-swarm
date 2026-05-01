//! Snapshot/backup/restore routes:
//! - `POST   /v1/instances/:id/snapshot`  → take a snapshot, kind=manual
//! - `POST   /v1/instances/:id/backup`    → take a snapshot then promote, kind=backup
//! - `POST   /v1/instances/:id/restore`   → restore from a snapshot id supplied
//!   in the body. The path `:id` is the source instance and is currently
//!   informational; the actual snapshot to restore is in the body so the
//!   caller can pick any snapshot of any instance to fork from.
//! - `DELETE /v1/snapshots/:id`           → permanently delete a snapshot.
//!   Removes on-disk bytes (and remote bytes for backup-class rows) and
//!   tombstones the row.  Idempotent: 204 even if already deleted.

use std::collections::BTreeMap;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::CallerIdentity;
use crate::http::instances::swarm_err_to_status;
use crate::http::AppState;
use crate::instance::CreatedInstance;
use crate::snapshot::SnapshotView;

/// A6: per-instance snapshot quota.  50 manual+backup snapshots per
/// instance keeps a runaway loop from filling cube disk + the host
/// filesystem.  Operators who genuinely need more can delete some;
/// the SPA already exposes the deleted-count alongside the live one.
pub const MAX_SNAPSHOTS_PER_INSTANCE: u64 = 50;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances/:id/snapshot", post(snapshot))
        .route(
            "/v1/instances/:id/snapshots",
            get(list_for_instance),
        )
        .route("/v1/instances/:id/backup", post(backup))
        .route("/v1/instances/:id/restore", post(restore))
        .route("/v1/snapshots/:id/pull", post(pull))
        .route("/v1/snapshots/:id", delete(delete_snapshot))
        .with_state(state)
}

async fn list_for_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<SnapshotView>>, StatusCode> {
    match state.snapshots.list_for_instance(&caller.user_id, &id).await {
        Ok(rows) => Ok(Json(rows.into_iter().map(SnapshotView::from).collect())),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

#[derive(Debug, Deserialize)]
struct RestoreBody {
    snapshot_id: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

async fn snapshot(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = check_quota(&state, &caller.user_id, &id).await {
        return resp;
    }
    match state.snapshots.snapshot(&caller.user_id, &id).await {
        Ok(row) => (StatusCode::CREATED, Json(SnapshotView::from(row))).into_response(),
        Err(e) => swarm_err_to_status(e).into_response(),
    }
}

async fn backup(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = check_quota(&state, &caller.user_id, &id).await {
        return resp;
    }
    match state.snapshots.backup(&caller.user_id, &id).await {
        Ok(row) => (StatusCode::CREATED, Json(SnapshotView::from(row))).into_response(),
        Err(e) => swarm_err_to_status(e).into_response(),
    }
}

/// A6: check the per-instance snapshot quota.  Returns `Err(response)`
/// if the caller is at or past the cap so the handler can short-
/// circuit; `Ok(())` otherwise (including the "store-error" case,
/// which is logged and ignored — fail-open on quota check is safer
/// than blocking legitimate snapshots when the count query glitches).
async fn check_quota(
    state: &AppState,
    owner_id: &str,
    instance_id: &str,
) -> Result<(), Response> {
    // Agent 1's `count_for_instance` returns count of *live* (non-
    // deleted) snapshot rows owned by `owner_id` for `instance_id`.
    // Anything else (NotFound, store error) we log and let through;
    // the snapshot service will catch the real error.
    match state
        .snapshots
        .count_for_instance(owner_id, instance_id)
        .await
    {
        Ok(n) if n >= MAX_SNAPSHOTS_PER_INSTANCE => {
            let body = serde_json::json!({
                "error": "snapshot quota exceeded",
                "limit": MAX_SNAPSHOTS_PER_INSTANCE,
            });
            Err((StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response())
        }
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!(
                owner_id,
                instance_id,
                error = %e,
                "snapshot quota check failed; allowing through",
            );
            Ok(())
        }
    }
}

async fn pull(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<SnapshotView>, StatusCode> {
    match state.snapshots.pull(&caller.user_id, &id).await {
        Ok(row) => Ok(Json(SnapshotView::from(row))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

async fn delete_snapshot(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    match state.snapshots.delete(&caller.user_id, &id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

async fn restore(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(_source_id): Path<String>,
    Json(body): Json<RestoreBody>,
) -> Result<(StatusCode, Json<CreatedInstance>), StatusCode> {
    match state
        .snapshots
        .restore(&caller.user_id, &body.snapshot_id, body.ttl_seconds, body.env)
        .await
    {
        Ok(c) => Ok((StatusCode::CREATED, Json(c))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}
