//! Snapshot/backup/restore routes:
//! - `POST /v1/instances/:id/snapshot` → take a snapshot, kind=manual
//! - `POST /v1/instances/:id/backup`   → take a snapshot then promote, kind=backup
//! - `POST /v1/instances/:id/restore`  → restore from a snapshot id supplied
//!   in the body. The path `:id` is the source instance and is currently
//!   informational; the actual snapshot to restore is in the body so the
//!   caller can pick any snapshot of any instance to fork from.

use std::collections::BTreeMap;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::CallerIdentity;
use crate::http::instances::warden_err_to_status;
use crate::http::AppState;
use crate::instance::CreatedInstance;
use crate::snapshot::SnapshotView;

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
        .with_state(state)
}

async fn list_for_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<SnapshotView>>, StatusCode> {
    match state.snapshots.list_for_instance(&caller.user_id, &id).await {
        Ok(rows) => Ok(Json(rows.into_iter().map(SnapshotView::from).collect())),
        Err(e) => Err(warden_err_to_status(e)),
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
) -> Result<(StatusCode, Json<SnapshotView>), StatusCode> {
    match state.snapshots.snapshot(&caller.user_id, &id).await {
        Ok(row) => Ok((StatusCode::CREATED, Json(SnapshotView::from(row)))),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

async fn backup(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<SnapshotView>), StatusCode> {
    match state.snapshots.backup(&caller.user_id, &id).await {
        Ok(row) => Ok((StatusCode::CREATED, Json(SnapshotView::from(row)))),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

async fn pull(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<SnapshotView>, StatusCode> {
    match state.snapshots.pull(&caller.user_id, &id).await {
        Ok(row) => Ok(Json(SnapshotView::from(row))),
        Err(e) => Err(warden_err_to_status(e)),
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
        Err(e) => Err(warden_err_to_status(e)),
    }
}
