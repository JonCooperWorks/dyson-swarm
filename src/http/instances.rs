//! `/v1/instances` routes:
//! - `POST   /v1/instances`              → create
//! - `GET    /v1/instances`              → list
//! - `GET    /v1/instances/:id`          → get
//! - `DELETE /v1/instances/:id`          → destroy
//! - `GET    /v1/instances/:id/url`      → just the sandbox URL
//! - `POST   /v1/instances/:id/probe`    → run a probe synchronously

use axum::extract::{Extension, Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::CallerIdentity;
use crate::error::WardenError;
use crate::http::{secrets::store_err_to_status, AppState};
use crate::instance::{CreateRequest, CreatedInstance};
use crate::traits::{InstanceRow, InstanceStatus, ListFilter, ProbeResult};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances", post(create_instance).get(list_instances))
        .route(
            "/v1/instances/:id",
            get(get_instance).delete(destroy_instance),
        )
        .route("/v1/instances/:id/url", get(instance_url))
        .route("/v1/instances/:id/probe", post(probe_instance))
        .with_state(state)
}

async fn create_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreatedInstance>), StatusCode> {
    match state.instances.create(&caller.user_id, req).await {
        Ok(c) => Ok((StatusCode::CREATED, Json(c))),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

async fn list_instances(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    uri: Uri,
) -> Result<Json<Vec<InstanceView>>, StatusCode> {
    let q = parse_query(uri.query().unwrap_or(""));
    let status = match q.get("status").map(|s| s.as_str()) {
        Some(s) => match InstanceStatus::parse(s) {
            Some(p) => Some(p),
            None => return Err(StatusCode::BAD_REQUEST),
        },
        None => None,
    };
    let include_destroyed = matches!(
        q.get("include_destroyed").map(|s| s.as_str()),
        Some("1" | "true" | "yes")
    );
    let filter = ListFilter {
        status,
        include_destroyed,
    };
    match state.instances.list(&caller.user_id, filter).await {
        Ok(rows) => Ok(Json(rows.into_iter().map(InstanceView::from).collect())),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

/// Tiny query-string parser. The brief forbids extra crates and the axum
/// `query` feature is also out, so this is hand-rolled. No URL-decoding —
/// values we accept here are flat ASCII enums.
fn parse_query(s: &str) -> std::collections::HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect()
}

async fn get_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<InstanceView>, StatusCode> {
    match state.instances.get(&caller.user_id, &id).await {
        Ok(row) => Ok(Json(InstanceView::from(row))),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

async fn destroy_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.instances.destroy(&caller.user_id, &id).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => warden_err_to_status(e),
    }
}

#[derive(Debug, Serialize)]
struct UrlView {
    url: String,
}

async fn probe_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<ProbeResult>, StatusCode> {
    match state
        .instances
        .probe(&caller.user_id, &*state.prober, &id)
        .await
    {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(warden_err_to_status(e)),
    }
}

async fn instance_url(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<UrlView>, StatusCode> {
    let row = match state.instances.get(&caller.user_id, &id).await {
        Ok(r) => r,
        Err(e) => return Err(warden_err_to_status(e)),
    };
    let Some(sb) = row.cube_sandbox_id else {
        return Err(StatusCode::CONFLICT);
    };
    Ok(Json(UrlView {
        url: format!("https://{sb}.{}", state.sandbox_domain),
    }))
}

/// Public view of an instance — strips the bearer token (returned only at
/// create time) and serialises enums into stable strings.
#[derive(Debug, Serialize)]
pub struct InstanceView {
    pub id: String,
    pub cube_sandbox_id: Option<String>,
    pub template_id: String,
    pub status: String,
    pub pinned: bool,
    pub expires_at: Option<i64>,
    pub last_active_at: i64,
    pub last_probe_at: Option<i64>,
    pub last_probe_status: Option<ProbeResult>,
    pub created_at: i64,
    pub destroyed_at: Option<i64>,
}

impl From<InstanceRow> for InstanceView {
    fn from(r: InstanceRow) -> Self {
        Self {
            id: r.id,
            cube_sandbox_id: r.cube_sandbox_id,
            template_id: r.template_id,
            status: r.status.as_str().into(),
            pinned: r.pinned,
            expires_at: r.expires_at,
            last_active_at: r.last_active_at,
            last_probe_at: r.last_probe_at,
            last_probe_status: r.last_probe_status,
            created_at: r.created_at,
            destroyed_at: r.destroyed_at,
        }
    }
}

pub(crate) fn warden_err_to_status(e: WardenError) -> StatusCode {
    match e {
        WardenError::NotFound => StatusCode::NOT_FOUND,
        WardenError::PolicyDenied(_) => StatusCode::FORBIDDEN,
        WardenError::Cube(_) => StatusCode::BAD_GATEWAY,
        WardenError::Store(s) => store_err_to_status(s),
        WardenError::Backup(_) => StatusCode::INTERNAL_SERVER_ERROR,
        WardenError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
