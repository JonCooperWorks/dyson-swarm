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
use serde::{Deserialize, Serialize};

use crate::auth::CallerIdentity;
use crate::error::SwarmError;
use crate::http::{secrets::store_err_to_status, AppState};
use crate::instance::{CreateRequest, CreatedInstance};
use crate::traits::{InstanceRow, InstanceStatus, ListFilter, ProbeResult};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances", post(create_instance).get(list_instances))
        .route(
            "/v1/instances/:id",
            get(get_instance).delete(destroy_instance).patch(update_instance),
        )
        .route("/v1/instances/:id/url", get(instance_url))
        .route("/v1/instances/:id/probe", post(probe_instance))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct PatchInstanceBody {
    /// New display name. Pass null/missing to leave unchanged.
    #[serde(default)]
    name: Option<String>,
    /// New task / mission. Pass null/missing to leave unchanged.
    #[serde(default)]
    task: Option<String>,
    /// New ordered model list.  When supplied, swarm pushes the new
    /// list into the running dyson via /api/admin/configure (Stage 8.3
    /// — runtime-reconfigure of the agent's model selection without
    /// destroying the sandbox).  Empty/missing leaves models unchanged.
    #[serde(default)]
    models: Option<Vec<String>>,
}

async fn update_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<PatchInstanceBody>,
) -> Result<Json<InstanceView>, StatusCode> {
    // PATCH semantics: missing fields stay unchanged. Read the row to
    // pick up the existing values for the un-touched identity fields.
    let current = match state.instances.get(&caller.user_id, &id).await {
        Ok(r) => r,
        Err(e) => return Err(swarm_err_to_status(e)),
    };

    // 1. Identity update (name + task).  `rename` also pushes the new
    //    identity into the running dyson via /api/admin/configure.
    let new_name = body.name.unwrap_or(current.name);
    let new_task = body.task.unwrap_or(current.task);
    let row = match state
        .instances
        .rename(&caller.user_id, &id, &new_name, &new_task)
        .await
    {
        Ok(row) => row,
        Err(e) => return Err(swarm_err_to_status(e)),
    };

    // 2. Models update (optional).  Synchronous so the SPA can show
    //    "saved" only after the agent's config has been patched
    //    (the agent rebuilds on the next turn via HotReloader).
    if let Some(models) = body.models.filter(|m| !m.is_empty())
        && let Err(e) = state
            .instances
            .update_models(&caller.user_id, &id, models)
            .await
    {
        return Err(swarm_err_to_status(e));
    }

    Ok(Json(InstanceView::from_row(row, state.hostname.as_deref())))
}

async fn create_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreatedInstance>), StatusCode> {
    match state.instances.create(&caller.user_id, req).await {
        Ok(mut c) => {
            // The cube client returns the raw `<sandbox>.cube.app` URL,
            // which a browser on the public internet can't resolve.  When
            // a swarm hostname is configured, rewrite to the
            // `<id>.<hostname>` shape — same value the SPA gets back from
            // GET /v1/instances/:id as `open_url`, so the modal's "open
            // profile" link actually works.
            if let Some(host) = state.hostname.as_deref().filter(|h| !h.is_empty()) {
                c.url = format!("https://{}.{}/", c.id, host.trim_end_matches('/'));
            }
            Ok((StatusCode::CREATED, Json(c)))
        }
        Err(e) => Err(swarm_err_to_status(e)),
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
        Ok(rows) => Ok(Json(rows.into_iter().map(|r| InstanceView::from_row(r, state.hostname.as_deref())).collect())),
        Err(e) => Err(swarm_err_to_status(e)),
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
        Ok(row) => Ok(Json(InstanceView::from_row(row, state.hostname.as_deref()))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

async fn destroy_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.instances.destroy(&caller.user_id, &id).await {
        Ok(()) => {
            // Stage 8: wipe the per-instance configure secret
            // sealed in `system_secrets["instance.<id>.configure"]`.
            // Best-effort — the destroy itself succeeded; lingering
            // sealed plaintext is benign (the sandbox is gone) but
            // worth cleaning so the table doesn't grow forever.
            crate::dyson_reconfig::forget_secret(&state.system_secrets, &id).await;
            StatusCode::NO_CONTENT
        }
        Err(e) => swarm_err_to_status(e),
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
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

async fn instance_url(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<UrlView>, StatusCode> {
    let row = match state.instances.get(&caller.user_id, &id).await {
        Ok(r) => r,
        Err(e) => return Err(swarm_err_to_status(e)),
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
///
/// `open_url` is the SPA's "open ↗" target.  Computed from the configured
/// `hostname` plus the instance id; `None` when swarm has no hostname
/// configured (the host-based dispatcher is a no-op in that case, so the
/// link can't actually reach the sandbox).
#[derive(Debug, Serialize)]
pub struct InstanceView {
    pub id: String,
    pub name: String,
    pub task: String,
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
    pub open_url: Option<String>,
}

impl InstanceView {
    /// Build a view from a row.  The hostname is needed to compute
    /// `open_url`; pass the value from `AppState::hostname`.  Empty /
    /// missing hostname yields `open_url = None`.
    pub fn from_row(r: InstanceRow, hostname: Option<&str>) -> Self {
        let open_url = hostname
            .filter(|h| !h.is_empty())
            .map(|h| format!("https://{}.{}/", r.id, h.trim_end_matches('/')));
        Self {
            id: r.id,
            name: r.name,
            task: r.task,
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
            open_url,
        }
    }
}

pub(crate) fn swarm_err_to_status(e: SwarmError) -> StatusCode {
    match e {
        SwarmError::NotFound => StatusCode::NOT_FOUND,
        SwarmError::PolicyDenied(_) => StatusCode::FORBIDDEN,
        SwarmError::Cube(_) => StatusCode::BAD_GATEWAY,
        SwarmError::Store(s) => store_err_to_status(s),
        SwarmError::Backup(_) => StatusCode::INTERNAL_SERVER_ERROR,
        SwarmError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
