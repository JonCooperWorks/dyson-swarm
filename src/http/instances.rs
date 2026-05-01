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
use crate::http::{AppState, secrets::store_err_to_status};
use crate::instance::{CreateRequest, CreatedInstance};
use crate::network_policy::NetworkPolicy;
use crate::traits::{InstanceRow, InstanceStatus, ListFilter, ProbeResult};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances", post(create_instance).get(list_instances))
        .route(
            "/v1/instances/:id",
            get(get_instance)
                .delete(destroy_instance)
                .patch(update_instance),
        )
        .route("/v1/instances/:id/url", get(instance_url))
        .route("/v1/instances/:id/probe", post(probe_instance))
        .route("/v1/instances/:id/change-network", post(change_network))
        .route("/v1/instances/:id/rotate-template", post(rotate_template))
        .route("/v1/instances/:id/recreate", post(recreate_instance))
        .route("/v1/instances/:id/reset", post(reset_instance))
        .with_state(state)
}

/// Admin-only routes mounted under `/v1/instances/*`.  Wired into the
/// admin chain so `require_admin_role` 404s non-admin callers — same
/// posture as `proxy_admin` and `admin_users`.
///
/// `/clone` is admin-gated because it can produce a copy of any
/// instance under any template (full snapshot or empty), which is
/// operator-shaped behaviour: tenants who want to rebuild their own
/// instance from the latest template use the tenant-facing
/// `/reset` route below, which is locked to clone-empty semantics
/// and respects ownership.
pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances/:id/clone", post(clone_instance))
        .with_state(state)
}

/// Standalone router for endpoints that intentionally bypass auth.  At
/// the moment that's just `GET /v1/internal/tls-allowlist`, the host
/// allowlist Caddy queries from `on_demand_tls.ask` at TLS-issuance
/// time.  Caddy can't carry a bearer (it's a server-to-server probe,
/// not a user request) so this endpoint MUST stay unauthenticated;
/// it leaks at most one bit ("is `<host>` a known instance?"), which
/// the wildcard cert and the public Caddy site list already expose.
///
/// Returns 200 with empty body when `host=` matches the swarm apex or
/// a single-label `<instance_id>.<apex>` subdomain that resolves to a
/// non-destroyed instance row.  404 otherwise.  Anything that 404s
/// means Caddy will refuse to issue a cert — preventing certificate
/// stockpiling under arbitrary attacker-chosen subdomains.
pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/internal/tls-allowlist", get(tls_allowlist))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct TlsAllowlistQuery {
    host: Option<String>,
}

async fn tls_allowlist(State(state): State<AppState>, uri: Uri) -> StatusCode {
    let q = parse_query(uri.query().unwrap_or(""));
    let TlsAllowlistQuery { host } = TlsAllowlistQuery {
        host: q.get("host").cloned(),
    };
    let Some(host) = host.as_deref().filter(|h| !h.is_empty()) else {
        return StatusCode::NOT_FOUND;
    };
    // Strip an optional port so callers don't have to.  Caddy passes
    // `host=<sni>` without a port in normal operation.
    let host_no_port = host.split(':').next().unwrap_or("");
    let Some(base) = state.hostname.as_deref().filter(|b| !b.is_empty()) else {
        // No swarm hostname configured = on_demand_tls allowlist disabled.
        return StatusCode::NOT_FOUND;
    };
    if host_no_port == base {
        // The swarm's own apex — Caddy needs a cert for the SPA itself.
        return StatusCode::OK;
    }
    let Some(instance_id) =
        crate::http::dyson_proxy::extract_instance_subdomain(host_no_port, base)
    else {
        return StatusCode::NOT_FOUND;
    };
    // Look the instance up unscoped — Caddy has no user identity to
    // scope by, and the only signal we want is "does this id exist as
    // a non-destroyed row".  `get_unscoped` returns NotFound for
    // already-destroyed rows, which is exactly what we want (don't
    // re-issue certs after destroy).
    match state.instances.get_unscoped(instance_id).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

#[derive(Debug, Deserialize)]
struct ChangeNetworkBody {
    network_policy: NetworkPolicy,
}

/// Change a Live instance's egress profile.  CubeAPI doesn't expose
/// a runtime PATCH for the eBPF maps, so the implementation pivots
/// to a fresh cube under the SAME swarm id via `rotate_in_place` —
/// DNS, bearer token, secrets, and webhook URLs all survive.
/// Workspace state survives via the snapshot.  Returns the post-
/// rotation row so the SPA can refresh its local copy without a
/// follow-up GET.
async fn change_network(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<ChangeNetworkBody>,
) -> Result<Json<InstanceView>, StatusCode> {
    match state
        .instances
        .change_network_policy(&caller.user_id, &id, &state.snapshots, body.network_policy)
        .await
    {
        Ok(row) => Ok(Json(InstanceView::from_row(row, state.hostname.as_deref()))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

#[derive(Debug, Deserialize)]
struct RotateTemplateBody {
    /// Target cube template id.  When omitted, the swarm's
    /// configured default template is used.
    #[serde(default)]
    template_id: Option<String>,
}

/// Rotate a Live instance onto a different cube template (or the
/// configured default) without changing its swarm id.  Same in-place
/// semantics as `change_network`: DNS, bearer, secrets, webhook URLs
/// all survive.  Returns the post-rotation row.
async fn rotate_template(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<RotateTemplateBody>,
) -> Result<Json<InstanceView>, StatusCode> {
    let target = body
        .template_id
        .clone()
        .or_else(|| state.auth_config.default_template_id.clone())
        .filter(|s| !s.trim().is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    match state
        .instances
        .rotate_in_place(&caller.user_id, &id, &state.snapshots, &target, None)
        .await
    {
        Ok(row) => Ok(Json(InstanceView::from_row(row, state.hostname.as_deref()))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

/// Snapshot-less template swap.  Same in-place semantics as
/// `rotate-template` for swarm-side metadata (DNS, bearer, name,
/// task, models, tools, secrets) but the in-VM workspace is
/// destroyed — the new cube boots from the template's clean rootfs.
/// Operator escape hatch when the cube snapshot path is unavailable.
async fn recreate_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<RotateTemplateBody>,
) -> Result<Json<InstanceView>, StatusCode> {
    let target = body
        .template_id
        .clone()
        .or_else(|| state.auth_config.default_template_id.clone())
        .filter(|s| !s.trim().is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    match state
        .instances
        .recreate_in_place(&caller.user_id, &id, &target, None)
        .await
    {
        Ok(row) => Ok(Json(InstanceView::from_row(row, state.hostname.as_deref()))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

#[derive(Debug, Deserialize)]
struct CloneInstanceBody {
    /// Target cube template id.  When omitted, the swarm's configured
    /// default template is used (the "latest" template).
    #[serde(default)]
    template_id: Option<String>,
    /// Optional new display name.  When omitted, the clone inherits
    /// the source's name verbatim.
    #[serde(default)]
    name: Option<String>,
    /// When true, hire a fresh empty instance instead of restoring
    /// from a snapshot — workspace files (SOUL/IDENTITY/MEMORY,
    /// chats, kb, skills) are NOT carried over; the new dyson boots
    /// from the template's clean rootfs.  Config (name, task, models,
    /// tools, network policy), per-instance secrets, and MCP servers
    /// still come along.  Use this when the cube snapshot path is
    /// unavailable.
    #[serde(default)]
    empty: bool,
}

/// Snapshot the source instance and restore onto a fresh swarm id +
/// cube under the target template.  The clone inherits name, task,
/// models, tools, network policy, per-instance secrets, and any MCP
/// server records (with active OAuth sessions preserved).  Source row
/// is left running.  Returns a `CreatedInstance` shaped exactly like
/// `POST /v1/instances` so the SPA can reuse its post-create flow.
///
/// When `empty=true`, takes the snapshot-less path: hires a fresh
/// empty cube instead of restoring from snapshot — workspace files
/// don't come along, but the rest of the clone behaviour is identical.
async fn clone_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<CloneInstanceBody>,
) -> Result<(StatusCode, Json<CreatedInstance>), StatusCode> {
    let target = body
        .template_id
        .clone()
        .or_else(|| state.auth_config.default_template_id.clone())
        .filter(|s| !s.trim().is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let result = if body.empty {
        state
            .instances
            .clone_empty(&caller.user_id, &id, &target, body.name)
            .await
    } else {
        state
            .instances
            .clone_instance(&caller.user_id, &id, &state.snapshots, &target, body.name)
            .await
    };
    match result {
        Ok(mut c) => {
            // Same hostname rewrite as create_instance — turn the raw
            // <sandbox>.cube.app URL into <id>.<hostname> so the SPA
            // gets a browser-resolvable open_url back.
            if let Some(host) = state.hostname.as_deref().filter(|h| !h.is_empty()) {
                c.url = format!("https://{}.{}/", c.id, host.trim_end_matches('/'));
            }
            Ok((StatusCode::CREATED, Json(c)))
        }
        Err(e) => Err(swarm_err_to_status(e)),
    }
}

/// **Destructive in-place rebuild.**  Reset the dyson on its existing
/// swarm id: hire a fresh cube under the latest template, preserving
/// name, task, models, tools, network policy, per-instance secrets,
/// MCP servers, bearer token, DNS, and webhook URLs — but NO
/// workspace state.  SOUL/IDENTITY/MEMORY, chat history, knowledge
/// base, learned skills, and any in-flight work are LOST: the new
/// cube boots from the template's clean rootfs.
///
/// Same id, same URL, same bearer.  Bookmarks survive.  Operator
/// escape hatch when the running dyson got into a bad state and the
/// user wants to start over without losing the instance's identity.
///
/// Tenant-facing — runs under the same user-identity middleware as
/// the rest of the instance routes; ownership is enforced inside
/// `recreate_in_place`.  No body fields.
async fn reset_instance(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<InstanceView>, StatusCode> {
    let target = state
        .auth_config
        .default_template_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    match state
        .instances
        .recreate_in_place(&caller.user_id, &id, &target, None)
        .await
    {
        Ok(row) => Ok(Json(InstanceView::from_row(row, state.hostname.as_deref()))),
        Err(e) => Err(swarm_err_to_status(e)),
    }
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
    /// New positive include list of built-in tools.  Pass `[]` to
    /// reset to "use dyson defaults" (every builtin registers); pass
    /// a non-empty list to restrict to that subset.  `null`/missing
    /// leaves the existing list unchanged.
    #[serde(default)]
    tools: Option<Vec<String>>,
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
    if let Err(e) = state
        .instances
        .rename(&caller.user_id, &id, &new_name, &new_task)
        .await
    {
        return Err(swarm_err_to_status(e));
    }

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

    // 3. Tools update (optional).  Empty `[]` is meaningful: it
    //    resets the row back to "use dyson defaults".  Use Some/None
    //    rather than `filter(|t| !t.is_empty())` so the all-checked
    //    case (frontend sends []) round-trips correctly.
    if let Some(tools) = body.tools
        && let Err(e) = state
            .instances
            .update_tools(&caller.user_id, &id, tools)
            .await
    {
        return Err(swarm_err_to_status(e));
    }

    // Re-fetch so the view reflects any tool/model writes above.
    let row = match state.instances.get(&caller.user_id, &id).await {
        Ok(r) => r,
        Err(e) => return Err(swarm_err_to_status(e)),
    };
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
    let status = match q.get("status").map(std::string::String::as_str) {
        Some(s) => match InstanceStatus::parse(s) {
            Some(p) => Some(p),
            None => return Err(StatusCode::BAD_REQUEST),
        },
        None => None,
    };
    let include_destroyed = matches!(
        q.get("include_destroyed").map(std::string::String::as_str),
        Some("1" | "true" | "yes")
    );
    let filter = ListFilter {
        status,
        include_destroyed,
    };
    match state.instances.list(&caller.user_id, filter).await {
        Ok(rows) => Ok(Json(
            rows.into_iter()
                .map(|r| InstanceView::from_row(r, state.hostname.as_deref()))
                .collect(),
        )),
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
    uri: Uri,
) -> impl IntoResponse {
    // Force is the default: a CubeError from `destroy_sandbox` is
    // swallowed and DB-side cleanup proceeds anyway, so a dead/
    // unreachable cube can't strand the row Live forever.  Pass
    // `?force=false` (or `0` / `no`) to opt back into the strict
    // path that bubbles cube errors as 502.
    let q = parse_query(uri.query().unwrap_or(""));
    let force = !matches!(
        q.get("force").map(std::string::String::as_str),
        Some("0" | "false" | "no")
    );
    match state.instances.destroy(&caller.user_id, &id, force).await {
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
    /// Per-instance egress profile + the user's raw entries (CIDR
    /// or hostname).  The SPA's detail-page badge reads this to show
    /// which profile is active and what the user typed.
    pub network_policy: NetworkPolicy,
    /// Post-DNS resolved IPv4 CIDR set the cube actually enforces.
    /// SPA shows this alongside `network_policy.entries` so the
    /// operator sees both "what you typed" and "what's enforced".
    pub network_policy_cidrs: Vec<String>,
    /// Model id list last persisted for this instance — primary
    /// first, then any failover entries.  The SPA's edit form
    /// pre-fills its picker from this; an empty vec means the
    /// instance predates the column or was hired without a model
    /// list (legacy create paths) and the user must repick.
    pub models: Vec<String>,
    /// Positive include list of built-in tools the running dyson
    /// is configured for.  Empty means "use dyson defaults" — the
    /// SPA edit form treats this as "all tools ticked".  Non-empty
    /// means "register only these".
    pub tools: Vec<String>,
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
            network_policy: r.network_policy,
            network_policy_cidrs: r.network_policy_cidrs,
            models: r.models,
            tools: r.tools,
        }
    }
}

pub(crate) fn swarm_err_to_status(e: SwarmError) -> StatusCode {
    match e {
        SwarmError::NotFound => StatusCode::NOT_FOUND,
        SwarmError::PolicyDenied(_) => StatusCode::FORBIDDEN,
        SwarmError::BadRequest(_) => StatusCode::BAD_REQUEST,
        // 502 — Cube/Internal: configure-push retry budget exhausted;
        // SnapshotCorrupt: content-hash mismatch on restore points at
        // the backup sink, not user input.  Both surface as bad-gateway
        // because retry/operator-action will resolve them.
        SwarmError::Cube(_) | SwarmError::Internal(_) | SwarmError::SnapshotCorrupt(_) => {
            StatusCode::BAD_GATEWAY
        }
        SwarmError::Store(s) => store_err_to_status(s),
        SwarmError::Backup(_) | SwarmError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        // SnapshotQuotaExceeded: 507 Insufficient Storage — semantically
        // closer than 429/403 because the user CAN proceed by deleting
        // existing snapshots, the operation isn't being rate-limited or
        // policy-denied.
        SwarmError::SnapshotQuotaExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,
    }
}
