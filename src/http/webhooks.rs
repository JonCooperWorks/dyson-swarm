//! `/v1/instances/:id/webhooks` (management, owner-scoped) and
//! `/webhooks/:instance_id/:name` (public, signature-gated).
//!
//! Two routers, mounted differently in `http/mod.rs`:
//!
//!   * Management — folded into the `tenant` tier, runs after
//!     `user_middleware`.  Owner-scoped via `ensure_owns_instance`,
//!     same shape as `secrets.rs` / `mcp_servers` paths.
//!
//!   * Public — `public_router()` is mounted on `normal` *outside*
//!     the user-auth layer (alongside `instances::internal_router`).
//!     The signature is the auth gate — `WebhookService::verify_and_dispatch`
//!     refuses requests whose body doesn't HMAC under the stored key
//!     (or whose Bearer token doesn't match, or — for `auth=none` —
//!     accepts unconditionally).

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CallerIdentity;
use crate::http::AppState;
use crate::traits::{DeliveryRow, WebhookAuthScheme, WebhookRow};
use crate::webhooks::{
    DEFAULT_DELIVERY_LIMIT, MAX_WEBHOOK_BODY, WebhookError, WebhookSpec,
    validate_webhook_name,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/instances/:id/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/v1/instances/:id/webhooks/:name",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/v1/instances/:id/webhooks/:name/deliveries",
            get(list_deliveries),
        )
        .with_state(state)
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/webhooks/:instance_id/:name", post(fire_webhook))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub name: String,
    pub description: String,
    pub auth_scheme: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// Whether a signing secret is set.  We never surface the value
    /// itself — the SPA uses this only to show a "secret stored"
    /// indicator + render the rotate affordance.
    pub has_secret: bool,
    /// `/webhooks/<instance_id>/<name>` — handy for one-click copy.
    pub path: String,
}

impl WebhookView {
    fn from_row(r: WebhookRow) -> Self {
        let path = format!("/webhooks/{}/{}", r.instance_id, r.name);
        Self {
            name: r.name,
            description: r.description,
            auth_scheme: r.auth_scheme.as_str().to_string(),
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            has_secret: r.secret_name.is_some(),
            path,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeliveryView {
    pub id: String,
    pub fired_at: i64,
    pub status_code: i32,
    pub latency_ms: i64,
    pub signature_ok: bool,
    pub request_id: Option<String>,
    pub error: Option<String>,
    /// Inbound body size in bytes — surfaced so the SPA can render
    /// "<n> bytes" alongside the delivery.  The body itself is
    /// audit-only and never crosses the wire here.
    pub body_size: Option<i64>,
    pub content_type: Option<String>,
}

impl DeliveryView {
    fn from_row(r: DeliveryRow) -> Self {
        Self {
            id: r.id,
            fired_at: r.fired_at,
            status_code: r.status_code,
            latency_ms: r.latency_ms,
            signature_ok: r.signature_ok,
            request_id: r.request_id,
            error: r.error,
            body_size: r.body_size,
            content_type: r.content_type,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub auth_scheme: String,
    /// Required when `auth_scheme` requires a key (hmac_sha256, bearer).
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookBody {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub auth_scheme: Option<String>,
    /// `Some(plaintext)` rotates the signing key; `None` leaves it.
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn default_true() -> bool {
    true
}

fn parse_scheme(s: &str) -> Result<WebhookAuthScheme, StatusCode> {
    WebhookAuthScheme::parse(s).ok_or(StatusCode::BAD_REQUEST)
}

fn err_to_status(e: &WebhookError) -> StatusCode {
    match e {
        WebhookError::NotFound => StatusCode::NOT_FOUND,
        WebhookError::BadRequest(_) => StatusCode::BAD_REQUEST,
        WebhookError::SignatureMismatch => StatusCode::UNAUTHORIZED,
        WebhookError::NotReady => StatusCode::SERVICE_UNAVAILABLE,
        WebhookError::Dispatch(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn list_webhooks(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<WebhookView>>, StatusCode> {
    let rows = state
        .webhooks
        .list(&caller.user_id, &id)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(rows.into_iter().map(WebhookView::from_row).collect()))
}

async fn get_webhook(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
) -> Result<Json<WebhookView>, StatusCode> {
    let row = state
        .webhooks
        .get(&caller.user_id, &id, &name)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(WebhookView::from_row(row)))
}

async fn create_webhook(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<CreateWebhookBody>,
) -> Result<(StatusCode, Json<WebhookView>), StatusCode> {
    if let Err(m) = validate_webhook_name(&body.name) {
        tracing::debug!(reason = %m, "webhook create: invalid name");
        return Err(StatusCode::BAD_REQUEST);
    }
    let scheme = parse_scheme(&body.auth_scheme)?;
    if scheme != WebhookAuthScheme::None
        && body.secret.as_deref().map_or(true, str::is_empty)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    // 409 when a row with this name already exists — POST is create-only;
    // PATCH is the update verb.  Lets the SPA distinguish "name taken"
    // from "you got the body wrong".
    if state
        .webhooks
        .get(&caller.user_id, &id, &body.name)
        .await
        .is_ok()
    {
        return Err(StatusCode::CONFLICT);
    }
    let spec = WebhookSpec {
        instance_id: id,
        name: body.name,
        description: body.description,
        auth_scheme: scheme,
        secret_plaintext: body.secret.filter(|s| !s.is_empty()),
        enabled: body.enabled,
    };
    let row = state
        .webhooks
        .put(&caller.user_id, spec)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok((StatusCode::CREATED, Json(WebhookView::from_row(row))))
}

async fn update_webhook(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
    Json(body): Json<UpdateWebhookBody>,
) -> Result<Json<WebhookView>, StatusCode> {
    let existing = state
        .webhooks
        .get(&caller.user_id, &id, &name)
        .await
        .map_err(|e| err_to_status(&e))?;
    let scheme = match body.auth_scheme.as_deref() {
        Some(s) => parse_scheme(s)?,
        None => existing.auth_scheme,
    };
    let secret_plaintext = body.secret.filter(|s| !s.is_empty());
    if scheme != WebhookAuthScheme::None
        && existing.auth_scheme != scheme
        && secret_plaintext.is_none()
    {
        // Switching scheme requires a fresh key (the old one was sized
        // for a different verb — bearer tokens vs HMAC keys, etc.).
        return Err(StatusCode::BAD_REQUEST);
    }
    let spec = WebhookSpec {
        instance_id: id,
        name: existing.name.clone(),
        description: body.description.unwrap_or(existing.description.clone()),
        auth_scheme: scheme,
        secret_plaintext,
        enabled: body.enabled.unwrap_or(existing.enabled),
    };
    let row = state
        .webhooks
        .put(&caller.user_id, spec)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(WebhookView::from_row(row)))
}

async fn delete_webhook(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.webhooks.delete(&caller.user_id, &id, &name).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => err_to_status(&e),
    }
}

async fn list_deliveries(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
    uri: Uri,
) -> Result<Json<Vec<DeliveryView>>, StatusCode> {
    let limit = uri
        .query()
        .and_then(|q| {
            q.split('&')
                .filter_map(|p| p.split_once('='))
                .find(|(k, _)| *k == "limit")
                .and_then(|(_, v)| v.parse::<u32>().ok())
        })
        .unwrap_or(DEFAULT_DELIVERY_LIMIT);
    let rows = state
        .webhooks
        .list_deliveries(&caller.user_id, &id, &name, limit)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(rows.into_iter().map(DeliveryView::from_row).collect()))
}

/// Public webhook delivery.  Strictly POST.  Body is buffered up to
/// `MAX_WEBHOOK_BODY`; oversize requests get 413.
async fn fire_webhook(
    State(state): State<AppState>,
    Path((instance_id, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if body.len() > MAX_WEBHOOK_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let sig_header = headers
        .get("x-swarm-signature")
        .and_then(|v| v.to_str().ok());
    let bearer_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let forward = forward_header_subset(&headers);

    match state
        .webhooks
        .verify_and_dispatch(
            &instance_id,
            &name,
            sig_header,
            bearer_header,
            request_id.as_deref(),
            forward,
            content_type,
            body.as_ref(),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => err_to_status(&e),
    }
}

/// Allowlist of headers we forward into the agent prompt.  Avoids
/// leaking `Authorization` / `Cookie` / our own `X-Swarm-*` headers
/// into the LLM context.  Lowercase comparison.
fn forward_header_subset(h: &HeaderMap) -> Vec<(String, String)> {
    const ALLOW: &[&str] = &[
        "content-type",
        "user-agent",
        "x-github-event",
        "x-github-delivery",
        "x-gitlab-event",
        "x-stripe-signature",
        "x-event-key",
        "x-hook-id",
    ];
    let mut out = Vec::new();
    for (k, v) in h {
        let name = k.as_str().to_ascii_lowercase();
        if ALLOW.contains(&name.as_str())
            && let Ok(val) = v.to_str()
        {
            out.push((name, val.to_string()));
        }
    }
    out
}
