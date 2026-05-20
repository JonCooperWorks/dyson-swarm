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
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::CallerIdentity;
use crate::http::AppState;
use crate::traits::{AdminAuditEntry, DeliveryRow, WebhookAuthScheme, WebhookRow};
use crate::webhooks::{
    DEFAULT_DELIVERY_LIMIT, DispatchCtx, MAX_WEBHOOK_BODY, SignatureAlgorithm, SignatureEncoding,
    WebhookError, WebhookSpec, WebhookVerifierConfig, WebhookVerifierMode, validate_webhook_name,
    webhook_presets,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/webhook-presets", get(list_webhook_presets))
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
        .route(
            "/v1/instances/:id/webhooks/:name/verify-only",
            post(verify_only),
        )
        .route(
            "/v1/instances/:id/webhooks/:name/replay/:delivery_id",
            post(replay_delivery),
        )
        // Cross-task audit log for the SPA's audit page.  Sibling of
        // /webhooks rather than nested under it because it spans every
        // task on the instance — the URL would otherwise lie about
        // scope.
        .route(
            "/v1/instances/:id/deliveries",
            get(list_instance_deliveries),
        )
        .route(
            "/v1/instances/:id/deliveries/:delivery_id",
            get(get_delivery),
        )
        .with_state(state)
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/webhooks/:instance_id/:name", post(fire_webhook))
        .route(
            "/webhooks/:instance_id/:name/:bearer_path_token",
            post(fire_webhook_with_path_token),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub name: String,
    pub description: String,
    pub auth_scheme: String,
    pub signature_header: String,
    pub verifier_mode: String,
    pub signature_algo: Option<String>,
    pub signature_encoding: Option<String>,
    pub signature_prefix: Option<String>,
    pub signature_separator: Option<String>,
    pub signature_value_split: Option<String>,
    pub timestamp_header: Option<String>,
    pub timestamp_skew_secs: Option<i64>,
    pub payload_template: Option<String>,
    pub idempotency_header: Option<String>,
    pub bearer_path_token: Option<String>,
    pub preset_id: Option<String>,
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
        let path = if r.verifier_mode == "bearer_v2" {
            match r.bearer_path_token.as_deref() {
                Some(token) => format!("/webhooks/{}/{}/{}", r.instance_id, r.name, token),
                None => format!("/webhooks/{}/{}", r.instance_id, r.name),
            }
        } else {
            format!("/webhooks/{}/{}", r.instance_id, r.name)
        };
        Self {
            name: r.name,
            description: r.description,
            auth_scheme: r.auth_scheme.as_str().to_owned(),
            signature_header: r.signature_header,
            verifier_mode: r.verifier_mode,
            signature_algo: r.signature_algo,
            signature_encoding: r.signature_encoding,
            signature_prefix: r.signature_prefix,
            signature_separator: r.signature_separator,
            signature_value_split: r.signature_value_split,
            timestamp_header: r.timestamp_header,
            timestamp_skew_secs: r.timestamp_skew_secs,
            payload_template: r.payload_template,
            idempotency_header: r.idempotency_header,
            bearer_path_token: r.bearer_path_token,
            preset_id: r.preset_id,
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
    pub verify_error: Option<String>,
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
            verify_error: r.verify_error,
            body_size: r.body_size,
            content_type: r.content_type,
        }
    }
}

/// Cross-task audit listing row — adds `webhook_name` to the standard
/// metadata view so the SPA can render which task each row belongs to.
#[derive(Debug, Serialize)]
pub struct AuditDeliveryView {
    pub id: String,
    pub webhook_name: String,
    pub fired_at: i64,
    pub status_code: i32,
    pub latency_ms: i64,
    pub signature_ok: bool,
    pub request_id: Option<String>,
    pub error: Option<String>,
    pub verify_error: Option<String>,
    pub body_size: Option<i64>,
    pub content_type: Option<String>,
}

impl AuditDeliveryView {
    fn from_row(r: DeliveryRow) -> Self {
        Self {
            id: r.id,
            webhook_name: r.webhook_name,
            fired_at: r.fired_at,
            status_code: r.status_code,
            latency_ms: r.latency_ms,
            signature_ok: r.signature_ok,
            request_id: r.request_id,
            error: r.error,
            verify_error: r.verify_error,
            body_size: r.body_size,
            content_type: r.content_type,
        }
    }
}

/// Detail-page payload — same shape as `AuditDeliveryView` plus the
/// request body.  We surface the body in two complementary forms:
/// `body_text` is the utf8-decoded view (set whenever the bytes are
/// valid utf8) so the SPA can render it directly; `body_b64` always
/// carries the raw bytes so binary payloads (and any utf8 surrogates
/// the JS layer would mangle) survive round-trip.  Operators reading
/// JSON payloads — the common case — only need `body_text`.
#[derive(Debug, Serialize)]
pub struct DeliveryDetailView {
    pub id: String,
    pub webhook_name: String,
    pub fired_at: i64,
    pub status_code: i32,
    pub latency_ms: i64,
    pub signature_ok: bool,
    pub request_id: Option<String>,
    pub error: Option<String>,
    pub verify_error: Option<String>,
    pub request_headers: Option<serde_json::Value>,
    pub replayed_from_delivery_id: Option<String>,
    pub replayed_by_user_id: Option<String>,
    pub body_size: Option<i64>,
    pub content_type: Option<String>,
    pub body_text: Option<String>,
    pub body_b64: Option<String>,
}

impl DeliveryDetailView {
    fn from_row(r: DeliveryRow) -> Self {
        let (body_text, body_b64) = match r.body.as_deref() {
            None => (None, None),
            Some(bytes) => {
                let text = std::str::from_utf8(bytes).ok().map(str::to_owned);
                let b64 = base64_encode(bytes);
                (text, Some(b64))
            }
        };
        let request_headers = r
            .request_headers
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok());
        Self {
            id: r.id,
            webhook_name: r.webhook_name,
            fired_at: r.fired_at,
            status_code: r.status_code,
            latency_ms: r.latency_ms,
            signature_ok: r.signature_ok,
            request_id: r.request_id,
            error: r.error,
            verify_error: r.verify_error,
            request_headers,
            replayed_from_delivery_id: r.replayed_from_delivery_id,
            replayed_by_user_id: r.replayed_by_user_id,
            body_size: r.body_size,
            content_type: r.content_type,
            body_text,
            body_b64,
        }
    }
}

/// Tiny base64 encoder so we don't drag a new crate in for one call
/// site.  Standard alphabet, padded.  Called once per detail-page
/// load, so a hot-path version isn't worth the bytes.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHA[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub preset_id: Option<String>,
    pub auth_scheme: String,
    #[serde(default)]
    pub signature_header: Option<String>,
    #[serde(default)]
    pub verifier_mode: Option<String>,
    #[serde(default)]
    pub signature_algo: Option<String>,
    #[serde(default)]
    pub signature_encoding: Option<String>,
    #[serde(default)]
    pub signature_prefix: Option<String>,
    #[serde(default)]
    pub signature_separator: Option<String>,
    #[serde(default)]
    pub signature_value_split: Option<String>,
    #[serde(default)]
    pub timestamp_header: Option<String>,
    #[serde(default)]
    pub timestamp_skew_secs: Option<i64>,
    #[serde(default)]
    pub payload_template: Option<String>,
    #[serde(default)]
    pub idempotency_header: Option<String>,
    #[serde(default)]
    pub bearer_path_token: Option<String>,
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
    pub preset_id: Option<Option<String>>,
    #[serde(default)]
    pub auth_scheme: Option<String>,
    #[serde(default)]
    pub signature_header: Option<String>,
    #[serde(default)]
    pub verifier_mode: Option<String>,
    #[serde(default)]
    pub signature_algo: Option<String>,
    #[serde(default)]
    pub signature_encoding: Option<String>,
    #[serde(default)]
    pub signature_prefix: Option<String>,
    #[serde(default)]
    pub signature_separator: Option<String>,
    #[serde(default)]
    pub signature_value_split: Option<String>,
    #[serde(default)]
    pub timestamp_header: Option<String>,
    #[serde(default)]
    pub timestamp_skew_secs: Option<i64>,
    #[serde(default)]
    pub payload_template: Option<String>,
    #[serde(default)]
    pub idempotency_header: Option<String>,
    #[serde(default)]
    pub bearer_path_token: Option<String>,
    /// `Some(plaintext)` rotates the signing key; `None` leaves it.
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOnlyBody {
    pub headers: serde_json::Value,
    pub body_b64: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyOnlyOk {
    pub ok: bool,
    pub rendered_payload_b64: Option<String>,
    pub matched_version: Option<String>,
}

fn default_true() -> bool {
    true
}

fn parse_scheme(s: &str) -> Result<WebhookAuthScheme, StatusCode> {
    WebhookAuthScheme::parse(s).ok_or(StatusCode::BAD_REQUEST)
}

fn parse_verifier_mode(s: &str) -> Result<WebhookVerifierMode, StatusCode> {
    WebhookVerifierMode::parse(s).ok_or(StatusCode::BAD_REQUEST)
}

fn parse_signature_algo(s: Option<&str>) -> Result<Option<SignatureAlgorithm>, StatusCode> {
    match s {
        Some(raw) => SignatureAlgorithm::parse(raw)
            .map(Some)
            .ok_or(StatusCode::BAD_REQUEST),
        None => Ok(None),
    }
}

fn parse_signature_encoding(s: Option<&str>) -> Result<Option<SignatureEncoding>, StatusCode> {
    match s {
        Some(raw) => SignatureEncoding::parse(raw)
            .map(Some)
            .ok_or(StatusCode::BAD_REQUEST),
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_verifier_config(
    verifier_mode: Option<&str>,
    signature_header: Option<String>,
    signature_algo: Option<&str>,
    signature_encoding: Option<&str>,
    signature_prefix: Option<String>,
    signature_separator: Option<String>,
    signature_value_split: Option<String>,
    timestamp_header: Option<String>,
    timestamp_skew_secs: Option<i64>,
    payload_template: Option<String>,
    idempotency_header: Option<String>,
    bearer_path_token: Option<String>,
) -> Result<Option<WebhookVerifierConfig>, StatusCode> {
    let Some(mode_raw) = verifier_mode else {
        return Ok(None);
    };
    let mode = parse_verifier_mode(mode_raw)?;
    Ok(Some(WebhookVerifierConfig {
        mode,
        signature_header: signature_header
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default(),
        signature_algo: parse_signature_algo(signature_algo)?,
        signature_encoding: parse_signature_encoding(signature_encoding)?,
        signature_prefix,
        signature_separator,
        signature_value_split,
        timestamp_header: timestamp_header.map(|s| s.trim().to_ascii_lowercase()),
        timestamp_skew_secs: timestamp_skew_secs.map(|v| v as u64),
        payload_template,
        idempotency_header: idempotency_header.map(|s| s.trim().to_ascii_lowercase()),
        bearer_path_token,
    }))
}

fn err_to_status(e: &WebhookError) -> StatusCode {
    match e {
        WebhookError::NotFound => StatusCode::NOT_FOUND,
        WebhookError::BadRequest(_) => StatusCode::BAD_REQUEST,
        WebhookError::SignatureMismatch => StatusCode::UNAUTHORIZED,
        WebhookError::Verify(_) => StatusCode::UNAUTHORIZED,
        WebhookError::ReplayDeduped(_) => StatusCode::OK,
        WebhookError::NotReady => StatusCode::SERVICE_UNAVAILABLE,
        WebhookError::Dispatch(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_response(status: StatusCode, detail: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": detail.into() }))).into_response()
}

fn webhook_error_response(e: WebhookError) -> Response {
    match &e {
        WebhookError::BadRequest(m) => error_response(StatusCode::BAD_REQUEST, m.clone()),
        _ => err_to_status(&e).into_response(),
    }
}

async fn list_webhook_presets() -> Json<Vec<crate::webhooks::WebhookVerifierPreset>> {
    Json(webhook_presets())
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
) -> Response {
    if let Err(m) = validate_webhook_name(&body.name) {
        tracing::debug!(reason = %m, "webhook create: invalid name");
        return error_response(StatusCode::BAD_REQUEST, m);
    }
    let scheme = match parse_scheme(&body.auth_scheme) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let verifier = match build_verifier_config(
        body.verifier_mode.as_deref(),
        body.signature_header.clone(),
        body.signature_algo.as_deref(),
        body.signature_encoding.as_deref(),
        body.signature_prefix.clone(),
        body.signature_separator.clone(),
        body.signature_value_split.clone(),
        body.timestamp_header.clone(),
        body.timestamp_skew_secs,
        body.payload_template.clone(),
        body.idempotency_header.clone(),
        body.bearer_path_token.clone(),
    ) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let secret_required = match verifier.as_ref().map(|v| v.mode) {
        Some(WebhookVerifierMode::HmacV2) => true,
        Some(WebhookVerifierMode::BearerV2 | WebhookVerifierMode::None) => false,
        None => scheme == WebhookAuthScheme::HmacSha256,
    };
    if secret_required && body.secret.as_deref().is_none_or(str::is_empty) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "auth scheme requires a signing secret",
        );
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
        return StatusCode::CONFLICT.into_response();
    }
    let spec = WebhookSpec {
        instance_id: id,
        name: body.name,
        description: body.description,
        auth_scheme: scheme,
        preset_id: body.preset_id,
        verifier,
        signature_header: body.signature_header,
        secret_plaintext: body.secret.filter(|s| !s.is_empty()),
        enabled: body.enabled,
    };
    match state.webhooks.put(&caller.user_id, spec).await {
        Ok(row) => (StatusCode::CREATED, Json(WebhookView::from_row(row))).into_response(),
        Err(e) => webhook_error_response(e),
    }
}

async fn update_webhook(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
    Json(body): Json<UpdateWebhookBody>,
) -> Response {
    let existing = match state.webhooks.get(&caller.user_id, &id, &name).await {
        Ok(row) => row,
        Err(e) => return webhook_error_response(e),
    };
    let scheme = match body.auth_scheme.as_deref() {
        Some(s) => match parse_scheme(s) {
            Ok(v) => v,
            Err(status) => return status.into_response(),
        },
        None => existing.auth_scheme,
    };
    let verifier = match build_verifier_config(
        body.verifier_mode.as_deref(),
        body.signature_header.clone(),
        body.signature_algo.as_deref(),
        body.signature_encoding.as_deref(),
        body.signature_prefix.clone(),
        body.signature_separator.clone(),
        body.signature_value_split.clone(),
        body.timestamp_header.clone(),
        body.timestamp_skew_secs,
        body.payload_template.clone(),
        body.idempotency_header.clone(),
        body.bearer_path_token.clone(),
    ) {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let secret_plaintext = body.secret.filter(|s| !s.is_empty());
    if scheme != WebhookAuthScheme::None
        && existing.auth_scheme != scheme
        && match verifier.as_ref().map(|v| v.mode) {
            Some(WebhookVerifierMode::HmacV2) => true,
            Some(WebhookVerifierMode::BearerV2 | WebhookVerifierMode::None) => false,
            None => scheme == WebhookAuthScheme::HmacSha256,
        }
        && secret_plaintext.is_none()
    {
        // Switching scheme requires a fresh key (the old one was sized
        // for a different verb — bearer tokens vs HMAC keys, etc.).
        return error_response(
            StatusCode::BAD_REQUEST,
            "switching auth scheme requires a fresh signing secret",
        );
    }
    let preset_id = match body.preset_id {
        Some(v) => v,
        None => existing.preset_id.clone(),
    };
    let spec = WebhookSpec {
        instance_id: id,
        name: existing.name.clone(),
        description: body.description.unwrap_or(existing.description.clone()),
        auth_scheme: scheme,
        preset_id,
        verifier,
        signature_header: body.signature_header,
        secret_plaintext,
        enabled: body.enabled.unwrap_or(existing.enabled),
    };
    match state.webhooks.put(&caller.user_id, spec).await {
        Ok(row) => Json(WebhookView::from_row(row)).into_response(),
        Err(e) => webhook_error_response(e),
    }
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

async fn verify_only(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name)): Path<(String, String)>,
    uri: Uri,
    body: Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let result = if query_param(uri.query(), "from").as_deref() == Some("last-failed") {
        state
            .webhooks
            .verify_only_last_failed(&caller.user_id, &id, &name)
            .await
    } else {
        let body: VerifyOnlyBody =
            serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let raw_body = B64
            .decode(body.body_b64.as_bytes())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let headers = json_headers_to_pairs(&body.headers)?;
        state
            .webhooks
            .verify_only(
                &caller.user_id,
                &id,
                &name,
                &headers,
                header_value(&headers, "authorization"),
                None,
                &raw_body,
            )
            .await
    };
    match result {
        Ok(outcome) => Ok(Json(serde_json::json!({
            "ok": true,
            "rendered_payload_b64": outcome.rendered_payload.as_deref().map(|b| B64.encode(b)),
            "matched_version": outcome.matched_version,
        }))),
        Err(WebhookError::Verify(e)) => serde_json::to_value(e)
            .map(Json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
        Err(e) => Err(err_to_status(&e)),
    }
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_owned())
}

async fn replay_delivery(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, name, delivery_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = state
        .webhooks
        .replay_delivery(&caller.user_id, &id, &delivery_id, &caller.user_id)
        .await
        .map_err(|e| err_to_status(&e))?;
    audit_replay(&state, &caller, &id, &name, &delivery_id).await?;
    Ok(Json(
        serde_json::json!({ "ok": true, "status_code": status }),
    ))
}

async fn list_instance_deliveries(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    uri: Uri,
) -> Result<Json<Vec<AuditDeliveryView>>, StatusCode> {
    let qs = parse_query(uri.query().unwrap_or(""));
    let limit = qs
        .get("limit")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_DELIVERY_LIMIT);
    let before = qs.get("before").and_then(|v| v.parse::<i64>().ok());
    let webhook = qs
        .get("webhook")
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let q_raw = qs.get("q").map(String::as_str).filter(|s| !s.is_empty());
    // Hard cap on the search needle — past a few hundred chars it's
    // almost certainly a paste of a payload, and store-side substring
    // scans can burn CPU on long needles.
    if q_raw.is_some_and(|q| q.len() > 256) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rows = state
        .webhooks
        .list_instance_deliveries(&caller.user_id, &id, webhook, q_raw, before, limit)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(
        rows.into_iter().map(AuditDeliveryView::from_row).collect(),
    ))
}

async fn get_delivery(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path((id, delivery_id)): Path<(String, String)>,
) -> Result<Json<DeliveryDetailView>, StatusCode> {
    let row = state
        .webhooks
        .get_delivery(&caller.user_id, &id, &delivery_id)
        .await
        .map_err(|e| err_to_status(&e))?;
    Ok(Json(DeliveryDetailView::from_row(row)))
}

/// Tiny query-string parser — extracted so the audit handler can pull
/// multiple keys without re-walking the string for each one.  Decodes
/// `+` as space and percent-escapes; on malformed input the value is
/// returned verbatim (the audit filters tolerate stray characters).
fn parse_query(qs: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    if qs.is_empty() {
        return out;
    }
    for pair in qs.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        out.insert(qs_decode(k), qs_decode(v));
    }
    out
}

fn qs_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

fn json_headers_to_pairs(raw: &serde_json::Value) -> Result<Vec<(String, String)>, StatusCode> {
    let Some(obj) = raw.as_object() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let mut out = Vec::with_capacity(obj.len());
    for (name, value) in obj {
        let Some(value) = value.as_str() else {
            return Err(StatusCode::BAD_REQUEST);
        };
        out.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(out)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

async fn audit_replay(
    state: &AppState,
    caller: &CallerIdentity,
    instance_id: &str,
    webhook_name: &str,
    delivery_id: &str,
) -> Result<(), StatusCode> {
    let params = serde_json::json!({
        "instance_id": instance_id,
        "webhook_name": webhook_name,
        "delivery_id": delivery_id,
    });
    let bytes = serde_json::to_vec(&params).map_err(|err| {
        tracing::warn!(error = %err, "webhook replay audit params encode failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let entry = AdminAuditEntry {
        actor_subject: caller.identity.subject.clone(),
        action: "webhook.replay".to_owned(),
        target_user: caller.user_id.clone(),
        params_hash: hex::encode(Sha256::digest(&bytes)),
        ts: crate::now_secs(),
    };
    state.admin_audit.insert(&entry).await.map_err(|err| {
        tracing::warn!(error = %err, "webhook replay audit insert failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Public webhook delivery.  Strictly POST.  Body is buffered up to
/// `MAX_WEBHOOK_BODY`; oversize requests get 413.
async fn fire_webhook(
    State(state): State<AppState>,
    Path((instance_id, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    fire_webhook_inner(state, instance_id, name, None, headers, body).await
}

async fn fire_webhook_with_path_token(
    State(state): State<AppState>,
    Path((instance_id, name, bearer_path_token)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    fire_webhook_inner(
        state,
        instance_id,
        name,
        Some(bearer_path_token),
        headers,
        body,
    )
    .await
}

async fn fire_webhook_inner(
    state: AppState,
    instance_id: String,
    name: String,
    bearer_path_token: Option<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_WEBHOOK_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let signature_headers = readable_header_values(&headers);
    let bearer_header = headers.get("authorization").and_then(|v| v.to_str().ok());
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
        .verify_and_dispatch(DispatchCtx {
            instance_id: &instance_id,
            name: &name,
            signature_headers: &signature_headers,
            bearer_header,
            bearer_path_token: bearer_path_token.as_deref(),
            request_id: request_id.as_deref(),
            forward_headers: forward,
            content_type,
            body: body.as_ref(),
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(WebhookError::ReplayDeduped(_)) => (
            [(
                axum::http::header::HeaderName::from_static("x-webhook-status"),
                "replay-deduped",
            )],
            StatusCode::OK,
        )
            .into_response(),
        Err(e) => err_to_status(&e).into_response(),
    }
}

fn readable_header_values(h: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in h {
        if let Ok(val) = v.to_str() {
            out.push((k.as_str().to_ascii_lowercase(), val.to_owned()));
        }
    }
    out
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
            out.push((name, val.to_owned()));
        }
    }
    out
}
