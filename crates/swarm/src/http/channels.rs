//! Instance channel management and Telegram webhook ingress.

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::auth::CallerIdentity;
use crate::channels::{
    ChannelsError, TELEGRAM_KIND, delivery_preview, telegram_update_allowed_by_sender,
};
use crate::http::AppState;
use crate::traits::{ChannelDeliveryRow, InstanceChannelRow, InstanceStatus};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances/:id/channels", get(list_channels))
        .route(
            "/v1/instances/:id/channels/telegram",
            post(connect_telegram)
                .delete(disconnect_telegram)
                .patch(patch_telegram),
        )
        .route(
            "/v1/instances/:id/channels/telegram/recent",
            get(recent_telegram),
        )
        .with_state(state)
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/channels/telegram/:instance_id/webhook",
            post(telegram_webhook),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct ChannelView {
    kind: String,
    handle: String,
    enabled: bool,
    allowed_senders: Vec<String>,
    last_inbound_at: Option<i64>,
    created_at: i64,
    health: String,
}

impl From<InstanceChannelRow> for ChannelView {
    fn from(row: InstanceChannelRow) -> Self {
        Self {
            kind: row.kind,
            handle: row.handle,
            enabled: row.enabled,
            allowed_senders: row.allowed_senders,
            last_inbound_at: row.last_inbound_at,
            created_at: row.created_at,
            health: if row.enabled { "green" } else { "paused" }.to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DeliveryView {
    timestamp: i64,
    status: i32,
    preview: String,
}

impl From<ChannelDeliveryRow> for DeliveryView {
    fn from(row: ChannelDeliveryRow) -> Self {
        Self {
            timestamp: row.received_at,
            status: row.status,
            preview: row.preview,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConnectTelegramBody {
    token: String,
    #[serde(default)]
    allowed_senders: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PatchTelegramBody {
    enabled: Option<bool>,
    allowed_senders: Option<Vec<String>>,
}

async fn list_channels(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<ChannelView>>, (StatusCode, String)> {
    let rows = state
        .channels
        .list(&caller.user_id, &id)
        .await
        .map_err(channel_err_to_response)?;
    Ok(Json(rows.into_iter().map(ChannelView::from).collect()))
}

async fn connect_telegram(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<ConnectTelegramBody>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !crate::channels::telegram_token_shape_valid(body.token.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Telegram token must match 123456:35-character-secret".into(),
        ));
    }
    let connected = state
        .channels
        .connect_telegram(&caller.user_id, &id, &body.token, body.allowed_senders)
        .await
        .map_err(channel_err_to_response)?;
    if let Err(err) = state
        .instances
        .sync_channels_to_dyson(&caller.user_id, &id)
        .await
    {
        tracing::warn!(instance = %id, error = %err, "telegram channel connected but dyson runtime sync failed");
    }
    Ok((StatusCode::CREATED, Json(connected)))
}

async fn disconnect_telegram(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state
        .channels
        .disconnect_telegram(&caller.user_id, &id)
        .await
        .map_err(channel_err_to_response)?;
    if let Err(err) = state
        .instances
        .sync_channels_to_dyson(&caller.user_id, &id)
        .await
    {
        tracing::warn!(instance = %id, error = %err, "telegram channel disconnected but dyson runtime sync failed");
    }
    Ok((StatusCode::OK, Json(serde_json::json!({ "ok": true }))))
}

async fn patch_telegram(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
    Json(body): Json<PatchTelegramBody>,
) -> Result<Json<ChannelView>, (StatusCode, String)> {
    let row = state
        .channels
        .set_telegram_settings(&caller.user_id, &id, body.enabled, body.allowed_senders)
        .await
        .map_err(channel_err_to_response)?;
    if let Err(err) = state
        .instances
        .sync_channels_to_dyson(&caller.user_id, &id)
        .await
    {
        tracing::warn!(instance = %id, error = %err, "telegram channel patched but dyson runtime sync failed");
    }
    Ok(Json(ChannelView::from(row)))
}

async fn recent_telegram(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<DeliveryView>>, (StatusCode, String)> {
    let rows = state
        .channels
        .recent_telegram(&caller.user_id, &id)
        .await
        .map_err(channel_err_to_response)?;
    Ok(Json(rows.into_iter().map(DeliveryView::from).collect()))
}

async fn telegram_webhook(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    req: Request,
) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let row = match state
        .channels
        .channels
        .get(&instance_id, TELEGRAM_KIND)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return text_response(StatusCode::NOT_FOUND, "channel not found"),
        Err(err) => {
            tracing::warn!(instance = %instance_id, error = %err, "telegram webhook channel lookup failed");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "channel lookup failed");
        }
    };
    let instance = match state.instances.get_unscoped(&instance_id).await {
        Ok(row) if row.status == InstanceStatus::Live => row,
        Ok(_) => return text_response(StatusCode::SERVICE_UNAVAILABLE, "instance not ready"),
        Err(_) => return text_response(StatusCode::SERVICE_UNAVAILABLE, "instance not ready"),
    };
    let expected = match state
        .channels
        .telegram_webhook_secret(&instance.owner_id, &row)
        .await
    {
        Ok(Some(secret)) => secret,
        Ok(None) => return text_response(StatusCode::UNAUTHORIZED, "missing webhook secret"),
        Err(err) => {
            tracing::warn!(instance = %instance_id, error = %err, "telegram webhook secret read failed");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "secret read failed");
        }
    };
    let Some(actual) = parts
        .headers
        .get("x-telegram-bot-api-secret-token")
        .and_then(|v| v.to_str().ok())
    else {
        return text_response(StatusCode::UNAUTHORIZED, "missing secret token");
    };
    if !ct_eq(actual.as_bytes(), expected.as_bytes()) {
        return text_response(StatusCode::UNAUTHORIZED, "wrong secret token");
    }

    let body_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "body too large"),
    };
    let now = crate::now_secs();
    if !row.enabled {
        let _ = state
            .channels
            .channels
            .update_last_inbound_at(&instance_id, TELEGRAM_KIND, now)
            .await;
        let _ = state
            .channels
            .channels
            .record_delivery(
                &instance_id,
                TELEGRAM_KIND,
                now,
                200,
                &delivery_preview(&body_bytes),
            )
            .await;
        return text_response(StatusCode::OK, "paused");
    }
    if !telegram_update_allowed_by_sender(&row.allowed_senders, &body_bytes) {
        let _ = state
            .channels
            .channels
            .record_delivery(
                &instance_id,
                TELEGRAM_KIND,
                now,
                403,
                &delivery_preview(&body_bytes),
            )
            .await;
        return text_response(StatusCode::OK, "sender not allowed");
    }

    let Some(sandbox_id) = instance
        .cube_sandbox_id
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return text_response(StatusCode::SERVICE_UNAVAILABLE, "instance not ready");
    };
    let url = cube_url(&state, sandbox_id, "/webhook/telegram");
    let mut builder = state.dyson_http.post(url).header(
        header::AUTHORIZATION.as_str(),
        format!("Bearer {}", instance.bearer_token),
    );
    if let Some(content_type) = parts.headers.get(header::CONTENT_TYPE) {
        builder = builder.header(header::CONTENT_TYPE.as_str(), content_type.clone());
    }
    let upstream = match builder.body(body_bytes.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(instance = %instance_id, error = %err, "telegram webhook dyson forward failed");
            let _ = state
                .channels
                .channels
                .update_last_inbound_at(&instance_id, TELEGRAM_KIND, now)
                .await;
            let _ = state
                .channels
                .channels
                .record_delivery(
                    &instance_id,
                    TELEGRAM_KIND,
                    now,
                    502,
                    &delivery_preview(&body_bytes),
                )
                .await;
            return text_response(StatusCode::BAD_GATEWAY, "dyson unreachable");
        }
    };
    let status = upstream.status();
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = upstream.bytes().await.unwrap_or_else(|_| Bytes::new());
    let _ = state
        .channels
        .channels
        .update_last_inbound_at(&instance_id, TELEGRAM_KIND, now)
        .await;
    let _ = state
        .channels
        .channels
        .record_delivery(
            &instance_id,
            TELEGRAM_KIND,
            now,
            status.as_u16().into(),
            &delivery_preview(&body_bytes),
        )
        .await;
    response_with(status, content_type, bytes)
}

fn cube_url(state: &AppState, sandbox_id: &str, path: &str) -> String {
    let cube_port = std::env::var("SWARM_CUBE_INTERNAL_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(80);
    format!(
        "https://{}-{}.{}{}",
        cube_port,
        sandbox_id,
        state.sandbox_domain.trim_end_matches('/'),
        path
    )
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};

    let a_hash = Sha256::digest(a);
    let b_hash = Sha256::digest(b);
    bool::from(a_hash.as_slice().ct_eq(b_hash.as_slice()))
}

fn response_with(
    status: reqwest::StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    if let (Some(headers), Some(content_type)) = (builder.headers_mut(), content_type) {
        headers.insert(header::CONTENT_TYPE, content_type);
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn text_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

pub fn channel_err_to_response(err: ChannelsError) -> (StatusCode, String) {
    match err {
        ChannelsError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        ChannelsError::Conflict => (StatusCode::CONFLICT, "channel already exists".into()),
        ChannelsError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
        ChannelsError::InstanceNotReady => {
            (StatusCode::SERVICE_UNAVAILABLE, "instance not ready".into())
        }
        ChannelsError::Telegram(msg) => (StatusCode::BAD_REQUEST, msg),
        ChannelsError::Store(_) | ChannelsError::Secrets(_) | ChannelsError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
}
