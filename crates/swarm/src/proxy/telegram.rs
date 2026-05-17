//! Telegram Bot API proxy for dyson instances.
//!
//! The cube authenticates with its existing per-instance proxy bearer.
//! Swarm resolves the instance's sealed BotFather token, rewrites the URL
//! to api.telegram.org, and strips the cube bearer before forwarding.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Response, StatusCode, header};
use axum::routing::{get, post};
use futures::TryStreamExt;

use crate::auth::extract_bearer;
use crate::channels::{TELEGRAM_KIND, telegram_bot_token_secret_name};
use crate::traits::{InstanceChannelStore, InstanceStore, TokenStore};
use dyson_swarm_core::http::InternalHttpClient;

#[derive(Clone)]
pub struct TelegramProxyService {
    pub tokens: Arc<dyn TokenStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub channels: Arc<dyn InstanceChannelStore>,
    pub user_secrets: Arc<crate::secrets::UserSecretsService>,
    pub client: InternalHttpClient,
    pub telegram_base_url: String,
}

impl TelegramProxyService {
    pub fn new(
        tokens: Arc<dyn TokenStore>,
        instances: Arc<dyn InstanceStore>,
        channels: Arc<dyn InstanceChannelStore>,
        user_secrets: Arc<crate::secrets::UserSecretsService>,
        telegram_base_url: impl Into<String>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            tokens,
            instances,
            channels,
            user_secrets,
            client: InternalHttpClient::new()?,
            telegram_base_url: telegram_base_url.into().trim_end_matches('/').to_owned(),
        })
    }
}

pub fn router(state: Arc<TelegramProxyService>) -> Router {
    Router::new()
        .route(
            "/v1/proxy/telegram/:instance_id/file/*file_path",
            get(file_download),
        )
        .route(
            "/v1/proxy/telegram/:instance_id/*method",
            post(method).get(method),
        )
        .with_state(state)
}

async fn method(
    State(state): State<Arc<TelegramProxyService>>,
    Path((instance_id, method)): Path<(String, String)>,
    req: Request,
) -> Response<Body> {
    if !allowed_method(&method) {
        return text(StatusCode::NOT_FOUND, "unknown Telegram API method");
    }
    let Some((owner_id, token)) = authorize_and_token(&state, &instance_id, req.headers()).await
    else {
        return text(StatusCode::UNAUTHORIZED, "invalid bearer");
    };
    drop(owner_id);

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return text(StatusCode::BAD_REQUEST, "body too large"),
    };
    let url = format!("{}/bot{}/{}", state.telegram_base_url, token, method);
    forward(&state.client, parts.method, &parts.headers, url, body_bytes).await
}

async fn file_download(
    State(state): State<Arc<TelegramProxyService>>,
    Path((instance_id, file_path)): Path<(String, String)>,
    req: Request,
) -> Response<Body> {
    if file_path.is_empty() || file_path.contains("..") {
        return text(StatusCode::NOT_FOUND, "invalid file path");
    }
    let Some((_owner_id, token)) = authorize_and_token(&state, &instance_id, req.headers()).await
    else {
        return text(StatusCode::UNAUTHORIZED, "invalid bearer");
    };
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return text(StatusCode::BAD_REQUEST, "body too large"),
    };
    let url = format!(
        "{}/file/bot{}/{}",
        state.telegram_base_url, token, file_path
    );
    forward(&state.client, parts.method, &parts.headers, url, body_bytes).await
}

async fn authorize_and_token(
    state: &TelegramProxyService,
    instance_id: &str,
    headers: &HeaderMap,
) -> Option<(String, String)> {
    let bearer = extract_bearer(headers)?;
    let record = state.tokens.resolve(&bearer).await.ok().flatten()?;
    if record.instance_id != instance_id || record.revoked_at.is_some() {
        return None;
    }
    let instance = state.instances.get(instance_id).await.ok().flatten()?;
    state
        .channels
        .get(instance_id, TELEGRAM_KIND)
        .await
        .ok()
        .flatten()?;
    let secret_name = telegram_bot_token_secret_name(instance_id);
    let token = state
        .user_secrets
        .get(&instance.owner_id, &secret_name)
        .await
        .ok()
        .flatten()?;
    Some((
        instance.owner_id,
        String::from_utf8_lossy(&token).into_owned(),
    ))
}

async fn forward(
    client: &InternalHttpClient,
    method: axum::http::Method,
    headers: &HeaderMap,
    url: String,
    body: Bytes,
) -> Response<Body> {
    let method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut builder = client.request(method, url);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        builder = builder.header(header::CONTENT_TYPE.as_str(), content_type.clone());
    }
    if !body.is_empty() {
        builder = builder.body(body);
    }
    let resp = match builder.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(error = %err, "telegram proxy upstream error");
            return text(StatusCode::BAD_GATEWAY, "telegram upstream failed");
        }
    };
    let status = resp.status();
    let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
    let stream = resp
        .bytes_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let mut builder = Response::builder().status(status);
    if let (Some(headers), Some(content_type)) = (builder.headers_mut(), content_type) {
        headers.insert(header::CONTENT_TYPE, content_type);
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn allowed_method(method: &str) -> bool {
    if method.contains('/') || method.is_empty() {
        return false;
    }
    matches!(
        method,
        "getMe"
            | "sendMessage"
            | "editMessageText"
            | "sendDocument"
            | "answerCallbackQuery"
            | "getFile"
            | "sendChatAction"
            | "setMyCommands"
            | "deleteWebhook"
            | "getWebhookInfo"
    )
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
