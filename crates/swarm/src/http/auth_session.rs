//! `POST /auth/session` — server-stamped HttpOnly cookie for Dyson subdomains.

use axum::extract::{Json, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde::Deserialize;

use crate::auth::{CallerIdentity, UserAuthState, extract_bearer, user_middleware};

use super::AppState;

const COOKIE_NAME: &str = "dyson_swarm_session";

#[derive(Debug, Deserialize)]
struct SessionBody {
    #[serde(default)]
    expires_at: Option<i64>,
}

pub fn router(state: AppState, user_auth: UserAuthState) -> Router {
    Router::new()
        .route(
            "/auth/session",
            post(create)
                .layer(middleware::from_fn_with_state(user_auth, user_middleware))
                .delete(clear),
        )
        .with_state(state)
}

async fn create(
    State(state): State<AppState>,
    Extension(_caller): Extension<CallerIdentity>,
    headers: HeaderMap,
    body: Option<Json<SessionBody>>,
) -> Response {
    let Some(token) = extract_bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let cookie = build_cookie(&state, &token, body.and_then(|Json(b)| b.expires_at), false);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

async fn clear(State(state): State<AppState>) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let cookie = build_cookie(&state, "", None, true);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

fn build_cookie(state: &AppState, token: &str, expires_at: Option<i64>, clear: bool) -> String {
    let mut parts = vec![
        format!("{COOKIE_NAME}={token}"),
        "Path=/".to_string(),
        "SameSite=Strict".to_string(),
        "HttpOnly".to_string(),
    ];
    if state.hostname.is_some() {
        parts.push("Secure".to_string());
    }
    if let Some(domain) = cookie_domain(state.hostname.as_deref()) {
        parts.push(format!("Domain={domain}"));
    }
    if clear {
        parts.push("Max-Age=0".to_string());
        parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string());
    } else if let Some(exp) = expires_at {
        let max_age = exp.saturating_sub(crate::now_secs()).max(0);
        parts.push(format!("Max-Age={max_age}"));
    }
    parts.join("; ")
}

fn cookie_domain(host: Option<&str>) -> Option<String> {
    let host = host?.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host.contains('.')
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return None;
    }
    Some(host)
}
