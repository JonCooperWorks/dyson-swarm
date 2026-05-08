use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};

use crate::error::{StoreError, SwarmError};

pub(super) fn swarm_err_to_resp(err: SwarmError) -> Response<Body> {
    let (status, msg) = match &err {
        SwarmError::NotFound => (StatusCode::NOT_FOUND, "not found".to_owned()),
        SwarmError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
        SwarmError::PolicyDenied(m) => (StatusCode::FORBIDDEN, m.clone()),
        SwarmError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        // Anything else maps to 500 — the management surface is small
        // and these other variants don't reach this code path.
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    error_resp(status, &msg)
}

pub(super) fn store_err_to_resp(err: StoreError) -> Response<Body> {
    let status = match &err {
        StoreError::NotFound => StatusCode::NOT_FOUND,
        StoreError::Constraint(_) | StoreError::Malformed(_) => StatusCode::BAD_REQUEST,
        StoreError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_resp(status, &err.to_string())
}

/// JSON-RPC error envelope as a 200-OK HTTP response.  The agent's
/// MCP client reads `error.message` to surface the failure; using a
/// proper JSON-RPC error (rather than HTTP 4xx) keeps the agent's
/// error path consistent with what an upstream rejection looks like.
pub(super) fn jsonrpc_error_resp(
    id: serde_json::Value,
    code: i64,
    message: &str,
) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    });
    let bytes = body.to_string().into_bytes();
    let mut resp = Response::new(Body::from(bytes.clone()));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut().insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from(bytes.len()),
    );
    resp
}

pub(super) fn error_resp(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": msg }).to_string();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}
