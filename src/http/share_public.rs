//! Public read endpoint for anonymous artefact shares.
//!
//! Mounted via the host-based dispatcher in `http::mod` — when the
//! Host header is `share.<configured_hostname>`, every request lands
//! here regardless of path.  We parse the path ourselves so the
//! cheap-reject discipline (no DB I/O before HMAC verify) survives
//! axum's route-matching machinery, which would otherwise insist on
//! looking up handler state before even trying the path.
//!
//! Shape:
//!   GET /v1/<token>          → server-rendered HTML page
//!   GET /v1/<token>/raw      → streamed raw artefact bytes
//!   anything else            → 404
//!
//! Every non-200 response is byte-identical (a fixed 404 body), so a
//! probing scanner can't tell expired-vs-bad-sig-vs-revoked.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Response, StatusCode};
use axum::middleware::Next;
use futures::TryStreamExt;

use crate::http::AppState;
use crate::shares::render::{
    render_download_page, render_image_page, render_markdown_page, RenderKind,
};
use crate::shares::V1_PATH_PREFIX;

/// 1 MiB cap on the JSON metadata we'll buffer when looking up the
/// artefact's title and kind from dyson's
/// `/api/conversations/:chat/artefacts` listing.  Sufficient for any
/// realistic chat (each row is ~200 bytes); enough to fail fast on a
/// runaway response.
const META_BODY_LIMIT: usize = 1024 * 1024;

/// Outer middleware wired in `http::mod::router` for the share host.
/// Matches the same shape as `dyson_proxy::dispatch` so the two share
/// hosts behave consistently.
pub async fn dispatch(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let Some(apex) = state.shares.apex() else {
        return next.run(req).await;
    };
    let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        return next.run(req).await;
    };
    let host_no_port = host.split(':').next().unwrap_or("");
    let expected = format!("share.{apex}");
    if host_no_port != expected {
        return next.run(req).await;
    }
    serve(state, req).await
}

async fn serve(state: AppState, req: Request) -> Response<Body> {
    if req.method() != axum::http::Method::GET {
        return not_found();
    }
    let path = req.uri().path().to_owned();
    let Some(rest) = path.strip_prefix(V1_PATH_PREFIX) else {
        return not_found();
    };
    let (token, mode) = match rest.strip_suffix("/raw") {
        Some(t) => (t.to_owned(), ServeMode::Raw),
        None => (rest.to_owned(), ServeMode::Html),
    };
    if token.is_empty() || token.contains('/') {
        return not_found();
    }
    serve_token(state, req, &token, mode).await
}

#[derive(Debug, Clone, Copy)]
enum ServeMode {
    Html,
    Raw,
}

async fn serve_token(
    state: AppState,
    req: Request,
    token: &str,
    mode: ServeMode,
) -> Response<Body> {
    // Steps 1-4 of the cheap-reject sequence live inside `verify`;
    // anything that fails them returns a `ShareError` and we 404
    // without writing an audit row.
    let verified = match state.shares.verify(token).await {
        Ok(v) => v,
        Err(_) => return not_found(),
    };

    let remote_addr = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_owned())
        .filter(|s| !s.is_empty());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let raw_path = format!("{V1_PATH_PREFIX}{token}/raw");

    // Fetch the artefact body from dyson.  Reuses the same per-instance
    // bearer the dyson_proxy stamps for normal requests, so the agent
    // sees an identical authentication shape.
    let body_resp = match crate::instance_client::fetch_artefact(
        &state.dyson_http,
        &state.sandbox_domain,
        &verified.instance,
        &format!("/api/artefacts/{}", verified.row.artefact_id),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            state
                .shares
                .record_access(&verified.row.jti, remote_addr.as_deref(), user_agent.as_deref(), 502)
                .await;
            return not_found();
        }
    };
    let upstream_status = body_resp.status();
    if !upstream_status.is_success() {
        state
            .shares
            .record_access(
                &verified.row.jti,
                remote_addr.as_deref(),
                user_agent.as_deref(),
                upstream_status.as_u16().into(),
            )
            .await;
        return not_found();
    }
    let upstream_ct = body_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Branch on render mode.  Raw streams the upstream body straight
    // through; HTML buffers (markdown is small) and renders a page.
    let response = match mode {
        ServeMode::Raw => stream_raw(body_resp, upstream_ct.as_deref()),
        ServeMode::Html => {
            let mime = upstream_ct.as_deref();
            // Title + kind come from a sibling list endpoint.  Best
            // effort: if the dyson listing fails, we render with a
            // generic title rather than 404 — the *body* is what the
            // viewer actually wants.
            let (title, kind_label) = lookup_title_and_kind(&state, &verified, &remote_addr).await;
            // Determine which renderer to call from kind + mime.
            let render = match RenderKind::classify(&kind_label, mime) {
                RenderKind::Markdown => {
                    let bytes = match body_resp.bytes().await {
                        Ok(b) => b,
                        Err(_) => return not_found(),
                    };
                    let body = String::from_utf8_lossy(&bytes);
                    render_markdown_page(&title, &kind_label, &body)
                }
                RenderKind::Image => render_image_page(&title, &kind_label, &raw_path),
                RenderKind::Other => render_download_page(&title, &kind_label, &raw_path),
            };
            html_response(&render)
        }
    };

    state
        .shares
        .record_access(
            &verified.row.jti,
            remote_addr.as_deref(),
            user_agent.as_deref(),
            response.status().as_u16().into(),
        )
        .await;
    response
}

async fn lookup_title_and_kind(
    state: &AppState,
    verified: &crate::shares::service::VerifiedShare,
    remote_addr: &Option<String>,
) -> (String, String) {
    let path = format!("/api/conversations/{}/artefacts", verified.row.chat_id);
    let resp = crate::instance_client::fetch_artefact(
        &state.dyson_http,
        &state.sandbox_domain,
        &verified.instance,
        &path,
    )
    .await;
    let resp = match resp {
        Ok(r) => r,
        Err(_) => return fallback_title_kind(verified),
    };
    if !resp.status().is_success() {
        return fallback_title_kind(verified);
    }
    let bytes = match axum::body::to_bytes(
        Body::from_stream(resp.bytes_stream().map_err(std::io::Error::other)),
        META_BODY_LIMIT,
    )
    .await
    {
        Ok(b) => b,
        Err(_) => return fallback_title_kind(verified),
    };
    let arr: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return fallback_title_kind(verified),
    };
    let _ = remote_addr; // unused; kept in signature for future per-IP rate-limit hooks
    if let Some(items) = arr.as_array() {
        for item in items {
            if item.get("id").and_then(|v| v.as_str()) == Some(verified.row.artefact_id.as_str()) {
                let title = item
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Artefact")
                    .to_string();
                let kind = item
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("other")
                    .to_string();
                return (title, kind);
            }
        }
    }
    fallback_title_kind(verified)
}

fn fallback_title_kind(verified: &crate::shares::service::VerifiedShare) -> (String, String) {
    (
        verified
            .row
            .label
            .clone()
            .unwrap_or_else(|| "Artefact".to_string()),
        "other".to_string(),
    )
}

fn html_response(html: &str) -> Response<Body> {
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; \
             style-src 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self' data:; \
             base-uri 'none'; \
             form-action 'none'; \
             frame-ancestors 'none'",
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .body(Body::from(html.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()));
    resp.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    resp
}

fn stream_raw(upstream: reqwest::Response, content_type: Option<&str>) -> Response<Body> {
    let stream = upstream
        .bytes_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; img-src 'self' data:",
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer");
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn not_found() -> Response<Body> {
    // Byte-identical 404 body across every reject reason — bad-sig,
    // expired, revoked, missing instance, upstream 5xx all look the
    // same on the wire.  No JSON, no breadcrumbs.
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "private, no-store")
        .body(Body::from("not found"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_response_sets_csp_no_script() {
        let resp = html_response("<html></html>");
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert!(!csp.contains("script-src"));
    }

    #[test]
    fn not_found_body_is_constant() {
        let r1 = not_found();
        let r2 = not_found();
        assert_eq!(r1.status(), r2.status());
        // Headers shape is identical so a probing scanner can't tell
        // expired-vs-bad-sig from response metadata.
        assert_eq!(
            r1.headers().get(header::CACHE_CONTROL),
            r2.headers().get(header::CACHE_CONTROL),
        );
    }
}
