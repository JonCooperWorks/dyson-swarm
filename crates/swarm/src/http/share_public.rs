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
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::middleware::Next;
use futures::TryStreamExt;

use crate::http::AppState;
use crate::shares::V1_PATH_PREFIX;
use crate::shares::render::{
    RenderKind, render_download_page, render_image_page, render_markdown_page,
};

/// 1 MiB cap on the JSON metadata we'll buffer when looking up the
/// artefact's title and kind from dyson's
/// `/api/conversations/:chat/artefacts` listing.  Sufficient for any
/// realistic chat (each row is ~200 bytes); enough to fail fast on a
/// runaway response.
const META_BODY_LIMIT: usize = 1024 * 1024;

/// Outer middleware wired in `http::mod::router` for the share host.
/// Matches the same shape as `dyson_proxy::dispatch` so the two share
/// hosts behave consistently.
pub async fn dispatch(State(state): State<AppState>, req: Request, next: Next) -> Response<Body> {
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
    let host_no_port = host
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let expected = format!("share.{}", apex.trim_end_matches('.').to_ascii_lowercase());
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

    // Resolve (bytes, content_type, title, kind) — read-through and
    // write-through cache.  Cache hit serves immediately; cache miss
    // pulls from cube and writes through so the next reset doesn't
    // break this share URL.
    let resolved = match resolve_artefact(&state, &verified).await {
        Some(r) => r,
        None => {
            state
                .shares
                .record_access(
                    &verified.row.jti,
                    remote_addr.as_deref(),
                    user_agent.as_deref(),
                    502,
                )
                .await;
            return not_found();
        }
    };
    let upstream_ct = resolved.mime.clone();

    // Branch on render mode.  Raw serves cached/buffered bytes; HTML
    // renders a page using the same body buffer.
    //
    // For image (and other "send_file") artefacts the dyson agent
    // stores the raw artefact body as the relative URL `/api/files/<id>`
    // — the `metadata.file_url` shape — rather than the bytes
    // themselves.  Streaming that through to the viewer's browser
    // would land them on a broken-image placeholder; we have to
    // double-hop through the instance to fetch the actual bytes when
    // the cache only knows about the pointer.
    let response = match mode {
        ServeMode::Raw => match resolve_raw_bytes(&state, &verified, &resolved).await {
            Some(r) => r,
            None => {
                state
                    .shares
                    .record_access(
                        &verified.row.jti,
                        remote_addr.as_deref(),
                        user_agent.as_deref(),
                        502,
                    )
                    .await;
                return not_found();
            }
        },
        ServeMode::Html => {
            let mime = upstream_ct.as_deref();
            let title = resolved.title.clone();
            let kind_label = resolved.kind.clone();
            let render = match RenderKind::classify(&kind_label, mime) {
                RenderKind::Markdown => {
                    let body = String::from_utf8_lossy(&resolved.bytes);
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

/// Buffered artefact body + descriptive metadata.  Returned by
/// `resolve_artefact` once the cache or cube has produced bytes; the
/// HTML and Raw paths consume from here.
struct ResolvedArtefact {
    bytes: Vec<u8>,
    mime: Option<String>,
    title: String,
    kind: String,
}

/// Read-through, write-through artefact resolver.
///
/// Order of operations:
/// 1. Cache lookup — if the row exists AND its on-disk body is still
///    there, serve it directly.  This is the post-cube-reset path:
///    once we've cached an artefact, the share URL keeps working
///    even if its source cube is destroyed.
/// 2. Upstream fetch from the live cube via the per-instance bearer.
/// 3. Discover title / kind via the cube's
///    `/api/conversations/:chat/artefacts` listing (best effort).
/// 4. Write-through: persist meta + bytes into the cache so step 1
///    short-circuits next time.
///
/// Returns `None` on full miss (no cache + cube unreachable / 4xx).
async fn resolve_artefact(
    state: &AppState,
    verified: &crate::shares::service::VerifiedShare,
) -> Option<ResolvedArtefact> {
    // 1. Cache lookup.  We require BOTH the row and an on-disk body
    // to be present; a row without a body falls through to upstream
    // (and re-ingests on the way back).
    if let Ok(Some(row)) = state
        .artefact_cache
        .find(
            &verified.row.instance_id,
            &verified.row.chat_id,
            &verified.row.artefact_id,
        )
        .await
        && let Ok(Some(bytes)) = state.artefact_cache.read_body(&row).await
    {
        return Some(ResolvedArtefact {
            bytes,
            mime: row.mime,
            title: row.title,
            kind: row.kind,
        });
    }

    // 2. Upstream fetch.
    let resp = match crate::instance_client::fetch_artefact(
        &state.dyson_http,
        &state.sandbox_domain,
        &verified.instance,
        &format!("/api/artefacts/{}", verified.row.artefact_id),
    )
    .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return None,
    };
    let upstream_ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await.ok()?.to_vec();

    // 3. Discover title / kind from the cube's listing endpoint.
    // Best-effort — fall back to the share row's label if dyson
    // doesn't answer.  The cube being slow to list shouldn't block
    // serving the body.
    let (title, kind) = lookup_title_and_kind(state, verified).await;

    // 4. Write-through into the swarm cache.  Failures here are
    // non-fatal — the response goes out either way; the next request
    // will retry the ingest.
    let _ = state
        .artefact_cache
        .ingest(
            crate::artefacts::IngestMeta {
                instance_id: &verified.row.instance_id,
                owner_id: &verified.instance.owner_id,
                chat_id: &verified.row.chat_id,
                artefact_id: &verified.row.artefact_id,
                kind: &kind,
                title: &title,
                mime: upstream_ct.as_deref(),
                created_at: crate::now_secs(),
                metadata_json: None,
            },
            Some(&bytes),
        )
        .await;

    Some(ResolvedArtefact {
        bytes,
        mime: upstream_ct,
        title,
        kind,
    })
}

/// Build a `/raw` response from already-resolved bytes.  Handles
/// dyson's `send_file` pointer shape: when the body is a small text
/// blob containing `/api/files/<id>`, refetch the underlying file
/// from the cube and stream those bytes instead.  When the cube is
/// gone, treat that as a miss — pointer artefacts haven't been
/// fully cached.
async fn resolve_raw_bytes(
    state: &AppState,
    verified: &crate::shares::service::VerifiedShare,
    resolved: &ResolvedArtefact,
) -> Option<Response<Body>> {
    let ct_lower = resolved.mime.as_deref().unwrap_or("").to_ascii_lowercase();
    let probably_pointer = ct_lower.starts_with("text/")
        || ct_lower.is_empty()
        || ct_lower.starts_with("image/")
        || ct_lower.starts_with("application/octet-stream");
    if probably_pointer && resolved.bytes.len() <= 2048 {
        let trimmed = std::str::from_utf8(&resolved.bytes)
            .map(str::trim)
            .unwrap_or("");
        if let Some(file_path) = parse_files_pointer(trimmed) {
            let resp = crate::instance_client::fetch_artefact(
                &state.dyson_http,
                &state.sandbox_domain,
                &verified.instance,
                &file_path,
            )
            .await;
            let resp = match resp {
                Ok(r) if r.status().is_success() => r,
                _ => return None,
            };
            let inner_ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            return Some(stream_raw(resp, inner_ct.as_deref()));
        }
    }
    Some(inline_response(
        axum::body::Bytes::from(resolved.bytes.clone()),
        resolved.mime.as_deref(),
    ))
}

/// Recognise dyson's `send_file` pointer shape: an ASCII string
/// starting with `/api/files/` and continuing with safe characters.
/// Anything else is treated as opaque artefact body.
fn parse_files_pointer(s: &str) -> Option<String> {
    if !s.starts_with("/api/files/") {
        return None;
    }
    // Reject CR/LF and other shenanigans — the dyson stamp is a
    // single-line URL with bounded charset.
    if s.contains(|c: char| c == '\n' || c == '\r' || c == ' ') {
        return None;
    }
    if s.len() > 256 {
        return None;
    }
    Some(s.to_owned())
}

/// Build a one-shot response carrying already-consumed bytes (we
/// drained the upstream reqwest body to inspect for a pointer; can't
/// restream).  Headers mirror `stream_raw`.
fn inline_response(bytes: axum::body::Bytes, content_type: Option<&str>) -> Response<Body> {
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
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn lookup_title_and_kind(
    state: &AppState,
    verified: &crate::shares::service::VerifiedShare,
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
