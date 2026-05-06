//! `GET /`, `GET /assets/*`, and browser deep-links — serve the
//! embedded React bundle.
//!
//! `build.rs` walks `src/http/web/dist/` at compile time and emits a
//! table of `include_bytes!` entries; [`super::assets::lookup`] is the
//! read side.  This module wires the table into an axum router that
//! serves the bundle without any auth layer.
//!
//! Path safety: the URI is decoded before the traversal check because
//! a raw `%2e%2e%2f` would slip past `contains("..")`.  Backslashes
//! and NUL bytes are also rejected — they have no business in a URL
//! path and the OS may treat them surprisingly.

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use super::assets;

const SPA_CSP: &str = "default-src 'self'; \
    script-src 'self'; \
    style-src 'self' 'unsafe-inline'; \
    connect-src 'self' https:; \
    img-src 'self' data: blob:; \
    font-src 'self' data:; \
    base-uri 'self'; \
    form-action 'self'; \
    frame-ancestors 'none'";

pub fn router() -> Router {
    // Explicit `/` plus a fallback that handles static files and
    // document navigations into SPA subpages. API routes (healthz,
    // /v1/*, /llm/*) are merged at the outer router and win concrete
    // route matches before this fallback fires.
    Router::new()
        .route("/", get(serve_root))
        .fallback(serve_fallback)
}

async fn serve_root() -> Response {
    serve_path("/", None)
}

async fn serve_fallback(req: Request) -> Response {
    serve_path(req.uri().path(), req.headers().get(header::ACCEPT))
}

fn serve_path(path: &str, accept: Option<&HeaderValue>) -> Response {
    let decoded = url_decode(path);
    if decoded.contains("..") || decoded.contains('\\') || decoded.contains('\0') {
        return not_found();
    }
    match assets::lookup(&decoded) {
        Some((bytes, ct)) => asset_response(bytes, ct),
        None if should_serve_spa_shell(&decoded, accept) => serve_index_shell(),
        None => not_found(),
    }
}

fn serve_index_shell() -> Response {
    match assets::lookup("/") {
        Some((bytes, ct)) => asset_response(bytes, ct),
        None => not_found(),
    }
}

fn asset_response(bytes: &'static [u8], content_type: &'static str) -> Response {
    security_headers(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
            .body(Body::from(bytes))
            .unwrap_or_else(|_| not_found()),
    )
}

fn should_serve_spa_shell(path: &str, accept: Option<&HeaderValue>) -> bool {
    if !accepts_html(accept) || is_reserved_route_prefix(path) || looks_like_asset_path(path) {
        return false;
    }
    true
}

fn accepts_html(accept: Option<&HeaderValue>) -> bool {
    accept.and_then(|v| v.to_str().ok()).is_some_and(|raw| {
        raw.split(',')
            .any(|part| part.trim().starts_with("text/html"))
    })
}

fn is_reserved_route_prefix(path: &str) -> bool {
    matches!(
        path,
        "/healthz" | "/auth" | "/v1" | "/llm" | "/mcp" | "/webhooks" | "/_swarm"
    ) || path.starts_with("/auth/")
        || path.starts_with("/v1/")
        || path.starts_with("/llm/")
        || path.starts_with("/mcp/")
        || path.starts_with("/webhooks/")
        || path.starts_with("/_swarm/")
}

fn looks_like_asset_path(path: &str) -> bool {
    path.starts_with("/assets/")
        || path
            .rsplit('/')
            .next()
            .is_some_and(|segment| segment.contains('.'))
}

fn not_found() -> Response {
    security_headers((StatusCode::NOT_FOUND, "not found").into_response())
}

fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SPA_CSP),
    );
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    resp
}

/// Minimal percent-decoder.  We don't bring in `percent-encoding` for
/// this — the input alphabet is already restricted by axum's URI
/// parser, and we only care about decoding hex escapes correctly so a
/// crafted `%2e%2e` doesn't bypass the traversal check.
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = from_hex(bytes[i + 1]);
            let lo = from_hex(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_handles_hex_escapes() {
        assert_eq!(url_decode("/foo%2ebar"), "/foo.bar");
        assert_eq!(url_decode("/%2e%2e/secret"), "/../secret");
    }

    #[test]
    fn url_decode_passes_through_unencoded() {
        assert_eq!(url_decode("/assets/index.js"), "/assets/index.js");
    }

    #[test]
    fn url_decode_leaves_malformed_escapes_alone() {
        assert_eq!(url_decode("/foo%2"), "/foo%2");
        assert_eq!(url_decode("/foo%xy"), "/foo%xy");
    }

    #[test]
    fn serve_path_stamps_spa_security_headers() {
        let resp = serve_path("/", None);
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff",);
        assert_eq!(headers.get("Referrer-Policy").unwrap(), "no-referrer");
        assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY");
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src 'self'"));
    }

    #[test]
    fn browser_deep_links_fall_back_to_spa_shell() {
        let resp = serve_path(
            "/i/fluffy-otter-042/model",
            Some(&HeaderValue::from_static("text/html,application/xhtml+xml")),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("text/html"))
        );
    }

    #[test]
    fn missing_assets_and_api_like_paths_stay_404() {
        let accept = HeaderValue::from_static("text/html,application/xhtml+xml");
        assert_eq!(
            serve_path("/assets/nope.js", Some(&accept)).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            serve_path("/favicon.ico", Some(&accept)).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            serve_path("/v1/nope", Some(&accept)).status(),
            StatusCode::NOT_FOUND
        );
    }
}
