//! `GET /` and `GET /assets/*` — serve the embedded React bundle.
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

pub fn router() -> Router {
    // Explicit `/` plus a fallback that handles every non-API path —
    // `/assets/<hash>.js`, `/favicon.ico`, etc.  API routes (healthz,
    // /v1/*, /llm/*) are merged at the outer router and win the route
    // match before the fallback fires.
    Router::new()
        .route("/", get(serve_root))
        .fallback(serve_fallback)
}

async fn serve_root() -> Response {
    serve_path("/")
}

async fn serve_fallback(req: Request) -> Response {
    serve_path(req.uri().path())
}

fn serve_path(path: &str) -> Response {
    let decoded = url_decode(path);
    if decoded.contains("..") || decoded.contains('\\') || decoded.contains('\0') {
        return not_found();
    }
    match assets::lookup(&decoded) {
        Some((bytes, ct)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
            .body(Body::from(bytes))
            .unwrap_or_else(|_| not_found()),
        None => not_found(),
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
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
}
