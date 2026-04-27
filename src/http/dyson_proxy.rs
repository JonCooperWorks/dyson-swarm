//! Host-based reverse proxy that fronts each Dyson sandbox.
//!
//! When warden is configured with a `hostname` (e.g. `warden.example.com`),
//! every running Dyson is reachable at `<instance_id>.<hostname>`.  The
//! [`dispatch`] middleware inspects every inbound request's `Host`
//! header; if it parses as a sandbox subdomain, the request is
//! authenticated, owner-checked, and forwarded to
//! `https://<cube_sandbox_id>.<sandbox_domain>/<original-path>`.  If it
//! doesn't, the request flows through to the regular API + SPA router.
//!
//! Why host-based, not path-based: Dyson's frontend (and the controller
//! it talks to) hard-code root-absolute URLs — `/api/conversations`,
//! `<base>` is unset in vite.config.js, the SSE cookie is `Path=/api/...`
//! etc.  A path-prefix proxy would require patching Dyson in five
//! places.  Subdomains let each Dyson "own" an origin so its existing
//! root-absolute URLs Just Work.  This is also how Cube itself
//! organizes sandboxes (`<sandbox_id>.cube.app`), so warden becomes a
//! reverse proxy that matches that shape from the outside while
//! reaching the private network internally.
//!
//! Auth shape:
//! - inbound  the OIDC chain runs inline — we can't reuse the tenant
//!            tier's `user_middleware` because it stamps an Extension
//!            for downstream handlers, but here there are no downstream
//!            handlers, just the proxy.  Same `Authenticator` trait,
//!            different invocation point.
//! - outbound `Authorization: Bearer <instance.bearer_token>`; cookies
//!            and inbound auth headers are stripped (different security
//!            boundary).
//!
//! Streaming:
//! - Request body buffered (8 MiB cap).
//! - Response streamed unbuffered via axum::body::Body::from_stream +
//!   reqwest's bytes_stream so SSE / chunked / large downloads pipe
//!   through without sitting in memory.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::middleware::Next;
use futures::TryStreamExt;

use crate::auth::{user::resolve_active_user, Authenticator};
use crate::http::AppState;
use crate::traits::InstanceRow;

/// Bundle of state the host dispatcher needs in addition to AppState.
/// `hostname` is the suffix we strip to read the leading subdomain;
/// when `None`, the dispatcher is a pass-through.
#[derive(Clone)]
pub struct DispatchState {
    pub app: AppState,
    pub authenticator: Arc<dyn Authenticator>,
    pub hostname: Option<String>,
}

impl DispatchState {
    pub fn new(app: AppState, authenticator: Arc<dyn Authenticator>, hostname: Option<String>) -> Self {
        Self { app, authenticator, hostname }
    }
}

/// Outer middleware applied around the entire warden router.  Inspects
/// the Host header; if it's a sandbox subdomain, authenticates +
/// forwards.  Otherwise hands the request to `next`.
pub async fn dispatch(
    axum::extract::State(state): axum::extract::State<DispatchState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let Some(base) = state.hostname.as_deref() else {
        return next.run(req).await;
    };
    let host = match req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => return next.run(req).await,
    };
    let Some(instance_id) = extract_instance_subdomain(host, base) else {
        return next.run(req).await;
    };
    forward(state, instance_id.to_string(), req).await
}

/// Pure parser — exposed for tests.  Returns the instance id slice from
/// `Host: <id>.<base>[:port]` when there's exactly one label in front
/// of the configured base.  Multi-label prefixes (`a.b.<base>`) and
/// the bare base host (`<base>`) both return `None`.
pub fn extract_instance_subdomain<'a>(host: &'a str, base: &str) -> Option<&'a str> {
    let host_no_port = host.split(':').next().unwrap_or("");
    // Match the suffix `.{base}` exactly.  A bare `host == base` must
    // not match — that's warden's own UI, not a sandbox.
    let suffix_len = base.len() + 1;
    if host_no_port.len() <= suffix_len {
        return None;
    }
    if !host_no_port.ends_with(base) {
        return None;
    }
    let dot_idx = host_no_port.len() - suffix_len;
    if !host_no_port.as_bytes().get(dot_idx).is_some_and(|&b| b == b'.') {
        return None;
    }
    let prefix = &host_no_port[..dot_idx];
    if prefix.is_empty() || prefix.contains('.') {
        return None;
    }
    Some(prefix)
}

async fn forward(state: DispatchState, instance_id: String, req: Request) -> Response<Body> {
    // 1. Authenticate inline.  We can't use `user_middleware` here
    //    because that variant stamps an Extension and calls next; this
    //    handler IS the terminal handler.  resolve_active_user shares
    //    its plumbing with user_middleware — JIT-create on first
    //    sighting, refuse non-Active accounts.
    let caller_user_id = match resolve_active_user(
        state.authenticator.as_ref(),
        state.app.users.as_ref(),
        req.headers(),
    )
    .await
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // 2. Owner-check.
    let row: InstanceRow = match state.app.instances.get(&caller_user_id, &instance_id).await {
        Ok(r) => r,
        Err(crate::error::WardenError::NotFound) => {
            return error_response(StatusCode::NOT_FOUND, "no such instance");
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance lookup failed");
        }
    };
    let sandbox_id = match row.cube_sandbox_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return error_response(StatusCode::SERVICE_UNAVAILABLE, "sandbox not yet ready"),
    };

    // 3. Build upstream URL.  No path manipulation needed — host-based
    //    routing means the request path IS the path the sandbox sees.
    //    CubeProxy expects the e2b-style hostname `<port>-<sandbox_id>.<domain>`
    //    so the leading port label tells nginx which container port to
    //    map to. Dyson always listens on 80 inside its VM, matching the
    //    template's `--expose-port 80 --probe 80`.
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let path_with_query = match parts.uri.query() {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    };
    let cube_port = std::env::var("WARDEN_CUBE_INTERNAL_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(80);
    let upstream_url = format!(
        "https://{}-{}.{}{}",
        cube_port,
        sandbox_id,
        state.app.sandbox_domain.trim_end_matches('/'),
        path_with_query
    );

    // 4. Body (8 MiB cap, mirrors the LLM proxy).
    let body_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request body too large"),
    };

    // 5. Outbound headers: strip hop-by-hop + cookie + host + the
    //    inbound Authorization (warden's OIDC bearer, useless to
    //    Dyson), then stamp the per-instance bearer.
    let mut out_headers = HeaderMap::new();
    for (k, v) in parts.headers.iter() {
        if is_hop_by_hop(k) || k == header::COOKIE || k == header::HOST || k == header::AUTHORIZATION {
            continue;
        }
        out_headers.insert(k.clone(), v.clone());
    }
    let bearer = format!("Bearer {}", row.bearer_token);
    if let Ok(v) = HeaderValue::from_str(&bearer) {
        out_headers.insert(header::AUTHORIZATION, v);
    }

    // 6. Send.
    let mut req_builder = state.app.dyson_http.request(method, &upstream_url);
    for (k, v) in out_headers.iter() {
        req_builder = req_builder.header(k.as_str(), v);
    }
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }
    let upstream_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, instance = %instance_id, "dyson proxy upstream error");
            return error_response(StatusCode::BAD_GATEWAY, "upstream unreachable");
        }
    };

    // 7. Stream response back.
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let stream = upstream_resp
        .bytes_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        for (k, v) in resp_headers.iter() {
            if is_hop_by_hop(k) {
                continue;
            }
            h.insert(k.clone(), v.clone());
        }
    }
    builder.body(Body::from_stream(stream)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("response build failed"))
            .unwrap()
    })
}

fn error_response(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
    )
}

/// Build the shared reqwest::Client used by the dyson proxy.
///
/// CubeSandbox's cubeproxy serves `*.cube.app` with TLS issued by a
/// per-host mkcert root that isn't in reqwest's webpki bundle. Set
/// `WARDEN_CUBE_ROOT_CA` to the absolute path of that PEM (the
/// installer drops it at `/etc/dyson-warden/cube-root-ca.pem`) and
/// the proxy will trust it as an additional root. Verification stays
/// on; the only thing changing is which CAs the client treats as
/// authoritative for cubeproxy's hostnames.
pub fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(30 * 60))
        .pool_idle_timeout(Duration::from_secs(60));
    if let Ok(path) = std::env::var("WARDEN_CUBE_ROOT_CA")
        && !path.is_empty()
    {
        match std::fs::read(&path) {
            Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    tracing::info!(path = %path, "dyson_proxy: trusting cube root CA");
                    b = b.add_root_certificate(cert);
                }
                Err(e) => tracing::error!(path = %path, error = %e, "WARDEN_CUBE_ROOT_CA: failed to parse PEM"),
            },
            Err(e) => tracing::error!(path = %path, error = %e, "WARDEN_CUBE_ROOT_CA: failed to read"),
        }
    }
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_subdomain_happy_path() {
        assert_eq!(
            extract_instance_subdomain("abc123.warden.example.com", "warden.example.com"),
            Some("abc123"),
        );
    }

    #[test]
    fn extract_subdomain_strips_port() {
        assert_eq!(
            extract_instance_subdomain("abc123.warden.example.com:8080", "warden.example.com"),
            Some("abc123"),
        );
    }

    #[test]
    fn bare_base_host_does_not_match() {
        // Browser hits warden's own UI on the apex hostname — not a
        // sandbox subdomain.
        assert!(extract_instance_subdomain("warden.example.com", "warden.example.com").is_none());
        assert!(extract_instance_subdomain("warden.example.com:8080", "warden.example.com").is_none());
    }

    #[test]
    fn multi_label_prefix_does_not_match() {
        // a.b.warden.example.com would mean a sandbox-of-a-sandbox; we
        // accept exactly one label in front.
        assert!(extract_instance_subdomain("a.b.warden.example.com", "warden.example.com").is_none());
    }

    #[test]
    fn unrelated_host_does_not_match() {
        assert!(extract_instance_subdomain("evil.com", "warden.example.com").is_none());
        // Substring-but-not-suffix attack.
        assert!(extract_instance_subdomain(
            "warden.example.com.evil.com",
            "warden.example.com",
        )
        .is_none());
    }

    #[test]
    fn empty_prefix_does_not_match() {
        // ".warden.example.com" — empty leading label.  `strip_suffix`
        // would otherwise return Some("") and we'd happily try to look
        // up an empty instance id.
        assert!(extract_instance_subdomain(".warden.example.com", "warden.example.com").is_none());
    }
}
