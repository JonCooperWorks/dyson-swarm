//! Host-based reverse proxy that fronts each Dyson sandbox.
//!
//! When swarm is configured with a `hostname` (e.g. `swarm.example.com`),
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
//! organizes sandboxes (`<sandbox_id>.cube.app`), so swarm becomes a
//! reverse proxy that matches that shape from the outside while
//! reaching the private network internally.
//!
//! Auth shape:
//!
//! - inbound: the OIDC chain runs inline — we can't reuse the tenant
//!   tier's `user_middleware` because it stamps an Extension for
//!   downstream handlers, but here there are no downstream handlers,
//!   just the proxy. Same `Authenticator` trait, different invocation
//!   point. Bearer source: `Authorization: Bearer ...` if present,
//!   otherwise the `dyson_swarm_session` cookie (the SPA mirrors the
//!   OIDC access token there with `Domain=<hostname>` so plain URL-bar
//!   navigation to a Dyson subdomain — open-in-new-tab, image src,
//!   anchor click — carries credentials. The cookie is `SameSite=Strict`
//!   and the dispatcher additionally enforces `Origin`/`Referer` on
//!   non-GET methods (post-F2 hardening); requests without a matching
//!   origin are rejected before reaching the cube.
//! - outbound: `Authorization: Bearer <instance.bearer_token>`;
//!   cookies and inbound auth headers are stripped (different security
//!   boundary).
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
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, header};
use axum::middleware::Next;
use futures::TryStreamExt;

use crate::auth::{Authenticator, user::resolve_active_user};
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
    pub fn new(
        app: AppState,
        authenticator: Arc<dyn Authenticator>,
        hostname: Option<String>,
    ) -> Self {
        Self {
            app,
            authenticator,
            hostname,
        }
    }
}

/// Outer middleware applied around the entire swarm router.  Inspects
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
    let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        return next.run(req).await;
    };
    let Some(instance_id) = extract_instance_subdomain(host, base) else {
        return next.run(req).await;
    };
    forward(state, instance_id, req).await
}

/// Pure parser — exposed for tests.  Returns the instance id slice from
/// `Host: <id>.<base>[:port]` when there's exactly one label in front
/// of the configured base.  Multi-label prefixes (`a.b.<base>`) and
/// the bare base host (`<base>`) both return `None`.
pub fn extract_instance_subdomain(host: &str, base: &str) -> Option<String> {
    let host_no_port = canonical_host(host);
    let base = canonical_host(base);
    // Match the suffix `.{base}` exactly.  A bare `host == base` must
    // not match — that's swarm's own UI, not a sandbox.
    let suffix_len = base.len() + 1;
    if host_no_port.len() <= suffix_len {
        return None;
    }
    if !host_no_port.ends_with(&base) {
        return None;
    }
    let dot_idx = host_no_port.len() - suffix_len;
    if host_no_port
        .as_bytes()
        .get(dot_idx)
        .is_none_or(|&b| b != b'.')
    {
        return None;
    }
    let prefix = &host_no_port[..dot_idx];
    if prefix.is_empty() || prefix.contains('.') {
        return None;
    }
    Some(prefix.to_string())
}

fn canonical_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

async fn forward(state: DispatchState, instance_id: String, req: Request) -> Response<Body> {
    // 0. CSRF defence-in-depth: reject non-GET requests whose Origin (or
    //    Referer fallback) doesn't match a swarm-controlled origin.
    //    The session cookie is `SameSite=Strict`, which already blocks
    //    cross-site state-changing requests in modern browsers — but
    //    older browsers, header-stripping middleboxes, and bugs in
    //    SameSite enforcement have all been observed in the wild.  An
    //    explicit server-side check on POST/PUT/PATCH/DELETE keeps the
    //    proxy honest regardless of browser behaviour.  GET / HEAD /
    //    OPTIONS skip the check (they're either non-state-changing or
    //    pre-flight).
    if !matches!(req.method().as_str(), "GET" | "HEAD" | "OPTIONS")
        && !origin_is_allowed(req.headers(), state.hostname.as_deref())
    {
        tracing::warn!(
            method = %req.method(),
            instance = %instance_id,
            origin = ?req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()),
            referer = ?req.headers().get(header::REFERER).and_then(|v| v.to_str().ok()),
            "dyson_proxy: cross-origin non-GET rejected"
        );
        return cross_origin_rejected();
    }

    // 1. Authenticate inline.  We can't use `user_middleware` here
    //    because that variant stamps an Extension and calls next; this
    //    handler IS the terminal handler.  resolve_active_user shares
    //    its plumbing with user_middleware — JIT-create on first
    //    sighting, refuse non-Active accounts.
    //
    //    Anonymous-probe carve-out: `/healthz` requests are forwarded
    //    without any auth or owner check so swarm's internal health
    //    prober can exercise the same end-to-end chain the user's
    //    browser does (Caddy → dispatch → cubeproxy → dyson) without
    //    needing a system credential.  /healthz returns just a tiny
    //    "ok"-ish payload; the only information leak is whether the
    //    sandbox is currently alive at this id, which is no worse
    //    than the wildcard cert already exposing the id's existence.
    //
    //    Otherwise: if the inbound request has no Authorization
    //    header but does carry a `dyson_swarm_session` cookie,
    //    synthesize the header from the cookie value before
    //    authenticating.  This is what makes the SPA's "open ↗"
    //    link work — a plain anchor click can't set Authorization
    //    but it ships cookies for the parent domain.
    let path = req.uri().path();
    let anonymous_probe = path == "/healthz";

    // 2. Look up the instance row.  Owner-scoped for normal user
    //    requests; system-scoped for the anonymous probe carve-out
    //    (which lacks a user identity to scope by).
    let row: InstanceRow = if anonymous_probe {
        match state.app.instances.get_unscoped(&instance_id).await {
            Ok(r) => r,
            Err(crate::error::SwarmError::NotFound) => {
                return error_response(StatusCode::NOT_FOUND, "no such instance");
            }
            Err(_) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance lookup failed");
            }
        }
    } else {
        let auth_headers = ensure_authorization_from_cookie(req.headers());
        let caller_user_id = match resolve_active_user(
            state.authenticator.as_ref(),
            state.app.users.as_ref(),
            &auth_headers,
        )
        .await
        {
            Ok(id) => id,
            Err(resp) => {
                // Browser top-level navigations (Accept: text/html on a
                // GET) get bounced to the apex login page with a
                // `return_to=<original URL>` query — once the SPA
                // exchanges its OIDC code, it parks the session cookie
                // on the parent domain and navigates back to this
                // subdomain.  Without this hop the user just sees a
                // bare 401 with no recovery path.  XHR / API callers
                // and non-GET verbs still get the original auth error
                // response (their callers handle 401 their own way and
                // following a 302 would silently swallow the
                // failure).
                if resp.status() == StatusCode::UNAUTHORIZED
                    && wants_login_redirect(req.method(), req.headers())
                    && let Some(redirect) =
                        build_login_redirect(state.hostname.as_deref(), req.headers(), req.uri())
                {
                    return redirect;
                }
                return resp;
            }
        };
        match state.app.instances.get(&caller_user_id, &instance_id).await {
            Ok(r) => r,
            Err(crate::error::SwarmError::NotFound) => {
                return error_response(StatusCode::NOT_FOUND, "no such instance");
            }
            Err(_) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance lookup failed");
            }
        }
    };
    let sandbox_id = match row.cube_sandbox_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return error_response(StatusCode::SERVICE_UNAVAILABLE, "sandbox not yet ready"),
    };

    // 2.5. Same-origin escape routes for swarm-side actions a sandbox
    //      SPA legitimately needs but can't trigger via cross-origin
    //      fetch (SameSite=Strict on the swarm session cookie blocks
    //      it; the access token only lives in the apex's
    //      sessionStorage).  We intercept BEFORE forwarding to the
    //      cube so the dyson SPA can call same-origin
    //      `<id>.<apex>/_swarm/share-mint` to mint anonymous artefact
    //      share URLs.  Limited surface — just the share-mint
    //      endpoint — extended carefully if more swarm flows ever
    //      need this shape.
    let req_path = req.uri().path();
    if req_path == "/_swarm/share-mint" && req.method() == axum::http::Method::POST {
        // anonymous_probe is the /healthz carve-out; it never has a
        // resolved user.  Reject share-mint there because the action
        // is user-attributed.
        let caller = if anonymous_probe {
            return error_response(StatusCode::UNAUTHORIZED, "auth required");
        } else {
            row.owner_id.clone()
        };
        return swarm_share_mint(&state, &caller, &instance_id, req).await;
    }

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
    let cube_port = std::env::var("SWARM_CUBE_INTERNAL_PORT")
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
    let Ok(body_bytes) = axum::body::to_bytes(body, 8 * 1024 * 1024).await else {
        return error_response(StatusCode::BAD_REQUEST, "request body too large");
    };

    // 5. Outbound headers: strip hop-by-hop + cookie + host + the
    //    inbound Authorization (swarm's OIDC bearer, useless to
    //    Dyson), then stamp the per-instance bearer.
    let mut out_headers = HeaderMap::new();
    for (k, v) in &parts.headers {
        if is_hop_by_hop(k)
            || k == header::COOKIE
            || k == header::HOST
            || k == header::AUTHORIZATION
        {
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
    for (k, v) in &out_headers {
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
        for (k, v) in &resp_headers {
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

fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Same-origin share-mint endpoint exposed at
/// `<id>.<apex>/_swarm/share-mint`.  Body shape mirrors the
/// authenticated `POST /v1/instances/:id/artefacts/:aid/shares`:
/// `{ artefact_id, chat_id, ttl, label? }`.  The user identity is
/// already resolved by `dyson_proxy::dispatch` (cookie or bearer →
/// CallerIdentity); we trust that and skip the regular OIDC layer.
async fn swarm_share_mint(
    state: &DispatchState,
    caller_user_id: &str,
    instance_id: &str,
    req: Request,
) -> Response<Body> {
    use crate::shares::ShareTtl;

    #[derive(serde::Deserialize)]
    struct Body0 {
        artefact_id: String,
        chat_id: String,
        ttl: String,
        #[serde(default)]
        label: Option<String>,
    }

    let (parts, body) = req.into_parts();
    if !origin_is_allowed(&parts.headers, state.hostname.as_deref()) {
        return cross_origin_rejected();
    }
    let bytes = match axum::body::to_bytes(body, 8 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "body too large"),
    };
    let parsed: Body0 = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad json"),
    };
    let Some(ttl) = ShareTtl::parse(&parsed.ttl) else {
        return error_response(StatusCode::BAD_REQUEST, "ttl must be 1d, 7d, or 30d");
    };
    if parsed.artefact_id.is_empty() || parsed.chat_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "artefact_id and chat_id required");
    }
    let label = parsed.label.filter(|s| !s.trim().is_empty());
    match state
        .app
        .shares
        .mint(
            caller_user_id,
            instance_id,
            &parsed.chat_id,
            &parsed.artefact_id,
            ttl,
            label,
        )
        .await
    {
        Ok(minted) => match serde_json::to_string(&minted) {
            Ok(s) => json_response(StatusCode::CREATED, &s),
            Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "encode failed"),
        },
        Err(crate::shares::service::ShareServiceError::NotFound) => {
            error_response(StatusCode::NOT_FOUND, "no such instance")
        }
        Err(crate::shares::service::ShareServiceError::BadRequest(m)) => {
            error_response(StatusCode::BAD_REQUEST, &m)
        }
        Err(e) => {
            tracing::warn!(instance = %instance_id, error = %e, "share-mint via _swarm escape route failed");
            error_response(StatusCode::BAD_GATEWAY, "mint failed")
        }
    }
}

/// 403 Forbidden with the canonical JSON shape the SPA's fetch layer
/// surfaces to the user — kept distinct from the plaintext bodies on
/// other proxy errors so a client can branch on `error == "cross-origin
/// request rejected"` without parsing free-form text.
fn cross_origin_rejected() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"cross-origin request rejected"}"#))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Returns true when the request's `Origin` header (preferred) or
/// `Referer` fallback parses to an HTTPS origin whose host is either
/// the swarm apex (`<base>`) or a single-label subdomain of it
/// (`<id>.<base>`).  Anything else — missing headers, non-HTTPS,
/// foreign host, multi-label prefix — is rejected.
///
/// `base` is the configured `hostname` (e.g. `swarm.example.com`).  When
/// `None`, the dispatcher is a pass-through and we never enter
/// `forward`; this function is unreachable in that case but defaults
/// to deny for safety.
fn origin_is_allowed(headers: &HeaderMap, base: Option<&str>) -> bool {
    let Some(base) = base else {
        return false;
    };
    // Origin first.  Per Fetch spec, `Origin` is sent on cross-origin
    // requests AND on same-origin non-GET, so it's reliable for our
    // purposes.  Referer is the fallback for older browsers / privacy
    // extensions that strip Origin but keep Referer; we accept it
    // because absence of both is unambiguous (= no browser provenance,
    // not a same-site request).
    let raw = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::REFERER).and_then(|v| v.to_str().ok()));
    let Some(raw) = raw else {
        return false;
    };
    origin_host_matches(raw, base)
}

/// Pure parser — exposed for tests.  Accepts an `Origin` or `Referer`
/// value and returns true if its scheme is `https` and its host is
/// `<base>` or `<one-label>.<base>` (matching the swarm apex or a
/// per-instance subdomain).  Port is permitted; userinfo / paths / queries
/// are tolerated on Referer values.
pub fn origin_host_matches(raw: &str, base: &str) -> bool {
    // Strip scheme.  Only HTTPS is allowed — Caddy redirects HTTP to
    // HTTPS so a legitimate browser never sends an http:// Origin to
    // swarm in production.
    if raw.len() < "https://".len() || !raw[..8].eq_ignore_ascii_case("https://") {
        return false;
    }
    let rest = &raw[8..];
    // Trim path/query/fragment if present (Referer carries them).
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo if present (`user:pw@host`).  Browsers don't emit
    // this on Origin, but Referer can carry whatever the page URL had.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = canonical_host(host_port);
    let base = canonical_host(base);
    if host.is_empty() {
        return false;
    }
    if host == base {
        return true;
    }
    // Same shape rule as `extract_instance_subdomain`: exactly one
    // label in front of `<base>`.
    let suffix_len = base.len() + 1;
    if host.len() <= suffix_len {
        return false;
    }
    if !host.ends_with(&base) {
        return false;
    }
    let dot_idx = host.len() - suffix_len;
    if host.as_bytes().get(dot_idx).is_none_or(|&b| b != b'.') {
        return false;
    }
    let prefix = &host[..dot_idx];
    !prefix.is_empty() && !prefix.contains('.')
}

/// If the inbound headers already carry `Authorization`, return them
/// as-is (cheaply — the caller borrows the result).  Otherwise, look
/// for a `dyson_swarm_session=<jwt>` cookie and, if found, return a
/// new `HeaderMap` with a stamped-in `Authorization: Bearer <jwt>`.
///
/// The cookie name is intentionally specific so it can't collide with
/// session cookies the upstream Dyson sets for itself.
fn ensure_authorization_from_cookie(inbound: &HeaderMap) -> HeaderMap {
    if inbound.get(header::AUTHORIZATION).is_some() {
        return inbound.clone();
    }
    let Some(token) = read_cookie(inbound, "dyson_swarm_session") else {
        return inbound.clone();
    };
    let mut out = inbound.clone();
    if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
        out.insert(header::AUTHORIZATION, v);
    }
    out
}

/// Read a single cookie value out of the `Cookie` header.  Returns the
/// first match; cookies are split on `; ` per RFC 6265.  Empty / missing
/// header yields `None`.
fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k == name
            && !v.is_empty()
        {
            return Some(v.to_owned());
        }
    }
    None
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
/// `SWARM_CUBE_ROOT_CA` to the absolute path of that PEM (the
/// installer drops it at `/etc/dyson-swarm/cube-root-ca.pem`) and
/// the proxy will trust it as an additional root. Verification stays
/// on; the only thing changing is which CAs the client treats as
/// authoritative for cubeproxy's hostnames.
pub fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    let mut b = reqwest::Client::builder()
        // This client is for host-side cubeproxy traffic only: the
        // reverse proxy, webhooks, and artefact fetches must not inherit
        // a host HTTP_PROXY/HTTPS_PROXY and loop through sandbox egress.
        .no_proxy()
        .timeout(Duration::from_secs(30 * 60))
        .pool_idle_timeout(Duration::from_secs(60));
    if let Ok(path) = std::env::var("SWARM_CUBE_ROOT_CA")
        && !path.is_empty()
    {
        match std::fs::read(&path) {
            Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    tracing::info!(path = %path, "dyson_proxy: trusting cube root CA");
                    b = b.add_root_certificate(cert);
                }
                Err(e) => {
                    tracing::error!(path = %path, error = %e, "SWARM_CUBE_ROOT_CA: failed to parse PEM")
                }
            },
            Err(e) => {
                tracing::error!(path = %path, error = %e, "SWARM_CUBE_ROOT_CA: failed to read")
            }
        }
    }
    b.build()
}

/// True when an unauthenticated request looks like a browser top-level
/// navigation (GET + `Accept: text/html`).  Anything else — XHR/fetch
/// from JS, sub-resource loads (`Accept: image/*`), HEAD/OPTIONS pre-flights,
/// state-changing verbs — keeps the bare 401 because a redirect would
/// either be silently followed (and confuse the caller) or drop a
/// pending payload.
fn wants_login_redirect(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET {
        return false;
    }
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept
        .split(',')
        .any(|m| m.trim().to_ascii_lowercase().starts_with("text/html"))
}

/// Build a `302 Found` to `https://<apex>/?return_to=<original URL>`.
///
/// `base` is the configured apex hostname; `None` disables the redirect
/// (the caller falls back to the original 401).  The original URL is
/// reconstructed from the `Host` header + request URI; we always emit
/// `https://` because the deployment is HTTPS-only via Caddy and an
/// `http://` return_to would be rejected by the SPA's validator anyway.
fn build_login_redirect(
    base: Option<&str>,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Option<Response<Body>> {
    let base = base?;
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok())?;
    // Defence-in-depth: only ever emit a return_to that matches the
    // configured base (the host MUST be a single-label subdomain of
    // `base`).  We're called from `forward()`, which already gated on
    // `extract_instance_subdomain`, so this is a tautology in
    // production — keeping it here means a refactor that exposes this
    // helper somewhere else can't accidentally redirect to an
    // attacker-controlled host.
    extract_instance_subdomain(host, base)?;
    let path_with_query = match uri.query() {
        Some(q) if !q.is_empty() => format!("{}?{}", uri.path(), q),
        _ => uri.path().to_owned(),
    };
    let target = format!("https://{host}{path_with_query}");
    let location = format!(
        "https://{}/?return_to={}",
        base,
        encode_query_value(&target)
    );
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        // Don't let intermediaries cache the bounce — credentials
        // change per request and a stale 302 in a CDN would pin every
        // user to the same return_to.
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .ok()
}

/// Minimal RFC 3986 percent-encoder for query values.  Escapes everything
/// that isn't an unreserved character (ALPHA / DIGIT / `-` / `.` / `_` /
/// `~`).  We keep it inline rather than pulling in `percent-encoding` —
/// the only call site is the login redirect Location header.
fn encode_query_value(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_subdomain_happy_path() {
        assert_eq!(
            extract_instance_subdomain("abc123.swarm.example.com", "swarm.example.com").as_deref(),
            Some("abc123"),
        );
    }

    #[test]
    fn extract_subdomain_strips_port() {
        assert_eq!(
            extract_instance_subdomain("abc123.swarm.example.com:8080", "swarm.example.com")
                .as_deref(),
            Some("abc123"),
        );
    }

    #[test]
    fn extract_subdomain_canonicalizes_host_case_and_trailing_dot() {
        assert_eq!(
            extract_instance_subdomain("ABC123.SWARM.EXAMPLE.COM.:443", "swarm.example.com")
                .as_deref(),
            Some("abc123"),
        );
    }

    #[test]
    fn bare_base_host_does_not_match() {
        // Browser hits swarm's own UI on the apex hostname — not a
        // sandbox subdomain.
        assert!(extract_instance_subdomain("swarm.example.com", "swarm.example.com").is_none());
        assert!(
            extract_instance_subdomain("swarm.example.com:8080", "swarm.example.com").is_none()
        );
    }

    #[test]
    fn multi_label_prefix_does_not_match() {
        // a.b.swarm.example.com would mean a sandbox-of-a-sandbox; we
        // accept exactly one label in front.
        assert!(extract_instance_subdomain("a.b.swarm.example.com", "swarm.example.com").is_none());
    }

    #[test]
    fn unrelated_host_does_not_match() {
        assert!(extract_instance_subdomain("evil.com", "swarm.example.com").is_none());
        // Substring-but-not-suffix attack.
        assert!(
            extract_instance_subdomain("swarm.example.com.evil.com", "swarm.example.com",)
                .is_none()
        );
    }

    #[test]
    fn empty_prefix_does_not_match() {
        // ".swarm.example.com" — empty leading label.  `strip_suffix`
        // would otherwise return Some("") and we'd happily try to look
        // up an empty instance id.
        assert!(extract_instance_subdomain(".swarm.example.com", "swarm.example.com").is_none());
    }

    // ── Origin / Referer allowlist (CSRF defence-in-depth) ────────────

    #[test]
    fn origin_apex_matches() {
        assert!(origin_host_matches(
            "https://swarm.example.com",
            "swarm.example.com"
        ));
        assert!(origin_host_matches(
            "https://swarm.example.com:8443",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_subdomain_matches() {
        assert!(origin_host_matches(
            "https://abc123.swarm.example.com",
            "swarm.example.com"
        ));
        assert!(origin_host_matches(
            "https://abc123.swarm.example.com:8443",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_match_is_case_insensitive() {
        assert!(origin_host_matches(
            "HTTPS://ABC123.SWARM.EXAMPLE.COM:443/path",
            "swarm.example.com",
        ));
    }

    #[test]
    fn origin_referer_with_path_matches() {
        // Referer carries a full URL; the path/query must not fool us.
        assert!(origin_host_matches(
            "https://abc123.swarm.example.com/some/path?x=1",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_http_scheme_rejected() {
        assert!(!origin_host_matches(
            "http://swarm.example.com",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_foreign_host_rejected() {
        assert!(!origin_host_matches(
            "https://evil.com",
            "swarm.example.com"
        ));
        // Substring-but-not-suffix attack.
        assert!(!origin_host_matches(
            "https://swarm.example.com.evil.com",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_multi_label_prefix_rejected() {
        assert!(!origin_host_matches(
            "https://a.b.swarm.example.com",
            "swarm.example.com"
        ));
    }

    #[test]
    fn origin_missing_headers_denied() {
        let h = HeaderMap::new();
        assert!(!origin_is_allowed(&h, Some("swarm.example.com")));
    }

    #[test]
    fn origin_falls_back_to_referer() {
        let mut h = HeaderMap::new();
        h.insert(
            header::REFERER,
            HeaderValue::from_static("https://abc.swarm.example.com/foo"),
        );
        assert!(origin_is_allowed(&h, Some("swarm.example.com")));
    }

    #[test]
    fn origin_is_allowed_prefers_origin_header() {
        // Origin is foreign, Referer is local.  We must use Origin and
        // reject — a browser only emits Origin when it's authoritative
        // for the request's source.
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_static("https://evil.com"));
        h.insert(
            header::REFERER,
            HeaderValue::from_static("https://swarm.example.com/whatever"),
        );
        assert!(!origin_is_allowed(&h, Some("swarm.example.com")));
    }

    #[test]
    fn origin_no_base_configured_denied() {
        // Defence-in-depth: if forward() is somehow reached with no
        // configured hostname, deny rather than fail-open.
        let mut h = HeaderMap::new();
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://swarm.example.com"),
        );
        assert!(!origin_is_allowed(&h, None));
    }

    // ── Login-redirect on auth failure ────────────────────────────────

    #[test]
    fn wants_login_redirect_browser_get() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        assert!(wants_login_redirect(&Method::GET, &h));
    }

    #[test]
    fn wants_login_redirect_xhr_does_not() {
        // Fetch/XHR JSON callers — handled by the SPA's fetch wrapper,
        // which surfaces 401 to the UI.  A 302 here would be silently
        // followed and the JSON parse on the apex login HTML would
        // confusingly fail downstream.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!wants_login_redirect(&Method::GET, &h));
    }

    #[test]
    fn wants_login_redirect_subresource_does_not() {
        // <img src=...> sends `Accept: image/*,*/*` — never text/html.
        // Matching this pattern would break broken-image debugging by
        // returning HTML where an image is expected.
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("image/avif,image/webp,*/*"),
        );
        assert!(!wants_login_redirect(&Method::GET, &h));
    }

    #[test]
    fn wants_login_redirect_no_accept_does_not() {
        // curl with no Accept header — keep the 401 so script callers
        // see the auth failure rather than chasing a redirect.
        let h = HeaderMap::new();
        assert!(!wants_login_redirect(&Method::GET, &h));
    }

    #[test]
    fn wants_login_redirect_post_does_not() {
        // Top-level POSTs (e.g. form submissions) cannot survive a
        // redirect; the body would be lost.  Always 401 a non-GET so
        // the caller can re-submit after auth.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        assert!(!wants_login_redirect(&Method::POST, &h));
        assert!(!wants_login_redirect(&Method::PUT, &h));
        assert!(!wants_login_redirect(&Method::DELETE, &h));
    }

    #[test]
    fn encode_query_value_escapes_reserved() {
        // `:` and `/` and `?` are reserved in query values; the
        // unreserved set survives untouched.
        assert_eq!(encode_query_value("abc-._~"), "abc-._~");
        assert_eq!(
            encode_query_value("https://abc.swarm.example.com/foo?x=1"),
            "https%3A%2F%2Fabc.swarm.example.com%2Ffoo%3Fx%3D1",
        );
        assert_eq!(encode_query_value("a b"), "a%20b");
    }

    #[test]
    fn build_login_redirect_includes_full_target_url() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            HeaderValue::from_static("abc123.swarm.example.com"),
        );
        let uri: axum::http::Uri = "/foo/bar?x=1&y=hello%20world".parse().unwrap();
        let resp = build_login_redirect(Some("swarm.example.com"), &h, &uri).unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://swarm.example.com/?return_to="));
        assert!(loc.contains("https%3A%2F%2Fabc123.swarm.example.com%2Ffoo%2Fbar"));
        // Cache-Control: no-store keeps middleboxes from pinning every
        // user to the same return_to URL.
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap()),
            Some("no-store"),
        );
    }

    #[test]
    fn build_login_redirect_omits_target_query_when_empty() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            HeaderValue::from_static("abc.swarm.example.com"),
        );
        let uri: axum::http::Uri = "/".parse().unwrap();
        let resp = build_login_redirect(Some("swarm.example.com"), &h, &uri).unwrap();
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        // Encoded form of `https://abc.swarm.example.com/` (no `?`).
        assert!(
            loc.ends_with("return_to=https%3A%2F%2Fabc.swarm.example.com%2F"),
            "unexpected Location: {loc}"
        );
    }

    #[test]
    fn build_login_redirect_refuses_when_host_is_not_a_subdomain() {
        // Belt-and-braces: even though forward() only calls us after
        // extract_instance_subdomain has already matched, this helper
        // must independently reject a non-subdomain Host so a future
        // refactor can't accidentally bounce the browser to an
        // attacker-controlled return_to.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("evil.com"));
        let uri: axum::http::Uri = "/".parse().unwrap();
        assert!(build_login_redirect(Some("swarm.example.com"), &h, &uri).is_none());
    }

    #[test]
    fn build_login_redirect_requires_configured_hostname() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            HeaderValue::from_static("abc.swarm.example.com"),
        );
        let uri: axum::http::Uri = "/".parse().unwrap();
        assert!(build_login_redirect(None, &h, &uri).is_none());
    }
}
