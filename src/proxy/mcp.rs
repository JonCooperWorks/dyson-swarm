//! MCP server proxy.
//!
//! Two router halves:
//! - [`router`] mounts `/mcp/:instance_id/:server_name` (per-instance bearer)
//!   and `/mcp/oauth/callback` (no auth, CSRF-gated by `state`).  Both live
//!   off the same [`McpService`] state and slot in next to the LLM proxy.
//! - [`user_router`] mounts `/v1/instances/:id/mcp/...` (user-session auth)
//!   for listing servers and starting an OAuth flow.  Slots into the
//!   tenant-auth Router in `http::router`.
//!
//! The agent only ever talks to the bearer-protected pass-through URL.
//! Real upstream URL + tokens stay encrypted in the user secret store
//! and are decrypted in-process per request.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{extract_bearer, CallerIdentity};
use crate::error::SwarmError;
use crate::instance::InstanceService;
use crate::mcp_servers::{
    self, AuthMetadata, DcrRequest, McpAuthSpec, McpOAuthTokens, McpServerEntry, McpServerSpec,
    OAuthFlowCache, PendingFlow,
};
use crate::secrets::UserSecretsService;
use crate::traits::{InstanceStore, TokenStore};

/// Wires the MCP routers.  Cheap to clone — every field is `Arc`.
#[derive(Clone)]
pub struct McpService {
    pub tokens: Arc<dyn TokenStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub user_secrets: Arc<UserSecretsService>,
    pub flows: OAuthFlowCache,
    pub http: reqwest::Client,
    /// Public origin of the swarm (e.g. `https://swarm.example.com`).
    /// Used to build the OAuth redirect URI that the upstream provider
    /// sees — must be reachable from the user's browser, which is why
    /// we route through swarm rather than the agent's loopback.
    pub public_origin: Option<String>,
    /// Instance service — owns the put/delete/sync_mcp helpers that
    /// rewrite user_secrets and push the new `mcp_servers` block to
    /// the running dyson.  None disables the management routes (the
    /// proxy + OAuth callback still work — they only need user_secrets).
    pub instance_svc: Option<Arc<InstanceService>>,
}

impl McpService {
    pub fn new(
        tokens: Arc<dyn TokenStore>,
        instances: Arc<dyn InstanceStore>,
        user_secrets: Arc<UserSecretsService>,
        public_origin: Option<String>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            tokens,
            instances,
            user_secrets,
            flows: OAuthFlowCache::new(),
            http: reqwest::Client::builder()
                .pool_idle_timeout(Some(std::time::Duration::from_secs(90)))
                .build()?,
            public_origin,
            instance_svc: None,
        })
    }

    /// Builder-style: plug the InstanceService in so the management
    /// routes (PUT / DELETE / disconnect) can rewrite user_secrets and
    /// push to the running dyson.
    pub fn with_instance_svc(mut self, svc: Arc<InstanceService>) -> Self {
        self.instance_svc = Some(svc);
        self
    }

    fn redirect_uri(&self) -> Option<String> {
        self.public_origin
            .as_deref()
            .map(|o| format!("{}/mcp/oauth/callback", o.trim_end_matches('/')))
    }
}

/// `/mcp/...` routes mounted alongside `/llm/...`.  No outer auth
/// middleware — each handler enforces its own.
pub fn router(svc: Arc<McpService>) -> Router {
    Router::new()
        .route("/mcp/oauth/callback", get(oauth_callback))
        .route("/mcp/:instance_id/:server_name", post(forward))
        .with_state(svc)
}

/// `/v1/instances/:id/mcp/...` routes — mounted into the tenant-auth
/// Router so `CallerIdentity` is already on the request extensions.
pub fn user_router(svc: Arc<McpService>) -> Router {
    Router::new()
        .route("/v1/instances/:id/mcp/servers", get(list_servers))
        .route("/v1/instances/:id/mcp/servers/:name", put(put_server))
        .route("/v1/instances/:id/mcp/servers/:name", delete(delete_server))
        .route(
            "/v1/instances/:id/mcp/servers/:name/disconnect",
            post(disconnect_server),
        )
        .route("/v1/instances/:id/mcp/oauth/start", post(oauth_start))
        .with_state(svc)
}

// ───────────────────────────────────────────────────────────────────
// JSON-RPC pass-through
// ───────────────────────────────────────────────────────────────────

async fn forward(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, server_name)): Path<(String, String)>,
    req: Request,
) -> Response<Body> {
    // 1. Authenticate the inbound bearer.  Same shape as the LLM proxy:
    //    a missing or wrong token gets a 401, and we never leak whether
    //    the row is missing vs revoked.
    let token = match extract_bearer(req.headers()) {
        Some(t) => t,
        None => return error_resp(StatusCode::UNAUTHORIZED, "missing bearer"),
    };
    let record = match svc.tokens.resolve(&token).await {
        Ok(Some(r)) if r.revoked_at.is_none() => r,
        Ok(_) => return error_resp(StatusCode::UNAUTHORIZED, "invalid bearer"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "token store error"),
    };
    // The bearer is bound to one instance — refuse cross-instance use.
    if record.instance_id != instance_id {
        return error_resp(StatusCode::FORBIDDEN, "instance mismatch");
    }
    let owner_id = match svc.instances.get(&instance_id).await {
        Ok(Some(row)) => row.owner_id,
        Ok(None) => return error_resp(StatusCode::UNAUTHORIZED, "instance gone"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "instance store error"),
    };

    // 2. Pull the server config out of user_secrets.  Decrypts in-process.
    let mut entry = match mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &server_name)
        .await
    {
        Ok(Some(e)) => e,
        Ok(None) => return error_resp(StatusCode::NOT_FOUND, "unknown mcp server"),
        Err(err) => {
            tracing::warn!(error = %err, instance = %instance_id, server = %server_name, "mcp: secret read failed");
            return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error");
        }
    };

    // 3. Refresh OAuth tokens if needed.  When the access token is past
    //    or near expiry, swap in a fresh pair using the refresh_token —
    //    the agent never sees the spin.
    if let Err(err) = ensure_fresh_oauth(&svc, &owner_id, &instance_id, &server_name, &mut entry).await {
        tracing::warn!(error = %err, "mcp: oauth refresh failed");
        return error_resp(StatusCode::BAD_GATEWAY, "oauth refresh failed");
    }

    // 4. Build the outbound request.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_resp(StatusCode::BAD_REQUEST, "body too large"),
    };

    let mut outbound = svc.http.post(&entry.url);
    // Pass through Content-Type and Accept verbatim so streamable HTTP
    // MCP servers see the SSE-or-JSON negotiation the agent intended.
    if let Some(ct) = parts.headers.get(axum::http::header::CONTENT_TYPE) {
        outbound = outbound.header(axum::http::header::CONTENT_TYPE, ct);
    }
    if let Some(acc) = parts.headers.get(axum::http::header::ACCEPT) {
        outbound = outbound.header(axum::http::header::ACCEPT, acc);
    }
    // Apply the upstream auth header.
    match &entry.auth {
        McpAuthSpec::None => {}
        McpAuthSpec::Bearer { token } => {
            outbound = outbound.bearer_auth(token);
        }
        McpAuthSpec::Oauth { .. } => match entry.oauth_tokens.as_ref() {
            Some(tk) => outbound = outbound.bearer_auth(&tk.access_token),
            None => return error_resp(StatusCode::PRECONDITION_REQUIRED, "oauth not authorised yet"),
        },
    }

    let resp = match outbound.body(body_bytes).send().await {
        Ok(r) => r,
        Err(err) => {
            // reqwest's Display includes the full URL (path + query)
            // in its error chain — and some MCP providers ship per-
            // tenant URLs with a token in the query string.  Scrub
            // to the domain before logging.
            tracing::warn!(
                error = %crate::mcp_servers::redact_reqwest_err(&err, &entry.url),
                server = %server_name,
                domain = %crate::mcp_servers::domain_of(&entry.url),
                "mcp: upstream send failed",
            );
            return error_resp(StatusCode::BAD_GATEWAY, "upstream unreachable");
        }
    };

    // 5. Stream the upstream response back to the agent.  Preserves the
    //    SSE envelope MCP streamable HTTP servers use.
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = Response::builder().status(status);
    let upstream_headers = resp.headers().clone();
    for (k, v) in upstream_headers.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    let stream = futures::TryStreamExt::map_err(resp.bytes_stream(), |e| {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    });
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| error_resp(StatusCode::INTERNAL_SERVER_ERROR, "build resp"))
}

async fn ensure_fresh_oauth(
    svc: &McpService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
    entry: &mut McpServerEntry,
) -> Result<(), String> {
    if !matches!(entry.auth, McpAuthSpec::Oauth { .. }) {
        return Ok(());
    }
    let needs = entry
        .oauth_tokens
        .as_ref()
        .map(|t| t.needs_refresh(crate::now_secs()))
        .unwrap_or(false);
    if !needs {
        return Ok(());
    }
    let tokens = entry.oauth_tokens.as_ref().ok_or("no tokens to refresh")?;
    let refresh = tokens
        .refresh_token
        .as_deref()
        .ok_or("token expired and no refresh_token available")?;
    let resp = mcp_servers::refresh_token(
        &tokens.token_url,
        refresh,
        &tokens.client_id,
        tokens.client_secret.as_deref(),
        &svc.http,
    )
    .await?;

    let now = crate::now_secs();
    let new_tokens = McpOAuthTokens {
        access_token: resp.access_token,
        // Refresh response may omit refresh_token (RFC 6749) — keep prior.
        refresh_token: resp.refresh_token.or_else(|| tokens.refresh_token.clone()),
        expires_at: resp.expires_in.map(|s| now + i64::try_from(s).unwrap_or(0)),
        token_url: tokens.token_url.clone(),
        client_id: tokens.client_id.clone(),
        client_secret: tokens.client_secret.clone(),
    };
    entry.oauth_tokens = Some(new_tokens);
    mcp_servers::put(&svc.user_secrets, owner_id, instance_id, server_name, entry)
        .await
        .map_err(|e| format!("persist refreshed tokens: {e}"))?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// User-side OAuth start
// ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OAuthStartBody {
    server_name: String,
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Serialize)]
struct OAuthStartResponse {
    authorization_url: String,
}

async fn oauth_start(
    State(svc): State<Arc<McpService>>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<OAuthStartBody>,
) -> Result<Json<OAuthStartResponse>, Response<Body>> {
    let _ = headers;
    let owner_id = caller.user_id.clone();
    if !owner_owns_instance(&svc, &owner_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let entry = mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &body.server_name)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mcp: oauth_start secret read failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
        })?
        .ok_or_else(|| error_resp(StatusCode::NOT_FOUND, "unknown mcp server"))?;
    let (scopes, client_id_in, client_secret_in, auth_url_override, token_url_override, registration_url_override) =
        match &entry.auth {
            McpAuthSpec::Oauth {
                scopes,
                client_id,
                client_secret,
                authorization_url,
                token_url,
                registration_url,
            } => (
                scopes.clone(),
                client_id.clone(),
                client_secret.clone(),
                authorization_url.clone(),
                token_url.clone(),
                registration_url.clone(),
            ),
            _ => return Err(error_resp(StatusCode::BAD_REQUEST, "server is not oauth-configured")),
        };

    let redirect_uri = svc
        .redirect_uri()
        .ok_or_else(|| error_resp(StatusCode::SERVICE_UNAVAILABLE, "swarm hostname not configured"))?;

    // Resolve metadata: caller-supplied URLs win; otherwise discover.
    let metadata = match (auth_url_override.as_ref(), token_url_override.as_ref()) {
        (Some(a), Some(t)) => AuthMetadata {
            authorization_endpoint: a.clone(),
            token_endpoint: t.clone(),
            registration_endpoint: registration_url_override.clone(),
        },
        _ => mcp_servers::discover_metadata(&entry.url, &svc.http).await.map_err(|e| {
            tracing::warn!(error = %e, "mcp: discovery failed");
            error_resp(StatusCode::BAD_GATEWAY, "oauth discovery failed")
        })?,
    };

    // DCR if no client_id was provided.
    let (client_id, client_secret) = match client_id_in {
        Some(id) => (id, client_secret_in),
        None => {
            let reg_url = metadata
                .registration_endpoint
                .clone()
                .or(registration_url_override)
                .ok_or_else(|| error_resp(StatusCode::BAD_REQUEST, "no client_id and no registration endpoint"))?;
            let dcr = mcp_servers::register_client(
                &reg_url,
                &DcrRequest {
                    client_name: "dyson-swarm".into(),
                    redirect_uris: vec![redirect_uri.clone()],
                    grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                    response_types: vec!["code".into()],
                    token_endpoint_auth_method: None,
                },
                &svc.http,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "mcp: DCR failed");
                error_resp(StatusCode::BAD_GATEWAY, "dynamic client registration failed")
            })?;
            (dcr.client_id, dcr.client_secret)
        }
    };

    let pkce = mcp_servers::generate_pkce();
    let state = mcp_servers::generate_state();
    let auth_url = mcp_servers::build_auth_url(
        &metadata.authorization_endpoint,
        &client_id,
        &scopes,
        &redirect_uri,
        &pkce.challenge,
        &state,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "mcp: build_auth_url failed");
        error_resp(StatusCode::BAD_REQUEST, "bad authorization endpoint")
    })?;

    svc.flows.insert(
        state,
        PendingFlow {
            owner_id,
            instance_id,
            server_name: body.server_name,
            pkce_verifier: pkce.verifier,
            redirect_uri,
            token_url: metadata.token_endpoint,
            client_id,
            client_secret,
            // 5-minute window — same envelope dyson uses.
            expires_at: crate::now_secs() + 300,
            return_to: body.return_to,
        },
    );

    Ok(Json(OAuthStartResponse {
        authorization_url: auth_url,
    }))
}

// ───────────────────────────────────────────────────────────────────
// OAuth callback — public, CSRF-gated by `state`.
// ───────────────────────────────────────────────────────────────────

async fn oauth_callback(
    State(svc): State<Arc<McpService>>,
    uri: Uri,
) -> Response<Body> {
    let q = parse_query_string(uri.query().unwrap_or(""));
    if let Some(err) = q.get("error") {
        let detail = q.get("error_description").map(String::as_str).unwrap_or_default();
        return callback_html(
            StatusCode::BAD_REQUEST,
            &format!("OAuth provider returned error: {err} {detail}"),
        );
    }
    let Some(state) = q.get("state").cloned() else {
        return callback_html(StatusCode::BAD_REQUEST, "missing state");
    };
    let Some(code) = q.get("code").cloned() else {
        return callback_html(StatusCode::BAD_REQUEST, "missing code");
    };
    let Some(flow) = svc.flows.take(&state) else {
        return callback_html(StatusCode::BAD_REQUEST, "unknown or expired state");
    };

    let token_resp = match mcp_servers::exchange_code(
        &flow.token_url,
        &code,
        &flow.pkce_verifier,
        &flow.client_id,
        flow.client_secret.as_deref(),
        &flow.redirect_uri,
        &svc.http,
    )
    .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "mcp: token exchange failed");
            return callback_html(StatusCode::BAD_GATEWAY, "token exchange failed");
        }
    };

    // Persist tokens onto the existing entry.
    let mut entry = match mcp_servers::get(
        &svc.user_secrets,
        &flow.owner_id,
        &flow.instance_id,
        &flow.server_name,
    )
    .await
    {
        Ok(Some(e)) => e,
        Ok(None) => return callback_html(StatusCode::NOT_FOUND, "server entry vanished"),
        Err(err) => {
            tracing::warn!(error = %err, "mcp: callback secret read failed");
            return callback_html(StatusCode::INTERNAL_SERVER_ERROR, "secret store error");
        }
    };
    let now = crate::now_secs();
    entry.oauth_tokens = Some(McpOAuthTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at: token_resp
            .expires_in
            .map(|s| now + i64::try_from(s).unwrap_or(0)),
        token_url: flow.token_url,
        client_id: flow.client_id,
        client_secret: flow.client_secret,
    });
    if let Err(err) = mcp_servers::put(
        &svc.user_secrets,
        &flow.owner_id,
        &flow.instance_id,
        &flow.server_name,
        &entry,
    )
    .await
    {
        tracing::warn!(error = %err, "mcp: callback secret write failed");
        return callback_html(StatusCode::INTERNAL_SERVER_ERROR, "persist tokens");
    }

    if let Some(loc) = flow.return_to.filter(|s| s.starts_with('/')) {
        return Redirect::to(&loc).into_response().map(|_| Body::empty());
    }
    callback_html(StatusCode::OK, "Connected. You can close this tab.")
}

fn callback_html(status: StatusCode, msg: &str) -> Response<Body> {
    // Plain HTML so the user lands on something readable rather than
    // a JSON dump.  Minimal — the SPA owns the rich UI.
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>MCP OAuth</title>\
         <style>body{{font:14px/1.45 system-ui;margin:3em auto;max-width:38em;padding:0 1em;color:#222}}</style>\
         </head><body><h1>MCP OAuth</h1><p>{}</p></body></html>",
        html_escape(msg)
    );
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ───────────────────────────────────────────────────────────────────
// Listing — used by the SPA's instance detail page.
// ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ServerSummary {
    name: String,
    url: String,
    auth_kind: &'static str,
    /// True when an OAuth flow has completed — surfaced so the UI can
    /// render a "connect" vs. "reconnect" button.
    connected: bool,
}

async fn list_servers(
    State(svc): State<Arc<McpService>>,
    Path(instance_id): Path<String>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<Vec<ServerSummary>>, Response<Body>> {
    let owner_id = caller.user_id.clone();
    if !owner_owns_instance(&svc, &owner_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let names = mcp_servers::list_names(&svc.user_secrets, &owner_id, &instance_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mcp: list secret read failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
        })?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        if let Ok(Some(e)) = mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &name).await {
            let auth_kind: &'static str = match &e.auth {
                McpAuthSpec::None => "none",
                McpAuthSpec::Bearer { .. } => "bearer",
                McpAuthSpec::Oauth { .. } => "oauth",
            };
            let connected = matches!(&e.auth, McpAuthSpec::Oauth { .. }) && e.oauth_tokens.is_some()
                || matches!(&e.auth, McpAuthSpec::Bearer { .. } | McpAuthSpec::None);
            out.push(ServerSummary { name, url: e.url, auth_kind, connected });
        }
    }
    Ok(Json(out))
}

async fn owner_owns_instance(svc: &McpService, owner_id: &str, instance_id: &str) -> bool {
    matches!(
        svc.instances.get(instance_id).await,
        Ok(Some(row)) if row.owner_id == owner_id
    )
}

// ───────────────────────────────────────────────────────────────────
// Management routes (put / delete / disconnect)
// ───────────────────────────────────────────────────────────────────

/// PUT body: an `McpServerSpec` minus the `name` (the URL path carries
/// the name).  Same wire shape the hire form already uses, so the SPA
/// can reuse its serializer.
#[derive(Deserialize)]
struct PutServerBody {
    pub url: String,
    pub auth: McpAuthSpec,
}

async fn put_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<PutServerBody>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    let spec = McpServerSpec { name, url: body.url, auth: body.auth };
    isvc.put_mcp_server(&caller.user_id, &instance_id, spec)
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    isvc.delete_mcp_server(&caller.user_id, &instance_id, &name)
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn disconnect_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    isvc.disconnect_mcp_oauth(&caller.user_id, &instance_id, &name)
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

fn swarm_err_to_resp(err: SwarmError) -> Response<Body> {
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

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

fn error_resp(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": msg }).to_string();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Tiny query-string parser — axum's `Query` extractor needs the
/// `query` feature, which the swarm doesn't enable.  Same shape as the
/// hand-rolled parser in `http::instances` (see `parse_query` there).
fn parse_query_string(s: &str) -> std::collections::HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    // OAuth providers percent-encode the `code` and `state` values.
    // Plus signs are valid space encodings in form-urlencoded query
    // strings (RFC 1866), so handle both shapes.
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxUserSecretStore;
    use crate::envelope::AgeCipherDirectory;

    async fn seeded_user_secrets() -> (tempfile::TempDir, Arc<UserSecretsService>) {
        let pool = open_in_memory().await.unwrap();
        // Seed a user row so the FK on user_secrets resolves.
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind("u1")
        .bind("u1")
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(SqlxUserSecretStore::new(pool));
        (tmp, Arc::new(UserSecretsService::new(store, dir)))
    }

    #[tokio::test]
    async fn oauth_flow_cache_round_trip() {
        let (_tmp, _svc) = seeded_user_secrets().await;
        let cache = OAuthFlowCache::new();
        cache.insert(
            "s".into(),
            PendingFlow {
                owner_id: "u1".into(),
                instance_id: "i".into(),
                server_name: "srv".into(),
                pkce_verifier: "v".into(),
                redirect_uri: "https://swarm/mcp/oauth/callback".into(),
                token_url: "https://up/token".into(),
                client_id: "c".into(),
                client_secret: None,
                expires_at: i64::MAX,
                return_to: None,
            },
        );
        let f = cache.take("s").unwrap();
        assert_eq!(f.client_id, "c");
        assert!(cache.take("s").is_none());
    }

    #[test]
    fn html_escape_handles_specials() {
        assert_eq!(html_escape("<a>\"&"), "&lt;a&gt;&quot;&amp;");
    }

    #[test]
    fn hop_by_hop_filters_known_set() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
    }
}
