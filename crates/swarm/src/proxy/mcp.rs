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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{CallerIdentity, extract_bearer};
use crate::error::StoreError;
use crate::instance::InstanceService;
use crate::mcp_servers::{
    self, AuthMetadata, DcrRequest, McpAuthSpec, McpOAuthTokens, McpRuntimeSpec, McpServerEntry,
    McpServerSpec, McpToolSummary, McpToolsCatalog, OAuthFlowCache, PendingFlow,
};
use crate::secrets::UserSecretsService;
use crate::traits::{
    InstanceStatus, InstanceStore, McpAuditEntry, McpAuditStore, McpDockerCatalogRow,
    McpDockerCatalogStore, TokenStore,
};
use crate::upstream_policy::OutboundUrlPolicy;
use dyson_swarm_core::http::ExternalHttpClient;

mod errors;
mod redaction;
mod runtime;
mod stream;
mod tools;

#[cfg(test)]
mod tests;

use errors::{error_resp, jsonrpc_error_resp, store_err_to_resp, swarm_err_to_resp};
use redaction::{html_escape, strip_url_query};
#[cfg(test)]
use runtime::RuntimeRequest;
use runtime::{
    MAX_RUNTIME_BODY_BYTES, call_runtime, forward_runtime_stdio, runtime_forward_request_for_entry,
    stop_deleted_runtime_server, stop_deleted_runtime_servers_best_effort,
};
pub use runtime::{
    RuntimeRestartReport, restart_active_runtime_servers, restart_runtime_server,
    stop_runtime_instance, stop_runtime_server,
};
use stream::{is_hop_by_hop, parse_sse_jsonrpc};
use tools::{filter_tools_list_body, peek_jsonrpc};

/// Wires the MCP routers.  Cheap to clone — every field is `Arc`.
#[derive(Clone)]
pub struct McpService {
    pub tokens: Arc<dyn TokenStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub user_secrets: Arc<UserSecretsService>,
    pub flows: OAuthFlowCache,
    pub external_http: Arc<ExternalHttpClient>,
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
    /// Unix socket for the dedicated Docker-backed stdio MCP runtime.
    /// When absent, remote HTTP/SSE MCP still works; container stdio
    /// entries return a clear 503.
    pub runtime_socket_path: Option<PathBuf>,
    /// Docker runtime name requested for Docker-backed stdio MCP
    /// containers. Config validation only permits `runsc`.
    pub docker_runtime: String,
    /// Operator-curated Docker stdio presets.  Users see a slim
    /// placeholder surface and read-only JSON preview instead of a
    /// free-form Docker command surface.
    pub docker_catalog: Vec<mcp_servers::McpDockerCatalogServer>,
    /// Whether raw Docker MCP JSON is accepted from user-session
    /// routes.  Trusted nodes can keep this on; public nodes can
    /// require catalog presets only.
    pub allow_user_docker_json: bool,
    /// DB-backed source of admin-managed Docker MCP presets.  When
    /// absent, the static config vector above is used as a fallback so
    /// small unit tests can construct the service without a pool.
    pub docker_catalog_store: Option<Arc<dyn McpDockerCatalogStore>>,
    /// Shared SSRF policy for remote HTTP/SSE MCP upstreams.  Docker
    /// runtime entries are local runtime requests and do not use this.
    pub mcp_upstream_policy: OutboundUrlPolicy,
    pub mcp_audit: Arc<dyn McpAuditStore>,
    rate: Arc<McpRateWindow>,
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
            external_http: Arc::new(ExternalHttpClient::new(Arc::new(
                OutboundUrlPolicy::default(),
            ))),
            public_origin,
            instance_svc: None,
            runtime_socket_path: None,
            docker_runtime: "runsc".to_owned(),
            docker_catalog: Vec::new(),
            allow_user_docker_json: false,
            docker_catalog_store: None,
            mcp_upstream_policy: OutboundUrlPolicy::default(),
            mcp_audit: Arc::new(crate::db::sqlite::audit::NoopMcpAuditStore),
            rate: Arc::new(McpRateWindow::default()),
        })
    }

    /// Builder-style: plug the InstanceService in so the management
    /// routes (PUT / DELETE / disconnect) can rewrite user_secrets and
    /// push to the running dyson.
    pub fn with_instance_svc(mut self, svc: Arc<InstanceService>) -> Self {
        self.instance_svc = Some(svc);
        self
    }

    pub fn with_runtime_socket(mut self, socket_path: Option<PathBuf>) -> Self {
        self.runtime_socket_path = socket_path;
        self
    }

    pub fn with_docker_runtime(mut self, runtime: impl Into<String>) -> Self {
        self.docker_runtime = runtime.into();
        self
    }

    pub fn with_docker_catalog(
        mut self,
        catalog: Vec<mcp_servers::McpDockerCatalogServer>,
        allow_user_docker_json: bool,
    ) -> Self {
        self.docker_catalog = catalog;
        self.allow_user_docker_json = allow_user_docker_json;
        self
    }

    pub fn with_docker_catalog_store(mut self, store: Arc<dyn McpDockerCatalogStore>) -> Self {
        self.docker_catalog_store = Some(store);
        self
    }

    pub fn with_mcp_upstream_policy(mut self, policy: OutboundUrlPolicy) -> Self {
        self.external_http = Arc::new(ExternalHttpClient::new(Arc::new(policy)));
        self.mcp_upstream_policy = policy;
        self
    }

    pub fn with_mcp_audit(mut self, audit: Arc<dyn McpAuditStore>) -> Self {
        self.mcp_audit = audit;
        self
    }

    fn redirect_uri(&self) -> Option<String> {
        self.public_origin
            .as_deref()
            .map(|o| format!("{}/mcp/oauth/callback", o.trim_end_matches('/')))
    }

    async fn docker_catalog_rows(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        if let Some(store) = &self.docker_catalog_store {
            return store.list_active().await;
        }
        Ok(self
            .docker_catalog
            .iter()
            .cloned()
            .map(|server| McpDockerCatalogRow {
                server,
                status: mcp_servers::McpDockerCatalogStatus::Active,
                source: "config".into(),
                requested_by_user_id: None,
                created_at: 0,
                updated_at: 0,
                deleted_at: None,
            })
            .collect())
    }

    async fn admin_docker_catalog_rows(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        if let Some(store) = &self.docker_catalog_store {
            return store.list().await;
        }
        Ok(self
            .docker_catalog
            .iter()
            .cloned()
            .map(|server| McpDockerCatalogRow {
                server,
                status: mcp_servers::McpDockerCatalogStatus::Active,
                source: "config".into(),
                requested_by_user_id: None,
                created_at: 0,
                updated_at: 0,
                deleted_at: None,
            })
            .collect())
    }

    async fn get_docker_catalog_server(
        &self,
        id: &str,
    ) -> Result<Option<mcp_servers::McpDockerCatalogServer>, StoreError> {
        if let Some(store) = &self.docker_catalog_store {
            return store
                .get_active(id)
                .await
                .map(|row| row.map(|row| row.server));
        }
        Ok(self
            .docker_catalog
            .iter()
            .find(|server| server.id == id)
            .cloned())
    }
}

const MCP_RPS_LIMIT: u32 = 20;

#[derive(Default)]
struct McpRateWindow {
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl McpRateWindow {
    fn observe(&self, owner_id: &str, server_name: &str) -> u32 {
        let mut buckets = self.buckets.lock().expect("mcp rate window poisoned");
        let key = format!("{owner_id}:{server_name}");
        let q = buckets.entry(key).or_default();
        let now = Instant::now();
        q.push_back(now);
        prune_mcp_rate(q, now);
        u32::try_from(q.len()).unwrap_or(u32::MAX)
    }
}

fn prune_mcp_rate(q: &mut VecDeque<Instant>, now: Instant) {
    let cutoff = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
    while let Some(front) = q.front() {
        if *front < cutoff {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn duration_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

fn tools_call_name(
    peek: Option<&(String, serde_json::Value, serde_json::Value)>,
) -> Option<String> {
    match peek {
        Some((method, _, params)) if method == "tools/call" => params
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        _ => None,
    }
}

async fn begin_mcp_audit(
    svc: &McpService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
    tool: Option<String>,
) -> Result<i64, Response<Body>> {
    svc.mcp_audit
        .insert(&McpAuditEntry {
            owner_id: owner_id.to_owned(),
            instance_id: instance_id.to_owned(),
            server_name: server_name.to_owned(),
            tool,
            status: 0,
            duration_ms: 0,
            ts: crate::now_secs(),
            completed: false,
        })
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "mcp_audit insert failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "audit store error")
        })
}

async fn finish_mcp_audit(svc: &McpService, audit_id: i64, started: Instant, status: StatusCode) {
    if let Err(err) = svc
        .mcp_audit
        .update_status(audit_id, i64::from(status.as_u16()), duration_ms(started))
        .await
    {
        tracing::warn!(error = %err, audit_id, "mcp_audit completion update failed");
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
        .route("/v1/mcp/docker-catalog", get(list_docker_catalog))
        .route(
            "/v1/mcp/docker-catalog/requests/:catalog_id",
            axum::routing::put(request_docker_catalog_server),
        )
        .route("/v1/instances/:id/mcp/servers", get(list_servers))
        .route(
            "/v1/instances/:id/mcp/docker-catalog/:catalog_id",
            axum::routing::put(put_docker_catalog_server),
        )
        .route(
            "/v1/instances/:id/mcp/config",
            get(get_vscode_config)
                .put(put_vscode_config)
                .delete(delete_vscode_config),
        )
        .route(
            "/v1/instances/:id/mcp/servers/:name",
            get(get_server).put(put_server).delete(delete_server),
        )
        .route(
            "/v1/instances/:id/mcp/servers/:name/disconnect",
            post(disconnect_server),
        )
        .route(
            "/v1/instances/:id/mcp/servers/:name/check",
            post(check_server),
        )
        .route(
            "/v1/instances/:id/mcp/servers/:name/enabled-tools",
            axum::routing::put(put_enabled_tools),
        )
        .route("/v1/instances/:id/mcp/oauth/start", post(oauth_start))
        .with_state(svc)
}

/// `/v1/admin/mcp/...` routes — mounted into the admin-only router.
pub fn admin_router(svc: Arc<McpService>) -> Router {
    Router::new()
        .route(
            "/v1/admin/mcp/docker-catalog",
            get(admin_list_docker_catalog),
        )
        .route(
            "/v1/admin/mcp/docker-catalog/:catalog_id",
            axum::routing::put(admin_put_docker_catalog_server)
                .delete(admin_delete_docker_catalog_server),
        )
        .with_state(svc)
}

async fn pinned_remote_mcp_client(
    svc: &McpService,
    entry: &McpServerEntry,
) -> Result<reqwest::Client, String> {
    external_mcp_client_for_url(svc, &entry.url)
        .await
        .map(|(client, _)| client)
}

async fn validate_remote_mcp_url(svc: &McpService, url: &str) -> Result<(), String> {
    external_mcp_client_for_url(svc, url)
        .await
        .map(|_| ())
        .map_err(|e| format!("mcp upstream URL rejected: {e}"))
}

async fn external_mcp_client_for_url(
    svc: &McpService,
    url: &str,
) -> Result<(reqwest::Client, reqwest::Url), String> {
    svc.external_http
        .for_url(url)
        .await
        .map_err(|e| e.to_string())
}

async fn validate_remote_mcp_auth_urls(svc: &McpService, auth: &McpAuthSpec) -> Result<(), String> {
    let McpAuthSpec::Oauth {
        authorization_url,
        token_url,
        registration_url,
        ..
    } = auth
    else {
        return Ok(());
    };
    for url in [authorization_url, token_url, registration_url]
        .into_iter()
        .flatten()
        .filter(|url| !url.trim().is_empty())
    {
        validate_remote_mcp_url(svc, url).await?;
    }
    Ok(())
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
    let instance = match svc.instances.get(&instance_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_resp(StatusCode::UNAUTHORIZED, "instance gone"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "instance store error"),
    };
    if instance.status != InstanceStatus::Live {
        return error_resp(StatusCode::FORBIDDEN, "instance is not live");
    }
    let owner_id = instance.owner_id;

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
    if let Err(err) =
        ensure_fresh_oauth(&svc, &owner_id, &instance_id, &server_name, &mut entry).await
    {
        tracing::warn!(error = %err, "mcp: oauth refresh failed");
        return error_resp(StatusCode::BAD_GATEWAY, "oauth refresh failed");
    }

    // 4. Build the outbound request.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_RUNTIME_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return error_resp(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
    };

    // Peek at the JSON-RPC envelope so we can enforce the per-tool
    // allowlist (`entry.enabled_tools`).  We only look — the body
    // forwarded upstream is unchanged.  Batched JSON-RPC arrays and
    // unparseable bodies skip filtering entirely (passes through).
    let peek = peek_jsonrpc(&body_bytes);
    let audit_started = Instant::now();
    let audit_id = match begin_mcp_audit(
        &svc,
        &owner_id,
        &instance_id,
        &server_name,
        tools_call_name(peek.as_ref()),
    )
    .await
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if svc.rate.observe(&owner_id, &server_name) > MCP_RPS_LIMIT {
        let status = StatusCode::TOO_MANY_REQUESTS;
        finish_mcp_audit(&svc, audit_id, audit_started, status).await;
        return error_resp(status, "mcp rate limit exceeded");
    }

    // Gate: when the call is `tools/call` for a name the admin has
    // disabled, refuse without forwarding.  Returns a JSON-RPC error
    // envelope so the agent's MCP client surfaces the failure cleanly.
    if let (Some(allowed), Some((method, id, params))) =
        (entry.enabled_tools.as_deref(), peek.as_ref())
    {
        if method == "tools/call" {
            if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                if !allowed.iter().any(|t| t == name) {
                    let resp = jsonrpc_error_resp(
                        id.clone(),
                        -32601,
                        &format!("tool '{name}' is disabled by admin"),
                    );
                    finish_mcp_audit(&svc, audit_id, audit_started, resp.status()).await;
                    return resp;
                }
            }
        }
    }

    if entry.runtime.is_some() {
        let resp = forward_runtime_stdio(
            &svc,
            &instance_id,
            &server_name,
            &entry,
            &body_bytes,
            peek.as_ref(),
        )
        .await;
        finish_mcp_audit(&svc, audit_id, audit_started, resp.status()).await;
        return resp;
    }

    if let Err(err) = validate_remote_mcp_auth_urls(&svc, &entry.auth).await {
        tracing::warn!(error = %err, server = %server_name, "mcp: auth URL rejected");
        let status = StatusCode::FORBIDDEN;
        finish_mcp_audit(&svc, audit_id, audit_started, status).await;
        return error_resp(status, "mcp upstream not allowed");
    }
    let pinned_http = match pinned_remote_mcp_client(&svc, &entry).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(error = %err, server = %server_name, "mcp: upstream rejected");
            let status = StatusCode::FORBIDDEN;
            finish_mcp_audit(&svc, audit_id, audit_started, status).await;
            return error_resp(status, "mcp upstream not allowed");
        }
    };

    let mut outbound = pinned_http.post(&entry.url);
    // Pass through Content-Type and Accept verbatim so streamable HTTP
    // MCP servers see the SSE-or-JSON negotiation the agent intended.
    if let Some(ct) = parts.headers.get(axum::http::header::CONTENT_TYPE) {
        outbound = outbound.header(axum::http::header::CONTENT_TYPE, ct);
    }
    if let Some(acc) = parts.headers.get(axum::http::header::ACCEPT) {
        outbound = outbound.header(axum::http::header::ACCEPT, acc);
    }
    // Apply extra VS Code-style headers, then the legacy auth shape.
    outbound = match apply_entry_headers_and_auth(outbound, &entry) {
        Ok(req) => req,
        Err(msg) => {
            let status = StatusCode::PRECONDITION_REQUIRED;
            finish_mcp_audit(&svc, audit_id, audit_started, status).await;
            return error_resp(status, &msg);
        }
    };

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
            let status = StatusCode::BAD_GATEWAY;
            finish_mcp_audit(&svc, audit_id, audit_started, status).await;
            return error_resp(status, "upstream unreachable");
        }
    };

    // 5. Stream the upstream response back to the agent.  Preserves the
    //    SSE envelope MCP streamable HTTP servers use.
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let upstream_headers = resp.headers().clone();
    let upstream_ct = upstream_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Filter: when the call is `tools/list` and the admin has narrowed
    // the allowlist, parse the JSON response and drop any tools not in
    // the set so the agent never sees them.  Only the JSON content type
    // is filtered — `text/event-stream` responses pass through (the
    // tools/call gate above still rejects calls to dropped tools, so
    // SSE-flavoured tools/list responses are a UX concession, not a
    // security gap).
    let should_filter_list = matches!(peek.as_ref(), Some((m, _, _)) if m == "tools/list")
        && entry.enabled_tools.is_some()
        && upstream_ct.starts_with("application/json")
        && status.is_success();

    if should_filter_list {
        let body_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = %err, "mcp: tools/list response read failed");
                let status = StatusCode::BAD_GATEWAY;
                finish_mcp_audit(&svc, audit_id, audit_started, status).await;
                return error_resp(status, "upstream read failed");
            }
        };
        let allowed = entry.enabled_tools.as_deref().unwrap_or(&[]);
        let filtered = match filter_tools_list_body(&body_bytes, allowed) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = %err, "mcp: tools/list filter failed; passing through");
                body_bytes.to_vec()
            }
        };

        let mut builder = Response::builder().status(status);
        for (k, v) in upstream_headers.iter() {
            if is_hop_by_hop(k.as_str()) || k == axum::http::header::CONTENT_LENGTH {
                continue;
            }
            builder = builder.header(k, v);
        }
        finish_mcp_audit(&svc, audit_id, audit_started, status).await;
        return builder
            .header(
                axum::http::header::CONTENT_LENGTH,
                HeaderValue::from(filtered.len()),
            )
            .body(Body::from(filtered))
            .unwrap_or_else(|_| error_resp(StatusCode::INTERNAL_SERVER_ERROR, "build resp"));
    }

    let mut builder = Response::builder().status(status);
    for (k, v) in upstream_headers.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    let stream = futures::TryStreamExt::map_err(resp.bytes_stream(), std::io::Error::other);
    finish_mcp_audit(&svc, audit_id, audit_started, status).await;
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
    let (http, token_url) = external_mcp_client_for_url(svc, &tokens.token_url)
        .await
        .map_err(|e| format!("mcp token URL rejected: {e}"))?;
    let resp = mcp_servers::refresh_token(
        token_url.as_str(),
        refresh,
        &tokens.client_id,
        tokens.client_secret.as_deref(),
        &http,
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
    let entry = mcp_servers::get(
        &svc.user_secrets,
        &owner_id,
        &instance_id,
        &body.server_name,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "mcp: oauth_start secret read failed");
        error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
    })?
    .ok_or_else(|| error_resp(StatusCode::NOT_FOUND, "unknown mcp server"))?;
    let (
        scopes,
        client_id_in,
        client_secret_in,
        auth_url_override,
        token_url_override,
        registration_url_override,
    ) = match &entry.auth {
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
        _ => {
            return Err(error_resp(
                StatusCode::BAD_REQUEST,
                "server is not oauth-configured",
            ));
        }
    };
    validate_remote_mcp_url(&svc, &entry.url).await.map_err(|err| {
        tracing::warn!(error = %err, server = %body.server_name, "mcp: oauth upstream rejected");
        error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed")
    })?;
    validate_remote_mcp_auth_urls(&svc, &entry.auth)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, server = %body.server_name, "mcp: oauth URL rejected");
            error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed")
        })?;

    let redirect_uri = svc.redirect_uri().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "swarm hostname not configured",
        )
    })?;

    // Resolve metadata: caller-supplied URLs win; otherwise discover.
    let metadata = match (auth_url_override.as_ref(), token_url_override.as_ref()) {
        (Some(a), Some(t)) => AuthMetadata {
            authorization_endpoint: a.clone(),
            token_endpoint: t.clone(),
            registration_endpoint: registration_url_override.clone(),
        },
        _ => {
            let (http, discovery_url) = external_mcp_client_for_url(&svc, &entry.url)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "mcp: discovery upstream rejected");
                    error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed")
                })?;
            mcp_servers::discover_metadata(discovery_url.as_str(), &http)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "mcp: discovery failed");
                    error_resp(StatusCode::BAD_GATEWAY, "oauth discovery failed")
                })?
        }
    };
    for url in [
        Some(&metadata.authorization_endpoint),
        Some(&metadata.token_endpoint),
        metadata.registration_endpoint.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_remote_mcp_url(&svc, url).await.map_err(|err| {
            tracing::warn!(error = %err, server = %body.server_name, "mcp: oauth metadata URL rejected");
            error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed")
        })?;
    }

    // DCR if no client_id was provided.
    let (client_id, client_secret) = match client_id_in {
        Some(id) => (id, client_secret_in),
        None => {
            let reg_url = metadata
                .registration_endpoint
                .clone()
                .or(registration_url_override)
                .ok_or_else(|| {
                    error_resp(
                        StatusCode::BAD_REQUEST,
                        "no client_id and no registration endpoint",
                    )
                })?;
            let (http, reg_url) =
                external_mcp_client_for_url(&svc, &reg_url)
                    .await
                    .map_err(|e| {
                        tracing::warn!(error = %e, "mcp: DCR upstream rejected");
                        error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed")
                    })?;
            let dcr = mcp_servers::register_client(
                reg_url.as_str(),
                &DcrRequest {
                    client_name: "dyson-swarm".into(),
                    redirect_uris: vec![redirect_uri.clone()],
                    grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                    response_types: vec!["code".into()],
                    token_endpoint_auth_method: None,
                    // Mirror requested scopes into DCR — strict ASes
                    // (Smithery) reject `authorize?scope=foo` when the
                    // client wasn't registered with that scope.
                    scope: if scopes.is_empty() {
                        None
                    } else {
                        Some(scopes.join(" "))
                    },
                },
                &http,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "mcp: DCR failed");
                error_resp(
                    StatusCode::BAD_GATEWAY,
                    "dynamic client registration failed",
                )
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

async fn oauth_callback(State(svc): State<Arc<McpService>>, uri: Uri) -> Response<Body> {
    let q = parse_query_string(uri.query().unwrap_or(""));
    if let Some(err) = q.get("error") {
        let detail = q
            .get("error_description")
            .map(String::as_str)
            .unwrap_or_default();
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
    let (http, token_url) = match external_mcp_client_for_url(&svc, &flow.token_url).await {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(error = %err, "mcp: callback token URL rejected");
            return callback_html(StatusCode::FORBIDDEN, "mcp upstream not allowed");
        }
    };

    let token_resp = match mcp_servers::exchange_code(
        token_url.as_str(),
        &code,
        &flow.pkce_verifier,
        &flow.client_id,
        flow.client_secret.as_deref(),
        &flow.redirect_uri,
        &http,
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

    if let Some(loc) = flow.return_to.as_deref().and_then(safe_local_return_path) {
        return Redirect::to(loc).into_response().map(|_| Body::empty());
    }
    callback_html(StatusCode::OK, "Connected. You can close this tab.")
}

fn safe_local_return_path(value: &str) -> Option<&str> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value)
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

#[derive(Serialize)]
struct DockerCatalogResponse {
    allow_raw_json: bool,
    servers: Vec<DockerCatalogServerSummary>,
}

#[derive(Serialize)]
struct DockerCatalogServerSummary {
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    template: String,
    placeholders: Vec<DockerCatalogPlaceholderSummary>,
}

#[derive(Serialize)]
struct DockerCatalogPlaceholderSummary {
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    required: bool,
    secret: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    placeholder: Option<String>,
}

async fn list_docker_catalog(
    State(svc): State<Arc<McpService>>,
) -> Result<Json<DockerCatalogResponse>, Response<Body>> {
    let rows = svc.docker_catalog_rows().await.map_err(store_err_to_resp)?;
    Ok(Json(DockerCatalogResponse {
        allow_raw_json: svc.allow_user_docker_json,
        servers: rows
            .iter()
            .map(|row| docker_catalog_summary(&row.server))
            .collect(),
    }))
}

#[derive(Serialize)]
struct AdminDockerCatalogResponse {
    allow_raw_json: bool,
    servers: Vec<AdminDockerCatalogServerSummary>,
}

#[derive(Serialize)]
struct AdminDockerCatalogServerSummary {
    #[serde(flatten)]
    server: DockerCatalogServerSummary,
    status: mcp_servers::McpDockerCatalogStatus,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_by_user_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Deserialize)]
struct AdminPutDockerCatalogBody {
    label: String,
    #[serde(default)]
    description: Option<String>,
    template: String,
    #[serde(default)]
    placeholders: Vec<mcp_servers::McpDockerPlaceholderSpec>,
}

async fn admin_list_docker_catalog(
    State(svc): State<Arc<McpService>>,
) -> Result<Json<AdminDockerCatalogResponse>, Response<Body>> {
    let rows = svc
        .admin_docker_catalog_rows()
        .await
        .map_err(store_err_to_resp)?;
    Ok(Json(AdminDockerCatalogResponse {
        allow_raw_json: svc.allow_user_docker_json,
        servers: rows.iter().map(admin_docker_catalog_summary).collect(),
    }))
}

async fn request_docker_catalog_server(
    State(svc): State<Arc<McpService>>,
    Path(catalog_id): Path<String>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<AdminPutDockerCatalogBody>,
) -> Result<Json<AdminDockerCatalogServerSummary>, Response<Body>> {
    let store = svc.docker_catalog_store.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp docker catalog store not configured",
        )
    })?;
    let server = mcp_servers::McpDockerCatalogServer {
        id: catalog_id,
        label: body.label,
        description: body.description,
        template: body.template,
        placeholders: body.placeholders,
    };
    mcp_servers::validate_docker_catalog_server(&server)
        .map_err(|err| error_resp(StatusCode::BAD_REQUEST, &err))?;
    let row = store
        .request_user(&server, &caller.user_id)
        .await
        .map_err(store_err_to_resp)?;
    Ok(Json(admin_docker_catalog_summary(&row)))
}

async fn admin_put_docker_catalog_server(
    State(svc): State<Arc<McpService>>,
    Path(catalog_id): Path<String>,
    Json(body): Json<AdminPutDockerCatalogBody>,
) -> Result<Json<AdminDockerCatalogServerSummary>, Response<Body>> {
    let store = svc.docker_catalog_store.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp docker catalog store not configured",
        )
    })?;
    let server = mcp_servers::McpDockerCatalogServer {
        id: catalog_id,
        label: body.label,
        description: body.description,
        template: body.template,
        placeholders: body.placeholders,
    };
    mcp_servers::validate_docker_catalog_server(&server)
        .map_err(|err| error_resp(StatusCode::BAD_REQUEST, &err))?;
    let row = store
        .upsert_admin(&server)
        .await
        .map_err(store_err_to_resp)?;
    Ok(Json(admin_docker_catalog_summary(&row)))
}

async fn admin_delete_docker_catalog_server(
    State(svc): State<Arc<McpService>>,
    Path(catalog_id): Path<String>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let store = svc.docker_catalog_store.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp docker catalog store not configured",
        )
    })?;
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    let deleted = store.delete(&catalog_id).await.map_err(store_err_to_resp)?;
    let removed = if deleted {
        isvc.delete_mcp_servers_for_docker_catalog(&catalog_id)
            .await
            .map_err(swarm_err_to_resp)?
    } else {
        Vec::new()
    };
    let runtime_cleanup_errors = stop_deleted_runtime_servers_best_effort(&svc, &removed).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "deleted": deleted,
        "removed_mcp_servers": removed.len(),
        "runtime_cleanup_errors": runtime_cleanup_errors,
    })))
}

fn docker_catalog_summary(
    server: &mcp_servers::McpDockerCatalogServer,
) -> DockerCatalogServerSummary {
    DockerCatalogServerSummary {
        id: server.id.clone(),
        label: server.label.clone(),
        description: server.description.clone(),
        template: server.template.clone(),
        placeholders: server
            .placeholders
            .iter()
            .map(|placeholder| DockerCatalogPlaceholderSummary {
                id: placeholder.id.clone(),
                label: placeholder.label.clone(),
                description: placeholder.description.clone(),
                required: placeholder.required,
                secret: placeholder.secret,
                placeholder: placeholder.placeholder.clone(),
            })
            .collect(),
    }
}

fn admin_docker_catalog_summary(row: &McpDockerCatalogRow) -> AdminDockerCatalogServerSummary {
    AdminDockerCatalogServerSummary {
        server: docker_catalog_summary(&row.server),
        status: row.status,
        source: row.source.clone(),
        requested_by_user_id: row.requested_by_user_id.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

#[derive(Serialize)]
struct ServerSummary {
    name: String,
    url: String,
    /// `remote` for HTTP/SSE servers created through the field UI,
    /// `docker` for Docker stdio servers created from MCP JSON.
    server_type: &'static str,
    /// Catalog id when the Docker server was created from an
    /// operator-curated preset.
    #[serde(skip_serializing_if = "Option::is_none")]
    docker_catalog_id: Option<String>,
    auth_kind: &'static str,
    /// True when an OAuth flow has completed — surfaced so the UI can
    /// render a "connect" vs. "reconnect" button.
    connected: bool,
    /// Cached `tools/list` result from the most recent /check call.
    /// `None` ⇒ admin hasn't run a check yet (UI shows "not connected").
    #[serde(skip_serializing_if = "Option::is_none")]
    tools_catalog: Option<McpToolsCatalog>,
    /// Cached failure from the most recent /check call. Persisted so
    /// a page refresh keeps showing a broken server as broken.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_check_error: Option<mcp_servers::McpCheckError>,
    /// Admin-selected tool allowlist.  Mirrors the built-in tools
    /// section: `None` ⇒ "use default" (SPA applies airgap rule on
    /// prefill); `Some(vec)` ⇒ explicit allowlist.
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled_tools: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PutDockerCatalogBody {
    #[serde(default)]
    placeholders: BTreeMap<String, String>,
}

async fn put_docker_catalog_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, catalog_id)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<PutDockerCatalogBody>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    if svc.runtime_socket_path.is_none() {
        return Err(error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "docker mcp runtime not configured",
        ));
    }
    if !owner_owns_instance(&svc, &caller.user_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let catalog = svc
        .get_docker_catalog_server(&catalog_id)
        .await
        .map_err(store_err_to_resp)?
        .ok_or_else(|| error_resp(StatusCode::NOT_FOUND, "no such docker mcp catalog entry"))?;
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    let name = isvc
        .put_docker_catalog_mcp_server(&caller.user_id, &instance_id, &catalog, body.placeholders)
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(serde_json::json!({ "ok": true, "name": name })))
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
        if let Ok(Some(e)) =
            mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &name).await
        {
            let auth_kind: &'static str = match &e.auth {
                McpAuthSpec::None => "none",
                McpAuthSpec::Bearer { .. } => "bearer",
                McpAuthSpec::Oauth { .. } => "oauth",
            };
            let connected = matches!(&e.auth, McpAuthSpec::Oauth { .. })
                && e.oauth_tokens.is_some()
                || matches!(&e.auth, McpAuthSpec::Bearer { .. } | McpAuthSpec::None);
            // Strip query string + fragment.  Many MCP servers carry their
            // API key as a `?apikey=...` query param (Alpha Vantage, a few
            // SaaS gateways), and the listing surface is the only place
            // that plaintext URL would otherwise leak — the proxy URL the
            // running agent sees is `<swarm>/mcp/<id>/<name>`, never the
            // upstream.  By dropping the query here, an operator who
            // glances at the SPA never sees the secret; if they want to
            // edit the row they have to re-enter the credential, which is
            // the right UX for a secret-bearing field anyway.  The full
            // URL stays sealed in user_secrets and the proxy decrypts it
            // per request — only the *display* is trimmed.
            let url = strip_url_query(&e.url);
            out.push(ServerSummary {
                name,
                url,
                server_type: if e.runtime.is_some() {
                    "docker"
                } else {
                    "remote"
                },
                docker_catalog_id: e.docker_catalog.as_ref().map(|binding| binding.id.clone()),
                auth_kind,
                connected,
                tools_catalog: e.tools_catalog,
                last_check_error: e.last_check_error,
                enabled_tools: e.enabled_tools,
            });
        }
    }
    Ok(Json(out))
}

/// Return `s` with `?...` and `#...` removed, if present.  Doesn't
/// validate the URL — non-URL strings round-trip unchanged (we'd rather
/// surface a stored value than swallow it).
async fn get_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<ServerSummary>, Response<Body>> {
    let owner_id = caller.user_id.clone();
    if !owner_owns_instance(&svc, &owner_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let entry = mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &name)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mcp: get secret read failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
        })?;
    let entry = match entry {
        Some(e) => e,
        None => return Err(error_resp(StatusCode::NOT_FOUND, "no such mcp server")),
    };
    let auth_kind: &'static str = match &entry.auth {
        McpAuthSpec::None => "none",
        McpAuthSpec::Bearer { .. } => "bearer",
        McpAuthSpec::Oauth { .. } => "oauth",
    };
    let connected = matches!(&entry.auth, McpAuthSpec::Oauth { .. })
        && entry.oauth_tokens.is_some()
        || matches!(&entry.auth, McpAuthSpec::Bearer { .. } | McpAuthSpec::None);
    Ok(Json(ServerSummary {
        name,
        url: entry.url,
        server_type: if entry.runtime.is_some() {
            "docker"
        } else {
            "remote"
        },
        docker_catalog_id: entry
            .docker_catalog
            .as_ref()
            .map(|binding| binding.id.clone()),
        auth_kind,
        connected,
        tools_catalog: entry.tools_catalog,
        last_check_error: entry.last_check_error,
        enabled_tools: entry.enabled_tools,
    }))
}

async fn owner_owns_instance(svc: &McpService, owner_id: &str, instance_id: &str) -> bool {
    matches!(
        svc.instances.get(instance_id).await,
        Ok(Some(row)) if row.owner_id == owner_id
    )
}

#[derive(Serialize)]
struct GetVscodeConfigResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<serde_json::Value>,
}

async fn get_vscode_config(
    State(svc): State<Arc<McpService>>,
    Path(instance_id): Path<String>,
    uri: Uri,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<GetVscodeConfigResponse>, Response<Body>> {
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    let server = uri.query().and_then(|query| query_param(query, "server"));
    let config = isvc
        .get_vscode_mcp_config(&caller.user_id, &instance_id, server.as_deref())
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(GetVscodeConfigResponse { config }))
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|part| {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        (percent_decode_query_component(k) == key).then(|| percent_decode_query_component(v))
    })
}

fn percent_decode_query_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn put_vscode_config(
    State(svc): State<Arc<McpService>>,
    Path(instance_id): Path<String>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    if !svc.allow_user_docker_json {
        return Err(error_resp(
            StatusCode::FORBIDDEN,
            "raw docker mcp JSON is disabled by the operator; choose a catalog entry",
        ));
    }
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    isvc.put_vscode_mcp_config(&caller.user_id, &instance_id, body)
        .await
        .map_err(swarm_err_to_resp)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_vscode_config(
    State(svc): State<Arc<McpService>>,
    Path(instance_id): Path<String>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let isvc = svc.instance_svc.as_ref().ok_or_else(|| {
        error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp management not configured",
        )
    })?;
    let deleted = isvc
        .delete_vscode_mcp_config(&caller.user_id, &instance_id)
        .await
        .map_err(swarm_err_to_resp)?;
    if let Some(deleted) = deleted.as_ref() {
        stop_deleted_runtime_server(&svc, deleted).await?;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
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
    /// Admin-selected tool allowlist (`None` ⇒ "use default", treated
    /// as pass-through; `Some(vec)` ⇒ explicit allowlist).  Mirrors
    /// the built-in tools section's behaviour.
    #[serde(default)]
    pub enabled_tools: Option<Vec<String>>,
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
    let spec = McpServerSpec {
        name,
        url: body.url,
        auth: body.auth,
        enabled_tools: body.enabled_tools,
    };
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
    let deleted = isvc
        .delete_mcp_server(&caller.user_id, &instance_id, &name)
        .await
        .map_err(swarm_err_to_resp)?;
    if let Some(deleted) = deleted.as_ref() {
        stop_deleted_runtime_server(&svc, deleted).await?;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Body for the dedicated enabled-tools update endpoint.  `null` (or
/// an absent field) means "use default" — the proxy stops filtering;
/// an array is an explicit allowlist.
#[derive(Deserialize)]
struct EnabledToolsBody {
    #[serde(default)]
    enabled_tools: Option<Vec<String>>,
}

async fn put_enabled_tools(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
    Json(body): Json<EnabledToolsBody>,
) -> Result<Json<serde_json::Value>, Response<Body>> {
    let owner_id = caller.user_id.clone();
    if !owner_owns_instance(&svc, &owner_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let mut entry = mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &name)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mcp: enabled-tools secret read failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
        })?
        .ok_or_else(|| error_resp(StatusCode::NOT_FOUND, "no such mcp server"))?;
    entry.enabled_tools = body.enabled_tools;
    if let Err(e) =
        mcp_servers::put(&svc.user_secrets, &owner_id, &instance_id, &name, &entry).await
    {
        tracing::warn!(error = %e, "mcp: enabled-tools write failed");
        return Err(error_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret store error",
        ));
    }
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

// ───────────────────────────────────────────────────────────────────
// On-demand connection check.  Runs `initialize` + `tools/list` against
// the upstream MCP server, persists the resulting catalog on the entry,
// and returns it to the SPA.  This is the only writer for
// `entry.tools_catalog` — admin-only, on-demand, never auto-fired so an
// idle SPA never wakes the upstream.
// ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResponse {
    ok: bool,
    tools: Vec<McpToolSummary>,
    last_checked_at: i64,
}

async fn check_server(
    State(svc): State<Arc<McpService>>,
    Path((instance_id, name)): Path<(String, String)>,
    axum::Extension(caller): axum::Extension<CallerIdentity>,
) -> Result<Json<CheckResponse>, Response<Body>> {
    let owner_id = caller.user_id.clone();
    if !owner_owns_instance(&svc, &owner_id, &instance_id).await {
        return Err(error_resp(StatusCode::NOT_FOUND, "no such instance"));
    }
    let mut entry = mcp_servers::get(&svc.user_secrets, &owner_id, &instance_id, &name)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mcp: check secret read failed");
            error_resp(StatusCode::INTERNAL_SERVER_ERROR, "secret store error")
        })?
        .ok_or_else(|| error_resp(StatusCode::NOT_FOUND, "no such mcp server"))?;

    // Refresh OAuth tokens if needed — same as the forward path so the
    // check button doesn't flake right after a token's refresh window.
    if let Err(err) = ensure_fresh_oauth(&svc, &owner_id, &instance_id, &name, &mut entry).await {
        tracing::warn!(error = %err, "mcp: check oauth refresh failed");
        return Err(error_resp(StatusCode::BAD_GATEWAY, "oauth refresh failed"));
    }

    let catalog = match run_tools_list(&svc, &instance_id, &name, &entry).await {
        Ok(c) => c,
        Err(err) => {
            entry.last_check_error = Some(mcp_servers::McpCheckError {
                message: err.clone(),
                checked_at: crate::now_secs(),
            });
            if let Err(write_err) =
                mcp_servers::put(&svc.user_secrets, &owner_id, &instance_id, &name, &entry).await
            {
                tracing::warn!(error = %write_err, "mcp: failed to persist check error");
            }
            tracing::warn!(
                error = %err,
                domain = %crate::mcp_servers::domain_of(&entry.url),
                server = %name,
                "mcp: check failed",
            );
            return Err(error_resp(
                StatusCode::BAD_GATEWAY,
                &format!("upstream check failed: {err}"),
            ));
        }
    };

    entry.tools_catalog = Some(catalog.clone());
    entry.last_check_error = None;
    if let Err(e) =
        mcp_servers::put(&svc.user_secrets, &owner_id, &instance_id, &name, &entry).await
    {
        tracing::warn!(error = %e, "mcp: check write-back failed");
        return Err(error_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret store error",
        ));
    }

    Ok(Json(CheckResponse {
        ok: true,
        tools: catalog.tools,
        last_checked_at: catalog.last_checked_at,
    }))
}

/// Run the MCP streamable-HTTP handshake against `entry.url`:
///   1. POST `initialize`.  Capture any `Mcp-Session-Id` response header.
///   2. POST `notifications/initialized` (fire-and-forget).
///   3. POST `tools/list` and parse `result.tools[]`.
///
/// Handles both `application/json` and `text/event-stream` responses
/// (streamable HTTP servers may pick either based on Accept; we send
/// both).  Bearer/None auth are sent via the existing `entry.auth`;
/// OAuth callers must have refreshed tokens before invoking this.
async fn run_tools_list(
    svc: &McpService,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
) -> Result<McpToolsCatalog, String> {
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "dyson-swarm",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    });
    let init_resp = post_jsonrpc_for_entry(svc, instance_id, server_name, entry, &init_req, None)
        .await
        .map_err(|e| format!("initialize: {e}"))?;
    let session_id = init_resp.session_id.clone();

    // Spec: client must send notifications/initialized after initialize
    // succeeds.  Notifications carry no `id` and the server SHOULD reply
    // 202 Accepted with empty body.  Treat any failure here as
    // non-fatal — some servers tolerate skipping it.
    let initialized_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let _ = post_jsonrpc_for_entry(
        svc,
        instance_id,
        server_name,
        entry,
        &initialized_notif,
        session_id.as_deref(),
    )
    .await;

    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    });
    let list_resp = post_jsonrpc_for_entry(
        svc,
        instance_id,
        server_name,
        entry,
        &list_req,
        session_id.as_deref(),
    )
    .await
    .map_err(|e| format!("tools/list: {e}"))?;

    if let Some(err) = list_resp.body.get("error") {
        return Err(format!("upstream tools/list error: {err}"));
    }
    let tools_value = list_resp
        .body
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .ok_or("missing result.tools in tools/list response")?;

    let tools: Vec<McpToolSummary> = tools_value
        .iter()
        .filter_map(|t| {
            let name = t.get("name").and_then(|n| n.as_str())?.to_owned();
            if name.is_empty() {
                return None;
            }
            let description = t
                .get("description")
                .and_then(|d| d.as_str())
                .map(String::from);
            Some(McpToolSummary { name, description })
        })
        .collect();

    Ok(McpToolsCatalog {
        tools,
        last_checked_at: crate::now_secs(),
    })
}

struct JsonRpcResponse {
    body: serde_json::Value,
    session_id: Option<String>,
}

async fn post_jsonrpc_for_entry(
    svc: &McpService,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
    body: &serde_json::Value,
    session_id: Option<&str>,
) -> Result<JsonRpcResponse, String> {
    if entry.runtime.is_none() {
        return post_jsonrpc(svc, entry, body, session_id).await;
    }
    let Some(socket_path) = svc.runtime_socket_path.as_deref() else {
        return Err("mcp runtime helper not configured".into());
    };
    if let Some(McpRuntimeSpec::HttpStreamable { url, .. }) = entry.runtime.as_ref() {
        validate_remote_mcp_url(svc, url).await?;
        validate_remote_mcp_auth_urls(svc, &entry.auth).await?;
    }
    let request_json = serde_json::to_string(body).map_err(|e| format!("encode JSON-RPC: {e}"))?;
    let request = runtime_forward_request_for_entry(
        svc.docker_runtime.as_str(),
        instance_id,
        server_name,
        entry,
        &request_json,
    )?;
    let resp = call_runtime(socket_path, &request).await?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("runtime HTTP {}: {}", resp.status, resp.body));
    }
    if resp.body.is_empty() {
        return Ok(JsonRpcResponse {
            body: serde_json::Value::Null,
            session_id: None,
        });
    }
    let body = serde_json::from_str(&resp.body).map_err(|e| format!("parse runtime json: {e}"))?;
    Ok(JsonRpcResponse {
        body,
        session_id: None,
    })
}

/// Single round-trip helper: POST a JSON-RPC envelope, parse whichever
/// of `application/json` or `text/event-stream` the server returns.
async fn post_jsonrpc(
    svc: &McpService,
    entry: &McpServerEntry,
    body: &serde_json::Value,
    session_id: Option<&str>,
) -> Result<JsonRpcResponse, String> {
    let http = pinned_remote_mcp_client(svc, entry).await?;
    validate_remote_mcp_auth_urls(svc, &entry.auth).await?;
    let mut req = http
        .post(&entry.url)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        // MCP streamable-HTTP servers split on Accept: ask for both so
        // single-shot responses come back as JSON when the server
        // chooses, and SSE-streamed responses still arrive when it
        // doesn't.
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        );
    if let Some(s) = session_id {
        req = req.header("Mcp-Session-Id", s);
    }
    req = apply_entry_headers_and_auth(req, entry)?;

    let resp = req.json(body).send().await.map_err(|e| {
        format!(
            "send: {}",
            crate::mcp_servers::redact_reqwest_err(&e, &entry.url)
        )
    })?;
    let status = resp.status();
    let session_id = resp
        .headers()
        .get("Mcp-Session-Id")
        .or_else(|| resp.headers().get("mcp-session-id"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let bytes = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;

    if !status.is_success() {
        // Echo a short body excerpt so a 4xx with detail is debuggable
        // — but cap the length so we don't log a megabyte error page.
        let snippet = String::from_utf8_lossy(&bytes);
        let snippet = snippet.chars().take(200).collect::<String>();
        return Err(format!("HTTP {status}: {snippet}"));
    }

    if bytes.is_empty() {
        return Ok(JsonRpcResponse {
            body: serde_json::Value::Null,
            session_id,
        });
    }

    let body = if ct.starts_with("text/event-stream") {
        parse_sse_jsonrpc(&bytes)?
    } else {
        serde_json::from_slice(&bytes).map_err(|e| format!("parse json: {e}"))?
    };
    Ok(JsonRpcResponse { body, session_id })
}

fn apply_entry_headers_and_auth(
    mut req: reqwest::RequestBuilder,
    entry: &McpServerEntry,
) -> Result<reqwest::RequestBuilder, String> {
    for (name, value) in &entry.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    match &entry.auth {
        McpAuthSpec::None => {}
        McpAuthSpec::Bearer { token } => req = req.bearer_auth(token),
        McpAuthSpec::Oauth { .. } => match entry.oauth_tokens.as_ref() {
            Some(tk) => req = req.bearer_auth(&tk.access_token),
            None => return Err("oauth not authorised yet".into()),
        },
    }
    Ok(req)
}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

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
