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

use std::collections::BTreeMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{CallerIdentity, extract_bearer};
use crate::db::mcp_catalog::{McpDockerCatalogRow, SqlxMcpDockerCatalogStore};
use crate::error::{StoreError, SwarmError};
use crate::instance::{DeletedMcpServer, InstanceService, SYSTEM_OWNER};
use crate::mcp_servers::{
    self, AuthMetadata, DcrRequest, McpAuthSpec, McpOAuthTokens, McpRuntimeSpec, McpServerEntry,
    McpServerSpec, McpToolSummary, McpToolsCatalog, OAuthFlowCache, PendingFlow,
};
use crate::secrets::UserSecretsService;
use crate::traits::{InstanceStatus, InstanceStore, ListFilter, TokenStore};
use crate::upstream_policy::{
    OutboundUrlPolicy, pinned_outbound_client_builder, validate_outbound_url,
};

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
    /// Unix socket for the dedicated Docker-backed stdio MCP runtime.
    /// When absent, remote HTTP/SSE MCP still works; container stdio
    /// entries return a clear 503.
    pub runtime_socket_path: Option<PathBuf>,
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
    pub docker_catalog_store: Option<Arc<SqlxMcpDockerCatalogStore>>,
    /// Shared SSRF policy for remote HTTP/SSE MCP upstreams.  Docker
    /// runtime entries are local runtime requests and do not use this.
    pub mcp_upstream_policy: OutboundUrlPolicy,
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
            runtime_socket_path: None,
            docker_catalog: Vec::new(),
            allow_user_docker_json: false,
            docker_catalog_store: None,
            mcp_upstream_policy: OutboundUrlPolicy::default(),
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

    pub fn with_docker_catalog(
        mut self,
        catalog: Vec<mcp_servers::McpDockerCatalogServer>,
        allow_user_docker_json: bool,
    ) -> Self {
        self.docker_catalog = catalog;
        self.allow_user_docker_json = allow_user_docker_json;
        self
    }

    pub fn with_docker_catalog_store(mut self, store: Arc<SqlxMcpDockerCatalogStore>) -> Self {
        self.docker_catalog_store = Some(store);
        self
    }

    pub fn with_mcp_upstream_policy(mut self, policy: OutboundUrlPolicy) -> Self {
        self.mcp_upstream_policy = policy;
        self
    }

    fn redirect_uri(&self) -> Option<String> {
        self.public_origin
            .as_deref()
            .map(|o| format!("{}/mcp/oauth/callback", o.trim_end_matches('/')))
    }

    async fn docker_catalog_rows(&self) -> Result<Vec<McpDockerCatalogRow>, StoreError> {
        if let Some(store) = &self.docker_catalog_store {
            return store.list().await;
        }
        Ok(self
            .docker_catalog
            .iter()
            .cloned()
            .map(|server| McpDockerCatalogRow {
                server,
                source: "config".into(),
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
            return store.get(id).await.map(|row| row.map(|row| row.server));
        }
        Ok(self
            .docker_catalog
            .iter()
            .find(|server| server.id == id)
            .cloned())
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
    let validated = validate_outbound_url(&svc.mcp_upstream_policy, &entry.url)
        .await
        .map_err(|e| format!("mcp upstream URL rejected: {e}"))?;
    pinned_outbound_client_builder(&validated)
        .build()
        .map_err(|e| format!("mcp upstream client build failed: {e}"))
}

async fn validate_remote_mcp_url(svc: &McpService, url: &str) -> Result<(), String> {
    validate_outbound_url(&svc.mcp_upstream_policy, url)
        .await
        .map(|_| ())
        .map_err(|e| format!("mcp upstream URL rejected: {e}"))
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
    if let Err(err) =
        ensure_fresh_oauth(&svc, &owner_id, &instance_id, &server_name, &mut entry).await
    {
        tracing::warn!(error = %err, "mcp: oauth refresh failed");
        return error_resp(StatusCode::BAD_GATEWAY, "oauth refresh failed");
    }

    // 4. Build the outbound request.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_resp(StatusCode::BAD_REQUEST, "body too large"),
    };

    // Peek at the JSON-RPC envelope so we can enforce the per-tool
    // allowlist (`entry.enabled_tools`).  We only look — the body
    // forwarded upstream is unchanged.  Batched JSON-RPC arrays and
    // unparseable bodies skip filtering entirely (passes through).
    let peek = peek_jsonrpc(&body_bytes);

    // Gate: when the call is `tools/call` for a name the admin has
    // disabled, refuse without forwarding.  Returns a JSON-RPC error
    // envelope so the agent's MCP client surfaces the failure cleanly.
    if let (Some(allowed), Some((method, id, params))) =
        (entry.enabled_tools.as_deref(), peek.as_ref())
    {
        if method == "tools/call" {
            if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                if !allowed.iter().any(|t| t == name) {
                    return jsonrpc_error_resp(
                        id.clone(),
                        -32601,
                        &format!("tool '{name}' is disabled by admin"),
                    );
                }
            }
        }
    }

    if entry.runtime.is_some() {
        return forward_runtime_stdio(
            &svc,
            &instance_id,
            &server_name,
            &entry,
            &body_bytes,
            peek.as_ref(),
        )
        .await;
    }

    if let Err(err) = validate_remote_mcp_auth_urls(&svc, &entry.auth).await {
        tracing::warn!(error = %err, server = %server_name, "mcp: auth URL rejected");
        return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
    }
    let pinned_http = match pinned_remote_mcp_client(&svc, &entry).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(error = %err, server = %server_name, "mcp: upstream rejected");
            return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
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
        Err(msg) => return error_resp(StatusCode::PRECONDITION_REQUIRED, &msg),
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
            return error_resp(StatusCode::BAD_GATEWAY, "upstream unreachable");
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
                return error_resp(StatusCode::BAD_GATEWAY, "upstream read failed");
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
    validate_remote_mcp_url(svc, &tokens.token_url).await?;
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

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum RuntimeRequest<'a> {
    Forward {
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
        request_json: &'a str,
    },
    StopServer {
        instance_id: &'a str,
        server_name: &'a str,
    },
    StopInstance {
        instance_id: &'a str,
    },
    RestartServer {
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
enum RuntimeTransportSpec<'a> {
    DockerStdio {
        args: &'a [String],
        env: &'a std::collections::HashMap<String, String>,
    },
    HttpStreamable {
        url: &'a str,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_bearer_env: Option<&'a str>,
    },
}

impl<'a> RuntimeRequest<'a> {
    fn forward_docker(
        instance_id: &'a str,
        server_name: &'a str,
        args: &'a [String],
        env: &'a std::collections::HashMap<String, String>,
        request_json: &'a str,
    ) -> Self {
        Self::Forward {
            instance_id,
            server_name,
            transport: RuntimeTransportSpec::DockerStdio { args, env },
            request_json,
        }
    }

    fn forward_http_streamable(
        instance_id: &'a str,
        server_name: &'a str,
        url: &'a str,
        headers: BTreeMap<String, String>,
        auth_bearer_env: Option<&'a str>,
        request_json: &'a str,
    ) -> Self {
        Self::Forward {
            instance_id,
            server_name,
            transport: RuntimeTransportSpec::HttpStreamable {
                url,
                headers,
                auth_bearer_env,
            },
            request_json,
        }
    }

    fn restart_server(
        instance_id: &'a str,
        server_name: &'a str,
        transport: RuntimeTransportSpec<'a>,
    ) -> Self {
        Self::RestartServer {
            instance_id,
            server_name,
            transport,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuntimeForwardResponse {
    status: u16,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    body: String,
}

async fn forward_runtime_stdio(
    svc: &McpService,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
    body_bytes: &[u8],
    peek: Option<&(String, serde_json::Value, serde_json::Value)>,
) -> Response<Body> {
    let Some(socket_path) = svc.runtime_socket_path.as_deref() else {
        return error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp runtime helper not configured",
        );
    };
    let request_json = match std::str::from_utf8(body_bytes) {
        Ok(s) => s,
        Err(_) => return error_resp(StatusCode::BAD_REQUEST, "JSON-RPC body must be UTF-8"),
    };
    if let Some(McpRuntimeSpec::HttpStreamable { url, .. }) = entry.runtime.as_ref() {
        if let Err(err) = validate_remote_mcp_url(svc, url).await {
            tracing::warn!(error = %err, server = %server_name, "mcp runtime: upstream rejected");
            return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
        }
        if let Err(err) = validate_remote_mcp_auth_urls(svc, &entry.auth).await {
            tracing::warn!(error = %err, server = %server_name, "mcp runtime: auth URL rejected");
            return error_resp(StatusCode::FORBIDDEN, "mcp upstream not allowed");
        }
    }
    let request =
        match runtime_forward_request_for_entry(instance_id, server_name, entry, request_json) {
            Ok(request) => request,
            Err(msg) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, &msg),
        };
    let runtime_resp = match call_runtime(socket_path, &request).await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                error = %err,
                server = %server_name,
                "mcp runtime: request failed"
            );
            return error_resp(StatusCode::BAD_GATEWAY, "mcp runtime request failed");
        }
    };
    let status =
        StatusCode::from_u16(runtime_resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = runtime_resp.content_type;
    let mut body = runtime_resp.body.into_bytes();
    let response_ct = content_type.as_deref().unwrap_or_else(|| {
        if body.is_empty() {
            ""
        } else {
            "application/json"
        }
    });
    let should_filter_list = matches!(peek, Some((m, _, _)) if m == "tools/list")
        && entry.enabled_tools.is_some()
        && response_ct.to_lowercase().starts_with("application/json")
        && status.is_success();
    if should_filter_list {
        let allowed = entry.enabled_tools.as_deref().unwrap_or(&[]);
        body = match filter_tools_list_body(&body, allowed) {
            Ok(filtered) => filtered,
            Err(err) => {
                tracing::warn!(error = %err, "mcp runtime: tools/list filter failed; passing through");
                body
            }
        };
    }
    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
    } else if !body.is_empty() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    if !body.is_empty() {
        builder = builder.header(
            axum::http::header::CONTENT_LENGTH,
            HeaderValue::from(body.len()),
        );
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| error_resp(StatusCode::INTERNAL_SERVER_ERROR, "build resp"))
}

fn runtime_forward_request_for_entry<'a>(
    instance_id: &'a str,
    server_name: &'a str,
    entry: &'a McpServerEntry,
    request_json: &'a str,
) -> Result<RuntimeRequest<'a>, String> {
    Ok(match runtime_transport_for_entry(entry)? {
        RuntimeTransportSpec::DockerStdio { args, env } => {
            RuntimeRequest::forward_docker(instance_id, server_name, args, env, request_json)
        }
        RuntimeTransportSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        } => RuntimeRequest::forward_http_streamable(
            instance_id,
            server_name,
            url,
            headers,
            auth_bearer_env,
            request_json,
        ),
    })
}

fn runtime_restart_request_for_entry<'a>(
    instance_id: &'a str,
    server_name: &'a str,
    entry: &'a McpServerEntry,
) -> Result<RuntimeRequest<'a>, String> {
    Ok(RuntimeRequest::restart_server(
        instance_id,
        server_name,
        runtime_transport_for_entry(entry)?,
    ))
}

fn runtime_transport_for_entry<'a>(
    entry: &'a McpServerEntry,
) -> Result<RuntimeTransportSpec<'a>, String> {
    match entry.runtime.as_ref() {
        Some(McpRuntimeSpec::DockerStdio { command, args, env }) => {
            if command != "docker" {
                return Err("invalid docker MCP runtime command".into());
            }
            Ok(RuntimeTransportSpec::DockerStdio { args, env })
        }
        Some(McpRuntimeSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        }) => {
            let mut runtime_headers: BTreeMap<String, String> = headers.clone();
            match &entry.auth {
                McpAuthSpec::None => {}
                McpAuthSpec::Bearer { token } => {
                    runtime_headers.insert("Authorization".into(), format!("Bearer {token}"));
                }
                McpAuthSpec::Oauth { .. } => {
                    let tokens = entry
                        .oauth_tokens
                        .as_ref()
                        .ok_or_else(|| "oauth not authorised yet".to_string())?;
                    runtime_headers.insert(
                        "Authorization".into(),
                        format!("Bearer {}", tokens.access_token),
                    );
                }
            }
            Ok(RuntimeTransportSpec::HttpStreamable {
                url,
                headers: runtime_headers,
                auth_bearer_env: auth_bearer_env.as_deref(),
            })
        }
        None => Err("invalid mcp runtime entry".into()),
    }
}

async fn call_runtime(
    socket_path: &FsPath,
    request: &RuntimeRequest<'_>,
) -> Result<RuntimeForwardResponse, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
    let line = serde_json::to_vec(request).map_err(|e| format!("encode request: {e}"))?;
    stream
        .write_all(&line)
        .await
        .map_err(|e| format!("write request: {e}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| format!("write newline: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut out = String::new();
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(125),
        reader.read_line(&mut out),
    )
    .await
    .map_err(|_| "runtime response timed out".to_string())?
    .map_err(|e| format!("read response: {e}"))?;
    if n == 0 {
        return Err("runtime closed without response".into());
    }
    serde_json::from_str(&out).map_err(|e| format!("decode response: {e}"))
}

pub async fn stop_runtime_server(
    socket_path: Option<&FsPath>,
    instance_id: &str,
    server_name: &str,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let resp = call_runtime(
        socket_path,
        &RuntimeRequest::StopServer {
            instance_id,
            server_name,
        },
    )
    .await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime stop_server HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

pub async fn stop_runtime_instance(
    socket_path: Option<&FsPath>,
    instance_id: &str,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let resp = call_runtime(socket_path, &RuntimeRequest::StopInstance { instance_id }).await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime stop_instance HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

pub async fn restart_runtime_server(
    socket_path: Option<&FsPath>,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
) -> Result<(), String> {
    let Some(socket_path) = socket_path else {
        return Ok(());
    };
    let req = runtime_restart_request_for_entry(instance_id, server_name, entry)?;
    let resp = call_runtime(socket_path, &req).await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!(
            "runtime restart_server HTTP {}: {}",
            resp.status, resp.body
        ))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRestartReport {
    pub visited_instances: usize,
    pub runtime_servers: usize,
    pub restarted: usize,
    pub failed: usize,
}

pub async fn restart_active_runtime_servers(
    svc: Arc<McpService>,
) -> Result<RuntimeRestartReport, SwarmError> {
    if svc.runtime_socket_path.is_none() {
        return Ok(RuntimeRestartReport::default());
    }
    let live = svc
        .instances
        .list(
            SYSTEM_OWNER,
            ListFilter {
                status: Some(InstanceStatus::Live),
                include_destroyed: false,
            },
        )
        .await?;
    let mut report = RuntimeRestartReport {
        visited_instances: live.len(),
        ..RuntimeRestartReport::default()
    };

    for row in live {
        let names = match mcp_servers::list_names(&svc.user_secrets, &row.owner_id, &row.id).await {
            Ok(names) => names,
            Err(err) => {
                report.failed += 1;
                tracing::warn!(
                    error = %err,
                    instance = %row.id,
                    "mcp runtime restart: list failed"
                );
                continue;
            }
        };
        for name in names {
            let entry =
                match mcp_servers::get(&svc.user_secrets, &row.owner_id, &row.id, &name).await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => continue,
                    Err(err) => {
                        report.failed += 1;
                        tracing::warn!(
                            error = %err,
                            instance = %row.id,
                            server = %name,
                            "mcp runtime restart: entry read failed"
                        );
                        continue;
                    }
                };
            let Some(runtime) = entry.runtime.as_ref() else {
                continue;
            };
            if matches!(entry.auth, McpAuthSpec::Oauth { .. }) && entry.oauth_tokens.is_none() {
                tracing::debug!(
                    instance = %row.id,
                    server = %name,
                    "mcp runtime restart: skipping unauthorised oauth server"
                );
                continue;
            }
            report.runtime_servers += 1;
            if let McpRuntimeSpec::HttpStreamable { url, .. } = runtime {
                if let Err(err) = validate_remote_mcp_url(&svc, url).await {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: upstream rejected"
                    );
                    continue;
                }
                if let Err(err) = validate_remote_mcp_auth_urls(&svc, &entry.auth).await {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: auth URL rejected"
                    );
                    continue;
                }
            }

            match restart_runtime_server(svc.runtime_socket_path.as_deref(), &row.id, &name, &entry)
                .await
            {
                Ok(()) => {
                    report.restarted += 1;
                    tracing::debug!(
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: restarted"
                    );
                }
                Err(err) => {
                    report.failed += 1;
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        "mcp runtime restart: failed"
                    );
                }
            }
        }
    }

    Ok(report)
}

async fn stop_deleted_runtime_server(
    svc: &McpService,
    deleted: &DeletedMcpServer,
) -> Result<(), Response<Body>> {
    if deleted.runtime.is_none() {
        return Ok(());
    }
    stop_runtime_server(
        svc.runtime_socket_path.as_deref(),
        &deleted.instance_id,
        &deleted.name,
    )
    .await
    .map_err(|err| {
        tracing::warn!(
            error = %err,
            owner = %deleted.owner_id,
            instance = %deleted.instance_id,
            server = %deleted.name,
            "mcp runtime: deleted server cleanup failed"
        );
        error_resp(StatusCode::BAD_GATEWAY, "mcp runtime cleanup failed")
    })
}

async fn stop_deleted_runtime_servers_best_effort(
    svc: &McpService,
    deleted: &[DeletedMcpServer],
) -> usize {
    let mut errors = 0usize;
    for server in deleted {
        if server.runtime.is_none() {
            continue;
        }
        if let Err(err) = stop_runtime_server(
            svc.runtime_socket_path.as_deref(),
            &server.instance_id,
            &server.name,
        )
        .await
        {
            errors += 1;
            tracing::warn!(
                error = %err,
                owner = %server.owner_id,
                instance = %server.instance_id,
                server = %server.name,
                "mcp runtime: catalog delete cleanup failed"
            );
        }
    }
    errors
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
        _ => mcp_servers::discover_metadata(&entry.url, &svc.http)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "mcp: discovery failed");
                error_resp(StatusCode::BAD_GATEWAY, "oauth discovery failed")
            })?,
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
            let dcr = mcp_servers::register_client(
                &reg_url,
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
                &svc.http,
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
    if let Err(err) = validate_remote_mcp_url(&svc, &flow.token_url).await {
        tracing::warn!(error = %err, "mcp: callback token URL rejected");
        return callback_html(StatusCode::FORBIDDEN, "mcp upstream not allowed");
    }

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
    source: String,
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
    let rows = svc.docker_catalog_rows().await.map_err(store_err_to_resp)?;
    Ok(Json(AdminDockerCatalogResponse {
        allow_raw_json: svc.allow_user_docker_json,
        servers: rows
            .iter()
            .map(|row| admin_docker_catalog_summary(row))
            .collect(),
    }))
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
        source: row.source.clone(),
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
                enabled_tools: e.enabled_tools,
            });
        }
    }
    Ok(Json(out))
}

/// Return `s` with `?...` and `#...` removed, if present.  Doesn't
/// validate the URL — non-URL strings round-trip unchanged (we'd rather
/// surface a stored value than swallow it).
fn strip_url_query(s: &str) -> String {
    let mut end = s.len();
    if let Some(q) = s.find('?') {
        end = end.min(q);
    }
    if let Some(h) = s.find('#') {
        end = end.min(h);
    }
    s[..end].to_string()
}

/// Single-server detail.  Surfaces the **full** URL — query string and
/// all — so the SPA's edit form can pre-fill without forcing the
/// operator to re-enter a query-string credential they already saved.
/// The list endpoint above strips queries by design; this one is the
/// "I'm about to edit, give me what I had" path.  Owner-scoped same as
/// list_servers.
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
            let name = t.get("name").and_then(|n| n.as_str())?.to_string();
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
    let request =
        runtime_forward_request_for_entry(instance_id, server_name, entry, &request_json)?;
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

/// Minimal SSE parser scoped to our use case: scan `data:` lines and
/// return the first one that looks like a JSON-RPC response (carries
/// `jsonrpc` and either `result` or `error`).  Multi-line `data:`
/// continuations are concatenated per the SSE spec.
fn parse_sse_jsonrpc(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("sse utf8: {e}"))?;
    let mut buf = String::new();
    let flush = |buf: &mut String| -> Option<serde_json::Value> {
        if buf.is_empty() {
            return None;
        }
        let payload = std::mem::take(buf);
        let value = serde_json::from_str::<serde_json::Value>(payload.trim()).ok()?;
        if value.get("jsonrpc").is_some()
            && (value.get("result").is_some() || value.get("error").is_some())
        {
            Some(value)
        } else {
            None
        }
    };
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            // Blank line ⇒ event boundary.
            if let Some(v) = flush(&mut buf) {
                return Ok(v);
            }
            buf.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(rest.trim_start());
        }
        // Any other field (id:, event:, retry:) is ignored.
    }
    if let Some(v) = flush(&mut buf) {
        return Ok(v);
    }
    Err("no JSON-RPC response in SSE stream".into())
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

fn store_err_to_resp(err: StoreError) -> Response<Body> {
    let status = match &err {
        StoreError::NotFound => StatusCode::NOT_FOUND,
        StoreError::Constraint(_) | StoreError::Malformed(_) => StatusCode::BAD_REQUEST,
        StoreError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_resp(status, &err.to_string())
}

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

/// Peek at a JSON-RPC envelope to extract `(method, id, params)`.
/// Returns `None` for batches, parse failures, or non-object roots —
/// the proxy passes those through untouched.  We deliberately don't
/// validate the JSON-RPC envelope strictly; this is a *gate*, not
/// validation.  The upstream MCP server will catch malformed bodies.
fn peek_jsonrpc(bytes: &[u8]) -> Option<(String, serde_json::Value, serde_json::Value)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let method = obj.get("method")?.as_str()?.to_string();
    let id = obj.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let params = obj
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Some((method, id, params))
}

/// JSON-RPC error envelope as a 200-OK HTTP response.  The agent's
/// MCP client reads `error.message` to surface the failure; using a
/// proper JSON-RPC error (rather than HTTP 4xx) keeps the agent's
/// error path consistent with what an upstream rejection looks like.
fn jsonrpc_error_resp(id: serde_json::Value, code: i64, message: &str) -> Response<Body> {
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

/// Filter the `result.tools[]` array of a `tools/list` JSON response
/// down to names in `allowed`.  Returns the re-serialised body.  A
/// parse failure or unexpected shape returns Err so the caller can
/// fall back to passing the upstream body through.
fn filter_tools_list_body(bytes: &[u8], allowed: &[String]) -> Result<Vec<u8>, String> {
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parse: {e}"))?;
    let allowed_set: std::collections::HashSet<&str> = allowed.iter().map(String::as_str).collect();
    let Some(tools) = value
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    else {
        return Err("response shape mismatch (no result.tools)".into());
    };
    tools.retain(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .map(|n| allowed_set.contains(n))
            .unwrap_or(false)
    });
    serde_json::to_vec(&value).map_err(|e| format!("re-serialise: {e}"))
}

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

    #[test]
    fn strip_url_query_drops_query_and_fragment() {
        assert_eq!(
            strip_url_query("https://mcp.alphavantage.co/mcp?apikey=AABBCC"),
            "https://mcp.alphavantage.co/mcp"
        );
        assert_eq!(
            strip_url_query("https://example.com/path#frag"),
            "https://example.com/path"
        );
        assert_eq!(
            strip_url_query("https://example.com/path?k=v#frag"),
            "https://example.com/path"
        );
    }

    #[test]
    fn strip_url_query_passes_through_clean_url() {
        let clean = "https://mcp.context7.com/mcp";
        assert_eq!(strip_url_query(clean), clean);
    }

    #[test]
    fn peek_jsonrpc_extracts_method_id_params() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"foo"}}"#;
        let (m, id, p) = peek_jsonrpc(body).expect("parses");
        assert_eq!(m, "tools/call");
        assert_eq!(id, serde_json::json!(7));
        assert_eq!(p["name"], "foo");
    }

    #[test]
    fn peek_jsonrpc_returns_none_for_batches_and_garbage() {
        // Batched JSON-RPC: array root.  Pass through unfiltered.
        assert!(peek_jsonrpc(b"[]").is_none());
        // Non-JSON.
        assert!(peek_jsonrpc(b"not json").is_none());
        // Object without method (a JSON-RPC response, not request).
        assert!(peek_jsonrpc(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_none());
    }

    #[test]
    fn filter_tools_list_keeps_only_allowed() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
            {"name":"a","description":"x"},
            {"name":"b"},
            {"name":"c","description":"z"}
        ]}}"#;
        let allowed = vec!["a".to_string(), "c".to_string()];
        let out = filter_tools_list_body(body, &allowed).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["a", "c"]);
    }

    #[test]
    fn filter_tools_list_empties_when_nothing_allowed() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}]}}"#;
        let out = filter_tools_list_body(body, &[]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v["result"]["tools"].as_array().unwrap().is_empty());
    }

    #[test]
    fn filter_tools_list_errors_on_unexpected_shape() {
        // No result.tools — caller should fall back to passing the
        // upstream body through unchanged rather than rewriting it.
        let body = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601}}"#;
        assert!(filter_tools_list_body(body, &["a".into()]).is_err());
    }

    #[tokio::test]
    async fn call_runtime_round_trips_fake_helper() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("runtime.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let req: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["op"], "forward");
            assert_eq!(req["instance_id"], "i-1");
            assert_eq!(req["server_name"], "echo");
            assert_eq!(req["transport"]["kind"], "DockerStdio");
            assert!(req.get("command").is_none());
            assert!(req["transport"].get("command").is_none());
            let resp = serde_json::json!({
                "status": 200,
                "content_type": "application/json",
                "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"
            });
            let mut stream = reader.into_inner();
            stream
                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                .await
                .unwrap();
            stream.write_all(b"\n").await.unwrap();
        });

        let args = vec!["run".to_string(), "example/mcp".to_string()];
        let env = std::collections::HashMap::new();
        let req = RuntimeRequest::forward_docker(
            "i-1",
            "echo",
            &args,
            &env,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        );
        let resp = call_runtime(&socket, &req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"ok\":true"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stop_runtime_server_sends_runtime_cleanup_op() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("runtime.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let req: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["op"], "stop_server");
            assert_eq!(req["instance_id"], "i-1");
            assert_eq!(req["server_name"], "brave");
            let resp = serde_json::json!({
                "status": 200,
                "content_type": "application/json",
                "body": "{\"ok\":true,\"stopped_sessions\":1,\"removed_containers\":1}"
            });
            let mut stream = reader.into_inner();
            stream
                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                .await
                .unwrap();
            stream.write_all(b"\n").await.unwrap();
        });

        stop_runtime_server(Some(&socket), "i-1", "brave")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn restart_runtime_server_sends_runtime_restart_op() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("runtime.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let req: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["op"], "restart_server");
            assert_eq!(req["instance_id"], "i-1");
            assert_eq!(req["server_name"], "brave");
            assert_eq!(req["transport"]["kind"], "DockerStdio");
            assert!(req["transport"].get("command").is_none());
            let resp = serde_json::json!({
                "status": 200,
                "content_type": "application/json",
                "body": "{\"ok\":true,\"stopped_sessions\":1,\"removed_containers\":1}"
            });
            let mut stream = reader.into_inner();
            stream
                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                .await
                .unwrap();
            stream.write_all(b"\n").await.unwrap();
        });

        let entry = McpServerEntry {
            url: "docker://example/mcp".into(),
            auth: McpAuthSpec::None,
            headers: std::collections::HashMap::new(),
            runtime: Some(McpRuntimeSpec::DockerStdio {
                command: "docker".into(),
                args: vec!["run".into(), "example/mcp".into()],
                env: std::collections::HashMap::new(),
            }),
            docker_catalog: None,
            raw_vscode_config: None,
            oauth_tokens: None,
            tools_catalog: None,
            enabled_tools: None,
        };
        restart_runtime_server(Some(&socket), "i-1", "brave", &entry)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn parse_sse_jsonrpc_picks_first_response_event() {
        // Two events: a server-side "ping" (no jsonrpc.result/error)
        // followed by the actual response.  Parser must skip the first.
        let sse = b"event: ping\ndata: {\"hello\":1}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n";
        let v = parse_sse_jsonrpc(sse).unwrap();
        assert_eq!(v["id"], 2);
        assert!(v["result"]["tools"].is_array());
    }

    #[test]
    fn parse_sse_jsonrpc_handles_multi_line_data() {
        // SSE allows multiple `data:` lines per event; they concatenate
        // with newlines.  Make sure the parser glues them correctly.
        let sse = b"data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":2,\"result\":{}}\n\n";
        let v = parse_sse_jsonrpc(sse).unwrap();
        assert_eq!(v["id"], 2);
    }

    #[test]
    fn strip_url_query_handles_fragment_before_query() {
        // RFC violators that put `#` before `?` — strip at the earliest
        // delimiter so we never accidentally render past it.
        assert_eq!(
            strip_url_query("https://example.com/path#frag?secret=x"),
            "https://example.com/path"
        );
    }

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
