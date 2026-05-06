//! Instance lifecycle: create, destroy, restore.
//!
//! Wires `CubeClient` + `InstanceStore` + `TokenStore`. The
//! env map handed to the sandbox is composed via [`crate::secrets::compose_env`]
//! using the priority (template → managed → caller).
//!
//! One **proxy token per instance** is minted at create time; the
//! `provider` column is set to `"*"` to indicate the same token authorises
//! the instance against any provider permitted by its policy. The proxy
//! (step 14) consults the URL path to decide which adapter to use.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SwarmError;
use crate::mcp_servers::{self, McpAuthSpec, McpServerSpec};
use crate::upstream_policy::{OutboundUrlPolicy, validate_outbound_url};

/// True when the OAuth-token-bearing fields of the auth shape
/// (kind + endpoints + scopes) haven't moved.  When they have, the
/// OAuth tokens we stored under the previous shape are stale —
/// clearing them forces the user to reconnect with the new metadata.
fn auth_shape_matches(prev: &McpAuthSpec, next: &McpAuthSpec) -> bool {
    use McpAuthSpec::*;
    match (prev, next) {
        (None, None) => true,
        (Bearer { .. }, Bearer { .. }) => true,
        (
            Oauth {
                scopes: a_s,
                authorization_url: a_a,
                token_url: a_t,
                ..
            },
            Oauth {
                scopes: b_s,
                authorization_url: b_a,
                token_url: b_t,
                ..
            },
        ) => a_s == b_s && a_a == b_a && a_t == b_t,
        _ => false,
    }
}

/// Static placeholder the SPA's MCP edit form pre-fills into
/// secret-bearing inputs — bullets, fixed length.  When the
/// inbound auth spec carries this verbatim, swarm interprets it
/// as "keep the existing sealed value" and the field on the row
/// is left untouched.  Picked to be a string a real API token
/// can't realistically contain, so a user typing this exact
/// pattern by accident is a non-concern.
pub(crate) const MCP_KEEP_TOKEN: &str = "••••••••";

/// Replace any [`MCP_KEEP_TOKEN`] sentinels in `next` with the
/// corresponding plaintext from `prev` so the SPA's "leave it
/// alone" UX round-trips without making the swarm re-decrypt.
/// Caller must have already verified `auth_shape_matches` —
/// otherwise the fields don't line up.
fn keep_existing_secrets(prev: &McpAuthSpec, next: &mut McpAuthSpec) {
    use McpAuthSpec::*;
    match (prev, next) {
        (Bearer { token: prev_token }, Bearer { token: next_token }) => {
            if next_token == MCP_KEEP_TOKEN {
                *next_token = prev_token.clone();
            }
        }
        (
            Oauth {
                client_secret: Some(prev_cs),
                ..
            },
            Oauth {
                client_secret: Some(next_cs),
                ..
            },
        ) => {
            if next_cs == MCP_KEEP_TOKEN {
                *next_cs = prev_cs.clone();
            }
        }
        _ => {}
    }
}
use crate::network_policy::{self, DnsHostResolver, HostResolver, NetworkPolicy};
use crate::now_secs;
use crate::secrets::{UserSecretsService, compose_env};
use crate::traits::{
    CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus, InstanceStore,
    ListFilter, ProbeResult, TokenStore,
};

/// Sentinel `provider` value used for the per-instance shared proxy token.
/// The proxy resolves the token, sees `"*"`, and accepts any provider that
/// the instance's policy allows.
pub const SHARED_PROVIDER: &str = "*";

/// Env-var names injected by the orchestrator into every sandbox.
pub const ENV_PROXY_URL: &str = "SWARM_PROXY_URL";
pub const ENV_PROXY_TOKEN: &str = "SWARM_PROXY_TOKEN";
pub const ENV_INSTANCE_ID: &str = "SWARM_INSTANCE_ID";
/// Bearer token the agent's HTTP server must accept. The host-based
/// dyson_proxy stamps `Authorization: Bearer <bearer_token>` on every
/// forwarded request — without this env, the agent has no way to know
/// the secret it's being challenged with.
pub const ENV_BEARER_TOKEN: &str = "SWARM_BEARER_TOKEN";
/// Human-readable label, e.g. "PR reviewer for foo/bar".
pub const ENV_NAME: &str = "SWARM_NAME";
/// Free-text mission statement. The agent reads this on first boot to
/// seed its self-knowledge files; swarm does not push subsequent
/// edits to a running sandbox.
pub const ENV_TASK: &str = "SWARM_TASK";
/// LLM model id the agent talks to via swarm's `/llm` proxy
/// (e.g. `"anthropic/claude-sonnet-4-5"`, `"openai/gpt-4o"`). Required
/// at create time — there is intentionally no server-side default,
/// since the right model is task-specific and a stale default leaks
/// into deployments long after it was the right call.
pub const ENV_MODEL: &str = "SWARM_MODEL";
/// Positive include list of built-in tools to register on the agent
/// side, CSV.  Empty / unset means "use dyson defaults".  Sourced
/// from the SPA "Advanced → Tools" picker; persisted on the row
/// and surfaced both via env at hire time and via
/// `/api/admin/configure` on edit (future) so the running dyson
/// can rewrite `skills.builtin.tools` accordingly.
pub const ENV_TOOLS: &str = "SWARM_TOOLS";
/// Optional image-generation model id for the dedicated image provider
/// configured at create time.  The SPA only sends this when
/// `image_generate` is enabled; unset falls back to the operator's
/// existing Gemini default.
pub const ENV_IMAGE_GENERATION_MODEL: &str = "SWARM_IMAGE_GENERATION_MODEL";

#[derive(Debug, Clone)]
pub struct DeletedMcpServer {
    pub owner_id: String,
    pub instance_id: String,
    pub name: String,
    pub runtime: Option<crate::mcp_servers::McpRuntimeSpec>,
}

/// Full URL the dyson agent's `Output::send_artefact` POSTs to when
/// pushing a finalised artefact back to swarm.  Resolved server-side
/// by appending `/v1/internal/ingest/artefact` to `self.proxy_base`,
/// so a single `[hostname]` change at the operator's TOML flips both
/// the chat proxy and the ingest endpoint together.
pub const ENV_INGEST_URL: &str = "SWARM_INGEST_URL";
/// Per-instance bearer the dyson agent stamps on artefact ingest
/// POSTs.  Distinct prefix (`it_`) and provider (`ingest`) from the
/// chat-side `pt_` proxy_token; both live in the same `proxy_tokens`
/// table so `revoke_for_instance` cleans them up together at destroy.
pub const ENV_INGEST_TOKEN: &str = "SWARM_INGEST_TOKEN";

/// Full URL the swarm-mode dyson's background state worker POSTs to
/// when mirroring selected workspace/chat files back to swarm.
pub const ENV_STATE_SYNC_URL: &str = "SWARM_STATE_SYNC_URL";
/// Per-instance bearer the state worker stamps on state-file POSTs.
/// Distinct prefix (`st_`) and provider (`state_sync`) from chat and
/// artefact ingest tokens.
pub const ENV_STATE_SYNC_TOKEN: &str = "SWARM_STATE_SYNC_TOKEN";

/// Path the ingest URL appends to `self.proxy_base`.  Kept as a
/// constant so the route mount in `http::internal_ingest::router`
/// and the env exposure here can't drift.
const INGEST_PATH: &str = "/v1/internal/ingest/artefact";
const STATE_SYNC_PATH: &str = "/v1/internal/state/file";

/// Comma-separated ordered fallback list of model ids.  First entry
/// matches `SWARM_MODEL`; trailing entries let agents that support
/// failover/rotation try alternate models in order.  Optional —
/// agents that only read `SWARM_MODEL` ignore this.
pub const ENV_MODELS: &str = "SWARM_MODELS";

/// Standard env-var triple that HTTP clients (curl, requests, urllib3,
/// reqwest, axios, etc.) honour for outbound traffic routing.  Pointed
/// at the host-resident dyson-egress-proxy on `mvm_gateway_ip:3128` so cube
/// outbound TCP transits the host's kernel TCP stack instead of the
/// eBPF SNAT path that some upstream networks (Google, GitHub via
/// Microsoft) silently drop.  See
/// `deploy/templates/dyson-egress-proxy.service.tmpl` for the proxy unit.
///
/// Injected only for policies that allow generic public egress
/// (`Open`, `NoLocalNet`, `Denylist`).  `Airgap` and `Allowlist` keep
/// these unset so a cube can't accidentally tunnel through the proxy
/// and bypass its stricter allow-list.
pub const ENV_HTTPS_PROXY: &str = "HTTPS_PROXY";
pub const ENV_HTTP_PROXY: &str = "HTTP_PROXY";
/// Hosts that must NOT go via the proxy: the swarm `/llm` endpoint,
/// the cube-proxy DNS resolver, and the loopbacks.  Without this the
/// dyson agent's calls back to swarm would attempt CONNECT through
/// the host egress proxy instead of using the direct, policy-owned path.
pub const ENV_NO_PROXY: &str = "NO_PROXY";
/// Lowercase variants exist purely because some tools (most notably
/// curl + libcurl-based bindings) only honour the lowercase names,
/// while others only honour the uppercase.  Set both.
pub const ENV_HTTPS_PROXY_LC: &str = "https_proxy";
pub const ENV_HTTP_PROXY_LC: &str = "http_proxy";
pub const ENV_NO_PROXY_LC: &str = "no_proxy";

/// The proxy URL cubes should target.  `169.254.68.5` is the eBPF
/// `mvm_gateway_ip` — the cube routes it via its default gateway and
/// the eBPF program DNATs the destination to `cubegw0_ip`
/// (`192.168.0.1`) where dyson-egress-proxy listens.
pub const CUBE_HTTP_PROXY_URL: &str = "http://169.254.68.5:3128";
/// `NO_PROXY` value matching what the agent already needs to reach
/// directly: swarm's /llm endpoint (same host, port 8080), the local
/// CoreDNS resolver, and loopbacks.
pub const CUBE_NO_PROXY: &str = "169.254.68.5,169.254.254.53,127.0.0.1,localhost";

/// Sentinel `owner_id` used by system-internal flows (TTL sweeper, probe
/// loop, proxy resolving via `proxy_token`) to bypass tenant filtering.
/// User-facing routes never pass this — the auth middleware resolves the
/// caller's real `user_id` and that's what flows in.
pub const SYSTEM_OWNER: &str = "*";

/// Build the `system_secrets` name for an instance's per-instance
/// configure secret (Stage 8).  Used by `instance.create` /
/// `instance.destroy` and the Stage-8.3 patch path; central so
/// rename mistakes can't desync.
pub fn configure_secret_name(instance_id: &str) -> String {
    format!("instance.{instance_id}.configure")
}

/// Retry the dyson reconfigure call with exponential-ish backoff —
/// the sandbox is `Live` by the time this fires, but the dyson HTTP
/// server inside (and the cubeproxy nginx in front of it) can take a
/// beat to settle, especially right after a fresh template is
/// registered: cubeproxy's per-sandbox upstream routing is lazily
/// populated and the first POST through can land before nginx has
/// the route, surfacing as a 502 Bad Gateway.
///
/// Total budget: ~75s.  Backoff: 0.5s, 1s, 2s, 4s, 8s, 8s, 8s, 8s, 8s,
/// 8s, 8s, 8s — caps at 8s once we're past the cube cold-start window.
/// The previous 15s budget routinely lost the race for new instances on
/// freshly-promoted templates: every push got 502 Bad Gateway, the
/// dyson kept its warmup-placeholder dyson.json, and the first turn
/// 401'd against `api.openai.com`.  See the regression test in
/// `controller::http::routes::turns` (dyson side) that ensures the
/// per-chat reloader picks up dyson.json on the next turn even after
/// a delayed reconfigure success.
pub async fn push_with_retry(
    r: &dyn DysonReconfigurer,
    instance_id: &str,
    sandbox_id: &str,
    body: &ReconfigureBody,
) -> Result<(), String> {
    let mut delay = std::time::Duration::from_millis(500);
    let mut last_err = String::new();
    for attempt in 0..12 {
        match r.push(instance_id, sandbox_id, body).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                tracing::debug!(
                    attempt,
                    instance = %instance_id,
                    error = %last_err,
                    "reconfigure: retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(8));
            }
        }
    }
    Err(last_err)
}

/// Same cubeproxy warm-up race as [`push_with_retry`], but for the
/// reset replay endpoint.  Reset calls this before the final configure
/// push enables the background state-sync worker, so losing the first
/// `/api/admin/state/file` POST to a transient 502 would otherwise
/// abort an otherwise healthy reset.
async fn restore_state_file_with_retry(
    r: &dyn DysonReconfigurer,
    instance_id: &str,
    sandbox_id: &str,
    body: &RestoreStateFileBody,
) -> Result<(), String> {
    let mut delay = std::time::Duration::from_millis(500);
    let mut last_err = String::new();
    for attempt in 0..12 {
        match r.restore_state_file(instance_id, sandbox_id, body).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                tracing::debug!(
                    attempt,
                    instance = %instance_id,
                    namespace = %body.namespace,
                    path = %body.path,
                    error = %last_err,
                    "restore-state-file: retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(8));
            }
        }
    }
    Err(last_err)
}

#[derive(Clone)]
pub struct InstanceService {
    cube: Arc<dyn CubeClient>,
    instances: Arc<dyn InstanceStore>,
    tokens: Arc<dyn TokenStore>,
    /// Public base URL of the swarm's `/llm/` proxy mount, e.g.
    /// `http://swarm:8080/llm`.
    proxy_base: String,
    /// Dyson reconfigurer — lets us push SWARM_MODEL / SWARM_TASK /
    /// SWARM_NAME into a freshly-created sandbox via Dyson's
    /// `/api/admin/configure` endpoint.  Stage 8 fix for cube's
    /// snapshot/restore freezing the dyson process's env at warmup
    /// time (when SWARM_* are unset → "warmup-placeholder" model).
    /// `None` skips reconfigure entirely (test/local-dev).
    reconfigurer: Option<Arc<dyn DysonReconfigurer>>,
    /// Image-generation defaults pushed at create-time and re-pushed
    /// by the startup sweep.  Hard-coded today (OpenRouter +
    /// Gemini 3 image preview); `None` disables image-gen wiring
    /// entirely so the sweep doesn't fight an operator's manual
    /// override of dyson.json.
    image_gen_defaults: Option<ImageGenDefaults>,
    /// CIDR of the swarm proxy the dyson agent talks to for `/llm`
    /// traffic.  Derived from `cfg.cube_facing_addr` at startup; used
    /// by `network_policy::resolve` for the Airgap and Allowlist
    /// profiles.  `None` for deployments without `cube_facing_addr`
    /// — those deployments can still hire `Open` and `Denylist`
    /// instances; `Airgap` and `Allowlist` will return BadRequest
    /// at hire time with a clear "set cube_facing_addr" message.
    llm_cidr: Option<String>,
    /// DNS resolver for hostname entries in Allowlist/Denylist.
    /// Production uses `DnsHostResolver`; tests inject a mock.
    resolver: Arc<dyn HostResolver>,
    /// Shared SSRF policy for tenant-supplied remote MCP upstream URLs.
    /// The same policy primitives back the BYO LLM upstream guard.
    mcp_upstream_policy: OutboundUrlPolicy,
    /// Per-user encrypted secret store used to persist the upstream
    /// URL + auth credentials for each MCP server attached to an
    /// instance.  `None` skips the persistence step (older callers
    /// and tests that don't exercise MCP).  When set, hire-time MCP
    /// specs are sealed under the owner's cipher and the running
    /// agent only ever sees the swarm proxy URL — never the real
    /// upstream + token.
    mcp_secrets: Option<Arc<UserSecretsService>>,
    /// Swarm-side sealed mirror of dyson workspace/chat state.  When
    /// present, rebuild paths replay this into the fresh sandbox before
    /// cutting traffic over, so redeploys do not surface an empty chat
    /// or workspace while the cube catches up.
    state_files: Option<crate::state_files::StateFiles>,
}

/// Anything that can push swarm-side identity/task/model state to a
/// running dyson sandbox via dyson's `/api/admin/configure` runtime
/// endpoint.  Trait so tests can substitute a recorder without
/// standing up an HTTP server.
///
/// Implementations own (a) the per-instance configure secret (a
/// random 32-hex string sealed in `system_secrets["instance.<id>.configure"]`,
/// generated lazily on first push and reused thereafter) and (b)
/// the cube-trusted HTTP client that reaches the sandbox via
/// cubeproxy.  Dyson hashes the inbound secret with argon2id on
/// first sighting (TOFU) and verifies on every subsequent call.
#[async_trait::async_trait]
pub trait DysonReconfigurer: Send + Sync {
    async fn push(
        &self,
        instance_id: &str,
        sandbox_id: &str,
        body: &ReconfigureBody,
    ) -> Result<(), String>;

    /// Replay one sealed swarm-side state file into a freshly recreated
    /// dyson before its background state-sync worker is enabled.  Default
    /// no-op keeps existing test doubles focused on configure-only paths.
    async fn restore_state_file(
        &self,
        _instance_id: &str,
        _sandbox_id: &str,
        _body: &RestoreStateFileBody,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Read dyson's idle state.  Returns `(idle, in_flight_chats)`.
    /// Used by the upgrade orchestrator's wait-loop to decide whether
    /// `quiesce` is worth attempting yet.  Default impl returns
    /// `Ok((true, 0))` so test mocks that only exercise `push`
    /// continue to compile — production overrides on
    /// `DysonReconfigurerHttp`.
    async fn is_idle(&self, _instance_id: &str, _sandbox_id: &str) -> Result<(bool, u32), String> {
        Ok((true, 0))
    }

    /// Atomically latch dyson's "refuse new turns" flag if and only if
    /// nothing is in flight.  Returns `Ok(true)` on success, `Ok(false)`
    /// if dyson is busy (caller retries later).  Default impl is a
    /// no-op success so unrelated tests don't have to plumb it.
    async fn quiesce(&self, _instance_id: &str, _sandbox_id: &str) -> Result<bool, String> {
        Ok(true)
    }

    /// Release the latch.  Idempotent — used only when an upgrade
    /// attempt aborts AFTER quiesce succeeded so the user's chat
    /// resumes on the original cube instead of being wedged behind
    /// 503.  Default no-op.
    async fn unquiesce(&self, _instance_id: &str, _sandbox_id: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Build the orchestrator-managed env envelope that gets handed to the
/// sandbox at create + restore time. Centralised so the two paths can't
/// drift on which keys they inject.
///
/// `ingest_token` is the per-instance `it_<32hex>` bearer the dyson
/// agent stamps on artefact ingest POSTs to swarm — minted at create
/// (or reused via `lookup_by_instance_for_provider("ingest")` on the
/// rotate paths).  The URL is derived from `proxy_base` so the route
/// path stays in lock-step with the swarm's mount in
/// `http::internal_ingest::router`.
fn managed_env(
    proxy_base: &str,
    proxy_token: &str,
    ingest_token: &str,
    state_sync_token: &str,
    instance_id: &str,
    bearer: &str,
    name: &str,
    task: &str,
    network_policy: &NetworkPolicy,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(ENV_PROXY_URL.into(), proxy_base.to_owned());
    out.insert(ENV_PROXY_TOKEN.into(), proxy_token.to_owned());
    out.insert(ENV_INGEST_URL.into(), build_ingest_url(proxy_base));
    out.insert(ENV_INGEST_TOKEN.into(), ingest_token.to_owned());
    out.insert(ENV_STATE_SYNC_URL.into(), build_state_sync_url(proxy_base));
    out.insert(ENV_STATE_SYNC_TOKEN.into(), state_sync_token.to_owned());
    out.insert(ENV_INSTANCE_ID.into(), instance_id.to_owned());
    out.insert(ENV_BEARER_TOKEN.into(), bearer.to_owned());
    out.insert(ENV_NAME.into(), name.to_owned());
    out.insert(ENV_TASK.into(), task.to_owned());
    // Inject HTTPS_PROXY only for policies that already permit broad
    // outbound traffic.  Airgap + Allowlist intentionally keep the
    // env unset so a sandbox can't tunnel out via the host proxy and
    // dodge its allow-list.  The lowercase names are duplicated
    // because some clients (curl/libcurl) honour only those.
    if policy_permits_generic_egress(network_policy) {
        out.insert(ENV_HTTPS_PROXY.into(), CUBE_HTTP_PROXY_URL.to_owned());
        out.insert(ENV_HTTPS_PROXY_LC.into(), CUBE_HTTP_PROXY_URL.to_owned());
        out.insert(ENV_HTTP_PROXY.into(), CUBE_HTTP_PROXY_URL.to_owned());
        out.insert(ENV_HTTP_PROXY_LC.into(), CUBE_HTTP_PROXY_URL.to_owned());
        out.insert(ENV_NO_PROXY.into(), CUBE_NO_PROXY.to_owned());
        out.insert(ENV_NO_PROXY_LC.into(), CUBE_NO_PROXY.to_owned());
    }
    out
}

fn is_reserved_env_name(name: &str) -> bool {
    if matches!(
        name,
        ENV_MODEL | ENV_MODELS | ENV_TOOLS | ENV_IMAGE_GENERATION_MODEL
    ) {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("SWARM_") || upper.starts_with("DYSON_") {
        return true;
    }
    matches!(
        upper.as_str(),
        "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "NO_PROXY"
            | "ALL_PROXY"
            | "HTTP_PROXY_REQUEST_FULLURI"
            | "HTTPS_PROXY_REQUEST_FULLURI"
    )
}

fn validate_caller_env(env: &BTreeMap<String, String>) -> Result<(), SwarmError> {
    let mut reserved: Vec<&str> = env
        .keys()
        .map(String::as_str)
        .filter(|name| is_reserved_env_name(name))
        .collect();
    reserved.sort_unstable();
    if reserved.is_empty() {
        return Ok(());
    }
    Err(SwarmError::BadRequest(format!(
        "reserved sandbox env keys may not be supplied by callers: {}",
        reserved.join(", ")
    )))
}

fn compose_sandbox_env(
    managed: &BTreeMap<String, String>,
    caller: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, SwarmError> {
    validate_caller_env(caller)?;
    Ok(compose_env(&BTreeMap::new(), managed, caller))
}

fn models_with_primary(existing: Vec<String>, selected: &str) -> Vec<String> {
    let selected = selected.trim();
    if selected.is_empty() {
        return existing;
    }
    let mut out = Vec::with_capacity(existing.len().max(1));
    out.push(selected.to_owned());
    out.extend(existing.into_iter().filter_map(|m| {
        let keep = {
            let trimmed = m.trim();
            !trimmed.is_empty() && trimmed != selected
        };
        keep.then_some(m)
    }));
    out
}

/// Build the `SWARM_INGEST_URL` value from the operator's `proxy_base`
/// (the same value already exposed as `SWARM_PROXY_URL`).  An empty
/// `proxy_base` falls through as an empty URL — dyson reads that as
/// "ingest disabled" and skips the push, same posture as the
/// `proxy_url`-empty case in `dyson swarm`'s warmup path.
fn build_ingest_url(proxy_base: &str) -> String {
    let trimmed = proxy_base.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    // proxy_base is the chat proxy path (`https://<host>/llm`); the
    // ingest endpoint sits one segment up at the swarm apex, so we
    // strip a trailing `/llm` if present and append the route path.
    // Operators can also point `proxy_base` at the apex directly
    // (`https://<host>`) and the strip is a no-op.
    let apex = trimmed.strip_suffix("/llm").unwrap_or(trimmed);
    format!("{apex}{INGEST_PATH}")
}

fn build_state_sync_url(proxy_base: &str) -> String {
    let trimmed = proxy_base.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let apex = trimmed.strip_suffix("/llm").unwrap_or(trimmed);
    format!("{apex}{STATE_SYNC_PATH}")
}

/// True when the network policy allows traffic to arbitrary public
/// destinations.  The proxy env injection gates on this — Airgap and
/// Allowlist exist precisely so the operator can constrain egress,
/// and routing through the host egress proxy would silently widen that.
fn policy_permits_generic_egress(p: &NetworkPolicy) -> bool {
    matches!(
        p,
        NetworkPolicy::Open | NetworkPolicy::NoLocalNet | NetworkPolicy::Denylist { .. }
    )
}

/// CIDRs persisted on the instance row for operator inspection and
/// for the host egress-policy generator.  Allow-style policies need
/// the resolved allow set; denylist needs the resolved deny set so the
/// host proxy can enforce the same frozen DNS decision as Cube.
fn row_policy_cidrs(
    policy: &NetworkPolicy,
    resolved: &network_policy::ResolvedPolicy,
) -> Vec<String> {
    match policy {
        NetworkPolicy::Denylist { .. } => resolved.deny_out.clone(),
        _ => resolved.allow_out.clone(),
    }
}

/// Body sent to dyson's `/api/admin/configure`.  Mirrors the dyson
/// side's `ConfigureBody` — the two structs are intentionally
/// duplicated rather than shared because swarm + dyson are two
/// separate crates and a shared crate just for this would be
/// significant churn for a 4-field struct.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ReconfigureBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// The per-instance proxy_token swarm minted at create-time.
    /// Becomes the value of `providers.<agent.provider>.api_key` in
    /// the running dyson's `dyson.json` — the agent uses this as its
    /// bearer when calling swarm's `/llm/...` endpoints.  Without
    /// this push the api_key stays at the boot-time `warmup-placeholder`
    /// (cube's snapshot/restore freezes `/proc/self/environ`, so the
    /// `SWARM_PROXY_TOKEN` swarm injects on create never reaches
    /// the dyson process — same root cause as the missing `models`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_token: Option<String>,
    /// The /llm proxy URL (`https://<hostname>/llm`).  Patched into
    /// `providers.<agent.provider>.base_url` so the dyson's api client
    /// hits Caddy → swarm instead of the loopback URL frozen at
    /// warmup.  Skipped when None (swarm runs without a hostname).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_base: Option<String>,
    /// Name to register the image-generation provider under.  Mirrors
    /// `ConfigureBody::image_provider_name` on the dyson side.  When
    /// set alongside `image_provider_block` the dyson handler inserts
    /// (or replaces) `providers.<image_provider_name>` in dyson.json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_provider_name: Option<String>,
    /// Full provider entry for the image-generation provider — the
    /// JSON body that lands at `providers.<image_provider_name>`.
    /// Same shape as the chat provider entry: `{ type, base_url,
    /// api_key, models }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_provider_block: Option<serde_json::Value>,
    /// Sets `agent.image_generation_provider`.  Usually equal to
    /// `image_provider_name`, but kept independent so a future caller
    /// could point the field at an already-registered provider
    /// without re-uploading its block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_generation_provider: Option<String>,
    /// Sets `agent.image_generation_model`.  Lets swarm bump the
    /// image-gen model id (e.g. preview → ga rename) without forcing
    /// every operator to re-hire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_generation_model: Option<String>,
    /// Reset `skills` to the loader's defaults (every builtin tool
    /// registered).  Older swarm boots wrote
    /// `skills.builtin.tools = []`, which the dyson loader parses as
    /// "register zero builtin tools".  Setting this flag on a sweep
    /// flips toolless instances back to the full toolbox without a
    /// re-hire.  False on every body that doesn't explicitly want
    /// the reset (rename / models-only updates leave skills alone).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset_skills: bool,
    /// Explicit builtin-tool allowlist.  When `Some`, dyson rewrites
    /// `skills.builtin.tools` to exactly this list.  Empty vec is
    /// meaningful (register zero builtins).  Distinct from
    /// `reset_skills`, which drops the block to inherit defaults.
    /// `tools` wins on the dyson side when both are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Per-server stanzas to write under `mcp_servers.<name>` in
    /// dyson.json.  Each value is the swarm-proxied entry the agent
    /// should talk to: `{ url, headers: { Authorization: "Bearer ..." } }`.
    /// `None` (the default) leaves any existing `mcp_servers` block
    /// untouched; an empty map clears it.  See [`mcp_servers::dyson_json_block`]
    /// for the canonical shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<serde_json::Map<String, serde_json::Value>>,
    /// Full URL the dyson agent's `Output::send_artefact` POSTs to.
    /// Mirrors `SWARM_INGEST_URL` in the env envelope; pushed via
    /// `/api/admin/configure` because the cube's snapshot/restore
    /// freezes `/proc/self/environ` at warmup time, same root cause
    /// as `proxy_token` / `proxy_base` already need a configure-push.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_url: Option<String>,
    /// Per-instance `it_<32hex>` bearer for the ingest endpoint.
    /// Mirrors `SWARM_INGEST_TOKEN` in the env envelope.  None on a
    /// configure-push for an instance that pre-dates the ingest token
    /// (legacy rows: dyson skips the push if the token is unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_token: Option<String>,
    /// Full URL the swarm-mode dyson's state mirror worker POSTs to.
    /// Mirrors `SWARM_STATE_SYNC_URL`; pushed for the same warmup-env
    /// freeze reason as `ingest_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_url: Option<String>,
    /// Per-instance `st_<32hex>` bearer for the state-file endpoint.
    /// Mirrors `SWARM_STATE_SYNC_TOKEN`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreStateFileBody {
    pub namespace: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

/// Image-generation defaults a swarm-managed dyson should run with.
/// Pushed at `create()` time and re-pushed by the startup sweep
/// (`rewire_image_generation_all`) so existing instances inherit
/// changes after a swarm redeploy without operator intervention.
///
/// `provider_block` is whatever JSON shape dyson's loader expects for
/// a provider entry; today that's `{ "type", "base_url", "api_key",
/// "models" }`.  The orchestrator templates it with the swarm's
/// `/llm/openrouter` proxy URL and the per-instance proxy_token at
/// the call site so the running dyson can use the same swarm hop the
/// chat path uses.
#[derive(Debug, Clone)]
pub struct ImageGenDefaults {
    pub provider_name: String,
    pub provider_type: String,
    pub model: String,
}

impl ImageGenDefaults {
    /// Default wiring: a second OpenRouter provider entry pointed at
    /// the same `/llm/openrouter` swarm proxy as chat, defaulting to
    /// the Gemini 3 image preview.  Centralised here (and mirrored in
    /// the `dyson swarm` boot writer) so a future bump is a one-line
    /// constant change in two known files.
    pub fn openrouter_gemini3_image() -> Self {
        Self {
            provider_name: "openrouter-image".to_string(),
            provider_type: "openrouter".to_string(),
            model: "google/gemini-3-pro-image-preview".to_string(),
        }
    }

    /// Render the provider block dyson.json expects.  `proxy_base`
    /// already includes the `/openrouter` segment (built by
    /// [`InstanceService::image_proxy_base`]) and `api_key` is the
    /// per-instance proxy_token.  Both pieces are required — without
    /// the swarm hop the dyson would talk to upstream OpenRouter
    /// directly with a token OpenRouter doesn't recognise.
    pub fn provider_block(&self, proxy_base: &str, api_key: &str) -> serde_json::Value {
        serde_json::json!({
            "type": self.provider_type,
            "base_url": proxy_base,
            "api_key": api_key,
            "models": [self.model],
        })
    }
}

impl InstanceService {
    pub fn new(
        cube: Arc<dyn CubeClient>,
        instances: Arc<dyn InstanceStore>,
        tokens: Arc<dyn TokenStore>,
        proxy_base: impl Into<String>,
    ) -> Self {
        Self {
            cube,
            instances,
            tokens,
            proxy_base: proxy_base.into(),
            reconfigurer: None,
            // Default to ON: every newly-deployed swarm rewires the
            // image-gen path on its dysons by default.  Tests that
            // want to suppress it call `with_image_gen_defaults(None)`
            // to keep their `pushed` recordings tight.
            image_gen_defaults: Some(ImageGenDefaults::openrouter_gemini3_image()),
            llm_cidr: None,
            resolver: Arc::new(DnsHostResolver),
            mcp_upstream_policy: OutboundUrlPolicy::default(),
            mcp_secrets: None,
            state_files: None,
        }
    }

    /// Builder-style: stamp the swarm-proxy CIDR derived from
    /// `cfg.cube_facing_addr` so the network-policy resolver can
    /// build Airgap / Allowlist allowOut entries.  Pass `None` for
    /// deployments without a stable cube-facing IP — Airgap and
    /// Allowlist hires will fail with a clear error in that case.
    pub fn with_llm_cidr(mut self, cidr: Option<String>) -> Self {
        self.llm_cidr = cidr;
        self
    }

    /// Builder-style: substitute a host resolver.  Production uses
    /// the default `DnsHostResolver`; tests inject a `BTreeMap`-
    /// backed mock so they don't depend on real DNS.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Builder-style: override remote MCP upstream URL policy.
    pub fn with_mcp_upstream_policy(mut self, policy: OutboundUrlPolicy) -> Self {
        self.mcp_upstream_policy = policy;
        self
    }

    /// Builder-style: plug in the dyson reconfigurer so post-create
    /// pushes the env envelope through dyson's runtime endpoint.
    pub fn with_reconfigurer(mut self, r: Arc<dyn DysonReconfigurer>) -> Self {
        self.reconfigurer = Some(r);
        self
    }

    /// Builder-style: override the image-generation defaults pushed
    /// to dysons.  `None` disables image-gen wiring entirely (e.g.
    /// tests that don't want to assert on the extra body fields).
    pub fn with_image_gen_defaults(mut self, defaults: Option<ImageGenDefaults>) -> Self {
        self.image_gen_defaults = defaults;
        self
    }

    /// Builder-style: plug in the per-user secrets store so the create
    /// path can persist MCP server records.  `None` (the default)
    /// keeps `CreateRequest.mcp_servers` accepted but ignored — useful
    /// for tests that don't need the proxy path.
    pub fn with_mcp_secrets(mut self, secrets: Arc<UserSecretsService>) -> Self {
        self.mcp_secrets = Some(secrets);
        self
    }

    /// Builder-style: plug in the sealed workspace/chat mirror used by
    /// rebuild paths.  Create/clone keep their existing behaviour; only
    /// paths that replace an existing sandbox use this as the durable
    /// source before state sync is re-enabled.
    pub fn with_state_files(mut self, state_files: crate::state_files::StateFiles) -> Self {
        self.state_files = Some(state_files);
        self
    }

    /// Build the `<proxy_base>/openrouter` URL the image-gen provider
    /// uses for its `base_url`.  Same shape as `swarm_provider_base_url`
    /// on the dyson-binary side — the trailing `/v1` is added by
    /// dyson's `OpenRouterImageProvider` when it builds the request.
    fn image_proxy_base(&self) -> String {
        format!("{}/openrouter", self.proxy_base.trim_end_matches('/'))
    }

    async fn validate_mcp_server_spec(&self, spec: &McpServerSpec) -> Result<(), SwarmError> {
        self.validate_mcp_url(&spec.url).await?;
        self.validate_mcp_auth_urls(&spec.auth).await
    }

    async fn validate_mcp_entry(
        &self,
        entry: &mcp_servers::McpServerEntry,
    ) -> Result<(), SwarmError> {
        match entry.runtime.as_ref() {
            Some(mcp_servers::McpRuntimeSpec::DockerStdio { .. }) => {}
            Some(mcp_servers::McpRuntimeSpec::HttpStreamable { url, .. }) => {
                self.validate_mcp_url(url).await?;
            }
            None => {
                self.validate_mcp_url(&entry.url).await?;
            }
        }
        self.validate_mcp_auth_urls(&entry.auth).await
    }

    async fn validate_mcp_auth_urls(&self, auth: &McpAuthSpec) -> Result<(), SwarmError> {
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
            self.validate_mcp_url(url).await?;
        }
        Ok(())
    }

    async fn validate_mcp_url(&self, url: &str) -> Result<(), SwarmError> {
        validate_outbound_url(&self.mcp_upstream_policy, url)
            .await
            .map(|_| ())
            .map_err(|e| SwarmError::BadRequest(format!("mcp upstream URL rejected: {e}")))
    }

    fn configure_body_for_existing_row(
        &self,
        source: &InstanceRow,
        proxy_token: &str,
        ingest_token: &str,
        state_sync_token: &str,
    ) -> ReconfigureBody {
        ReconfigureBody {
            name: Some(source.name.clone()).filter(|s| !s.is_empty()),
            task: Some(source.task.clone()).filter(|s| !s.is_empty()),
            models: source.models.clone(),
            instance_id: Some(source.id.clone()),
            proxy_token: Some(proxy_token.to_owned()),
            proxy_base: Some(format!(
                "{}/openrouter",
                self.proxy_base.trim_end_matches('/')
            )),
            ingest_url: {
                let u = build_ingest_url(&self.proxy_base);
                if u.is_empty() { None } else { Some(u) }
            },
            ingest_token: Some(ingest_token.to_owned()),
            state_sync_url: {
                let u = build_state_sync_url(&self.proxy_base);
                if u.is_empty() { None } else { Some(u) }
            },
            state_sync_token: Some(state_sync_token.to_owned()),
            image_provider_name: self
                .image_gen_defaults
                .as_ref()
                .map(|d| d.provider_name.clone()),
            image_provider_block: self
                .image_gen_defaults
                .as_ref()
                .map(|d| d.provider_block(&self.image_proxy_base(), proxy_token)),
            image_generation_provider: self
                .image_gen_defaults
                .as_ref()
                .map(|d| d.provider_name.clone()),
            image_generation_model: self.image_gen_defaults.as_ref().map(|d| d.model.clone()),
            reset_skills: source.tools.is_empty(),
            tools: (!source.tools.is_empty()).then(|| source.tools.clone()),
            mcp_servers: None,
        }
    }

    async fn mcp_servers_block_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
        proxy_token: &str,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let Some(secrets) = self.mcp_secrets.as_ref() else {
            return None;
        };
        let names = match mcp_servers::list_names(secrets, owner_id, instance_id).await {
            Ok(names) if !names.is_empty() => names,
            Ok(_) => return None,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    instance = %instance_id,
                    "mcp sync: list failed; skipping mcp_servers configure block"
                );
                return None;
            }
        };
        let mut block = serde_json::Map::with_capacity(names.len());
        for name in names {
            block.insert(
                name.clone(),
                mcp_servers::dyson_json_block(instance_id, &name, &self.proxy_base, proxy_token),
            );
        }
        Some(block)
    }

    async fn clear_identity_fields_when_mirror_is_authoritative(
        &self,
        body: &mut ReconfigureBody,
        owner_id: &str,
        instance_id: &str,
        state_files: &crate::state_files::StateFileService,
    ) -> Result<(), SwarmError> {
        let Some(row) = state_files
            .find(instance_id, "workspace", "IDENTITY.md")
            .await
            .map_err(|e| SwarmError::Internal(format!("find mirrored identity: {e}")))?
        else {
            return Ok(());
        };
        if row.owner_id != owner_id {
            return Err(SwarmError::Internal(format!(
                "state row owner mismatch for {}:{}",
                row.namespace, row.path
            )));
        }
        body.name = None;
        body.task = None;
        Ok(())
    }

    /// Re-push the image-generation defaults to every Live instance.
    /// Idempotent — a dyson that already has the right values gets
    /// the same JSON written back.  Best-effort: a sandbox that's
    /// asleep / mid-restore will fail the push and be retried on the
    /// next sweep.  Returns `(visited, succeeded)` so the caller can
    /// log a one-line summary.
    pub async fn rewire_image_generation_all(&self) -> Result<(usize, usize), SwarmError> {
        let Some(defaults) = self.image_gen_defaults.clone() else {
            return Ok((0, 0));
        };
        let Some(reconfigurer) = self.reconfigurer.as_ref() else {
            return Ok((0, 0));
        };
        let proxy_base = self.image_proxy_base();
        let live = self
            .instances
            .list(
                SYSTEM_OWNER,
                ListFilter {
                    status: Some(InstanceStatus::Live),
                    include_destroyed: false,
                },
            )
            .await?;
        let mut succeeded = 0usize;
        for row in &live {
            let Some(sandbox_id) = &row.cube_sandbox_id else {
                tracing::debug!(
                    instance = %row.id,
                    "rewire-image-gen: skipping — no cube_sandbox_id on row"
                );
                continue;
            };
            // Use the per-instance proxy_token (re-mint NOT needed —
            // the existing token is still valid).  Look it up from
            // the token store.
            let token = match self.tokens.lookup_by_instance(&row.id).await {
                Ok(Some(t)) => t,
                Ok(None) => {
                    tracing::debug!(
                        instance = %row.id,
                        "rewire-image-gen: skipping — no proxy_token (instance pre-Stage-8?)"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        instance = %row.id,
                        error = %e,
                        "rewire-image-gen: token lookup failed — skipping"
                    );
                    continue;
                }
            };
            let state_sync_token = match self
                .tokens
                .lookup_by_instance_for_provider(&row.id, crate::db::tokens::STATE_SYNC_PROVIDER)
                .await
            {
                Ok(Some(t)) => t,
                Ok(None) => match self.tokens.mint_state_sync(&row.id).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(
                            instance = %row.id,
                            error = %e,
                            "rewire-image-gen: state-sync token mint failed — skipping"
                        );
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        instance = %row.id,
                        error = %e,
                        "rewire-image-gen: state-sync token lookup failed — skipping"
                    );
                    continue;
                }
            };
            // Re-render the mcp_servers block on every sweep so any
            // change to the proxied URL propagates into running dysons
            // without operator intervention.
            let mcp_servers = self
                .mcp_servers_block_for_instance(&row.owner_id, &row.id, &token)
                .await;
            let body = ReconfigureBody {
                image_provider_name: Some(defaults.provider_name.clone()),
                image_provider_block: Some(defaults.provider_block(&proxy_base, &token)),
                image_generation_provider: Some(defaults.provider_name.clone()),
                image_generation_model: Some(defaults.model.clone()),
                // Preserve the admin-selected built-in tool allowlist
                // during the startup rewire sweep.  Empty row.tools is
                // still the legacy/default sentinel, so those instances
                // get reset back to Dyson defaults; non-empty rows must
                // be pushed as an explicit allowlist or a redeploy
                // re-enables tools the operator deliberately disabled.
                reset_skills: row.tools.is_empty(),
                tools: (!row.tools.is_empty()).then(|| row.tools.clone()),
                state_sync_url: {
                    let u = build_state_sync_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                state_sync_token: Some(state_sync_token),
                mcp_servers,
                ..Default::default()
            };
            match reconfigurer.push(&row.id, sandbox_id, &body).await {
                Ok(()) => {
                    succeeded += 1;
                    tracing::debug!(instance = %row.id, "rewire-image-gen: pushed");
                }
                Err(e) => {
                    tracing::warn!(
                        instance = %row.id,
                        error = %e,
                        "rewire-image-gen: push failed (will retry next sweep)"
                    );
                }
            }
        }
        let visited = live.len();
        tracing::info!(visited, succeeded, "rewire-image-gen: sweep complete");
        Ok((visited, succeeded))
    }

    /// Snapshot+restore every Live instance whose `template_id` doesn't
    /// match `target_template_id` onto a fresh sandbox built from the
    /// target template, then destroy the source.  Closes the gap left
    /// by config-only rewires: when the bug lives in the dyson binary
    /// (new ConfigureBody fields, tool registration, the no-skills
    /// boot fix), no `/api/admin/configure` payload can rescue an
    /// instance still running an old binary.  The cube template is
    /// what pins the binary; only a fresh sandbox cuts the dependency.
    ///
    /// The sweep is **not atomic** — a crash between restore and
    /// destroy must be safely re-runnable.  `set_rotated_to` is
    /// stamped on the source row right after the new instance reaches
    /// Live, before the destroy step runs.  On a re-run, sources that
    /// already carry `rotated_to` skip the snapshot+restore (which
    /// already produced the successor) and only retry the destroy.
    /// Sources without the marker get the full pipeline.
    ///
    /// Pre-Stage-8 rows (no `cube_sandbox_id`, no proxy_token row) are
    /// skipped silently — they predate the snapshot/restore wiring and
    /// can't be rotated by the same code path.
    ///
    /// Best-effort per row: an individual failure (snapshot, restore,
    /// destroy) is recorded in `RotateReport.failed` and the sweep
    /// proceeds to the next candidate.  Successive boots continue to
    /// retry — failures aren't sticky beyond the marker invariant.
    ///
    /// Architectural note: this method takes `&SnapshotService` as a
    /// parameter rather than holding it on `InstanceService` because
    /// `SnapshotService::new` already takes `Arc<InstanceService>`,
    /// so embedding the snapshot service as a field would close the
    /// loop.  Callers in `main.rs` already hold both `Arc`s by the
    /// time the startup sweep fires.
    pub async fn rotate_binary_all(
        &self,
        snapshot_svc: &crate::snapshot::SnapshotService,
        target_template_id: &str,
    ) -> Result<RotateReport, SwarmError> {
        if target_template_id.trim().is_empty() {
            return Err(SwarmError::PolicyDenied(
                "rotate-binary: target_template_id must be non-empty".into(),
            ));
        }
        let live = self
            .instances
            .list(
                SYSTEM_OWNER,
                ListFilter {
                    status: Some(InstanceStatus::Live),
                    include_destroyed: false,
                },
            )
            .await?;
        let mut report = RotateReport::default();
        for row in live {
            // Already on the target binary — no work.
            if row.template_id == target_template_id {
                continue;
            }
            // Pre-Stage-8 row: no cube sandbox to snapshot.  Skip
            // silently so a sweep across a mixed-vintage deployment
            // doesn't get stuck on an ancient row that operators have
            // already written off.
            let Some(sandbox_id) = row.cube_sandbox_id.as_deref().filter(|s| !s.is_empty()) else {
                tracing::debug!(
                    instance = %row.id,
                    "rotate-binary: skipping — no cube_sandbox_id (pre-Stage-8)"
                );
                continue;
            };
            report.visited += 1;
            tracing::info!(
                instance = %row.id,
                from_template = %row.template_id,
                to_template = %target_template_id,
                already_rotated = row.rotated_to.is_some(),
                "rotate-binary: visiting outdated instance"
            );
            match self
                .rotate_one(snapshot_svc, &row, sandbox_id, target_template_id)
                .await
            {
                Ok(()) => {
                    report.rotated += 1;
                    tracing::info!(
                        instance = %row.id,
                        "rotate-binary: completed"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        instance = %row.id,
                        error = %err,
                        "rotate-binary: failed (will retry next sweep)"
                    );
                    report.failed.push((row.id.clone(), err));
                }
            }
        }
        tracing::info!(
            visited = report.visited,
            rotated = report.rotated,
            failed = report.failed.len(),
            "rotate-binary: sweep complete"
        );
        Ok(report)
    }

    /// Per-row state machine for [`rotate_binary_all`].  Delegates to
    /// [`rotate_in_place`] so DNS, bearer token, and secrets all
    /// survive the rotation.  Returns Err with a `String` so the
    /// sweep's `RotateReport.failed` can include the reason without
    /// the typed `SwarmError` machinery.
    async fn rotate_one(
        &self,
        snapshot_svc: &crate::snapshot::SnapshotService,
        source: &InstanceRow,
        _source_sandbox_id: &str,
        target_template_id: &str,
    ) -> Result<(), String> {
        self.rotate_in_place(
            &source.owner_id,
            &source.id,
            snapshot_svc,
            target_template_id,
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// Change the egress profile on a Live instance.
    ///
    /// CubeAPI doesn't expose a runtime PATCH for the eBPF egress
    /// maps (see the swarm README's "Network policies" section), so
    /// the implementation pivots to a fresh cube under the SAME swarm
    /// id via [`rotate_in_place`] — DNS, bearer token, secrets, and
    /// webhook URLs all survive.  Workspace state survives via the
    /// snapshot.
    ///
    /// Owner-scoped via `get_for_owner`; admin uses `SYSTEM_OWNER`/`"*"`
    /// to override.  Validates the new policy BEFORE taking a
    /// snapshot — a malformed CIDR or unresolvable hostname returns
    /// `BadRequest` and leaves the existing instance untouched.
    pub async fn change_network_policy(
        &self,
        owner_id: &str,
        instance_id: &str,
        snapshot_svc: &crate::snapshot::SnapshotService,
        new_policy: NetworkPolicy,
    ) -> Result<InstanceRow, SwarmError> {
        // Read the row up front so the no-op check is opaque to
        // callers — the same reason `rotate_in_place` enforces it.
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.network_policy == new_policy {
            return Err(SwarmError::BadRequest(
                "instance already has this network policy".into(),
            ));
        }
        let target_template = source.template_id.clone();
        self.rotate_in_place(
            owner_id,
            instance_id,
            snapshot_svc,
            &target_template,
            Some(new_policy),
        )
        .await
    }

    /// In-place rotation: pivot a Live row onto a new template (and
    /// optionally a new network policy) WITHOUT changing the row's
    /// swarm id.  Snapshot the workspace, spin up a fresh cube under
    /// the new template + same swarm id, swap `cube_sandbox_id` +
    /// `template_id` (+ policy when supplied) on the row, push the
    /// configure envelope, then destroy the old cube.
    ///
    /// Side effects on the row that DO survive the rotation:
    /// `id`, `name`, `task`, `bearer_token`, `models`, `tools`,
    /// `pinned`, `expires_at`, `created_at`, owner, and MCP server records
    /// keyed through user secret storage.
    ///
    /// What changes: `cube_sandbox_id` (fresh), `template_id` (target),
    /// optionally `network_policy` + `network_policy_cidrs`,
    /// `last_active_at` (now), and the probe fields are reset (the new
    /// cube has no probe history yet).
    ///
    /// Returns the post-rotation row.  Caller-visible identity is the
    /// same id they supplied — no successor surfaces, DNS keeps
    /// resolving, bookmarks survive.
    pub async fn rotate_in_place(
        &self,
        owner_id: &str,
        instance_id: &str,
        snapshot_svc: &crate::snapshot::SnapshotService,
        new_template_id: &str,
        new_network_policy: Option<NetworkPolicy>,
    ) -> Result<InstanceRow, SwarmError> {
        if new_template_id.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot rotate a destroyed instance".into(),
            ));
        }
        let old_sandbox_id = source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::BadRequest(
                    "instance has no live cube sandbox; rotation requires a Live row".into(),
                )
            })?
            .to_owned();

        // Pick the policy: caller override or the row's existing one.
        // Validate before snapshotting — bad input must fail fast.
        let target_policy = new_network_policy.unwrap_or(source.network_policy.clone());
        let resolved =
            network_policy::resolve(&target_policy, self.llm_cidr.as_deref(), &*self.resolver)
                .await?;

        let no_op_template = source.template_id == new_template_id;
        let no_op_policy = source.network_policy == target_policy;
        if no_op_template && no_op_policy {
            return Err(SwarmError::BadRequest(
                "rotation is a no-op (same template, same network policy)".into(),
            ));
        }

        tracing::info!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %new_template_id,
            from_policy = %source.network_policy.kind_str(),
            to_policy = %target_policy.kind_str(),
            "rotate-in-place: starting snapshot+swap+destroy pipeline"
        );

        // Phase 0: wait for dyson to be naturally idle, then atomically
        // latch the "refuse new turns" flag so the snapshot in Phase 1
        // captures a consistent disk state.  Without this, a turn the
        // user starts during the snapshot would write to disk after the
        // snapshot moment and be lost when we swap to the new cube.
        //
        // The poll cadence (every 30s) matches the cube cold-boot time
        // — we expect to wait roughly one VM lifetime for the user to
        // pause naturally.  If the instance is perpetually busy past
        // the timeout, bail without quiescing so the next sweep retries.
        // Best-effort: a reconfigurer error (network blip, dyson down)
        // logs a warning and proceeds without the gate — rotation is
        // still better than no rotation, and the snapshot mechanism is
        // best-effort consistent under live load anyway.
        let mut quiesced = false;
        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            const POLL_INTERVAL_SECS: u64 = 30;
            const MAX_WAIT_SECS: u64 = 300; // 5 idle-checks
            let started = std::time::Instant::now();
            loop {
                match reconfigurer.is_idle(&source.id, &old_sandbox_id).await {
                    Ok((true, _)) => {
                        match reconfigurer.quiesce(&source.id, &old_sandbox_id).await {
                            Ok(true) => {
                                quiesced = true;
                                tracing::info!(
                                    instance = %source.id,
                                    sandbox = %old_sandbox_id,
                                    "rotate-in-place: dyson quiesced"
                                );
                                break;
                            }
                            Ok(false) => {
                                tracing::debug!(
                                    instance = %source.id,
                                    "rotate-in-place: quiesce 409'd (turn slipped in); retrying"
                                );
                            }
                            Err(err) => {
                                tracing::warn!(
                                    instance = %source.id,
                                    error = %err,
                                    "rotate-in-place: quiesce errored; rotating without gate"
                                );
                                break;
                            }
                        }
                    }
                    Ok((false, in_flight)) => {
                        tracing::info!(
                            instance = %source.id,
                            in_flight,
                            "rotate-in-place: waiting for dyson to go idle"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            instance = %source.id,
                            error = %err,
                            "rotate-in-place: idle check errored; rotating without gate"
                        );
                        break;
                    }
                }
                if started.elapsed().as_secs() >= MAX_WAIT_SECS {
                    return Err(SwarmError::BadRequest(format!(
                        "instance {} did not go idle within {MAX_WAIT_SECS}s; will retry next sweep",
                        source.id,
                    )));
                }
                tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
        }

        // RAII-ish unquiesce-on-failure: any error path between here
        // and the pointer swap (Phase 4) leaves the user wedged behind
        // 503 until we tell dyson otherwise.  Helper that takes the
        // reconfigurer + sandbox id and best-efforts an unquiesce.
        // The new cube boots unquiesced regardless (the flag is
        // in-memory), so we only need to undo OLD on failure.
        let unquiesce_on_drop = |reason: &str, err: &dyn std::fmt::Display| {
            tracing::warn!(
                instance = %source.id,
                sandbox = %old_sandbox_id,
                error = %err,
                "rotate-in-place: {reason}; unquiescing OLD so user can resume"
            );
        };

        // Phase 1: snapshot the source workspace.
        let snap = match snapshot_svc.snapshot(SYSTEM_OWNER, &source.id).await {
            Ok(s) => s,
            Err(e) => {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("snapshot failed", &e);
                        let _ = rc.unquiesce(&source.id, &old_sandbox_id).await;
                    }
                }
                return Err(e);
            }
        };
        tracing::info!(
            instance = %source.id,
            snapshot = %snap.id,
            sandbox = %old_sandbox_id,
            "rotate-in-place: snapshot taken"
        );

        // Phase 2: build env envelope using the EXISTING bearer + id.
        // The proxy_token is reused — same token that already has a
        // tokens row keyed on this instance id.  Legacy rows missing
        // a token (Stage-7 vintage) get a fresh mint here.
        let proxy_token = match self.tokens.lookup_by_instance(&source.id).await? {
            Some(t) => t,
            None => self.tokens.mint(&source.id, SHARED_PROVIDER).await?,
        };
        // Same lookup-or-mint posture for the ingest token.  Legacy
        // rows that pre-date the ingest token get one minted here so
        // post-rotation the agent's artefact pushes work without an
        // operator re-hire.
        let ingest_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::INGEST_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_ingest(&source.id).await?,
        };
        let state_sync_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::STATE_SYNC_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_state_sync(&source.id).await?,
        };
        let replay_state_files = self.state_files.clone();
        let mut managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &target_policy,
        );
        if replay_state_files.is_some() {
            // The fresh cube must not mirror a template-default or
            // snapshot-stale chat tree back over the durable swarm copy
            // before replay completes. The configure push after replay
            // enables state sync with the same token.
            managed.remove(ENV_STATE_SYNC_URL);
            managed.remove(ENV_STATE_SYNC_TOKEN);
        }
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;

        // Phase 3: spin up a fresh cube under the new template using
        // the snapshot we just took.
        let info = match self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: new_template_id.to_owned(),
                env,
                from_snapshot_path: Some(std::path::PathBuf::from(&snap.path)),
                resolved_policy: resolved.clone(),
            })
            .await
        {
            Ok(i) => i,
            Err(e) => {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("cube create failed", &e);
                        let _ = rc.unquiesce(&source.id, &old_sandbox_id).await;
                    }
                }
                return Err(e.into());
            }
        };
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "rotate-in-place: new cube live"
        );

        if let Some(state_files) = replay_state_files.as_ref() {
            if let Err(err) = self
                .replay_state_files_to_sandbox(
                    owner_id,
                    &source.id,
                    &info.sandbox_id,
                    state_files,
                    true,
                )
                .await
            {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("state replay failed", &err);
                        let _ = rc.unquiesce(&source.id, &old_sandbox_id).await;
                    }
                }
                let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
                return Err(err);
            }

            let reconfigurer = self.reconfigurer.as_ref().ok_or_else(|| {
                SwarmError::PolicyDenied("dyson reconfigurer not configured".into())
            })?;
            let mut body = self.configure_body_for_existing_row(
                &source,
                &proxy_token,
                &ingest_token,
                &state_sync_token,
            );
            self.clear_identity_fields_when_mirror_is_authoritative(
                &mut body,
                owner_id,
                &source.id,
                state_files,
            )
            .await?;
            body.mcp_servers = self
                .mcp_servers_block_for_instance(owner_id, &source.id, &proxy_token)
                .await;
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                if quiesced {
                    unquiesce_on_drop("configure-push failed after state replay", &err);
                    let _ = reconfigurer.unquiesce(&source.id, &old_sandbox_id).await;
                }
                let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
                return Err(SwarmError::Internal(format!(
                    "rotate configure-push failed after state replay: {err}"
                )));
            }
        }

        // Phase 4: swap on the row.  After this commit, DNS for
        // `<id>.<host>` resolves to the new sandbox — that's the
        // user-visible cutover.  After this point, OLD is doomed and
        // we don't need to unquiesce it (it's about to be destroyed).
        if let Err(e) = self
            .instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                new_template_id,
                &target_policy,
                &row_policy_cidrs(&target_policy, &resolved),
                now_secs(),
            )
            .await
        {
            // Roll back: NEW is orphaned, OLD still authoritative;
            // we owe the user an unquiesce on OLD.  Best-effort destroy
            // NEW so we don't leak a cube — the row never pointed at it.
            if quiesced {
                if let Some(rc) = self.reconfigurer.as_ref() {
                    unquiesce_on_drop("DB swap failed", &e);
                    let _ = rc.unquiesce(&source.id, &old_sandbox_id).await;
                }
            }
            if let Err(d) = self.cube.destroy_sandbox(&info.sandbox_id).await {
                tracing::warn!(
                    instance = %source.id,
                    new_sandbox = %info.sandbox_id,
                    error = %d,
                    "rotate-in-place: orphan cube destroy after DB swap failure (janitor will sweep)"
                );
            }
            return Err(e.into());
        }

        // Phase 5: push the configure envelope so the new cube
        // boots out of warmup-placeholder mode.  Mirrors the create
        // path's body shape — name, task, models, image-gen,
        // mcp_servers.  Best-effort: a failure here leaves the row
        // pointing at a Live cube that hasn't been reconfigured yet;
        // the image-gen rewire sweep will retry the non-identity
        // parts on the next swarm restart.
        if replay_state_files.is_none()
            && let Some(reconfigurer) = self.reconfigurer.as_ref()
        {
            let mut body = self.configure_body_for_existing_row(
                &source,
                &proxy_token,
                &ingest_token,
                &state_sync_token,
            );
            body.mcp_servers = self
                .mcp_servers_block_for_instance(owner_id, &source.id, &proxy_token)
                .await;
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                tracing::warn!(
                    instance = %source.id,
                    error = %err,
                    "rotate-in-place: configure-push failed; will be retried by next sweep"
                );
            }
        }

        // Phase 6: destroy the old cube.  Force=true so a stuck
        // cube doesn't leave the row half-live.  This is the only
        // step where a failure has lasting effect — but the swarm
        // row already points to the new sandbox, so subsequent
        // reads are correct; a leaked cube is a janitor problem,
        // not a correctness problem.
        if let Err(err) = self.cube.destroy_sandbox(&old_sandbox_id).await {
            tracing::warn!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                error = %err,
                "rotate-in-place: old cube destroy failed (orphan cube — janitor will sweep)"
            );
        } else {
            tracing::info!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                "rotate-in-place: old cube destroyed"
            );
        }

        // Re-fetch so callers see the post-swap row state.
        self.instances
            .get_for_owner(owner_id, &source.id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    /// Recover a swarm row onto a fresh cube using an already-captured
    /// snapshot.  Unlike [`Self::rotate_in_place`], this does not try to
    /// snapshot the old cube first; it is for operator recovery after the
    /// Cube runtime has been reinstalled and the old sandbox is already
    /// gone or unreliable.  The swarm-side identity survives: DNS,
    /// bearer token, proxy/artifact tokens, per-instance secrets, MCP
    /// records, network policy, name, task, models, and tools all remain
    /// keyed to the same `instance_id`.
    pub async fn restore_snapshot_in_place(
        &self,
        owner_id: &str,
        instance_id: &str,
        snapshot_path: std::path::PathBuf,
        target_template_id: Option<String>,
    ) -> Result<InstanceRow, SwarmError> {
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot recover a destroyed instance".into(),
            ));
        }
        let old_sandbox_id = source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let target_template = target_template_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| source.template_id.clone());
        if target_template.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }

        let resolved = network_policy::resolve(
            &source.network_policy,
            self.llm_cidr.as_deref(),
            &*self.resolver,
        )
        .await?;

        tracing::warn!(
            instance = %source.id,
            old_sandbox = ?old_sandbox_id,
            to_template = %target_template,
            snapshot_path = %snapshot_path.display(),
            "restore-snapshot-in-place: creating replacement cube from deploy snapshot"
        );

        let proxy_token = match self.tokens.lookup_by_instance(&source.id).await? {
            Some(t) => t,
            None => self.tokens.mint(&source.id, SHARED_PROVIDER).await?,
        };
        let ingest_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::INGEST_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_ingest(&source.id).await?,
        };
        let state_sync_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::STATE_SYNC_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_state_sync(&source.id).await?,
        };
        let managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &source.network_policy,
        );
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;

        let info = self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: target_template.clone(),
                env,
                from_snapshot_path: Some(snapshot_path),
                resolved_policy: resolved.clone(),
            })
            .await?;
        tracing::info!(
            instance = %source.id,
            new_sandbox = %info.sandbox_id,
            "restore-snapshot-in-place: replacement cube live"
        );

        if let Err(e) = self
            .instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                &target_template,
                &source.network_policy,
                &row_policy_cidrs(&source.network_policy, &resolved),
                now_secs(),
            )
            .await
        {
            if let Err(d) = self.cube.destroy_sandbox(&info.sandbox_id).await {
                tracing::warn!(
                    instance = %source.id,
                    new_sandbox = %info.sandbox_id,
                    error = %d,
                    "restore-snapshot-in-place: orphan cube destroy after DB swap failure"
                );
            }
            return Err(e.into());
        }

        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            let mut body = ReconfigureBody {
                name: Some(source.name.clone()).filter(|s| !s.is_empty()),
                task: Some(source.task.clone()).filter(|s| !s.is_empty()),
                models: source.models.clone(),
                instance_id: Some(source.id.clone()),
                proxy_token: Some(proxy_token.clone()),
                proxy_base: Some(format!(
                    "{}/openrouter",
                    self.proxy_base.trim_end_matches('/')
                )),
                ingest_url: {
                    let u = build_ingest_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                ingest_token: Some(ingest_token.clone()),
                state_sync_url: {
                    let u = build_state_sync_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                state_sync_token: Some(state_sync_token.clone()),
                image_provider_name: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_name.clone()),
                image_provider_block: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_block(&self.image_proxy_base(), &proxy_token)),
                image_generation_provider: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_name.clone()),
                image_generation_model: self.image_gen_defaults.as_ref().map(|d| d.model.clone()),
                reset_skills: source.tools.is_empty(),
                tools: (!source.tools.is_empty()).then(|| source.tools.clone()),
                mcp_servers: None,
            };
            body.mcp_servers = self
                .mcp_servers_block_for_instance(owner_id, &source.id, &proxy_token)
                .await;
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                tracing::warn!(
                    instance = %source.id,
                    error = %err,
                    "restore-snapshot-in-place: configure-push failed; will be retried by next sweep"
                );
            }
        }

        if let Some(old) = old_sandbox_id.filter(|old| old != &info.sandbox_id)
            && let Err(err) = self.cube.destroy_sandbox(&old).await
        {
            tracing::warn!(
                instance = %source.id,
                old_sandbox = %old,
                error = %err,
                "restore-snapshot-in-place: old cube destroy failed or old cube was already gone"
            );
        }

        self.instances
            .get_for_owner(owner_id, &source.id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    /// Snapshot-less variant of [`Self::rotate_in_place`].  Spins up a
    /// fresh cube under `new_template_id` using the same swarm id,
    /// bearer, name, task, models, tools, and per-instance secrets;
    /// swaps the row; pushes the configure envelope; destroys the
    /// old cube.  No cube snapshot is taken; when the sealed swarm-side
    /// state mirror is configured, workspace/chat files are replayed
    /// before cutover so the user never lands in an empty fresh rootfs.
    /// Without that mirror this remains a destructive escape hatch.
    ///
    /// Used as the operator escape hatch when the cube snapshot path
    /// is broken but a template swap still has to happen.  The DNS,
    /// bearer, and DB-side metadata all survive identically to the
    /// snapshot-preserving rotation.
    pub async fn recreate_in_place(
        &self,
        owner_id: &str,
        instance_id: &str,
        new_template_id: &str,
        new_network_policy: Option<NetworkPolicy>,
    ) -> Result<InstanceRow, SwarmError> {
        if new_template_id.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot recreate a destroyed instance".into(),
            ));
        }
        let old_sandbox_id = source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::BadRequest(
                    "instance has no live cube sandbox; recreate requires a Live row".into(),
                )
            })?
            .to_owned();
        let target_policy = new_network_policy.unwrap_or(source.network_policy.clone());
        let resolved =
            network_policy::resolve(&target_policy, self.llm_cidr.as_deref(), &*self.resolver)
                .await?;

        tracing::warn!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %new_template_id,
            state_replay = self.state_files.is_some(),
            "recreate-in-place: starting clean swap"
        );

        let proxy_token = match self.tokens.lookup_by_instance(&source.id).await? {
            Some(t) => t,
            None => self.tokens.mint(&source.id, SHARED_PROVIDER).await?,
        };
        let ingest_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::INGEST_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_ingest(&source.id).await?,
        };
        let state_sync_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::STATE_SYNC_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_state_sync(&source.id).await?,
        };
        let replay_state_files = self.state_files.clone();
        let mut managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &target_policy,
        );
        if replay_state_files.is_some() {
            // Keep the clean cube from syncing template-default state
            // back over the durable mirror before replay lands.
            managed.remove(ENV_STATE_SYNC_URL);
            managed.remove(ENV_STATE_SYNC_TOKEN);
        }
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;

        let info = self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: new_template_id.to_owned(),
                env,
                from_snapshot_path: None,
                resolved_policy: resolved.clone(),
            })
            .await?;
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "recreate-in-place: new cube live"
        );

        if let Some(state_files) = replay_state_files.as_ref() {
            if let Err(err) = self
                .replay_state_files_to_sandbox(
                    owner_id,
                    &source.id,
                    &info.sandbox_id,
                    state_files,
                    false,
                )
                .await
            {
                let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
                return Err(err);
            }

            let reconfigurer = self.reconfigurer.as_ref().ok_or_else(|| {
                SwarmError::PolicyDenied("dyson reconfigurer not configured".into())
            })?;
            let mut body = self.configure_body_for_existing_row(
                &source,
                &proxy_token,
                &ingest_token,
                &state_sync_token,
            );
            self.clear_identity_fields_when_mirror_is_authoritative(
                &mut body,
                owner_id,
                &source.id,
                state_files,
            )
            .await?;
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
                return Err(SwarmError::Internal(format!(
                    "recreate configure-push failed after state replay: {err}"
                )));
            }
        }

        self.instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                new_template_id,
                &target_policy,
                &row_policy_cidrs(&target_policy, &resolved),
                now_secs(),
            )
            .await?;

        if replay_state_files.is_none()
            && let Some(reconfigurer) = self.reconfigurer.as_ref()
        {
            let body = self.configure_body_for_existing_row(
                &source,
                &proxy_token,
                &ingest_token,
                &state_sync_token,
            );
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                tracing::warn!(
                    instance = %source.id,
                    error = %err,
                    "recreate-in-place: configure-push failed; will be retried by next sweep"
                );
            }
        }

        if let Err(err) = self.cube.destroy_sandbox(&old_sandbox_id).await {
            tracing::warn!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                error = %err,
                "recreate-in-place: old cube destroy failed (orphan cube — janitor will sweep)"
            );
        } else {
            tracing::info!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                "recreate-in-place: old cube destroyed"
            );
        }

        self.instances
            .get_for_owner(owner_id, &source.id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    /// Reset onto a clean cube while replaying the sealed swarm-side
    /// state mirror before the new dyson starts shunting files back up.
    /// Same surviving identity as [`Self::recreate_in_place`], but
    /// memory, knowledge-base files, skills, and chats are restored from
    /// `instance_state_files`.
    pub async fn reset_in_place_from_state(
        &self,
        owner_id: &str,
        instance_id: &str,
        new_template_id: &str,
        state_files: &crate::state_files::StateFileService,
    ) -> Result<InstanceRow, SwarmError> {
        if new_template_id.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot reset a destroyed instance".into(),
            ));
        }
        let old_sandbox_id = source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::BadRequest(
                    "instance has no live cube sandbox; reset requires a Live row".into(),
                )
            })?
            .to_owned();
        let resolved = network_policy::resolve(
            &source.network_policy,
            self.llm_cidr.as_deref(),
            &*self.resolver,
        )
        .await?;

        tracing::info!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %new_template_id,
            "reset-in-place: starting clean rebuild with sealed state replay"
        );

        let proxy_token = match self.tokens.lookup_by_instance(&source.id).await? {
            Some(t) => t,
            None => self.tokens.mint(&source.id, SHARED_PROVIDER).await?,
        };
        let ingest_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::INGEST_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_ingest(&source.id).await?,
        };
        let state_sync_token = match self
            .tokens
            .lookup_by_instance_for_provider(&source.id, crate::db::tokens::STATE_SYNC_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_state_sync(&source.id).await?,
        };
        let mut managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &source.network_policy,
        );
        // The clean cube must not mirror its template-default workspace
        // back over the durable swarm copy before replay completes.  The
        // final configure push below enables state sync after the files
        // have landed.
        managed.remove(ENV_STATE_SYNC_URL);
        managed.remove(ENV_STATE_SYNC_TOKEN);
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;

        let info = self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: new_template_id.to_owned(),
                env,
                from_snapshot_path: None,
                resolved_policy: resolved.clone(),
            })
            .await?;
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "reset-in-place: clean cube live; replaying state"
        );

        if let Err(err) = self
            .replay_state_files_to_sandbox(
                owner_id,
                &source.id,
                &info.sandbox_id,
                state_files,
                true,
            )
            .await
        {
            let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
            return Err(err);
        }

        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            let mut body = ReconfigureBody {
                name: Some(source.name.clone()).filter(|s| !s.is_empty()),
                task: Some(source.task.clone()).filter(|s| !s.is_empty()),
                models: source.models.clone(),
                instance_id: Some(source.id.clone()),
                proxy_token: Some(proxy_token.clone()),
                proxy_base: Some(format!(
                    "{}/openrouter",
                    self.proxy_base.trim_end_matches('/')
                )),
                ingest_url: {
                    let u = build_ingest_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                ingest_token: Some(ingest_token.clone()),
                state_sync_url: {
                    let u = build_state_sync_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                state_sync_token: Some(state_sync_token.clone()),
                image_provider_name: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_name.clone()),
                image_provider_block: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_block(&self.image_proxy_base(), &proxy_token)),
                image_generation_provider: self
                    .image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_name.clone()),
                image_generation_model: self.image_gen_defaults.as_ref().map(|d| d.model.clone()),
                reset_skills: source.tools.is_empty(),
                tools: (!source.tools.is_empty()).then(|| source.tools.clone()),
                mcp_servers: None,
            };
            self.clear_identity_fields_when_mirror_is_authoritative(
                &mut body,
                owner_id,
                &source.id,
                state_files,
            )
            .await?;
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &source.id, &info.sandbox_id, &body).await
            {
                let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
                return Err(SwarmError::Internal(format!(
                    "reset configure-push failed after state replay: {err}"
                )));
            }
        } else {
            let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
            return Err(SwarmError::PolicyDenied(
                "dyson reconfigurer not configured".into(),
            ));
        }

        if let Err(err) = self
            .instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                new_template_id,
                &source.network_policy,
                &row_policy_cidrs(&source.network_policy, &resolved),
                now_secs(),
            )
            .await
        {
            let _ = self.cube.destroy_sandbox(&info.sandbox_id).await;
            return Err(err.into());
        }

        if let Err(err) = self.cube.destroy_sandbox(&old_sandbox_id).await {
            tracing::warn!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                error = %err,
                "reset-in-place: old cube destroy failed (orphan cube — janitor will sweep)"
            );
        } else {
            tracing::info!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                "reset-in-place: old cube destroyed"
            );
        }

        self.instances
            .get_for_owner(owner_id, &source.id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    async fn replay_state_files_to_sandbox(
        &self,
        owner_id: &str,
        instance_id: &str,
        sandbox_id: &str,
        state_files: &crate::state_files::StateFileService,
        allow_unreadable_rows: bool,
    ) -> Result<usize, SwarmError> {
        let rows = state_files
            .list_for_instance(instance_id)
            .await
            .map_err(|e| SwarmError::Internal(format!("list state files: {e}")))?;
        if rows.is_empty() {
            return Ok(0);
        }
        let reconfigurer = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        let mut replayed = 0usize;
        for row in rows {
            if row.owner_id != owner_id {
                return Err(SwarmError::Internal(format!(
                    "state row owner mismatch for {}:{}",
                    row.namespace, row.path
                )));
            }
            let (deleted, body_b64) = if row.deleted_at.is_some() {
                (true, None)
            } else {
                let plain = match state_files.read_body(&row).await {
                    Ok(Some(plain)) => plain,
                    Ok(None) if allow_unreadable_rows => {
                        tracing::warn!(
                            instance = %instance_id,
                            namespace = %row.namespace,
                            path = %row.path,
                            "state-replay: skipping unreadable mirror row; continuing with readable mirrored state"
                        );
                        continue;
                    }
                    Ok(None) => {
                        return Err(SwarmError::Internal(format!(
                            "state file body missing or unsealed for {}:{}",
                            row.namespace, row.path
                        )));
                    }
                    Err(e) if allow_unreadable_rows => {
                        tracing::warn!(
                            instance = %instance_id,
                            namespace = %row.namespace,
                            path = %row.path,
                            error = %e,
                            "state-replay: skipping unreadable mirror row; continuing with readable mirrored state"
                        );
                        continue;
                    }
                    Err(e) => {
                        return Err(SwarmError::Internal(format!("open state file: {e}")));
                    }
                };
                (false, Some(B64.encode(plain)))
            };
            let body = RestoreStateFileBody {
                namespace: row.namespace.clone(),
                path: row.path.clone(),
                mime: row.mime.clone(),
                deleted,
                body_b64,
            };
            restore_state_file_with_retry(reconfigurer.as_ref(), instance_id, sandbox_id, &body)
                .await
                .map_err(|e| {
                    SwarmError::Internal(format!(
                        "restore state file {}:{}: {e}",
                        row.namespace, row.path
                    ))
                })?;
            replayed += 1;
        }
        tracing::info!(
            instance = %instance_id,
            sandbox = %sandbox_id,
            files = replayed,
            "state-replay: replayed sealed state files"
        );
        Ok(replayed)
    }

    /// Snapshot-less clone — hires a fresh empty instance under
    /// `new_template_id` with the source's name, task, models, tools,
    /// network policy, per-instance secrets, and MCP server records
    /// (URL, auth, oauth_tokens preserved).  The new cube boots from
    /// the latest template's clean rootfs, so workspace files
    /// (SOUL/IDENTITY/MEMORY, chats, kb, skills) DO NOT come along —
    /// the agent re-seeds itself from the new IDENTITY pushed by the
    /// configure envelope.  Source row stays running and untouched.
    ///
    /// Use this when the cube snapshot path is unavailable (e.g.
    /// snapshot endpoint is down) and the user is willing to start
    /// the clone with empty workspace state.  For a full clone that
    /// also carries workspace files, use [`Self::clone_instance`].
    pub async fn clone_empty(
        &self,
        owner_id: &str,
        source_id: &str,
        new_template_id: &str,
        name_override: Option<String>,
    ) -> Result<CreatedInstance, SwarmError> {
        if new_template_id.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, source_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot clone a destroyed instance".into(),
            ));
        }

        // Reuse the production create path — same validation, fresh
        // id/bearer/proxy_token, fresh cube under the requested
        // template, configure-push of the carried-over identity.
        // Drive models + tools through SWARM_MODELS / SWARM_MODEL /
        // SWARM_TOOLS so create's existing decoders persist them on
        // the row AND ride the Stage 8 reconfigure push to the new
        // dyson — no second round-trip needed after create returns.
        let mut env = BTreeMap::new();
        if let Some(m0) = source.models.first() {
            env.insert(ENV_MODEL.into(), m0.clone());
        }
        if !source.models.is_empty() {
            env.insert(ENV_MODELS.into(), source.models.join(","));
        }
        if !source.tools.is_empty() {
            env.insert(ENV_TOOLS.into(), source.tools.join(","));
        }

        let req = CreateRequest {
            template_id: new_template_id.to_owned(),
            name: Some(name_override.unwrap_or_else(|| source.name.clone()))
                .filter(|s| !s.is_empty()),
            task: Some(source.task.clone()).filter(|s| !s.is_empty()),
            env,
            ttl_seconds: None,
            network_policy: source.network_policy.clone(),
            // MCP specs aren't on the source row — they live in
            // user_secrets keyed by source id.  Pass an empty list
            // here and copy the records into place under the new id
            // after `create()` returns (preserves oauth_tokens; the
            // CreateRequest path would only round-trip URL+auth).
            mcp_servers: Vec::new(),
        };
        let created = self.create(owner_id, req).await?;

        // Carry MCP server records (URL, auth, oauth_tokens preserved).
        // Two steps: copy the rows to user_secrets under the new id,
        // then push the rendered mcp_servers block to the running
        // dyson via /api/admin/configure.  Without the second step the
        // template-default dyson.json has no MCP block, McpSkill never
        // loads, and the agent reports zero MCP tools — even though
        // the user_secrets rows are sitting there waiting.
        if let Some(secrets) = self.mcp_secrets.as_ref() {
            match mcp_servers::copy_all(secrets, owner_id, &source.id, &created.id).await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        source = %source.id,
                        clone = %created.id,
                        count = n,
                        "clone-empty: mcp servers copied"
                    );
                    if let Err(err) = self.sync_mcp_to_dyson(owner_id, &created.id).await {
                        tracing::warn!(
                            clone = %created.id,
                            error = %err,
                            "clone-empty: mcp sync push failed; the rewire-image-gen sweep will retry on next swarm restart"
                        );
                    } else {
                        tracing::info!(
                            clone = %created.id,
                            "clone-empty: mcp block pushed to running dyson"
                        );
                    }
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    source = %source.id,
                    clone = %created.id,
                    error = %err,
                    "clone-empty: mcp copy failed; clone will boot without MCP attached"
                ),
            }
        }

        Ok(created)
    }

    /// Snapshot the source instance and restore onto a fresh swarm id +
    /// cube under `new_template_id`.  The new instance inherits the
    /// source's name, task, models, tools, network policy, and per-
    /// instance secrets; gets a brand-new bearer, proxy token, and DNS
    /// subdomain; and boots from the latest template's rootfs with the
    /// source's workspace volume restored on top.  The source row is
    /// left running and untouched.
    ///
    /// MCP server records (URL + auth + any active OAuth session) are
    /// re-keyed onto the clone too, so the user doesn't have to re-
    /// authorise upstream MCP after cloning.
    ///
    /// Callers should resolve `new_template_id` from the operator's
    /// `default_template_id` (same as `rotate_template` in the HTTP
    /// layer); an empty string is a 400 BadRequest.
    pub async fn clone_instance(
        &self,
        owner_id: &str,
        source_id: &str,
        snapshot_svc: &crate::snapshot::SnapshotService,
        new_template_id: &str,
        name_override: Option<String>,
    ) -> Result<CreatedInstance, SwarmError> {
        if new_template_id.trim().is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, source_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(
                "cannot clone a destroyed instance".into(),
            ));
        }
        if source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .is_none()
        {
            return Err(SwarmError::BadRequest(
                "instance has no live cube sandbox; clone requires a Live row".into(),
            ));
        }

        let snap = snapshot_svc.snapshot(SYSTEM_OWNER, &source.id).await?;
        tracing::info!(
            source = %source.id,
            snapshot = %snap.id,
            to_template = %new_template_id,
            "clone: snapshot taken; restoring onto fresh swarm id"
        );

        let req = RestoreRequest {
            template_id: new_template_id.to_owned(),
            snapshot_path: std::path::PathBuf::from(&snap.path),
            source_instance_id: Some(source.id.clone()),
            name: Some(name_override.unwrap_or_else(|| source.name.clone()))
                .filter(|s| !s.is_empty()),
            task: Some(source.task.clone()).filter(|s| !s.is_empty()),
            env: BTreeMap::new(),
            ttl_seconds: None,
            network_policy: source.network_policy.clone(),
            models: source.models.clone(),
            tools: source.tools.clone(),
        };
        let created = self.restore(owner_id, req).await?;

        // Carry MCP server records (URL, auth, and any active OAuth
        // session) onto the new instance id, then push the rendered
        // mcp_servers block.  The restore() above preserves the source
        // cube's dyson.json (workspace volume), so without the push
        // the agent's mcp_servers config still references
        // /mcp/<source_id>/<name> URLs — which the proxy 404s because
        // the source's user_secrets rows aren't keyed for the clone.
        // Best-effort: a failure here is logged; the rewire-image-gen
        // sweep retries on next swarm restart.
        if let Some(secrets) = self.mcp_secrets.as_ref() {
            match mcp_servers::copy_all(secrets, owner_id, &source.id, &created.id).await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        source = %source.id,
                        clone = %created.id,
                        count = n,
                        "clone: mcp servers copied"
                    );
                    if let Err(err) = self.sync_mcp_to_dyson(owner_id, &created.id).await {
                        tracing::warn!(
                            clone = %created.id,
                            error = %err,
                            "clone: mcp sync push failed; the rewire-image-gen sweep will retry on next swarm restart"
                        );
                    } else {
                        tracing::info!(
                            clone = %created.id,
                            "clone: mcp block pushed to running dyson"
                        );
                    }
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    source = %source.id,
                    clone = %created.id,
                    error = %err,
                    "clone: mcp copy failed; clone will boot without MCP attached"
                ),
            }
        }

        Ok(created)
    }

    pub async fn create(
        &self,
        owner_id: &str,
        req: CreateRequest,
    ) -> Result<CreatedInstance, SwarmError> {
        // The agent boot config refuses to start without a model id, so
        // catch the missing-model case here with a clean error instead
        // of letting the cube start a doomed sandbox we then have to
        // garbage-collect. Trim-empty counts as missing.
        if req.env.get(ENV_MODEL).is_none_or(|s| s.trim().is_empty()) {
            return Err(SwarmError::PolicyDenied(format!(
                "{ENV_MODEL} is required in the create request's `env` \
                 (e.g. \"anthropic/claude-sonnet-4-5\"); there is no default"
            )));
        }

        let id = self.mint_unique_instance_id(owner_id).await?;
        let bearer = Uuid::new_v4().simple().to_string();
        let now = now_secs();
        // Dysons are long-lived employees, not throwaway batch jobs —
        // default to no expiry.  The TTL sweeper filters
        // `expires_at IS NOT NULL`, so None means "never reaped".
        // Callers that genuinely want a deadline can still pass
        // `ttl_seconds` explicitly (used by the snapshot/restore
        // flow's smoke tests and by anything that wants a self-
        // destructing scratch instance).
        let expires_at = req.ttl_seconds.map(|ttl| now + ttl);
        let name = req.name.clone().unwrap_or_default();
        let task = req.task.clone().unwrap_or_default();

        // Resolve the network policy BEFORE inserting the row so a
        // bad CIDR / missing LLM-CIDR / unresolvable hostname surfaces
        // as 400 BadRequest before any persistent state lands.
        let resolved_policy = network_policy::resolve(
            &req.network_policy,
            self.llm_cidr.as_deref(),
            &*self.resolver,
        )
        .await?;

        for spec in &req.mcp_servers {
            self.validate_mcp_server_spec(spec).await?;
        }

        // Decode the model list once: SWARM_MODELS (CSV) is the
        // multi-model wire shape; legacy clients still pass the
        // single SWARM_MODEL.  We persist the same vec the
        // reconfigurer push uses below so the read-side recovers
        // exactly what the running dyson was hired with.
        let mut models: Vec<String> = req
            .env
            .get(ENV_MODELS)
            .map(|s| {
                s.split(',')
                    .map(|m| m.trim().to_owned())
                    .filter(|m| !m.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if models.is_empty()
            && let Some(m) = req.env.get(ENV_MODEL).map(|s| s.trim().to_owned())
            && !m.is_empty()
        {
            models.push(m);
        }

        // Decode the tool include list once.  Empty / unset → no
        // override, dyson uses its full builtin catalogue.  Non-empty
        // → swarm persists the positive set and surfaces it via the
        // env envelope below; future edits push via /api/admin/configure.
        let tools: Vec<String> = req
            .env
            .get(ENV_TOOLS)
            .map(|s| {
                s.split(',')
                    .map(|m| m.trim().to_owned())
                    .filter(|m| !m.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Insert the instance row first so the FK target exists; mint the
        // proxy token; then call Cube. If Cube fails we mark the row
        // destroyed to keep state consistent.
        let row = InstanceRow {
            id: id.clone(),
            owner_id: owner_id.to_owned(),
            name: name.clone(),
            task: task.clone(),
            cube_sandbox_id: None,
            template_id: req.template_id.clone(),
            status: InstanceStatus::Cold,
            bearer_token: bearer.clone(),
            pinned: false,
            expires_at,
            last_active_at: now,
            last_probe_at: None,
            last_probe_status: None,
            created_at: now,
            destroyed_at: None,
            rotated_to: None,
            network_policy: req.network_policy.clone(),
            network_policy_cidrs: row_policy_cidrs(&req.network_policy, &resolved_policy),
            models: models.clone(),
            tools: tools.clone(),
        };
        self.instances.create(row).await?;

        let proxy_token = self.tokens.mint(&id, SHARED_PROVIDER).await?;
        // Per-instance ingest token, sibling of the chat proxy token
        // in `proxy_tokens`.  Same revoke path (`revoke_for_instance`
        // at destroy) so we don't need a parallel cleanup hook.
        let ingest_token = self.tokens.mint_ingest(&id).await?;
        let state_sync_token = self.tokens.mint_state_sync(&id).await?;

        // Persist MCP server records under the owner's cipher so the
        // proxy path can decrypt them per-request.  We do this BEFORE
        // any reconfigure push so the running agent's first JSON-RPC
        // call lands on a populated entry rather than a 404.  Failure
        // is fatal to the create — the alternative is an instance
        // whose dyson.json points at /mcp/<id>/<name> but the secret
        // store has no row, which would surface as confusing 404s.
        let mcp_specs = req.mcp_servers.clone();
        if !mcp_specs.is_empty()
            && let Some(secrets) = self.mcp_secrets.as_ref()
        {
            mcp_servers::put_all(secrets, owner_id, &id, mcp_specs.clone())
                .await
                .map_err(|err| {
                    tracing::warn!(error = %err, instance = %id, "mcp: persist failed");
                    SwarmError::Internal(format!("mcp persist failed: {err}"))
                })?;
        }

        // Identity envelope. The agent reads these on first boot to seed
        // its own self-knowledge files (SOUL.md and friends in Dyson's
        // case); subsequent edits to the swarm row don't propagate to a
        // running sandbox, by design.
        let managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &id,
            &bearer,
            &name,
            &task,
            &req.network_policy,
        );

        // Templates aren't materialised inside swarm — they live in Cube,
        // so the "template" half of the merge is empty here.
        let env = compose_sandbox_env(&managed, &req.env)?;

        let info = match self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: req.template_id,
                env,
                from_snapshot_path: None,
                resolved_policy,
            })
            .await
        {
            Ok(info) => info,
            Err(e) => {
                let _ = self.tokens.revoke_for_instance(&id).await;
                let _ = self
                    .instances
                    .update_status(&id, InstanceStatus::Destroyed)
                    .await;
                return Err(e.into());
            }
        };
        self.instances
            .set_cube_sandbox_id(&id, &info.sandbox_id)
            .await?;
        self.instances
            .update_status(&id, InstanceStatus::Live)
            .await?;

        // Caddy's on_demand TLS for `<id>.<hostname>` is warmed by the
        // SPA in the background (no-cors fetch + <link rel="preconnect">
        // when the detail page mounts).  Doing it here would add 5–15s
        // of synchronous wait to every create, which the user feels.

        // Stage 8: push the env envelope (name, task, models) into the
        // running dyson via /api/admin/configure.  Cube's snapshot/
        // restore freezes the warmup-mode dyson process's env; without
        // this push, every instance shows "warmup-placeholder" forever
        // and IDENTITY.md is empty.  Best-effort with retries — the
        // sandbox is Live by here but the dyson HTTP server inside
        // can take a beat to settle, especially on cold cubeproxy.
        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            let image_gen_defaults = self.image_gen_defaults.as_ref().map(|defaults| {
                let mut defaults = defaults.clone();
                if let Some(model) = req
                    .env
                    .get(ENV_IMAGE_GENERATION_MODEL)
                    .map(|m| m.trim())
                    .filter(|m| !m.is_empty())
                {
                    defaults.model = model.to_owned();
                }
                defaults
            });
            let body = ReconfigureBody {
                name: req.name.clone().filter(|s| !s.is_empty()),
                task: req.task.clone().filter(|s| !s.is_empty()),
                models: models.clone(),
                instance_id: Some(id.clone()),
                // Push the freshly-minted proxy_token + the resolved
                // /llm base URL into the running dyson's dyson.json so
                // the agent stops trying to call upstream with the
                // boot-time `warmup-placeholder` api_key.  The
                // `/openrouter` suffix matches what `dyson swarm`'s
                // warmup config writer constructs — keeps dyson's admin
                // handler agnostic to which provider the agent fronts.
                proxy_token: Some(proxy_token.clone()),
                // `<proxy_base>/openrouter` — the trailing `/v1` is added
                // by dyson's `OpenAiCompatClient` when it builds the
                // request URL (`{base_url}/v1/chat/completions`).  Stamping
                // `/v1` here too doubles it up and routes to OR's
                // marketing site, which dyson surfaces as a generic
                // "upstream HTTP error".  See the regression test
                // `create_pushes_proxy_base_without_trailing_v1`.
                proxy_base: Some(format!(
                    "{}/openrouter",
                    self.proxy_base.trim_end_matches('/')
                )),
                // Same configure-push posture as proxy_token/proxy_base:
                // cube's snapshot/restore freezes the agent's env at
                // warmup, so the SWARM_INGEST_URL / SWARM_INGEST_TOKEN
                // we just stamped into the env envelope never reaches
                // the running dyson process.  Pushing them here lands
                // them in the per-chat HttpState the SseOutput reads
                // on every send_artefact, completing the wire end-to-
                // end without an operator-visible re-hire.
                ingest_url: {
                    let u = build_ingest_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                ingest_token: Some(ingest_token.clone()),
                state_sync_url: {
                    let u = build_state_sync_url(&self.proxy_base);
                    if u.is_empty() { None } else { Some(u) }
                },
                state_sync_token: Some(state_sync_token.clone()),
                // Image-generation defaults — register the dedicated
                // image provider entry and point the agent at it.  The
                // same proxy_token authenticates against swarm's `/llm`
                // proxy for both chat and image traffic, so we reuse
                // it as the api_key on the image provider block.  When
                // `image_gen_defaults` is None on InstanceService all
                // four fields stay None and the dyson handler skips
                // the patch.
                image_provider_name: image_gen_defaults.as_ref().map(|d| d.provider_name.clone()),
                image_provider_block: image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_block(&self.image_proxy_base(), &proxy_token)),
                image_generation_provider: image_gen_defaults
                    .as_ref()
                    .map(|d| d.provider_name.clone()),
                image_generation_model: image_gen_defaults.as_ref().map(|d| d.model.clone()),
                // Belt-and-braces: the new dyson swarm boot writer
                // already honors SWARM_TOOLS, but creates that ride an
                // older binary template ship a stale skills block.
                // When the operator picked an explicit subset, push it
                // here too; otherwise reset to defaults.
                reset_skills: tools.is_empty(),
                tools: (!tools.is_empty()).then(|| tools.clone()),
                // Render the proxied stanza for each attached MCP server.
                // The agent sees `https://<swarm>/mcp/<id>/<name>` plus a
                // bearer header; the upstream URL + real credentials stay
                // in user_secrets and never reach dyson.json.
                mcp_servers: if mcp_specs.is_empty() {
                    None
                } else {
                    let mut map = serde_json::Map::with_capacity(mcp_specs.len());
                    for spec in &mcp_specs {
                        map.insert(
                            spec.name.clone(),
                            mcp_servers::dyson_json_block(
                                &id,
                                &spec.name,
                                &self.proxy_base,
                                &proxy_token,
                            ),
                        );
                    }
                    Some(map)
                },
            };
            // Await the configure-push before returning Live.  Previously
            // this was tokio::spawn'd (fire-and-forget): the SPA could
            // race the user's first chat turn against the patch, and
            // dyson's per-chat agent cached the warmup-placeholder
            // client (warmup api_key + api.openai.com base_url).  Even
            // dev Claude's per-chat HotReloader can't recover, because
            // its baseline mtime is set AFTER the cached agent build,
            // so a subsequent turn sees no dyson.json change and
            // reuses the stale client.  Blocking here costs the create
            // call ~1s on the happy path and avoids the race entirely.
            // Failure is fatal to the create — we'd rather surface the
            // problem at create time than ship a half-broken instance.
            push_with_retry(reconfigurer.as_ref(), &id, &info.sandbox_id, &body)
                .await
                .map_err(|err| {
                    tracing::warn!(
                        error = %err,
                        instance = %id,
                        sandbox = %info.sandbox_id,
                        "reconfigure: failed during create — instance would stay on warmup-placeholder"
                    );
                    SwarmError::Internal(format!("configure-push failed: {err}"))
                })?;
        }

        Ok(CreatedInstance {
            id,
            url: info.url,
            bearer_token: bearer,
            proxy_token,
        })
    }

    /// Owner-scoped lookup: returns NotFound for rows the user doesn't own.
    pub async fn get(&self, owner_id: &str, id: &str) -> Result<InstanceRow, SwarmError> {
        self.instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    /// System lookup: returns the row regardless of owner.  Used by
    /// the anonymous `/healthz` probe carve-out in `dyson_proxy::dispatch`
    /// (the prober has no user identity) and by background sweepers
    /// like the TTL loop.  Caller is responsible for not exposing the
    /// row across tenant boundaries — this skips the normal
    /// owner-filter that the per-handler `get` enforces.
    pub async fn get_unscoped(&self, id: &str) -> Result<InstanceRow, SwarmError> {
        self.instances.get(id).await?.ok_or(SwarmError::NotFound)
    }

    /// Mint an instance id (`<adj>-<noun>-<NNN>-<user-slug>`) that is
    /// not already taken in the `instances` table.  The user-slug pins
    /// the per-user namespace so two operators can both have a
    /// `fluffy-otter-042-<theirs>` simultaneously without collision;
    /// the retry loop covers the rare case where the same operator
    /// rolls a duplicate within their own 250M-combo keyspace.
    async fn mint_unique_instance_id(&self, owner_id: &str) -> Result<String, SwarmError> {
        // 8 attempts is overkill for single-tenant deployments — even
        // with 100k live ids per user the per-attempt collision rate
        // is ~0.04%, so 8 retries puts the failure floor below 1 in
        // 10^28.  Bumping if a future deployment runs hotter is a
        // one-line change.
        const ATTEMPTS: usize = 8;
        for _ in 0..ATTEMPTS {
            let candidate = crate::instance_id::mint_candidate(owner_id);
            if self.instances.get(&candidate).await?.is_none() {
                return Ok(candidate);
            }
        }
        Err(SwarmError::Internal(
            "instance id mint exhausted attempts".into(),
        ))
    }

    pub async fn list(
        &self,
        owner_id: &str,
        filter: ListFilter,
    ) -> Result<Vec<InstanceRow>, SwarmError> {
        Ok(self.instances.list(owner_id, filter).await?)
    }

    /// Run a single probe synchronously, persist the result on the row, and
    /// hand it back to the caller. Used by `POST /v1/instances/:id/probe`.
    pub async fn probe(
        &self,
        owner_id: &str,
        prober: &dyn HealthProber,
        id: &str,
    ) -> Result<ProbeResult, SwarmError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let result = prober.probe(&row).await;
        self.instances.record_probe(id, result.clone()).await?;
        Ok(result)
    }

    /// Owner-scoped identity update.  Updates swarm's row AND pushes
    /// the new identity into the running dyson via /api/admin/configure
    /// so IDENTITY.md (and the agent's system prompt on the next turn)
    /// reflects the change.  Returns `NotFound` if the row isn't owned
    /// by the caller, matching the rest of the service's
    /// no-cross-tenant-oracle policy.
    pub async fn rename(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
        task: &str,
    ) -> Result<InstanceRow, SwarmError> {
        self.instances
            .update_identity(owner_id, id, name, task)
            .await?;
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if let (Some(r), Some(sb)) = (
            self.reconfigurer.as_ref(),
            row.cube_sandbox_id.as_deref().filter(|s| !s.is_empty()),
        ) {
            let body = ReconfigureBody {
                name: Some(name.to_owned()).filter(|s| !s.is_empty()),
                task: Some(task.to_owned()).filter(|s| !s.is_empty()),
                models: Vec::new(), // identity-only update; leave models alone
                instance_id: Some(id.to_owned()),
                // Identity update doesn't touch provider config; leave
                // proxy_token / proxy_base unchanged on the dyson side.
                proxy_token: None,
                proxy_base: None,
                ..Default::default()
            };
            push_with_retry(r.as_ref(), id, sb, &body)
                .await
                .map_err(|err| {
                    tracing::warn!(error = %err, instance = %id, "rename: reconfigure push failed");
                    SwarmError::Internal(format!("identity configure-push failed: {err}"))
                })?;
        }
        Ok(row)
    }

    /// Mirror identity that originated inside the running dyson.
    ///
    /// Unlike [`rename`], this only updates swarm's metadata row. The
    /// instance is the source of truth for this path, so pushing the
    /// same body back through `/api/admin/configure` would risk racing
    /// an agent-authored edit with stale swarm state.
    pub async fn mirror_identity_from_instance(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
        task: &str,
    ) -> Result<InstanceRow, SwarmError> {
        self.instances
            .update_identity(owner_id, id, name, task)
            .await?;
        self.instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)
    }

    /// Owner-scoped models update.  Stage 8.3 entry point — lets a
    /// user change which model(s) the agent uses without destroying
    /// the dyson.  Updates dyson.json's
    /// `providers.<agent.provider>.models` array via the runtime
    /// reconfigure endpoint; `HotReloader` rebuilds the agent on the
    /// next turn.  Empty `models` is a no-op (the user has to pick at
    /// least one).  Returns `NotFound` for cross-owner ids and
    /// `PolicyDenied` when the reconfigurer isn't wired in
    /// (production has it; tests + local dev may not).
    /// Read the current MCP server set from user_secrets, render the
    /// proxied dyson.json blocks (using the running instance's
    /// proxy_token), and push the whole `mcp_servers` map to the
    /// running dyson via the configure endpoint.  Empty set
    /// is pushed as `Some({})` so the dyson handler clears the block.
    ///
    /// Failure modes:
    /// - `NotFound` for cross-owner ids and missing instances.
    /// - `PolicyDenied` when reconfigurer / mcp_secrets isn't configured
    ///   (test/local-dev), the instance has no live sandbox, or no
    ///   active proxy_token (pre-Stage-8 instances).
    pub async fn sync_mcp_to_dyson(&self, owner_id: &str, id: &str) -> Result<(), SwarmError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::PolicyDenied("instance has no live sandbox to reconfigure".into())
            })?;
        let r = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let proxy_token = self.tokens.lookup_by_instance(id).await?.ok_or_else(|| {
            SwarmError::PolicyDenied("instance has no active proxy_token (pre-Stage-8 row)".into())
        })?;

        let names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        let mut block = serde_json::Map::with_capacity(names.len());
        for name in names {
            block.insert(
                name.clone(),
                mcp_servers::dyson_json_block(id, &name, &self.proxy_base, &proxy_token),
            );
        }

        let body = ReconfigureBody {
            instance_id: Some(id.to_owned()),
            mcp_servers: Some(block),
            ..Default::default()
        };
        push_with_retry(&**r, id, sandbox_id, &body)
            .await
            .map_err(SwarmError::PolicyDenied)
    }

    /// Add or replace one MCP server attached to an instance.  Sealed
    /// in user_secrets, then a reconfigure push is fired so the running
    /// dyson registers the new tool set on the next HotReloader tick.
    /// Used by the instance-detail page's MCP management panel.
    ///
    /// Credential-keep semantics: the SPA's edit form pre-fills
    /// secret-bearing fields (bearer token, OAuth client_secret) with
    /// a static [`MCP_KEEP_TOKEN`] placeholder rather than the real
    /// sealed value (we never decrypt to display).  When the inbound
    /// spec carries that exact sentinel, this method swaps it for
    /// the previously-sealed value before persisting — so a user
    /// who only renamed a URL doesn't accidentally clobber their
    /// stored token.
    pub async fn put_mcp_server(
        &self,
        owner_id: &str,
        id: &str,
        spec: McpServerSpec,
    ) -> Result<(), SwarmError> {
        // Owner-scoped existence check first — never reveal that an id
        // belongs to a different user.
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let McpServerSpec {
            name,
            url,
            mut auth,
            enabled_tools,
        } = spec;
        if name.trim().is_empty() {
            return Err(SwarmError::BadRequest("server name is required".into()));
        }
        if url.trim().is_empty() {
            return Err(SwarmError::BadRequest("server url is required".into()));
        }
        self.validate_mcp_url(&url).await?;
        self.validate_mcp_auth_urls(&auth).await?;
        // Read-modify-write the entry under its current oauth_tokens
        // (if any) so an OAuth-already-connected server doesn't lose
        // its tokens just because the user edited the URL.  We also
        // preserve `tools_catalog` across edits — the cached list of
        // tools doesn't get invalidated by URL/auth tweaks (the
        // /check endpoint is the only writer for that field).
        let mut entry = mcp_servers::get(secrets, owner_id, id, &name)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?
            .unwrap_or_else(|| crate::mcp_servers::McpServerEntry {
                url: url.clone(),
                auth: auth.clone(),
                headers: std::collections::HashMap::new(),
                runtime: None,
                docker_catalog: None,
                raw_vscode_config: None,
                oauth_tokens: None,
                tools_catalog: None,
                enabled_tools: enabled_tools.clone(),
            });
        // Keep-existing semantics: the SPA never reads back sealed
        // credentials, so its edit form pre-fills secret-bearing
        // inputs with the static MCP_KEEP_TOKEN bullet sentinel.
        // When that sentinel survives to the wire, swap it for the
        // value already on the row.  Skipped when auth shapes don't
        // match — switching shape always rotates / wipes anyway.
        if auth_shape_matches(&entry.auth, &auth) {
            keep_existing_secrets(&entry.auth, &mut auth);
        }
        // If the auth shape changed (e.g. bearer → oauth, or scopes
        // changed), wipe the old OAuth tokens — they'd be stale anyway.
        if !auth_shape_matches(&entry.auth, &auth) {
            entry.oauth_tokens = None;
        }
        entry.url = url;
        entry.auth = auth;
        entry.headers.clear();
        entry.runtime = None;
        entry.docker_catalog = None;
        entry.raw_vscode_config = None;
        // The SPA always submits the current selection on save; mirror
        // it onto the entry (None ⇒ "use default", Some(vec) ⇒ explicit).
        entry.enabled_tools = enabled_tools;
        mcp_servers::put(secrets, owner_id, id, &name, &entry)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp put: {e}")))?;

        // Update the index so subsequent list_names finds the new entry.
        let mut names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        if !names.iter().any(|n| n == &name) {
            names.push(name);
            // put_all rewrites the whole index.  Pass empty specs so we
            // don't rewrite each server's blob (already sealed above);
            // we just need the index touched.
            let idx = serde_json::to_vec(&names)
                .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
            // Direct index rewrite — same shape mcp_servers::put_all uses.
            secrets
                .put(owner_id, &mcp_servers::index_key(id), &idx)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;
        }

        // Best-effort reconfigure push — if the instance is mid-restore
        // or the reconfigurer is not wired we still want the secret to
        // land so the next push (e.g. a rename) can pick it up.
        if let Err(err) = self.sync_mcp_to_dyson(owner_id, id).await {
            tracing::warn!(error = %err, instance = %id, "mcp put: sync_mcp_to_dyson failed (entry persisted)");
        }
        Ok(())
    }

    /// Add or replace exactly one MCP server from an MCP JSON document.
    /// The raw JSON is sealed on the resulting entry so the SPA can
    /// round-trip the familiar config, while dyson still receives only
    /// the hidden swarm proxy URL.
    pub async fn put_vscode_mcp_config(
        &self,
        owner_id: &str,
        id: &str,
        raw: serde_json::Value,
    ) -> Result<(), SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let (name, entry) =
            mcp_servers::entry_from_vscode_config(raw).map_err(SwarmError::BadRequest)?;
        self.validate_mcp_entry(&entry).await?;

        mcp_servers::put(secrets, owner_id, id, &name, &entry)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp put: {e}")))?;
        let mut names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        if !names.iter().any(|n| n == &name) {
            names.push(name);
            let idx = serde_json::to_vec(&names)
                .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
            secrets
                .put(owner_id, &mcp_servers::index_key(id), &idx)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;
        }

        if let Err(err) = self.sync_mcp_to_dyson(owner_id, id).await {
            tracing::warn!(error = %err, instance = %id, "mcp vscode put: sync_mcp_to_dyson failed (entry persisted)");
        }
        Ok(())
    }

    /// Add or replace one Docker MCP server from the operator-curated
    /// catalog.  The user only submits placeholder values; swarm renders
    /// the configured JSON template, validates it through the same
    /// Docker parser as raw JSON, seals the rendered runtime config,
    /// and records the catalog binding so future template updates can
    /// keep existing placeholder values.
    pub async fn put_docker_catalog_mcp_server(
        &self,
        owner_id: &str,
        id: &str,
        catalog: &mcp_servers::McpDockerCatalogServer,
        placeholders: BTreeMap<String, String>,
    ) -> Result<String, SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;

        let names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        let mut existing_catalog_entry = None;
        for name in &names {
            let entry = mcp_servers::get(secrets, owner_id, id, name)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?;
            if let Some(entry) = entry {
                if matches!(
                    entry.docker_catalog.as_ref(),
                    Some(binding) if binding.id == catalog.id
                ) {
                    existing_catalog_entry = Some((name.clone(), entry));
                    break;
                }
            }
        }

        let (name, mut entry) = mcp_servers::entry_from_docker_catalog_template(
            catalog,
            &placeholders,
            existing_catalog_entry.as_ref().map(|(_, entry)| entry),
        )
        .map_err(SwarmError::BadRequest)?;
        if let Some((_, previous)) = &existing_catalog_entry {
            entry.tools_catalog = previous.tools_catalog.clone();
            entry.enabled_tools = previous.enabled_tools.clone();
        }

        mcp_servers::put(secrets, owner_id, id, &name, &entry)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp put: {e}")))?;

        if let Some((old_name, _)) = &existing_catalog_entry {
            if old_name != &name {
                if let Err(err) = secrets
                    .delete(owner_id, &mcp_servers::entry_key(id, old_name))
                    .await
                {
                    tracing::warn!(
                        error = %err,
                        instance = %id,
                        server = %old_name,
                        "mcp catalog put: old row delete failed"
                    );
                }
            }
        }

        let mut next_names: Vec<String> = names
            .into_iter()
            .filter(|n| match &existing_catalog_entry {
                Some((old_name, _)) => n != old_name || n == &name,
                None => true,
            })
            .collect();
        if !next_names.iter().any(|n| n == &name) {
            next_names.push(name.clone());
        }
        let idx = serde_json::to_vec(&next_names)
            .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
        secrets
            .put(owner_id, &mcp_servers::index_key(id), &idx)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;

        if let Err(err) = self.sync_mcp_to_dyson(owner_id, id).await {
            tracing::warn!(error = %err, instance = %id, "mcp catalog put: sync_mcp_to_dyson failed (entry persisted)");
        }
        Ok(name)
    }

    /// Fetch exact MCP JSON previously saved through the Docker add path.
    /// When `server_name` is set, only that entry is considered. Returns
    /// `None` when there is no raw JSON-backed MCP entry on the instance.
    pub async fn get_vscode_mcp_config(
        &self,
        owner_id: &str,
        id: &str,
        server_name: Option<&str>,
    ) -> Result<Option<serde_json::Value>, SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        if let Some(server_name) = server_name {
            let entry = mcp_servers::get(secrets, owner_id, id, server_name)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?;
            return Ok(entry.and_then(|e| e.raw_vscode_config));
        }
        let names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        for name in names {
            let entry = mcp_servers::get(secrets, owner_id, id, &name)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?;
            if let Some(raw) = entry.and_then(|e| e.raw_vscode_config) {
                return Ok(Some(raw));
            }
        }
        Ok(None)
    }

    /// Clear the first raw JSON-backed MCP config entry and push the
    /// resulting MCP block to the running dyson.
    pub async fn delete_vscode_mcp_config(
        &self,
        owner_id: &str,
        id: &str,
    ) -> Result<Option<DeletedMcpServer>, SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let names = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?;
        let mut delete_entry = None;
        for name in &names {
            let entry = mcp_servers::get(secrets, owner_id, id, name)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?;
            if matches!(
                entry.as_ref().and_then(|e| e.raw_vscode_config.as_ref()),
                Some(_)
            ) {
                delete_entry = entry.map(|entry| (name.clone(), entry));
                break;
            }
        }
        let Some((delete_name, delete_entry)) = delete_entry else {
            return Ok(None);
        };
        if let Err(err) = secrets
            .delete(owner_id, &mcp_servers::entry_key(id, &delete_name))
            .await
        {
            tracing::warn!(error = %err, instance = %id, server = %delete_name, "mcp vscode delete: row delete failed");
        }
        let names: Vec<String> = names.into_iter().filter(|n| n != &delete_name).collect();
        if names.is_empty() {
            let _ = secrets.delete(owner_id, &mcp_servers::index_key(id)).await;
        } else {
            let idx = serde_json::to_vec(&names)
                .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
            secrets
                .put(owner_id, &mcp_servers::index_key(id), &idx)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;
        }
        if let Err(err) = self.sync_mcp_to_dyson(owner_id, id).await {
            tracing::warn!(error = %err, instance = %id, "mcp vscode delete: sync_mcp_to_dyson failed");
        }
        Ok(Some(DeletedMcpServer {
            owner_id: owner_id.to_string(),
            instance_id: id.to_string(),
            name: delete_name,
            runtime: delete_entry.runtime,
        }))
    }

    /// Remove one MCP server from an instance.  Wipes the user_secrets
    /// row, removes it from the index, and pushes the new (smaller)
    /// `mcp_servers` block to the running dyson.
    pub async fn delete_mcp_server(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
    ) -> Result<Option<DeletedMcpServer>, SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let deleted_entry = mcp_servers::get(secrets, owner_id, id, name)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?;
        // Idempotent: a delete on a missing entry just returns Ok.
        if let Err(err) = secrets
            .delete(owner_id, &mcp_servers::entry_key(id, name))
            .await
        {
            tracing::warn!(error = %err, instance = %id, server = %name, "mcp delete: row delete failed");
        }
        let names: Vec<String> = mcp_servers::list_names(secrets, owner_id, id)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp list: {e}")))?
            .into_iter()
            .filter(|n| n != name)
            .collect();
        if names.is_empty() {
            // Drop the index row entirely — keeps the user_secrets table
            // tidy when the user clears every MCP server.
            let _ = secrets.delete(owner_id, &mcp_servers::index_key(id)).await;
        } else {
            let idx = serde_json::to_vec(&names)
                .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
            secrets
                .put(owner_id, &mcp_servers::index_key(id), &idx)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;
        }
        if let Err(err) = self.sync_mcp_to_dyson(owner_id, id).await {
            tracing::warn!(error = %err, instance = %id, "mcp delete: sync_mcp_to_dyson failed");
        }
        Ok(deleted_entry.map(|entry| DeletedMcpServer {
            owner_id: owner_id.to_string(),
            instance_id: id.to_string(),
            name: name.to_string(),
            runtime: entry.runtime,
        }))
    }

    /// Remove every provisioned MCP server that came from one Docker
    /// catalog template. Used when an admin deletes a template so user
    /// instances do not keep running an orphaned Docker MCP entry.
    pub async fn delete_mcp_servers_for_docker_catalog(
        &self,
        catalog_id: &str,
    ) -> Result<Vec<DeletedMcpServer>, SwarmError> {
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let instances = self
            .instances
            .list(
                "*",
                ListFilter {
                    status: None,
                    include_destroyed: true,
                },
            )
            .await?;
        let mut removed = Vec::new();
        for row in instances {
            let names = match mcp_servers::list_names(secrets, &row.owner_id, &row.id).await {
                Ok(names) => names,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        "mcp catalog delete: list failed"
                    );
                    continue;
                }
            };
            if names.is_empty() {
                continue;
            }

            let mut next_names = Vec::with_capacity(names.len());
            let mut removed_for_instance = false;
            for name in names {
                let entry = match mcp_servers::get(secrets, &row.owner_id, &row.id, &name).await {
                    Ok(entry) => entry,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            instance = %row.id,
                            server = %name,
                            "mcp catalog delete: entry read failed"
                        );
                        next_names.push(name);
                        continue;
                    }
                };
                let Some(entry) = entry else {
                    next_names.push(name);
                    continue;
                };
                let should_delete = matches!(
                    entry.docker_catalog.as_ref(),
                    Some(binding) if binding.id == catalog_id
                );
                if !should_delete {
                    next_names.push(name);
                    continue;
                }

                if let Err(err) = secrets
                    .delete(&row.owner_id, &mcp_servers::entry_key(&row.id, &name))
                    .await
                {
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        server = %name,
                        catalog = %catalog_id,
                        "mcp catalog delete: row delete failed"
                    );
                }
                removed_for_instance = true;
                removed.push(DeletedMcpServer {
                    owner_id: row.owner_id.clone(),
                    instance_id: row.id.clone(),
                    name,
                    runtime: entry.runtime,
                });
            }

            if !removed_for_instance {
                continue;
            }
            if next_names.is_empty() {
                let _ = secrets
                    .delete(&row.owner_id, &mcp_servers::index_key(&row.id))
                    .await;
            } else {
                let idx = serde_json::to_vec(&next_names)
                    .map_err(|e| SwarmError::Internal(format!("mcp index serialise: {e}")))?;
                secrets
                    .put(&row.owner_id, &mcp_servers::index_key(&row.id), &idx)
                    .await
                    .map_err(|e| SwarmError::Internal(format!("mcp index put: {e}")))?;
            }

            if row.status != InstanceStatus::Destroyed {
                if let Err(err) = self.sync_mcp_to_dyson(&row.owner_id, &row.id).await {
                    tracing::warn!(
                        error = %err,
                        instance = %row.id,
                        catalog = %catalog_id,
                        "mcp catalog delete: sync_mcp_to_dyson failed"
                    );
                }
            }
        }
        Ok(removed)
    }

    /// Clear OAuth tokens from one server entry.  The next request
    /// through the proxy will 428 with "oauth not authorised yet" until
    /// the user reconnects via /mcp/oauth/start.  Used by the SPA's
    /// "disconnect" button.
    pub async fn disconnect_mcp_oauth(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
    ) -> Result<(), SwarmError> {
        let _row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let secrets = self
            .mcp_secrets
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("mcp secrets store not configured".into()))?;
        let mut entry = mcp_servers::get(secrets, owner_id, id, name)
            .await
            .map_err(|e| SwarmError::Internal(format!("mcp get: {e}")))?
            .ok_or(SwarmError::NotFound)?;
        if entry.oauth_tokens.is_some() {
            entry.oauth_tokens = None;
            mcp_servers::put(secrets, owner_id, id, name, &entry)
                .await
                .map_err(|e| SwarmError::Internal(format!("mcp put: {e}")))?;
        }
        Ok(())
    }

    pub async fn update_models(
        &self,
        owner_id: &str,
        id: &str,
        models: Vec<String>,
    ) -> Result<(), SwarmError> {
        if models.is_empty() {
            return Err(SwarmError::PolicyDenied(
                "models list must contain at least one entry".into(),
            ));
        }
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::PolicyDenied("instance has no live sandbox to reconfigure".into())
            })?;
        let r = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        let body = ReconfigureBody {
            name: None,
            task: None,
            models: models.clone(),
            instance_id: Some(id.to_owned()),
            // Edit-models-only path: provider config stays as-is.
            proxy_token: None,
            proxy_base: None,
            ..Default::default()
        };
        push_with_retry(&**r, id, sandbox_id, &body)
            .await
            .map_err(SwarmError::PolicyDenied)?;
        // Persist AFTER the push so the row records what dyson
        // actually accepted.  Failure here means the cube agent has
        // the new vec but our DB still shows the old one — rare and
        // self-healing (the next save overwrites), so we surface the
        // store error instead of swallowing it.
        self.instances.set_models(id, &models).await?;
        Ok(())
    }

    /// Record a model switch that already happened inside the running
    /// Dyson UI. Unlike [`Self::update_models`], this does not push
    /// `/api/admin/configure` back into the sandbox: the proxied
    /// `/api/model` request has already updated the live dyson.json and
    /// any loaded agents. We only mirror the primary model into swarm's
    /// row so binary redeploys / snapshot restores replay the user's
    /// latest choice instead of the stale hire-time default.
    pub async fn record_runtime_model_selection(
        &self,
        owner_id: &str,
        id: &str,
        model: &str,
    ) -> Result<(), SwarmError> {
        let selected = model.trim();
        if selected.is_empty() {
            return Err(SwarmError::BadRequest("model must be non-empty".into()));
        }
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let models = models_with_primary(row.models, selected);
        self.instances.set_models(id, &models).await?;
        Ok(())
    }

    /// Owner-scoped tool include-list update.  Mirrors
    /// `update_models`: pushes the change into the running dyson via
    /// `/api/admin/configure` first, then persists the row so the DB
    /// records what dyson actually accepted.  Empty `tools` is
    /// meaningful — registers zero builtins.  An ALL-builtins choice
    /// is expressed by the caller flipping `reset_skills` instead, not
    /// by this path; this method always sends an explicit allowlist.
    pub async fn update_tools(
        &self,
        owner_id: &str,
        id: &str,
        tools: Vec<String>,
    ) -> Result<(), SwarmError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SwarmError::PolicyDenied("instance has no live sandbox to reconfigure".into())
            })?;
        let r = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        // Empty list = "use dyson defaults" (per PatchInstanceBody
        // docstring).  Map it to `reset_skills: true, tools: None` so
        // the loader's no-skills-block branch fires and every builtin
        // registers — same shape the create + recreate paths use.
        // Sending `tools: Some([])` hits dyson's allowlist branch and
        // registers ZERO builtins, which silently breaks bash on
        // every tools-defaulted instance.
        let body = ReconfigureBody {
            instance_id: Some(id.to_owned()),
            reset_skills: tools.is_empty(),
            tools: (!tools.is_empty()).then(|| tools.clone()),
            ..Default::default()
        };
        push_with_retry(&**r, id, sandbox_id, &body)
            .await
            .map_err(SwarmError::PolicyDenied)?;
        self.instances.set_tools(id, &tools).await?;
        Ok(())
    }

    /// Destroy an instance.  When `force` is true, a `CubeError` from
    /// `destroy_sandbox` is logged and swallowed so the row can still
    /// be reaped — admin escape hatch for the case where the underlying
    /// cube sandbox is already dead/unreachable and cubemaster keeps
    /// 502'ing.  DB-side cleanup (token revoke + status flip) still runs
    /// and its errors are still fatal: `force` only buys forgiveness for
    /// the cube call.
    pub async fn destroy(&self, owner_id: &str, id: &str, force: bool) -> Result<(), SwarmError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if let Some(sb) = &row.cube_sandbox_id {
            match self.cube.destroy_sandbox(sb).await {
                Ok(()) => {}
                Err(e) if force => {
                    tracing::warn!(
                        error = %e,
                        instance = %id,
                        sandbox = %sb,
                        "destroy: cube destroy_sandbox failed; force=true, proceeding with DB-side cleanup"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
        self.tokens.revoke_for_instance(id).await?;
        // Wipe any MCP server records associated with this instance so
        // the sealed plaintext doesn't outlive the dyson it served.
        // Best-effort — failures are logged but don't fail destroy
        // (same posture as `dyson_reconfig::forget_secret`).
        if let Some(secrets) = self.mcp_secrets.as_ref() {
            if let Err(err) = mcp_servers::forget_all(secrets, owner_id, id).await {
                tracing::warn!(
                    error = %err,
                    instance = %id,
                    "destroy: mcp forget_all failed; sealed plaintext lingers"
                );
            }
        }
        self.instances
            .update_status(id, InstanceStatus::Destroyed)
            .await?;
        Ok(())
    }

    /// Restore a new instance from a snapshot's bytes on the Cube host.
    /// The caller may supply non-reserved sandbox env through `req.env`;
    /// external credentials should be configured through MCP/user/system
    /// secret storage instead of restore-time env.
    pub async fn restore(
        &self,
        owner_id: &str,
        req: RestoreRequest,
    ) -> Result<CreatedInstance, SwarmError> {
        let id = self.mint_unique_instance_id(owner_id).await?;
        let bearer = Uuid::new_v4().simple().to_string();
        let now = now_secs();
        // Same default-no-expiry policy as `create`; opt-in via ttl_seconds.
        let expires_at = req.ttl_seconds.map(|ttl| now + ttl);

        if let Some(src) = &req.source_instance_id {
            self.instances
                .get_for_owner(owner_id, src)
                .await?
                .ok_or(SwarmError::NotFound)?;
        }

        // Resolve policy first — same as `create`.  Bad input fails
        // before anything else lands.
        let resolved_policy = network_policy::resolve(
            &req.network_policy,
            self.llm_cidr.as_deref(),
            &*self.resolver,
        )
        .await?;

        let restored_name = req.name.clone().unwrap_or_default();
        let restored_task = req.task.clone().unwrap_or_default();
        let row = InstanceRow {
            id: id.clone(),
            owner_id: owner_id.to_owned(),
            name: restored_name.clone(),
            task: restored_task.clone(),
            cube_sandbox_id: None,
            template_id: req.template_id.clone(),
            status: InstanceStatus::Cold,
            bearer_token: bearer.clone(),
            pinned: false,
            expires_at,
            last_active_at: now,
            last_probe_at: None,
            last_probe_status: None,
            created_at: now,
            destroyed_at: None,
            rotated_to: None,
            network_policy: req.network_policy.clone(),
            network_policy_cidrs: row_policy_cidrs(&req.network_policy, &resolved_policy),
            models: req.models.clone(),
            tools: req.tools.clone(),
        };
        self.instances.create(row).await?;

        let proxy_token = self.tokens.mint(&id, SHARED_PROVIDER).await?;
        // Mint a fresh ingest token for the restored instance — it has
        // a brand-new instance id and bearer, so a sibling token here
        // is a fresh row, not a reused one.
        let ingest_token = self.tokens.mint_ingest(&id).await?;
        let state_sync_token = self.tokens.mint_state_sync(&id).await?;

        // Identity envelope. Re-injected on restore so a fresh sandbox
        // (no SOUL.md) can seed itself; an inherited image with prior
        // self-knowledge will simply ignore them.
        let managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &ingest_token,
            &state_sync_token,
            &id,
            &bearer,
            &restored_name,
            &restored_task,
            &req.network_policy,
        );

        let env = compose_sandbox_env(&managed, &req.env)?;

        let info = match self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: req.template_id,
                env,
                from_snapshot_path: Some(req.snapshot_path),
                resolved_policy,
            })
            .await
        {
            Ok(info) => info,
            Err(e) => {
                let _ = self.tokens.revoke_for_instance(&id).await;
                let _ = self
                    .instances
                    .update_status(&id, InstanceStatus::Destroyed)
                    .await;
                return Err(e.into());
            }
        };

        self.instances
            .set_cube_sandbox_id(&id, &info.sandbox_id)
            .await?;
        self.instances
            .update_status(&id, InstanceStatus::Live)
            .await?;

        Ok(CreatedInstance {
            id,
            url: info.url,
            bearer_token: bearer,
            proxy_token,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateRequest {
    pub template_id: String,
    /// Human-readable label for the employee. Optional — defaults to the
    /// short id when unset. Surfaced as `SWARM_NAME` in the sandbox env.
    #[serde(default)]
    pub name: Option<String>,
    /// Free-text task / mission. Optional but strongly recommended;
    /// surfaced as `SWARM_TASK` so the agent reads its job description
    /// at boot.
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    /// Per-instance egress profile.  Default `Open` matches the
    /// pre-feature wire shape — existing callers don't need to change.
    /// See [`crate::network_policy`] for the four profiles.
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    /// Optional MCP servers attached to the dyson at hire time.
    /// Each entry's URL + auth is sealed under the owner's cipher in
    /// `user_secrets`; the agent only ever sees the swarm proxy URL.
    /// Empty (the default) keeps the existing wire shape.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RestoreRequest {
    pub template_id: String,
    /// Path on the Cube host where the snapshot bundle currently lives.
    pub snapshot_path: std::path::PathBuf,
    /// If present, this instance's secrets are copied to the new instance.
    pub source_instance_id: Option<String>,
    /// Carry-over identity. Populated by `SnapshotService::restore` from
    /// the source instance row so the restored employee keeps its name.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    /// Per-instance egress profile, carried from the source row by
    /// `SnapshotService::restore` and the binary-rotation sweep.  A
    /// raw HTTP `POST /v1/instances/:id/restore` from a CLI with no
    /// policy specified gets `NoLocalNet` (the post-A1 default that
    /// blocks RFC1918 / link-local / cloud-metadata egress).
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    /// Model id list, carried from the source row by
    /// `SnapshotService::restore` and the binary-rotation sweep so
    /// the restored employee keeps its model selection.  Empty when
    /// the source row predates the column or a raw HTTP restore
    /// caller didn't supply one — the SPA edit form treats empty as
    /// "user must pick before saving".
    #[serde(default)]
    pub models: Vec<String>,
    /// Positive include list of built-in tools — same carry-over
    /// semantics as `models`.  Empty means "use dyson defaults".
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedInstance {
    pub id: String,
    pub url: String,
    pub bearer_token: String,
    pub proxy_token: String,
}

/// Per-sweep tally returned by [`InstanceService::rotate_binary_all`].
/// `visited` counts every Live-but-outdated instance the sweep
/// considered (whether or not it succeeded); `rotated` counts the
/// ones that reached destroyed-source-and-Live-successor; `failed`
/// preserves a per-row error so an operator can pick up stragglers
/// without grepping logs.  The error string is whatever the failing
/// step returned — kept opaque on purpose so this struct doesn't
/// pin the rotation pipeline to a specific error taxonomy.
#[derive(Debug, Clone, Default)]
pub struct RotateReport {
    pub visited: usize,
    pub rotated: usize,
    pub failed: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::tokens::SqlxTokenStore;
    use crate::error::CubeError;
    use crate::traits::{CubeClient, SandboxInfo, SnapshotInfo};

    #[derive(Default)]
    struct CapturedCreate {
        template_id: String,
        env: BTreeMap<String, String>,
        from_snapshot: Option<std::path::PathBuf>,
        resolved_policy: crate::network_policy::ResolvedPolicy,
    }

    #[derive(Default)]
    struct MockCube {
        last_create: Mutex<Option<CapturedCreate>>,
        creates: Mutex<Vec<CapturedCreate>>,
        destroyed: Mutex<Vec<String>>,
        snapshotted: Mutex<Vec<String>>,
        next_sandbox_id: Mutex<u32>,
        next_snapshot_id: Mutex<u32>,
        /// When set, `destroy_sandbox` returns a synthetic CubeError
        /// instead of recording the call — used to simulate the
        /// "cube already dead/unreachable" repro the force-destroy
        /// path is meant to handle.
        fail_destroy: Mutex<bool>,
        /// When set, `snapshot_sandbox` returns a synthetic CubeError
        /// — used by `rotate_binary_failed_snapshot_is_recorded_and_skipped`
        /// to assert the rotation pipeline survives a per-row failure.
        fail_snapshot: Mutex<bool>,
    }

    impl MockCube {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn last_create(&self) -> CapturedCreate {
            self.last_create.lock().unwrap().take().unwrap()
        }
        fn fail_destroys(&self) {
            *self.fail_destroy.lock().unwrap() = true;
        }
        fn fail_snapshots(&self) {
            *self.fail_snapshot.lock().unwrap() = true;
        }
    }

    #[test]
    fn caller_env_rejects_reserved_control_keys() {
        let env = BTreeMap::from([
            (ENV_MODEL.to_string(), "openrouter/ok".to_string()),
            (ENV_PROXY_TOKEN.to_string(), "attacker".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://example.invalid:3128".to_string(),
            ),
        ]);
        let err = validate_caller_env(&env).expect_err("reserved keys rejected");
        assert!(
            err.to_string().contains(ENV_PROXY_TOKEN),
            "error names the reserved SWARM key: {err}"
        );
        assert!(
            err.to_string().contains("HTTP_PROXY"),
            "error names the proxy key: {err}"
        );
    }

    #[test]
    fn compose_sandbox_env_rejects_reserved_caller_keys_and_keeps_managed_values() {
        let managed = BTreeMap::from([
            (ENV_PROXY_TOKEN.to_string(), "managed-token".to_string()),
            (ENV_BEARER_TOKEN.to_string(), "managed-bearer".to_string()),
        ]);
        let caller = BTreeMap::from([
            (ENV_MODEL.to_string(), "openrouter/model".to_string()),
            ("APP_SETTING".to_string(), "caller".to_string()),
        ]);
        let env = compose_sandbox_env(&managed, &caller).expect("valid env");

        assert_eq!(env[ENV_PROXY_TOKEN], "managed-token");
        assert_eq!(env[ENV_BEARER_TOKEN], "managed-bearer");
        assert_eq!(env[ENV_MODEL], "openrouter/model");
        assert_eq!(env["APP_SETTING"], "caller");
    }

    #[test]
    fn models_with_primary_promotes_selection_and_preserves_fallbacks() {
        let models = models_with_primary(
            vec![
                "openrouter/default".into(),
                "openai/gpt-5".into(),
                "openrouter/fallback".into(),
                " ".into(),
            ],
            " openai/gpt-5 ",
        );
        assert_eq!(
            models,
            vec![
                "openai/gpt-5".to_string(),
                "openrouter/default".to_string(),
                "openrouter/fallback".to_string(),
            ]
        );
    }

    #[async_trait]
    impl CubeClient for MockCube {
        async fn create_sandbox(&self, args: CreateSandboxArgs) -> Result<SandboxInfo, CubeError> {
            let mut n = self.next_sandbox_id.lock().unwrap();
            *n += 1;
            let sid = format!("sb-{}", *n);
            let captured = CapturedCreate {
                template_id: args.template_id.clone(),
                env: args.env.clone(),
                from_snapshot: args.from_snapshot_path.clone(),
                resolved_policy: args.resolved_policy.clone(),
            };
            *self.last_create.lock().unwrap() = Some(CapturedCreate {
                template_id: args.template_id,
                env: args.env,
                from_snapshot: args.from_snapshot_path,
                resolved_policy: args.resolved_policy,
            });
            self.creates.lock().unwrap().push(captured);
            Ok(SandboxInfo {
                sandbox_id: sid.clone(),
                host_ip: "10.0.0.1".into(),
                url: format!("https://{sid}.cube.test"),
            })
        }

        async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), CubeError> {
            if *self.fail_destroy.lock().unwrap() {
                return Err(CubeError::Status {
                    status: 502,
                    body: "cube unreachable".into(),
                });
            }
            self.destroyed.lock().unwrap().push(sandbox_id.into());
            Ok(())
        }

        async fn snapshot_sandbox(
            &self,
            sandbox_id: &str,
            _name: &str,
        ) -> Result<SnapshotInfo, CubeError> {
            if *self.fail_snapshot.lock().unwrap() {
                return Err(CubeError::Status {
                    status: 500,
                    body: "snapshot unavailable".into(),
                });
            }
            self.snapshotted.lock().unwrap().push(sandbox_id.into());
            let mut n = self.next_snapshot_id.lock().unwrap();
            *n += 1;
            let id = format!("snap-{sandbox_id}-{}", *n);
            Ok(SnapshotInfo {
                snapshot_id: id.clone(),
                path: format!("/var/snaps/{id}"),
                host_ip: "10.0.0.1".into(),
            })
        }

        async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), CubeError> {
            // Rotation never deletes snapshots — they survive the
            // sweep so an operator can roll back if rotation produced
            // a worse instance.  This stub is enough for the tests.
            Ok(())
        }
    }

    async fn build() -> (
        InstanceService,
        Arc<MockCube>,
        Arc<dyn TokenStore>,
        Arc<dyn InstanceStore>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool,
            crate::db::test_system_cipher(),
        ));
        let svc = InstanceService::new(
            cube.clone(),
            instances.clone(),
            tokens.clone(),
            "http://swarm.test:8080/llm",
        );
        (svc, cube, tokens, instances)
    }

    /// Tests share this helper so the SWARM_MODEL requirement isn't
    /// re-stated everywhere. Returns an env map with just the model set
    /// to a placeholder; callers add their own keys on top.
    fn env_with_model() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(ENV_MODEL.into(), "anthropic/claude-sonnet-4-5".into());
        m
    }

    #[tokio::test]
    async fn create_with_name_and_task_stamps_row_and_env() {
        let (svc, cube, _tokens, instances) = build().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("PR reviewer".into()),
                    task: Some("Watch foo/bar PRs and comment on style".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        let captured = cube.last_create();
        assert_eq!(captured.env[ENV_NAME], "PR reviewer");
        assert_eq!(
            captured.env[ENV_TASK],
            "Watch foo/bar PRs and comment on style"
        );

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.name, "PR reviewer");
        assert_eq!(row.task, "Watch foo/bar PRs and comment on style");
    }

    #[tokio::test]
    async fn runtime_model_selection_updates_row_without_reconfigure() {
        let (svc, _cube, _tokens, instances) = build().await;
        let mut env = env_with_model();
        env.insert(
            ENV_MODELS.into(),
            "openrouter/default,openrouter/fallback".into(),
        );
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env,
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        svc.record_runtime_model_selection("legacy", &created.id, " openai/gpt-5 ")
            .await
            .unwrap();

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(
            row.models,
            vec![
                "openai/gpt-5".to_string(),
                "openrouter/default".to_string(),
                "openrouter/fallback".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn rename_updates_row_but_does_not_re_emit_env() {
        // Per the design, edits in swarm don't propagate to a running
        // sandbox.  This test is the contract: rename mutates the row,
        // but the cube was only invoked at create time, so its captured
        // env snapshot still has the original (empty) values.
        let (svc, cube, _tokens, _instances) = build().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        let renamed = svc
            .rename("legacy", &created.id, "renamed", "new task")
            .await
            .unwrap();
        assert_eq!(renamed.name, "renamed");
        assert_eq!(renamed.task, "new task");

        // Cube received the original empty values at create time and
        // hasn't been called since.
        let captured = cube.last_create();
        assert_eq!(captured.env[ENV_NAME], "");
        assert_eq!(captured.env[ENV_TASK], "");
    }

    #[tokio::test]
    async fn create_returns_url_and_injects_managed_env() {
        let (svc, cube, tokens, instances) = build().await;
        let mut caller = env_with_model();
        caller.insert("EXTRA".into(), "yes".into());
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-x".into(),
                    name: None,
                    task: None,
                    env: caller,
                    ttl_seconds: Some(60),
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert!(created.url.starts_with("https://sb-1."));
        assert_eq!(created.bearer_token.len(), 32);
        assert!(created.proxy_token.starts_with("pt_"));
        assert_eq!(created.proxy_token.len(), 35);

        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-x");
        assert_eq!(captured.env[ENV_PROXY_URL], "http://swarm.test:8080/llm");
        assert_eq!(captured.env[ENV_PROXY_TOKEN], created.proxy_token);
        assert_eq!(captured.env[ENV_INSTANCE_ID], created.id);
        assert_eq!(captured.env["EXTRA"], "yes");
        assert!(captured.from_snapshot.is_none());
        // Identity envelope: name + task were unset, so the env carries
        // empty strings — the agent reads them on first boot and either
        // seeds itself from blanks or falls through to its own defaults.
        assert_eq!(captured.env[ENV_NAME], "");
        assert_eq!(captured.env[ENV_TASK], "");

        let resolved = tokens.resolve(&created.proxy_token).await.unwrap().unwrap();
        assert_eq!(resolved.instance_id, created.id);
        assert_eq!(resolved.provider, SHARED_PROVIDER);

        // Phase 2: ingest token + URL must also land on the env envelope
        // alongside the chat proxy token.  Prefix is `it_` (sibling of
        // the chat token's `pt_`) and the URL is derived from the
        // operator's proxy_base (apex + /v1/internal/ingest/artefact).
        let ingest_token = &captured.env[ENV_INGEST_TOKEN];
        assert!(
            ingest_token.starts_with("it_"),
            "ingest env carries an it_ token"
        );
        assert_eq!(ingest_token.len(), 35);
        assert_eq!(
            captured.env[ENV_INGEST_URL],
            "http://swarm.test:8080/v1/internal/ingest/artefact"
        );
        let ingest_resolved = tokens.resolve(ingest_token).await.unwrap().unwrap();
        assert_eq!(ingest_resolved.instance_id, created.id);
        assert_eq!(ingest_resolved.provider, crate::db::tokens::INGEST_PROVIDER);
        let state_sync_token = &captured.env[ENV_STATE_SYNC_TOKEN];
        assert!(
            state_sync_token.starts_with("st_"),
            "state sync env carries an st_ token"
        );
        assert_eq!(state_sync_token.len(), 35);
        assert_eq!(
            captured.env[ENV_STATE_SYNC_URL],
            "http://swarm.test:8080/v1/internal/state/file"
        );
        let state_resolved = tokens.resolve(state_sync_token).await.unwrap().unwrap();
        assert_eq!(state_resolved.instance_id, created.id);
        assert_eq!(
            state_resolved.provider,
            crate::db::tokens::STATE_SYNC_PROVIDER
        );

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Live);
    }

    /// Regression for the cube → host egress proxy workaround
    /// (`http://169.254.68.5:3128`).  Some upstream networks silently
    /// drop SYN-ACKs for cube traffic that goes through the eBPF SNAT
    /// path; routing TCP via a host-resident HTTP proxy makes those
    /// destinations reachable.  Auto-injection of HTTPS_PROXY only
    /// fires when the policy already permits broad public egress —
    /// Airgap and Allowlist must not get the env, otherwise a
    /// supposedly-restricted cube can tunnel out through a broader
    /// proxy path.  These tests pin the gating directly on
    /// the helper so future policy additions force a deliberate
    /// decision (the matcher in `policy_permits_generic_egress` is
    /// exhaustive — adding an enum variant won't compile).
    #[test]
    fn proxy_env_injected_for_open_policy() {
        let env = managed_env(
            "http://swarm:8080/llm",
            "tok",
            "ingest_tok",
            "state_tok",
            "id",
            "bear",
            "n",
            "t",
            &NetworkPolicy::Open,
        );
        assert_eq!(env[ENV_HTTPS_PROXY], CUBE_HTTP_PROXY_URL);
        assert_eq!(env[ENV_HTTP_PROXY], CUBE_HTTP_PROXY_URL);
        assert_eq!(env[ENV_HTTPS_PROXY_LC], CUBE_HTTP_PROXY_URL);
        assert_eq!(env[ENV_HTTP_PROXY_LC], CUBE_HTTP_PROXY_URL);
        assert_eq!(env[ENV_NO_PROXY], CUBE_NO_PROXY);
        assert_eq!(env[ENV_NO_PROXY_LC], CUBE_NO_PROXY);
    }

    #[test]
    fn proxy_env_injected_for_nolocalnet_policy() {
        let env = managed_env(
            "http://swarm:8080/llm",
            "tok",
            "ingest_tok",
            "state_tok",
            "id",
            "bear",
            "n",
            "t",
            &NetworkPolicy::NoLocalNet,
        );
        assert_eq!(env[ENV_HTTPS_PROXY], CUBE_HTTP_PROXY_URL);
    }

    #[test]
    fn proxy_env_injected_for_denylist_policy() {
        let env = managed_env(
            "http://swarm:8080/llm",
            "tok",
            "ingest_tok",
            "state_tok",
            "id",
            "bear",
            "n",
            "t",
            &NetworkPolicy::Denylist {
                entries: vec!["1.2.3.4/32".into()],
            },
        );
        // Denylist allows everything except listed networks — proxy is
        // the sane fallback when listed networks happen to include the
        // upstream-blocked ones.
        assert_eq!(env[ENV_HTTPS_PROXY], CUBE_HTTP_PROXY_URL);
    }

    #[test]
    fn proxy_env_omitted_for_airgap_policy() {
        let env = managed_env(
            "http://swarm:8080/llm",
            "tok",
            "ingest_tok",
            "state_tok",
            "id",
            "bear",
            "n",
            "t",
            &NetworkPolicy::Airgap,
        );
        // The proxy env vars must be ABSENT under Airgap so a
        // supposedly-isolated cube can't tunnel out through the proxy.
        assert!(!env.contains_key(ENV_HTTPS_PROXY));
        assert!(!env.contains_key(ENV_HTTP_PROXY));
        assert!(!env.contains_key(ENV_NO_PROXY));
    }

    #[test]
    fn proxy_env_omitted_for_allowlist_policy() {
        let env = managed_env(
            "http://swarm:8080/llm",
            "tok",
            "ingest_tok",
            "state_tok",
            "id",
            "bear",
            "n",
            "t",
            // Allowlist is the operator's explicit "only these"
            // statement; auto-injecting a proxy that bypasses the
            // allow-list would silently widen it.
            &NetworkPolicy::Allowlist {
                entries: vec!["1.2.3.4/32".into()],
            },
        );
        assert!(!env.contains_key(ENV_HTTPS_PROXY));
    }

    #[test]
    fn ingest_env_keys_are_stamped_alongside_proxy_keys() {
        // SWARM_INGEST_URL and SWARM_INGEST_TOKEN must land on every
        // managed env envelope so the dyson agent's send_artefact has
        // somewhere to push.  URL is derived by stripping `/llm` from
        // the chat proxy base and appending the ingest route path.
        let env = managed_env(
            "http://swarm.example/llm",
            "pt_chat",
            "it_ingest",
            "st_state",
            "id",
            "bear",
            "n",
            "t",
            &NetworkPolicy::Open,
        );
        assert_eq!(env[ENV_INGEST_TOKEN], "it_ingest");
        assert_eq!(
            env[ENV_INGEST_URL],
            "http://swarm.example/v1/internal/ingest/artefact"
        );
        assert_eq!(env[ENV_STATE_SYNC_TOKEN], "st_state");
        assert_eq!(
            env[ENV_STATE_SYNC_URL],
            "http://swarm.example/v1/internal/state/file"
        );
    }

    #[test]
    fn ingest_url_handles_proxy_base_without_llm_suffix() {
        // Some deploys point `proxy_base` at the apex directly (no
        // `/llm` segment).  The strip is a no-op and the path appends
        // cleanly.
        assert_eq!(
            build_ingest_url("https://swarm.example"),
            "https://swarm.example/v1/internal/ingest/artefact",
        );
        // Trailing slash on the apex is tolerated.
        assert_eq!(
            build_ingest_url("https://swarm.example/"),
            "https://swarm.example/v1/internal/ingest/artefact",
        );
    }

    #[test]
    fn ingest_url_empty_when_proxy_base_unset() {
        // Local dev / tests boot swarm without a hostname, so
        // proxy_base is empty.  The empty URL signals dyson to skip
        // ingest pushes — same posture as the proxy_url-empty branch
        // in `dyson swarm`'s warmup config writer.
        assert_eq!(build_ingest_url(""), "");
        assert_eq!(build_ingest_url("/"), "");
    }

    #[tokio::test]
    async fn caller_env_cannot_override_managed_control_keys() {
        let (svc, cube, _tokens, _instances) = build().await;
        let mut caller = env_with_model();
        caller.insert(ENV_PROXY_URL.into(), "http://override".into());
        let err = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: caller,
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .expect_err("reserved env override rejected");
        assert!(err.to_string().contains(ENV_PROXY_URL));
        assert!(
            cube.last_create.lock().unwrap().is_none(),
            "sandbox must not be created after reserved env rejection"
        );
    }

    #[tokio::test]
    async fn caller_env_still_allows_non_reserved_keys() {
        let (svc, cube, _tokens, _instances) = build().await;
        let mut caller = env_with_model();
        caller.insert("APP_SETTING".into(), "caller-value".into());
        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: caller,
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = cube.last_create();
        assert_eq!(captured.env["APP_SETTING"], "caller-value");
    }

    #[tokio::test]
    async fn destroy_revokes_proxy_tokens_and_marks_destroyed() {
        let (svc, cube, tokens, instances) = build().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert!(
            tokens
                .resolve(&created.proxy_token)
                .await
                .unwrap()
                .is_some()
        );
        // Pull the ingest token sibling that create() also minted
        // (we don't expose it on CreatedInstance) so we can assert
        // destroy revokes it alongside the chat token.
        let ingest_token = tokens
            .lookup_by_instance_for_provider(&created.id, crate::db::tokens::INGEST_PROVIDER)
            .await
            .unwrap()
            .expect("create must mint an ingest token");

        svc.destroy("legacy", &created.id, false).await.unwrap();
        assert!(
            tokens
                .resolve(&created.proxy_token)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            tokens.resolve(&ingest_token).await.unwrap().is_none(),
            "destroy must revoke ingest token alongside chat token",
        );

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Destroyed);
        assert!(row.destroyed_at.is_some());

        assert_eq!(cube.destroyed.lock().unwrap().as_slice(), ["sb-1"]);
    }

    #[tokio::test]
    async fn destroy_unknown_returns_not_found() {
        let (svc, _cube, _tokens, _instances) = build().await;
        let err = svc
            .destroy("legacy", "nope", false)
            .await
            .expect_err("must error");
        matches!(err, SwarmError::NotFound);
    }

    /// Repro for the dead-cube case: an admin tries to destroy an
    /// instance whose underlying sandbox cubemaster can't reach.
    /// Without `force`, the cube error bubbles and the row stays Live
    /// forever (the bug).  With `force=true`, the service logs the
    /// cube failure and still revokes tokens + flips the row to
    /// Destroyed so the API stops 502'ing on it.
    #[tokio::test]
    async fn destroy_force_proceeds_when_cube_errors() {
        let (svc, cube, tokens, instances) = build().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        cube.fail_destroys();

        // Strict path bubbles the cube error and leaves the row Live.
        let err = svc
            .destroy("legacy", &created.id, false)
            .await
            .expect_err("non-force destroy must surface cube error");
        assert!(matches!(err, SwarmError::Cube(_)));
        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Live);
        assert!(
            tokens
                .resolve(&created.proxy_token)
                .await
                .unwrap()
                .is_some()
        );

        // Force path swallows the cube error and reaps DB-side.
        svc.destroy("legacy", &created.id, true).await.unwrap();
        assert!(
            tokens
                .resolve(&created.proxy_token)
                .await
                .unwrap()
                .is_none()
        );
        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Destroyed);
        assert!(row.destroyed_at.is_some());
        // Cube destroy was attempted (and rejected) — the destroyed
        // list stays empty because the mock returns Err before
        // recording.
        assert!(cube.destroyed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn restore_uses_snapshot_path_without_carrying_env_secrets() {
        let (svc, cube, _tokens, _instances) = build().await;
        let src = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        let restored = svc
            .restore(
                "legacy",
                RestoreRequest {
                    template_id: "tpl".into(),
                    snapshot_path: "/var/snaps/snap-1".into(),
                    source_instance_id: Some(src.id.clone()),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    models: Vec::new(),
                    tools: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert_ne!(restored.id, src.id);

        let captured = cube.last_create();
        assert_eq!(
            captured.from_snapshot.as_deref(),
            Some(std::path::Path::new("/var/snaps/snap-1"))
        );
        assert!(
            !captured.env.contains_key("K"),
            "restore must not read or carry per-instance secrets into sandbox env"
        );
    }

    /// Recorder reconfigurer.  Captures every body push so tests can
    /// inspect the values swarm chose.  Always succeeds — failure paths
    /// have their own coverage in the retry/backoff tests.
    #[derive(Default)]
    struct RecordingReconfigurer {
        pushed: Mutex<Vec<(String, String, ReconfigureBody)>>,
        restored: Mutex<Vec<(String, String, RestoreStateFileBody)>>,
        events: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DysonReconfigurer for RecordingReconfigurer {
        async fn push(
            &self,
            instance_id: &str,
            sandbox_id: &str,
            body: &ReconfigureBody,
        ) -> Result<(), String> {
            self.pushed
                .lock()
                .unwrap()
                .push((instance_id.into(), sandbox_id.into(), body.clone()));
            self.events.lock().unwrap().push("push".into());
            Ok(())
        }

        async fn restore_state_file(
            &self,
            instance_id: &str,
            sandbox_id: &str,
            body: &RestoreStateFileBody,
        ) -> Result<(), String> {
            self.restored.lock().unwrap().push((
                instance_id.into(),
                sandbox_id.into(),
                body.clone(),
            ));
            self.events
                .lock()
                .unwrap()
                .push(format!("restore:{}:{}", body.namespace, body.path));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FlakyRestoreReconfigurer {
        attempts: Mutex<usize>,
    }

    #[async_trait]
    impl DysonReconfigurer for FlakyRestoreReconfigurer {
        async fn push(
            &self,
            _instance_id: &str,
            _sandbox_id: &str,
            _body: &ReconfigureBody,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn restore_state_file(
            &self,
            _instance_id: &str,
            _sandbox_id: &str,
            _body: &RestoreStateFileBody,
        ) -> Result<(), String> {
            let mut attempts = self.attempts.lock().unwrap();
            *attempts += 1;
            if *attempts == 1 {
                return Err("dyson /api/admin/state/file 502 Bad Gateway".into());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn restore_state_file_retry_survives_transient_cubeproxy_502() {
        let reconfigurer = FlakyRestoreReconfigurer::default();
        let body = RestoreStateFileBody {
            namespace: "workspace".into(),
            path: "memory/SOUL.md".into(),
            mime: Some("text/markdown".into()),
            deleted: false,
            body_b64: Some("cmVtZW1iZXI=".into()),
        };

        restore_state_file_with_retry(&reconfigurer, "inst-a", "sandbox-a", &body)
            .await
            .unwrap();

        assert_eq!(*reconfigurer.attempts.lock().unwrap(), 2);
    }

    /// Regression for the chat-hang-then-`upstream HTTP error` bug.
    ///
    /// `proxy_base` ends up in dyson.json's `providers.openrouter.base_url`,
    /// and dyson's `OpenAiCompatClient` appends `/v1/chat/completions` to
    /// it on every request.  If swarm hands dyson a base ending in `/v1`,
    /// the URL doubles up to `.../openrouter/v1/v1/chat/completions` —
    /// OpenRouter's CDN serves the marketing site at that path and dyson
    /// surfaces the resulting non-200 as a generic "upstream HTTP error".
    /// This test pins the contract: swarm's reconfigure push uses
    /// `<proxy_base>/openrouter`, with no trailing `/v1`.
    #[tokio::test]
    async fn create_pushes_proxy_base_without_trailing_v1() {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool,
            crate::db::test_system_cipher(),
        ));
        let svc = InstanceService::new(
            cube.clone(),
            instances,
            tokens,
            "https://dyson.example.com/llm",
        );
        let recorder = Arc::new(RecordingReconfigurer::default());
        let svc = svc.with_reconfigurer(recorder.clone());

        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: Some("alice".into()),
                task: Some("review prs".into()),
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();

        // The reconfigure push happens in a tokio::spawn — give it a
        // moment to land.  Five 50ms probes is plenty for the in-process
        // recorder.
        for _ in 0..5 {
            if !recorder.pushed.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let pushed = recorder.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1, "exactly one reconfigure push expected");
        let (_, _, body) = &pushed[0];
        let proxy_base = body
            .proxy_base
            .as_deref()
            .expect("proxy_base must be set on create-time push");
        assert_eq!(
            proxy_base, "https://dyson.example.com/llm/openrouter",
            "proxy_base must NOT end in /v1 — dyson's openai client appends \
             /v1/chat/completions itself, doubling /v1 hits OR's marketing \
             site at /v1/v1/... and surfaces as 'upstream HTTP error'"
        );
    }

    /// Helper: stand up an InstanceService backed by sqlx stores and a
    /// recording reconfigurer.  Used by the image-gen rewire tests
    /// below; folded into a helper because every test needs the same
    /// 6-line dance.
    async fn build_with_recorder() -> (
        Arc<InstanceService>,
        Arc<MockCube>,
        Arc<dyn TokenStore>,
        Arc<dyn InstanceStore>,
        Arc<RecordingReconfigurer>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool,
            crate::db::test_system_cipher(),
        ));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let svc = InstanceService::new(
            cube.clone(),
            instances.clone(),
            tokens.clone(),
            "https://dyson.example.com/llm",
        )
        .with_reconfigurer(recorder.clone());
        (Arc::new(svc), cube, tokens, instances, recorder)
    }

    /// Block until N pushes have landed in the recorder, or 1s passes.
    /// The configure push runs in `create()`'s tail so a race-free
    /// test needs to poll, not assume.
    async fn wait_for_pushes(recorder: &RecordingReconfigurer, want: usize) {
        for _ in 0..40 {
            if recorder.pushed.lock().unwrap().len() >= want {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn rename_waits_for_identity_reconfigure() {
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("old".into()),
                    task: Some("old task".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        recorder.pushed.lock().unwrap().clear();

        svc.rename("legacy", &created.id, "new", "new task")
            .await
            .unwrap();

        let pushed = recorder.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1, "rename should finish after configure push");
        let (_instance_id, _sandbox_id, body) = &pushed[0];
        assert_eq!(body.name.as_deref(), Some("new"));
        assert_eq!(body.task.as_deref(), Some("new task"));
        assert_eq!(body.instance_id.as_deref(), Some(created.id.as_str()));
    }

    #[tokio::test]
    async fn mirror_identity_from_instance_updates_row_without_reconfigure() {
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        let created = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("old".into()),
                    task: Some("old task".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        recorder.pushed.lock().unwrap().clear();

        let mirrored = svc
            .mirror_identity_from_instance(
                "legacy",
                &created.id,
                "axelrod",
                "# IDENTITY.md — Who Am I?\n\n- **Name:** axelrod",
            )
            .await
            .unwrap();

        assert_eq!(mirrored.name, "axelrod");
        assert_eq!(
            mirrored.task,
            "# IDENTITY.md — Who Am I?\n\n- **Name:** axelrod"
        );
        assert!(
            recorder.pushed.lock().unwrap().is_empty(),
            "instance-originated identity sync must not push stale state back"
        );
    }

    #[tokio::test]
    async fn create_push_carries_image_generation_defaults() {
        // Every freshly-hired dyson must arrive with the image-gen
        // wiring already pushed — no operator follow-up required, no
        // manual `/api/admin/configure` call.  The block points at the
        // same swarm /llm/openrouter hop the chat path uses (so the
        // reused proxy_token authenticates) and the agent fields
        // resolve to that block's name.
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: Some("alice".into()),
                task: Some("review prs".into()),
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = &pushed[0];

        assert_eq!(
            body.image_provider_name.as_deref(),
            Some("openrouter-image")
        );
        assert_eq!(
            body.image_generation_provider.as_deref(),
            Some("openrouter-image"),
        );
        assert_eq!(
            body.image_generation_model.as_deref(),
            Some("google/gemini-3-pro-image-preview"),
        );
        let block = body
            .image_provider_block
            .as_ref()
            .expect("image provider block must be present");
        assert_eq!(block["type"], "openrouter");
        assert_eq!(
            block["base_url"],
            "https://dyson.example.com/llm/openrouter"
        );
        assert_eq!(block["models"][0], "google/gemini-3-pro-image-preview");
        // The api_key on the image block is the same proxy_token the
        // chat block uses — proves the swarm hop is reused (no second
        // mint, no second token to revoke on destroy).
        let chat_token = body
            .proxy_token
            .as_deref()
            .expect("chat proxy_token must be set");
        assert_eq!(block["api_key"], chat_token);
        // Skills reset must ride along on every create — closes the
        // toolless-dyson bug for instances that booted from an older
        // template whose dyson swarm writer wrote
        // `skills.builtin.tools = []`.
        assert!(body.reset_skills, "create push must flip reset_skills");
    }

    #[tokio::test]
    async fn create_push_uses_requested_image_generation_model() {
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        let mut env = env_with_model();
        env.insert(
            ENV_IMAGE_GENERATION_MODEL.into(),
            "google/gemini-custom-image".into(),
        );

        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: Some("alice".into()),
                task: Some("draw things".into()),
                env,
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = &pushed[0];

        assert_eq!(
            body.image_generation_model.as_deref(),
            Some("google/gemini-custom-image"),
        );
        let block = body
            .image_provider_block
            .as_ref()
            .expect("image provider block must be present");
        assert_eq!(block["models"][0], "google/gemini-custom-image");
    }

    #[tokio::test]
    async fn create_persists_mcp_specs_and_pushes_proxied_entries() {
        // The whole feature: a hire that supplies MCP servers must
        //   (1) seal the upstream URL + auth in user_secrets under the
        //       owner's cipher (so a stolen sqlite row leaks nothing),
        //   (2) build the dyson.json block with the SWARM proxy URL +
        //       the per-instance bearer (so the agent never sees the
        //       upstream URL or its credentials),
        //   (3) ride the configure push as `mcp_servers` so the running
        //       dyson reloads with MCP wired up on the next turn.
        let pool = crate::db::open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(tmp.path()).unwrap());
        let user_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(UserSecretsService::new(user_store, dir));
        let svc = Arc::new(
            InstanceService::new(cube, instances, tokens, "https://dyson.example.com/llm")
                .with_reconfigurer(recorder.clone())
                .with_mcp_secrets(user_secrets.clone()),
        );

        // The age cipher rejects non-hex user ids ("legacy" is a sentinel
        // the migration seeds; for this test we want a real owner whose
        // id round-trips through `CipherDirectory::for_user`).
        let owner = "deadbeef".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();

        let created = svc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("alice".into()),
                    task: Some("triage".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: vec![
                        crate::mcp_servers::McpServerSpec {
                            name: "linear".into(),
                            url: "https://8.8.8.8/mcp".into(),
                            auth: crate::mcp_servers::McpAuthSpec::Bearer {
                                token: "lin_secret".into(),
                            },
                            enabled_tools: None,
                        },
                        crate::mcp_servers::McpServerSpec {
                            name: "no_auth".into(),
                            url: "https://8.8.4.4/mcp".into(),
                            auth: crate::mcp_servers::McpAuthSpec::None,
                            enabled_tools: None,
                        },
                    ],
                },
            )
            .await
            .unwrap();

        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = &pushed[0];
        let block = body
            .mcp_servers
            .as_ref()
            .expect("mcp_servers must ride the configure push");
        assert_eq!(block.len(), 2, "both servers must appear in the body");

        let linear = &block["linear"];
        // Origin only — `/llm` is stripped because LLM and MCP mount
        // off the same swarm origin.  See `dyson_json_block`.
        let expected_url = format!("https://dyson.example.com/mcp/{}/linear", created.id,);
        assert_eq!(linear["url"], expected_url);
        let header = linear["headers"]["Authorization"].as_str().unwrap();
        let want_header = format!("Bearer {}", created.proxy_token);
        assert_eq!(
            header, want_header,
            "agent's MCP bearer must equal the per-instance proxy_token"
        );

        // Persistence: the upstream URL + bearer are sealed in user_secrets.
        let entry = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "linear")
            .await
            .unwrap()
            .expect("linear entry must be persisted");
        assert_eq!(entry.url, "https://8.8.8.8/mcp");
        match entry.auth {
            crate::mcp_servers::McpAuthSpec::Bearer { token } => {
                assert_eq!(
                    token, "lin_secret",
                    "real upstream token round-trips through user_secrets verbatim"
                );
            }
            other => panic!("expected bearer auth, got {other:?}"),
        }

        // Index row lists every name attached to this instance.
        let names = crate::mcp_servers::list_names(&user_secrets, &owner, &created.id)
            .await
            .unwrap();
        let mut sorted = names;
        sorted.sort();
        assert_eq!(sorted, vec!["linear", "no_auth"]);
    }

    #[tokio::test]
    async fn put_mcp_server_persists_and_pushes_proxied_block() {
        // The instance-detail panel calls into put_mcp_server when the
        // user adds or edits a server.  Two invariants matter:
        //   (1) the upstream URL + token round-trip through user_secrets
        //       under the OWNER's cipher (no plaintext at rest), and
        //   (2) the configure push sees the FULL proxied block — not
        //       just the new entry — so the running dyson's mcp_servers
        //       map ends up consistent with what's persisted (otherwise
        //       a delete-then-add via the panel would silently drop
        //       earlier entries on the dyson side).
        let (svc, _cube, _tokens, _instances, recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;
        // Drain the create-time push so we assert on the put path's body.
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "linear".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Bearer {
                    token: "lin_xxx".into(),
                },
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = pushed.last().unwrap();
        let block = body
            .mcp_servers
            .as_ref()
            .expect("put must push mcp_servers");
        assert!(block.contains_key("linear"));

        // Persistence carried the real upstream + bearer.
        let entry = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "linear")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.url, "https://8.8.8.8/mcp");
        match entry.auth {
            crate::mcp_servers::McpAuthSpec::Bearer { token } => assert_eq!(token, "lin_xxx"),
            _ => panic!("bearer auth expected"),
        }

        // Index has the new name.
        let names = crate::mcp_servers::list_names(&user_secrets, &owner, &created.id)
            .await
            .unwrap();
        assert_eq!(names, vec!["linear"]);
    }

    #[tokio::test]
    async fn put_mcp_server_rejects_loopback_upstream_url() {
        let (svc, _cube, _tokens, _instances, _recorder, _user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;

        let err = svc
            .put_mcp_server(
                &owner,
                &created.id,
                McpServerSpec {
                    name: "local".into(),
                    url: "http://127.0.0.1:11434/mcp".into(),
                    auth: crate::mcp_servers::McpAuthSpec::None,
                    enabled_tools: None,
                },
            )
            .await
            .expect_err("loopback MCP upstream must be rejected by SSRF policy");
        assert!(
            matches!(err, SwarmError::BadRequest(_) | SwarmError::PolicyDenied(_)),
            "unexpected error: {err:?}",
        );
    }

    #[tokio::test]
    async fn put_vscode_mcp_config_adds_docker_without_replacing_remote_servers() {
        let (svc, _cube, _tokens, _instances, recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "linear".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::None,
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        let raw = serde_json::json!({
            "servers": {
                "github": {
                    "type": "stdio",
                    "command": "docker",
                    "args": ["run", "-i", "--rm", "ghcr.io/example/github-mcp"]
                }
            }
        });
        svc.put_vscode_mcp_config(&owner, &created.id, raw.clone())
            .await
            .unwrap();

        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = pushed.last().unwrap();
        let block = body
            .mcp_servers
            .as_ref()
            .expect("put must push mcp_servers");
        assert!(block.contains_key("linear"));
        assert!(block.contains_key("github"));

        let mut names = crate::mcp_servers::list_names(&user_secrets, &owner, &created.id)
            .await
            .unwrap();
        names.sort();
        assert_eq!(names, vec!["github", "linear"]);

        let github = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(github.raw_vscode_config, Some(raw.clone()));
        assert!(matches!(
            github.runtime,
            Some(crate::mcp_servers::McpRuntimeSpec::DockerStdio { .. })
        ));
        assert_eq!(
            svc.get_vscode_mcp_config(&owner, &created.id, None)
                .await
                .unwrap(),
            Some(raw.clone())
        );
        assert_eq!(
            svc.get_vscode_mcp_config(&owner, &created.id, Some("github"))
                .await
                .unwrap(),
            Some(raw)
        );
    }

    #[tokio::test]
    async fn put_docker_catalog_mcp_server_renders_template_and_pushes_proxy_block() {
        let (svc, _cube, _tokens, _instances, recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        let catalog = crate::mcp_servers::McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "-e", "GITHUB_TOKEN", "ghcr.io/example/github-mcp"],
                        "env": { "GITHUB_TOKEN": "{{placeholder.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![crate::mcp_servers::McpDockerPlaceholderSpec {
                id: "github_token".into(),
                label: "GitHub token".into(),
                description: None,
                required: true,
                secret: true,
                placeholder: None,
            }],
        };

        let name = svc
            .put_docker_catalog_mcp_server(
                &owner,
                &created.id,
                &catalog,
                BTreeMap::from([("github_token".into(), "ghp_secret".into())]),
            )
            .await
            .unwrap();
        assert_eq!(name, "github");

        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = pushed.last().unwrap();
        let block = body
            .mcp_servers
            .as_ref()
            .expect("catalog put must push mcp_servers");
        assert!(block.contains_key("github"));

        let entry = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.raw_vscode_config, None);
        assert_eq!(entry.docker_catalog.as_ref().unwrap().id, "github");
        match entry.runtime {
            Some(crate::mcp_servers::McpRuntimeSpec::DockerStdio { env, .. }) => {
                assert_eq!(env["GITHUB_TOKEN"], "ghp_secret");
            }
            other => panic!("expected docker stdio runtime, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_docker_catalog_mcp_servers_removes_bound_entries_and_resyncs() {
        let (svc, _cube, _tokens, _instances, recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        let catalog = crate::mcp_servers::McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "-e", "GITHUB_TOKEN", "ghcr.io/example/github-mcp"],
                        "env": { "GITHUB_TOKEN": "{{placeholder.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![crate::mcp_servers::McpDockerPlaceholderSpec {
                id: "github_token".into(),
                label: "GitHub token".into(),
                description: None,
                required: true,
                secret: true,
                placeholder: None,
            }],
        };
        svc.put_docker_catalog_mcp_server(
            &owner,
            &created.id,
            &catalog,
            BTreeMap::from([("github_token".into(), "ghp_secret".into())]),
        )
        .await
        .unwrap();
        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "linear".into(),
                url: "https://8.8.4.4/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::None,
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 2).await;
        recorder.pushed.lock().unwrap().clear();

        let removed = svc
            .delete_mcp_servers_for_docker_catalog("github")
            .await
            .unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].instance_id, created.id);
        assert_eq!(removed[0].name, "github");
        assert!(removed[0].runtime.is_some());

        assert!(
            crate::mcp_servers::get(&user_secrets, &owner, &created.id, "github")
                .await
                .unwrap()
                .is_none()
        );
        let names = crate::mcp_servers::list_names(&user_secrets, &owner, &created.id)
            .await
            .unwrap();
        assert_eq!(names, vec!["linear"]);

        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = pushed.last().unwrap();
        let block = body
            .mcp_servers
            .as_ref()
            .expect("catalog delete must push mcp_servers");
        assert!(!block.contains_key("github"));
        assert!(block.contains_key("linear"));
    }

    #[tokio::test]
    async fn put_mcp_server_preserves_oauth_tokens_when_shape_unchanged() {
        // A user editing only the URL (or scopes irrelevant fields)
        // shouldn't have to re-run the OAuth flow.  put_mcp_server's
        // auth_shape_matches branch keeps existing tokens alive when
        // the auth shape (kind + scopes + endpoints) is unchanged.
        let (svc, _cube, _tokens, _instances, _recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;

        // Initial OAuth server with no tokens yet.
        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "gh".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Oauth {
                    scopes: vec!["read".into()],
                    client_id: None,
                    client_secret: None,
                    authorization_url: None,
                    token_url: None,
                    registration_url: None,
                },
                enabled_tools: None,
            },
        )
        .await
        .unwrap();

        // Stamp tokens directly (simulates a completed OAuth callback).
        let mut entry = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "gh")
            .await
            .unwrap()
            .unwrap();
        entry.oauth_tokens = Some(crate::mcp_servers::McpOAuthTokens {
            access_token: "AT".into(),
            refresh_token: Some("RT".into()),
            expires_at: Some(crate::now_secs() + 3600),
            token_url: "https://8.8.8.8/token".into(),
            client_id: "c".into(),
            client_secret: None,
        });
        crate::mcp_servers::put(&user_secrets, &owner, &created.id, "gh", &entry)
            .await
            .unwrap();

        // Edit only the URL — auth shape unchanged.
        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "gh".into(),
                url: "https://8.8.4.4/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Oauth {
                    scopes: vec!["read".into()],
                    client_id: None,
                    client_secret: None,
                    authorization_url: None,
                    token_url: None,
                    registration_url: None,
                },
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        let after = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "gh")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.url, "https://8.8.4.4/mcp");
        let tokens = after.oauth_tokens.expect("oauth tokens must be preserved");
        assert_eq!(tokens.access_token, "AT");
    }

    #[tokio::test]
    async fn put_mcp_server_clears_oauth_tokens_when_scopes_change() {
        // Changing scopes invalidates the existing access token (its
        // grant covers the old scope set, not the new one).  Wiping
        // tokens forces a reconnect and is the safe move.
        let (svc, _cube, _tokens, _instances, _recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;

        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "x".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Oauth {
                    scopes: vec!["read".into()],
                    client_id: None,
                    client_secret: None,
                    authorization_url: None,
                    token_url: None,
                    registration_url: None,
                },
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        let mut e = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "x")
            .await
            .unwrap()
            .unwrap();
        e.oauth_tokens = Some(crate::mcp_servers::McpOAuthTokens {
            access_token: "old".into(),
            refresh_token: None,
            expires_at: None,
            token_url: "u".into(),
            client_id: "c".into(),
            client_secret: None,
        });
        crate::mcp_servers::put(&user_secrets, &owner, &created.id, "x", &e)
            .await
            .unwrap();

        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "x".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Oauth {
                    scopes: vec!["write".into()],
                    client_id: None,
                    client_secret: None,
                    authorization_url: None,
                    token_url: None,
                    registration_url: None,
                },
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        let after = crate::mcp_servers::get(&user_secrets, &owner, &created.id, "x")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.oauth_tokens.is_none(),
            "scope change must wipe stale tokens"
        );
    }

    #[tokio::test]
    async fn delete_mcp_server_drops_index_when_last_entry_removed() {
        // After removing the last MCP server, the index row should be
        // gone too — keeps user_secrets tidy and avoids an empty
        // `mcp_servers` block lingering in dyson.json reload after reload.
        let (svc, _cube, _tokens, _instances, _recorder, user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;

        svc.put_mcp_server(
            &owner,
            &created.id,
            McpServerSpec {
                name: "only".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::None,
                enabled_tools: None,
            },
        )
        .await
        .unwrap();
        svc.delete_mcp_server(&owner, &created.id, "only")
            .await
            .unwrap();

        assert!(
            crate::mcp_servers::get(&user_secrets, &owner, &created.id, "only")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            crate::mcp_servers::list_names(&user_secrets, &owner, &created.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn put_mcp_server_rejects_cross_owner_instance() {
        // Owner-scoped existence: another user's id must surface as
        // NotFound, not as a successful write the legitimate owner
        // could later read.  We only need a user_id the cipher will
        // accept (32-hex) — get_for_owner returns None for the
        // mismatch before we ever touch user_secrets, so seeding the
        // "other" user row in the DB isn't required.
        let (svc, _cube, _tokens, _instances, _recorder, _user_secrets, owner) =
            build_with_mcp_secrets().await;
        let created = hire_minimal(&svc, &owner).await;
        let other = "feedface".repeat(4);
        let err = svc
            .put_mcp_server(
                &other,
                &created.id,
                McpServerSpec {
                    name: "x".into(),
                    url: "https://8.8.8.8/mcp".into(),
                    auth: crate::mcp_servers::McpAuthSpec::None,
                    enabled_tools: None,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, SwarmError::NotFound),
            "cross-owner put must surface as NotFound, got {err:?}"
        );
    }

    /// Build a service with everything wired (recorder, mcp_secrets, real
    /// pool, real cipher dir) and a hex owner the cipher will accept.
    /// Returns enough handles for the put/delete tests to assert on
    /// each layer (recorder → push body, user_secrets → at-rest blob).
    async fn build_with_mcp_secrets() -> (
        Arc<InstanceService>,
        Arc<MockCube>,
        Arc<dyn TokenStore>,
        Arc<dyn InstanceStore>,
        Arc<RecordingReconfigurer>,
        Arc<UserSecretsService>,
        String,
    ) {
        let pool = crate::db::open_in_memory().await.unwrap();
        let owner = "deadbeef".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let tmp = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(tmp.path()).unwrap());
        let user_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(UserSecretsService::new(user_store, dir));
        let svc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens.clone(),
                "https://dyson.example.com/llm",
            )
            .with_reconfigurer(recorder.clone())
            .with_mcp_secrets(user_secrets.clone()),
        );
        (svc, cube, tokens, instances, recorder, user_secrets, owner)
    }

    async fn hire_minimal(svc: &InstanceService, owner: &str) -> CreatedInstance {
        svc.create(
            owner,
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn create_with_no_mcp_servers_omits_block_in_push() {
        // No MCP specs means `mcp_servers: None` in the configure body
        // — the dyson admin handler treats that as "leave existing
        // block alone", so we never accidentally clobber a manually-
        // patched dyson.json when the user hires without MCP.
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushed = recorder.pushed.lock().unwrap();
        let (_, _, body) = &pushed[0];
        assert!(
            body.mcp_servers.is_none(),
            "an empty hire-form mcp_servers must serialise as None, not Some({{}})"
        );
    }

    #[tokio::test]
    async fn rewire_image_generation_visits_each_live_instance_with_its_token() {
        // Hire two dysons.  After the create-time pushes drain, run
        // the sweep — it must visit each one and stamp the SAME
        // proxy_token already embedded in the chat path on each
        // instance's image provider block.  Pre-Stage-8 instances
        // (no token row) are skipped silently.
        let (svc, _cube, tokens, _instances, recorder) = build_with_recorder().await;
        let a = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let explicit_tools = vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "search_files".to_string(),
        ];
        let mut b_env = env_with_model();
        b_env.insert(ENV_TOOLS.into(), explicit_tools.join(","));
        let b = svc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: b_env,
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 2).await;
        // Drop the create-time pushes so the sweep's are the only ones
        // we assert on.
        recorder.pushed.lock().unwrap().clear();

        let (visited, succeeded) = svc
            .rewire_image_generation_all()
            .await
            .expect("sweep must succeed against an in-memory store");
        assert_eq!(visited, 2);
        assert_eq!(succeeded, 2);

        let pushed = recorder.pushed.lock().unwrap().clone();
        assert_eq!(pushed.len(), 2);
        // Map by instance_id for stable assertions regardless of
        // store iteration order.
        let by_id: std::collections::HashMap<_, _> =
            pushed.into_iter().map(|(id, _, body)| (id, body)).collect();

        for (created, expect_token) in [(&a.id, &a.proxy_token), (&b.id, &b.proxy_token)] {
            let body = by_id.get(created).expect("each instance must be visited");
            assert_eq!(
                body.image_provider_name.as_deref(),
                Some("openrouter-image")
            );
            assert_eq!(
                body.image_generation_model.as_deref(),
                Some("google/gemini-3-pro-image-preview"),
            );
            let block = body.image_provider_block.as_ref().unwrap();
            assert_eq!(block["api_key"], *expect_token);
            // Sweep pushes ONLY image-gen fields — no chat-side
            // mutation that could clobber a legitimate operator
            // override of dyson.json.
            assert!(
                body.proxy_token.is_none(),
                "sweep must not push proxy_token"
            );
            assert!(body.proxy_base.is_none(), "sweep must not push proxy_base");
            assert!(body.models.is_empty(), "sweep must not push models");
        }
        let a_body = by_id.get(&a.id).unwrap();
        assert!(
            a_body.reset_skills,
            "default-tool instances still self-heal to dyson defaults"
        );
        assert!(
            a_body.tools.is_none(),
            "default-tool instances should not push an explicit allowlist"
        );
        let b_body = by_id.get(&b.id).unwrap();
        assert!(
            !b_body.reset_skills,
            "explicit tool allowlists must not be reset on sweep"
        );
        assert_eq!(
            b_body.tools.as_deref(),
            Some(explicit_tools.as_slice()),
            "sweep must preserve the admin-selected tool allowlist"
        );
        // Verify the token-store reverse lookup returns each token —
        // the sweep depends on this and a regression here would make
        // the sweep silently skip every instance.
        for (id, expect) in [(&a.id, &a.proxy_token), (&b.id, &b.proxy_token)] {
            let got = tokens.lookup_by_instance(id).await.unwrap();
            assert_eq!(got.as_ref(), Some(expect));
        }
    }

    #[tokio::test]
    async fn rewire_image_generation_no_op_when_defaults_disabled() {
        // Operators who manually patched dyson.json get an opt-out:
        // `with_image_gen_defaults(None)` makes the sweep do nothing
        // so a swarm restart doesn't fight their override.
        let (svc, _cube, _tokens, _instances, recorder) = build_with_recorder().await;
        // Rebuild the service with image-gen disabled.  The same
        // recorder + stores are reused, so prior creates still count.
        let pool_svc = std::sync::Arc::try_unwrap(svc)
            .ok()
            .unwrap()
            .with_image_gen_defaults(None);
        let svc = std::sync::Arc::new(pool_svc);
        svc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        let (visited, succeeded) = svc.rewire_image_generation_all().await.unwrap();
        assert_eq!(visited, 0, "disabled defaults must short-circuit the sweep");
        assert_eq!(succeeded, 0);
        assert!(
            recorder.pushed.lock().unwrap().is_empty(),
            "no pushes should fire when image_gen_defaults is None"
        );
    }

    // ---- Binary-rotation sweep tests ------------------------------
    //
    // The rotation pipeline calls SnapshotService::snapshot, which is
    // owned by the snapshot module — so the test fixtures here build
    // both InstanceService and SnapshotService against shared sqlite
    // and a single MockCube.  The local backup sink is enough; the
    // rotation tests don't exercise any S3 path.

    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::snapshots::SqliteSnapshotStore;
    use crate::snapshot::SnapshotService;
    use crate::traits::{BackupSink, SnapshotStore, UserRow, UserStatus, UserStore};

    /// Stand up an InstanceService + SnapshotService backed by sqlx
    /// stores and a single shared MockCube + RecordingReconfigurer.
    /// The two services share the underlying sqlite pool so a row
    /// inserted by one is visible to the other.  Returns enough
    /// handles for tests to seed users, query the row count, and
    /// inspect cube call records.
    async fn build_with_snapshot() -> (
        Arc<InstanceService>,
        Arc<SnapshotService>,
        Arc<MockCube>,
        Arc<dyn InstanceStore>,
        Arc<dyn UserStore>,
        Arc<RecordingReconfigurer>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        // Leak the tempdir so its lifetime exceeds the test (the
        // CipherDirectory's filesystem reads happen lazily as users
        // are minted, so dropping the dir mid-test would fail those).
        std::mem::forget(keys_tmp);
        let users: Arc<dyn UserStore> = Arc::new(crate::db::users::SqlxUserStore::new(
            pool.clone(),
            cipher_dir,
        ));
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone()),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let ssvc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps,
            backup,
            isvc.clone(),
        ));
        (isvc, ssvc, cube, instances, users, recorder)
    }

    /// `BTreeMap`-backed mock resolver for the network-policy tests.
    /// `with(&[("github.com", &["140.82.121.4"])])` builds one with
    /// known A-records; an unmapped hostname returns
    /// `HostUnresolvable`.  Same shape as the resolver used in
    /// network_policy::tests, duplicated here so the two test modules
    /// don't have to import each other's private types.
    #[derive(Default)]
    struct PolicyMockResolver {
        map: std::sync::Mutex<std::collections::BTreeMap<String, Vec<String>>>,
    }

    impl PolicyMockResolver {
        fn with(map: &[(&str, &[&str])]) -> Arc<Self> {
            let mut m = std::collections::BTreeMap::new();
            for (host, ips) in map {
                m.insert(
                    (*host).to_owned(),
                    ips.iter().map(|ip| format!("{ip}/32")).collect(),
                );
            }
            Arc::new(Self {
                map: std::sync::Mutex::new(m),
            })
        }
    }

    #[async_trait]
    impl crate::network_policy::HostResolver for PolicyMockResolver {
        async fn resolve_ipv4(
            &self,
            host: &str,
        ) -> Result<Vec<String>, crate::network_policy::PolicyError> {
            self.map.lock().unwrap().get(host).cloned().ok_or_else(|| {
                crate::network_policy::PolicyError::HostUnresolvable(host.to_owned())
            })
        }
    }

    /// Same as `build_with_snapshot`, but stamps an LLM CIDR and a
    /// configurable host resolver on the InstanceService so the
    /// network-policy resolver path is exercised.
    async fn build_with_snapshot_and_policy(
        llm_cidr: Option<&str>,
        resolver: Arc<dyn crate::network_policy::HostResolver>,
    ) -> (
        Arc<InstanceService>,
        Arc<SnapshotService>,
        Arc<MockCube>,
        Arc<dyn InstanceStore>,
        Arc<dyn UserStore>,
        Arc<RecordingReconfigurer>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        std::mem::forget(keys_tmp);
        let users: Arc<dyn UserStore> = Arc::new(crate::db::users::SqlxUserStore::new(
            pool.clone(),
            cipher_dir,
        ));
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone())
            .with_llm_cidr(llm_cidr.map(str::to_owned))
            .with_resolver(resolver),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let ssvc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps,
            backup,
            isvc.clone(),
        ));
        (isvc, ssvc, cube, instances, users, recorder)
    }

    /// Seed a user row so `instance.create(owner=...)` doesn't trip
    /// the FK on `instances.owner_id`.  The default `legacy` user is
    /// auto-seeded by migration 0002, but rotation tests that pin
    /// `owner_id` to a real user have to materialise that user first.
    async fn seed_user(users: &Arc<dyn UserStore>, sub: &str) {
        users
            .create(UserRow {
                id: sub.into(),
                subject: sub.into(),
                email: Some(format!("{sub}@test")),
                display_name: Some(sub.into()),
                status: UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rotate_binary_skips_instances_already_on_target_template() {
        // Hire an instance directly on the target template — the
        // sweep has nothing to do.  No snapshots, no destroys, no
        // failures: visited=0, rotated=0, failed empty.
        let (isvc, ssvc, cube, _instances, _users, recorder) = build_with_snapshot().await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl-current".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        recorder.pushed.lock().unwrap().clear();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-current").await.unwrap();
        assert_eq!(report.visited, 0, "rows already on target are no-op");
        assert_eq!(report.rotated, 0);
        assert!(report.failed.is_empty());
        assert!(
            cube.snapshotted.lock().unwrap().is_empty(),
            "matched-template rows must not be snapshotted"
        );
        assert!(
            cube.destroyed.lock().unwrap().is_empty(),
            "matched-template rows must not be destroyed"
        );
    }

    #[tokio::test]
    async fn rotate_binary_visits_each_outdated_instance() {
        // In-place rotation contract: after the sweep:
        //   * visited == 2, rotated == 2, failed empty.
        //   * Each row keeps its swarm id (DNS / bookmarks survive).
        //   * Each row stays Live with template_id flipped to target.
        //   * Each row's cube_sandbox_id is FRESH (old sandbox destroyed).
        //   * Identity (name, task, owner) carries through.
        let (isvc, ssvc, cube, instances, _users, recorder) = build_with_snapshot().await;
        let a = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: Some("alpha".into()),
                    task: Some("alpha task".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let b = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: Some("beta".into()),
                    task: Some("beta task".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 2).await;

        let pre_a = instances.get(&a.id).await.unwrap().unwrap();
        let pre_b = instances.get(&b.id).await.unwrap().unwrap();
        let old_cube_a = pre_a.cube_sandbox_id.clone().unwrap();
        let old_cube_b = pre_b.cube_sandbox_id.clone().unwrap();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        assert_eq!(report.visited, 2);
        assert_eq!(report.rotated, 2);
        assert!(
            report.failed.is_empty(),
            "rotation must not record failures for happy-path rows"
        );

        // Cube saw two snapshots (one per outdated row) and two
        // destroys (one per old sandbox).
        assert_eq!(cube.snapshotted.lock().unwrap().len(), 2);
        assert_eq!(cube.destroyed.lock().unwrap().len(), 2);

        // In-place: same swarm id, Live, on the new template, fresh cube.
        let post_a = instances.get(&a.id).await.unwrap().unwrap();
        let post_b = instances.get(&b.id).await.unwrap().unwrap();
        assert_eq!(post_a.status, InstanceStatus::Live);
        assert_eq!(post_b.status, InstanceStatus::Live);
        assert_eq!(post_a.template_id, "tpl-new");
        assert_eq!(post_b.template_id, "tpl-new");
        assert_ne!(
            post_a.cube_sandbox_id,
            Some(old_cube_a),
            "rotation must spin up a fresh cube; the old sandbox is destroyed"
        );
        assert_ne!(post_b.cube_sandbox_id, Some(old_cube_b));
        // Identity carried through.
        assert_eq!(post_a.name, "alpha");
        assert_eq!(post_a.task, "alpha task");
        assert_eq!(post_b.name, "beta");
        assert_eq!(post_b.task, "beta task");
        // Bearer survives — clients holding the old token keep working.
        assert_eq!(post_a.bearer_token, pre_a.bearer_token);
    }

    #[tokio::test]
    async fn rotate_binary_preserves_owner_id() {
        // Hire under "alice" (a real user, not the legacy sentinel).
        // After rotation, the new row MUST also be owned by "alice"
        // — restoring under SYSTEM_OWNER would silently re-tenant the
        // dyson and break tenant-scoped UI lookups.
        let (isvc, ssvc, _cube, instances, users, recorder) = build_with_snapshot().await;
        seed_user(&users, "alice").await;
        let src = isvc
            .create(
                "alice",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: Some("alice's reviewer".into()),
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 1).await;

        let report = isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        assert_eq!(report.rotated, 1);

        // In-place: same id, owner preserved (no SYSTEM_OWNER re-tenant).
        let row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(
            row.owner_id, "alice",
            "rotation must preserve owner_id; SYSTEM_OWNER re-tenant is the bug"
        );
        assert_eq!(row.template_id, "tpl-new");
        assert_eq!(row.status, InstanceStatus::Live);
    }

    #[tokio::test]
    async fn rotate_binary_skips_when_no_cube_sandbox_id() {
        // Pre-Stage-8 row: Live but has never had a cube_sandbox_id
        // set.  These rows can't be snapshotted, so the sweep skips
        // them silently — no entry in `failed` either, since the row
        // simply isn't a viable rotation candidate.
        let (isvc, ssvc, cube, instances, _users, _recorder) = build_with_snapshot().await;
        // Insert directly via the store so we can craft a
        // pre-Stage-8 row without going through `create` (which
        // always sets cube_sandbox_id once the cube returns).
        let row = InstanceRow {
            id: "ancient".into(),
            owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
            cube_sandbox_id: None,
            template_id: "tpl-old".into(),
            status: InstanceStatus::Live,
            bearer_token: "b".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        };
        instances.create(row).await.unwrap();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        assert_eq!(report.visited, 0, "no-cube-sandbox rows are not visited");
        assert_eq!(report.rotated, 0);
        assert!(
            report.failed.is_empty(),
            "pre-Stage-8 skip must not surface as failure"
        );
        assert!(cube.snapshotted.lock().unwrap().is_empty());
        // The row is untouched.
        let still = instances.get("ancient").await.unwrap().unwrap();
        assert_eq!(still.status, InstanceStatus::Live);
        assert!(still.rotated_to.is_none());
    }

    #[tokio::test]
    async fn rotate_binary_failed_snapshot_is_recorded_and_skipped() {
        // The cube refuses to snapshot.  The source row stays Live,
        // no successor is created, and the error surfaces in
        // RotateReport.failed so an operator can pick it up.
        let (isvc, ssvc, cube, instances, _users, recorder) = build_with_snapshot().await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 1).await;
        cube.fail_snapshots();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        assert_eq!(report.visited, 1);
        assert_eq!(report.rotated, 0, "no rotation completed");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, src.id);
        assert!(
            report.failed[0].1.contains("snapshot"),
            "failure message should pin the failing step"
        );
        // Source row is untouched: still Live, still on tpl-old, no
        // rotated_to marker — so the next sweep retries the full
        // pipeline, not just the destroy.
        let row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Live);
        assert_eq!(row.template_id, "tpl-old");
        assert!(row.rotated_to.is_none());
    }

    #[tokio::test]
    async fn rotate_binary_disabled_is_a_noop() {
        // Mirrors the gate in main.rs: when `rotate_binary_on_startup`
        // is false, `rotate_binary_all` is never called.  This test
        // proves the flag short-circuits the sweep — the cube mock
        // sees zero snapshot calls because the sweep never fires.
        let (isvc, ssvc, cube, _instances, _users, recorder) = build_with_snapshot().await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl-old".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::default(),
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let snapshots_before = cube.snapshotted.lock().unwrap().len();

        // The actual main.rs check, lifted verbatim so the test
        // tracks the wiring contract:
        //   if cfg.rotate_binary_on_startup { rotate_binary_all(...).await }
        let rotate_binary_on_startup = false;
        if rotate_binary_on_startup {
            isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        }

        assert_eq!(
            cube.snapshotted.lock().unwrap().len(),
            snapshots_before,
            "flag-off sweep must not call cube.snapshot_sandbox"
        );
    }

    // ---- Network-policy tests --------------------------------------
    //
    // Cover the four create-time profile arms, the change-network
    // pipeline (snapshot+restore+destroy), and the auth boundaries
    // (owner-scoped + admin bypass).  The PolicyMockResolver is
    // shared across these so hostname-allowlist scenarios don't
    // depend on real DNS.

    #[tokio::test]
    async fn create_passes_open_policy_to_cube_byte_identical_to_legacy_shape() {
        // The Open profile MUST emit the same wire bytes as the
        // pre-feature hardcoded body — we don't want a "harmless
        // refactor" to silently change the cube's egress posture for
        // every new instance on every existing deploy.
        let (isvc, _ssvc, cube, _instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("192.168.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::Open,
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = cube.last_create();
        assert!(captured.resolved_policy.allow_internet_access);
        assert_eq!(
            captured.resolved_policy.allow_out,
            vec!["0.0.0.0/0", "192.168.0.1/32"]
        );
        // deny_out is the full curated DEFAULT_DENY_OUT (post-A1
        // hardening adds 0.0.0.0/8, 100.64/10, multicast, and class-E
        // on top of the original RFC1918+link-local set).  Single
        // source of truth — the constant in network_policy.rs.
        assert_eq!(
            captured.resolved_policy.deny_out,
            crate::network_policy::DEFAULT_DENY_OUT
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
        );
    }

    #[tokio::test]
    async fn create_passes_airgap_policy_to_cube() {
        let (isvc, _ssvc, cube, _instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.20.30.40/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::Airgap,
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = cube.last_create();
        assert!(!captured.resolved_policy.allow_internet_access);
        assert_eq!(captured.resolved_policy.allow_out, vec!["10.20.30.40/32"]);
    }

    #[tokio::test]
    async fn create_passes_allowlist_policy_with_resolved_hostnames_to_cube() {
        let resolver = PolicyMockResolver::with(&[("github.com", &["140.82.121.4"])]);
        let (isvc, _ssvc, cube, _instances, _users, _recorder) =
            build_with_snapshot_and_policy(Some("10.0.0.1/32"), resolver).await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::Allowlist {
                    entries: vec!["github.com".into(), "8.8.8.8/32".into()],
                },
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = cube.last_create();
        assert!(!captured.resolved_policy.allow_internet_access);
        assert!(
            captured
                .resolved_policy
                .allow_out
                .contains(&"10.0.0.1/32".to_owned())
        );
        assert!(
            captured
                .resolved_policy
                .allow_out
                .contains(&"140.82.121.4/32".to_owned())
        );
        assert!(
            captured
                .resolved_policy
                .allow_out
                .contains(&"8.8.8.8/32".to_owned())
        );
    }

    #[tokio::test]
    async fn create_passes_denylist_policy_appending_to_default_deny() {
        let resolver = PolicyMockResolver::with(&[("evil.example", &["1.2.3.4"])]);
        let (isvc, _ssvc, cube, _instances, _users, _recorder) =
            build_with_snapshot_and_policy(Some("10.0.0.1/32"), resolver).await;
        isvc.create(
            "legacy",
            CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
                network_policy: NetworkPolicy::Denylist {
                    entries: vec!["evil.example".into(), "5.6.7.0/24".into()],
                },
                mcp_servers: Vec::new(),
            },
        )
        .await
        .unwrap();
        let captured = cube.last_create();
        assert!(captured.resolved_policy.allow_internet_access);
        // Default deny still present.
        assert!(
            captured
                .resolved_policy
                .deny_out
                .iter()
                .any(|c| c == "10.0.0.0/8")
        );
        // User entries (post-DNS) appended.
        assert!(
            captured
                .resolved_policy
                .deny_out
                .iter()
                .any(|c| c == "1.2.3.4/32")
        );
        assert!(
            captured
                .resolved_policy
                .deny_out
                .iter()
                .any(|c| c == "5.6.7.0/24")
        );
    }

    #[tokio::test]
    async fn create_persists_network_policy_on_row() {
        let (isvc, _ssvc, _cube, instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("192.168.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let created = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Airgap,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.network_policy, NetworkPolicy::Airgap);
        assert_eq!(row.network_policy_cidrs, vec!["192.168.0.1/32"]);
    }

    #[tokio::test]
    async fn create_airgap_without_llm_cidr_returns_bad_request() {
        // Operator hasn't set cube_facing_addr.  Airgap and Allowlist
        // can't function without an LLM hop CIDR — fail loudly at hire
        // time, not silently at first chat turn.
        let (isvc, _ssvc, _cube, _instances, _users, _recorder) =
            build_with_snapshot_and_policy(None, Arc::new(PolicyMockResolver::default())).await;
        let err = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Airgap,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_with_invalid_cidr_returns_bad_request() {
        let (isvc, _ssvc, _cube, _instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let err = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Allowlist {
                        entries: vec!["1.2.3.4/99".into()],
                    },
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));
    }

    #[tokio::test]
    async fn restore_carries_source_network_policy_through() {
        // Hire under Airgap, then drive a manual restore through
        // SnapshotService.  The new row + the cube call must inherit
        // the source's policy verbatim — silently widening egress
        // through restore would defeat the whole feature.
        let (isvc, ssvc, cube, instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Airgap,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let snap = ssvc.snapshot("legacy", &src.id).await.unwrap();
        let restored = ssvc
            .restore("legacy", &snap.id, None, BTreeMap::new())
            .await
            .unwrap();

        let row = instances.get(&restored.id).await.unwrap().unwrap();
        assert_eq!(row.network_policy, NetworkPolicy::Airgap);
        let captured = cube.last_create();
        assert!(!captured.resolved_policy.allow_internet_access);
        assert_eq!(captured.resolved_policy.allow_out, vec!["10.0.0.1/32"]);
    }

    #[tokio::test]
    async fn rotate_binary_preserves_network_policy() {
        // The rotation sweep must not silently widen egress on any
        // existing instance.  Hire on Allowlist with a hostname,
        // rotate, assert the successor inherits Allowlist + the same
        // resolved CIDR set.
        let resolver = PolicyMockResolver::with(&[("example.com", &["93.184.216.34"])]);
        let (isvc, ssvc, cube, instances, _users, _recorder) =
            build_with_snapshot_and_policy(Some("10.0.0.1/32"), resolver).await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: Some("alpha".into()),
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Allowlist {
                        entries: vec!["example.com".into()],
                    },
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-new").await.unwrap();
        assert_eq!(report.rotated, 1);

        // In-place: same id, same policy, fresh sandbox.
        let row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(
            row.network_policy,
            NetworkPolicy::Allowlist {
                entries: vec!["example.com".to_owned()],
            }
        );
        // Cube saw two creates: the original and the rotation's
        // fresh sandbox.  The rotation's resolved policy still
        // carries the LLM CIDR + the hostname's resolved CIDR.
        let captured = cube.last_create();
        assert!(
            captured
                .resolved_policy
                .allow_out
                .contains(&"93.184.216.34/32".to_owned())
        );
    }

    #[tokio::test]
    async fn change_network_takes_snapshot_swaps_policy_in_place() {
        // The full change-network pipeline.  Hire on Open, change to
        // Airgap, verify in-place semantics:
        //   * cube.snapshotted records the source.
        //   * the row keeps its swarm id, name, owner, bearer.
        //   * the row's network_policy flips to Airgap.
        //   * the row's cube_sandbox_id is fresh (old destroyed).
        //   * the cube saw a second create call carrying the Airgap
        //     resolved policy (single LLM CIDR, no internet).
        let (isvc, ssvc, cube, instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("alpha".into()),
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let pre = instances.get(&src.id).await.unwrap().unwrap();
        let old_cube = pre.cube_sandbox_id.clone().unwrap();

        let row = isvc
            .change_network_policy("legacy", &src.id, &ssvc, NetworkPolicy::Airgap)
            .await
            .unwrap();
        // In-place: same swarm id surfaces.
        assert_eq!(row.id, src.id);
        assert_eq!(row.network_policy, NetworkPolicy::Airgap);
        assert_eq!(row.network_policy_cidrs, vec!["10.0.0.1/32"]);
        assert_ne!(row.cube_sandbox_id.as_deref(), Some(old_cube.as_str()));
        assert_eq!(row.bearer_token, pre.bearer_token);
        assert_eq!(row.status, InstanceStatus::Live);

        // Cube saw exactly one snapshot of the source and one destroy
        // (the old sandbox).
        assert_eq!(cube.snapshotted.lock().unwrap().len(), 1);
        assert_eq!(cube.destroyed.lock().unwrap().len(), 1);
        let last = cube.last_create();
        assert!(!last.resolved_policy.allow_internet_access);
        assert_eq!(last.resolved_policy.allow_out, vec!["10.0.0.1/32"]);
    }

    #[tokio::test]
    async fn change_network_preserves_owner_and_identity() {
        // Owner_id, name, task all carried through.  A change-network
        // that re-tenanted the dyson would be a serious bug.
        let (isvc, ssvc, _cube, instances, users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        seed_user(&users, "alice").await;
        let src = isvc
            .create(
                "alice",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("alice's reviewer".into()),
                    task: Some("review prs".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let new_inst = isvc
            .change_network_policy("alice", &src.id, &ssvc, NetworkPolicy::Airgap)
            .await
            .unwrap();
        let new_row = instances.get(&new_inst.id).await.unwrap().unwrap();
        assert_eq!(new_row.owner_id, "alice");
        assert_eq!(new_row.name, "alice's reviewer");
        assert_eq!(new_row.task, "review prs");
    }

    #[tokio::test]
    async fn change_network_owner_scoped_returns_not_found_for_wrong_tenant() {
        let (isvc, ssvc, _cube, _instances, users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        seed_user(&users, "alice").await;
        seed_user(&users, "mallory").await;
        let alice_inst = isvc
            .create(
                "alice",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let err = isvc
            .change_network_policy("mallory", &alice_inst.id, &ssvc, NetworkPolicy::Airgap)
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::NotFound));
    }

    #[tokio::test]
    async fn change_network_admin_bypass_with_system_owner() {
        // SYSTEM_OWNER ("*") is the admin bypass — same precedent as
        // the rotation sweep and the TTL loop.  Lets an admin change
        // a tenant's policy without impersonating them.
        let (isvc, ssvc, _cube, instances, users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        seed_user(&users, "alice").await;
        let alice_inst = isvc
            .create(
                "alice",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let new_inst = isvc
            .change_network_policy(SYSTEM_OWNER, &alice_inst.id, &ssvc, NetworkPolicy::Airgap)
            .await
            .unwrap();
        // Owner_id is preserved (NOT re-tenanted to SYSTEM_OWNER).
        let new_row = instances.get(&new_inst.id).await.unwrap().unwrap();
        assert_eq!(new_row.owner_id, "alice");
        assert_eq!(new_row.network_policy, NetworkPolicy::Airgap);
    }

    #[tokio::test]
    async fn restore_snapshot_in_place_preserves_identity_and_uses_snapshot() {
        let (isvc, ssvc, cube, instances, _users, _recorder) = build_with_snapshot().await;
        let created = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl-old".into(),
                    name: Some("TARS".into()),
                    task: Some("stay useful".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::NoLocalNet,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let before = instances.get(&created.id).await.unwrap().unwrap();
        let old_sandbox = before.cube_sandbox_id.clone().unwrap();
        let snap = ssvc.snapshot("legacy", &created.id).await.unwrap();

        let recovered = ssvc
            .restore_in_place("legacy", &created.id, &snap.id, None)
            .await
            .unwrap();

        assert_eq!(recovered.id, created.id);
        assert_eq!(recovered.owner_id, before.owner_id);
        assert_eq!(recovered.bearer_token, before.bearer_token);
        assert_eq!(recovered.template_id, "tpl-old");
        assert_eq!(recovered.network_policy, NetworkPolicy::NoLocalNet);
        assert_ne!(recovered.cube_sandbox_id, before.cube_sandbox_id);

        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-old");
        assert_eq!(
            captured.from_snapshot.as_deref(),
            Some(std::path::Path::new(&snap.path))
        );
        assert_eq!(
            captured.env.get(ENV_INSTANCE_ID).map(String::as_str),
            Some(created.id.as_str())
        );
        assert_eq!(
            captured.env.get(ENV_BEARER_TOKEN).map(String::as_str),
            Some(created.bearer_token.as_str())
        );
        assert_eq!(
            captured.env.get(ENV_PROXY_TOKEN).map(String::as_str),
            Some(created.proxy_token.as_str())
        );
        assert!(
            cube.destroyed.lock().unwrap().contains(&old_sandbox),
            "old sandbox should be best-effort destroyed after pointer swap"
        );
    }

    #[tokio::test]
    async fn change_network_invalid_cidr_returns_bad_request_and_does_not_destroy() {
        // Bad input MUST fail before snapshot + restore + destroy.  A
        // mid-pipeline failure that destroyed the source would lose
        // workspace state.
        let (isvc, ssvc, cube, instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let snapshots_before = cube.snapshotted.lock().unwrap().len();

        let err = isvc
            .change_network_policy(
                "legacy",
                &src.id,
                &ssvc,
                NetworkPolicy::Allowlist {
                    entries: vec!["1.2.3.4/99".into()],
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));

        // No snapshot taken; source row untouched.
        assert_eq!(cube.snapshotted.lock().unwrap().len(), snapshots_before);
        let row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Live);
        assert_eq!(row.network_policy, NetworkPolicy::Open);
    }

    #[tokio::test]
    async fn change_network_no_op_when_policy_unchanged() {
        // Caller asked for the same policy that's already on the
        // row.  Refuse — the SPA should never churn a sandbox for
        // nothing.
        let (isvc, ssvc, cube, _instances, _users, _recorder) = build_with_snapshot_and_policy(
            Some("10.0.0.1/32"),
            Arc::new(PolicyMockResolver::default()),
        )
        .await;
        let src = isvc
            .create(
                "legacy",
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let snapshots_before = cube.snapshotted.lock().unwrap().len();
        let err = isvc
            .change_network_policy("legacy", &src.id, &ssvc, NetworkPolicy::Open)
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));
        assert_eq!(cube.snapshotted.lock().unwrap().len(), snapshots_before);
    }

    /// Build the everything-wired stack a clone test needs: the
    /// InstanceService has both a reconfigurer recorder AND mcp_secrets,
    /// and shares its InstanceStore + SnapshotStore + UserSecretsService
    /// with the SnapshotService so a single test can
    /// exercise the full clone pipeline (snapshot → restore → MCP carry).
    /// The recorder is returned too so tests can assert what configure
    /// bodies the clone pushed to the running dyson.
    async fn build_with_snapshot_and_mcp() -> (
        Arc<InstanceService>,
        Arc<SnapshotService>,
        Arc<MockCube>,
        Arc<dyn InstanceStore>,
        Arc<UserSecretsService>,
        Arc<RecordingReconfigurer>,
        String,
    ) {
        let pool = open_in_memory().await.unwrap();
        let owner = "deadbeef".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let tmp = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(tmp.path()).unwrap());
        let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(UserSecretsService::new(user_secrets_store, cipher_dir));
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone())
            .with_mcp_secrets(user_secrets.clone()),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let ssvc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps,
            backup,
            isvc.clone(),
        ));
        (isvc, ssvc, cube, instances, user_secrets, recorder, owner)
    }

    #[tokio::test]
    async fn clone_carries_config_files_and_mcp_onto_fresh_id() {
        // End-to-end: a Live source with name/task/models/tools/policy,
        // and one MCP server gets cloned to a fresh id under a new
        // template.  Every carried-over field round-trips, ids/bearers
        // diverge, and the source is untouched.
        let (isvc, ssvc, cube, instances, user_secrets, _recorder, owner) =
            build_with_snapshot_and_mcp().await;

        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl-v1".into(),
                    name: Some("axelrod".into()),
                    task: Some("game-theory triage".into()),
                    env: {
                        let mut m = env_with_model();
                        m.insert("EXTRA".into(), "x".into());
                        m
                    },
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: vec![crate::mcp_servers::McpServerSpec {
                        name: "linear".into(),
                        url: "https://8.8.8.8/mcp".into(),
                        auth: crate::mcp_servers::McpAuthSpec::Bearer {
                            token: "lin_secret".into(),
                        },
                        enabled_tools: None,
                    }],
                },
            )
            .await
            .unwrap();

        // Stamp an oauth_tokens blob into the MCP entry so we can
        // prove the active OAuth session survives the clone.
        let entry = crate::mcp_servers::McpServerEntry {
            url: "https://8.8.8.8/mcp".into(),
            auth: crate::mcp_servers::McpAuthSpec::Bearer {
                token: "lin_secret".into(),
            },
            headers: std::collections::HashMap::new(),
            runtime: None,
            docker_catalog: None,
            raw_vscode_config: None,
            oauth_tokens: Some(crate::mcp_servers::McpOAuthTokens {
                access_token: "atk".into(),
                refresh_token: Some("rtk".into()),
                expires_at: Some(9_999_999_999),
                token_url: "https://auth/token".into(),
                client_id: "cid".into(),
                client_secret: None,
            }),
            tools_catalog: None,
            enabled_tools: None,
        };
        crate::mcp_servers::put(&user_secrets, &owner, &src.id, "linear", &entry)
            .await
            .unwrap();

        let snapshots_before = cube.snapshotted.lock().unwrap().len();

        let cloned = isvc
            .clone_instance(&owner, &src.id, &ssvc, "tpl-v2", None)
            .await
            .unwrap();

        // 1. New id ≠ source; new bearer ≠ source bearer.
        assert_ne!(cloned.id, src.id);
        assert_ne!(cloned.bearer_token, src.bearer_token);

        // 2. New row carries name, task, models, tools, network policy
        //    from source; template_id is the override.
        let new_row = instances.get(&cloned.id).await.unwrap().unwrap();
        assert_eq!(new_row.owner_id, owner);
        assert_eq!(new_row.name, "axelrod");
        assert_eq!(new_row.task, "game-theory triage");
        assert_eq!(new_row.template_id, "tpl-v2");
        assert_eq!(new_row.network_policy, NetworkPolicy::Open);
        assert_eq!(new_row.status, InstanceStatus::Live);

        // 3. MCP entry was re-keyed onto the new instance, with
        //    oauth_tokens preserved.
        let names = crate::mcp_servers::list_names(&user_secrets, &owner, &cloned.id)
            .await
            .unwrap();
        assert_eq!(names, vec!["linear".to_string()]);
        let cloned_entry = crate::mcp_servers::get(&user_secrets, &owner, &cloned.id, "linear")
            .await
            .unwrap()
            .expect("clone must have a linear MCP entry");
        assert_eq!(cloned_entry.url, "https://8.8.8.8/mcp");
        let oauth = cloned_entry.oauth_tokens.expect("oauth_tokens preserved");
        assert_eq!(oauth.access_token, "atk");
        assert_eq!(oauth.refresh_token.as_deref(), Some("rtk"));

        // 4. A snapshot was actually taken.
        assert_eq!(
            cube.snapshotted.lock().unwrap().len(),
            snapshots_before + 1,
            "clone must take exactly one snapshot of the source"
        );

        // 5. The cube create call for the clone passed both the new
        //    template id AND a from_snapshot path — that's the
        //    "new template, old workspace" composition.
        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-v2");
        assert!(
            captured.from_snapshot.is_some(),
            "clone must hire the new cube with from_snapshot set"
        );

        // 6. Source row is left running and untouched.
        let src_row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(src_row.status, InstanceStatus::Live);
        assert_eq!(src_row.template_id, "tpl-v1");
    }

    #[tokio::test]
    async fn clone_rejects_destroyed_source() {
        let (isvc, ssvc, _cube, instances, _user_secrets, _recorder, owner) =
            build_with_snapshot_and_mcp().await;
        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        instances
            .update_status(&src.id, InstanceStatus::Destroyed)
            .await
            .unwrap();
        let err = isvc
            .clone_instance(&owner, &src.id, &ssvc, "tpl-v2", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));
    }

    #[tokio::test]
    async fn clone_empty_template_id_rejected() {
        let (isvc, ssvc, _cube, _instances, _user_secrets, _recorder, owner) =
            build_with_snapshot_and_mcp().await;
        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl".into(),
                    name: None,
                    task: None,
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        let err = isvc
            .clone_instance(&owner, &src.id, &ssvc, "   ", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::BadRequest(_)));
    }

    #[tokio::test]
    async fn clone_empty_carries_config_and_mcp_no_snapshot() {
        // Snapshot-less clone: fresh empty cube, but config + MCP records
        // (with oauth_tokens) come across.
        let (isvc, _ssvc, cube, instances, user_secrets, recorder, owner) =
            build_with_snapshot_and_mcp().await;

        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl-v1".into(),
                    name: Some("axelrod".into()),
                    task: Some("game-theory triage".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: vec![crate::mcp_servers::McpServerSpec {
                        name: "linear".into(),
                        url: "https://8.8.8.8/mcp".into(),
                        auth: crate::mcp_servers::McpAuthSpec::Bearer {
                            token: "lin_secret".into(),
                        },
                        enabled_tools: None,
                    }],
                },
            )
            .await
            .unwrap();
        let mcp_entry = crate::mcp_servers::McpServerEntry {
            url: "https://8.8.8.8/mcp".into(),
            auth: crate::mcp_servers::McpAuthSpec::Bearer {
                token: "lin_secret".into(),
            },
            headers: std::collections::HashMap::new(),
            runtime: None,
            docker_catalog: None,
            raw_vscode_config: None,
            oauth_tokens: Some(crate::mcp_servers::McpOAuthTokens {
                access_token: "atk".into(),
                refresh_token: Some("rtk".into()),
                expires_at: Some(9_999_999_999),
                token_url: "https://auth/token".into(),
                client_id: "cid".into(),
                client_secret: None,
            }),
            tools_catalog: None,
            enabled_tools: None,
        };
        crate::mcp_servers::put(&user_secrets, &owner, &src.id, "linear", &mcp_entry)
            .await
            .unwrap();

        let snapshots_before = cube.snapshotted.lock().unwrap().len();

        let cloned = isvc
            .clone_empty(&owner, &src.id, "tpl-v2", None)
            .await
            .unwrap();

        // 1. NO snapshot was taken — that's the whole point.
        assert_eq!(
            cube.snapshotted.lock().unwrap().len(),
            snapshots_before,
            "clone-empty must skip the snapshot step"
        );

        // 2. New row carries name, task, models (via SWARM_MODELS env),
        //    network policy, and gets the new template.
        let new_row = instances.get(&cloned.id).await.unwrap().unwrap();
        assert_ne!(cloned.id, src.id);
        assert_eq!(new_row.owner_id, owner);
        assert_eq!(new_row.name, "axelrod");
        assert_eq!(new_row.task, "game-theory triage");
        assert_eq!(new_row.template_id, "tpl-v2");
        assert_eq!(new_row.network_policy, NetworkPolicy::Open);

        // 3. Cube was hired with the new template AND no from_snapshot.
        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-v2");
        assert!(
            captured.from_snapshot.is_none(),
            "clone-empty must hire a fresh cube without from_snapshot"
        );

        // 4. MCP entry was re-keyed with oauth_tokens preserved.
        let names = crate::mcp_servers::list_names(&user_secrets, &owner, &cloned.id)
            .await
            .unwrap();
        assert_eq!(names, vec!["linear".to_string()]);
        let cloned_entry = crate::mcp_servers::get(&user_secrets, &owner, &cloned.id, "linear")
            .await
            .unwrap()
            .expect("clone must have a linear MCP entry");
        assert_eq!(cloned_entry.url, "https://8.8.8.8/mcp");
        assert_eq!(
            cloned_entry
                .oauth_tokens
                .as_ref()
                .map(|t| t.access_token.as_str()),
            Some("atk")
        );

        // 6. Source row is left running and untouched.
        let src_row = instances.get(&src.id).await.unwrap().unwrap();
        assert_eq!(src_row.status, InstanceStatus::Live);
        assert_eq!(src_row.template_id, "tpl-v1");

        // 7. clone-empty must push the rendered mcp_servers block to
        //    the new dyson via /api/admin/configure — without this
        //    the template-default dyson.json has no mcp_servers
        //    block, McpSkill never loads, and the agent reports zero
        //    MCP tools even though user_secrets is populated.
        let pushed = recorder.pushed.lock().unwrap();
        let mcp_push = pushed
            .iter()
            .find(|(target_id, _, body)| target_id == &cloned.id && body.mcp_servers.is_some())
            .expect("clone-empty must follow up the create-time push with a configure that includes mcp_servers");
        let block = mcp_push
            .2
            .mcp_servers
            .as_ref()
            .expect("body must carry mcp_servers");
        assert!(
            block.contains_key("linear"),
            "rendered mcp_servers block must include the cloned `linear` server, got keys {:?}",
            block.keys().collect::<Vec<_>>()
        );
        // Stamp the new instance id (not the source id) into the
        // proxy URL — that's the whole point of the second push.
        let url = block["linear"]["url"].as_str().unwrap();
        assert!(
            url.contains(&cloned.id),
            "mcp proxy URL must reference the clone's id, got {url}"
        );
        assert!(
            !url.contains(&src.id),
            "mcp proxy URL must NOT reference the source id, got {url}"
        );
    }

    #[tokio::test]
    async fn reset_replays_sealed_state_before_enabling_sync() {
        let pool = open_in_memory().await.unwrap();
        let owner = "feedface".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();

        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone()),
        );
        let state_root = tempfile::tempdir().unwrap();
        let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let state_files = crate::state_files::StateFileService::new(
            pool.clone(),
            state_root.path().into(),
            ciphers,
        );

        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl-v1".into(),
                    name: Some("memoryful".into()),
                    task: Some("keep context".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        recorder.pushed.lock().unwrap().clear();
        recorder.restored.lock().unwrap().clear();
        recorder.events.lock().unwrap().clear();

        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "IDENTITY.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_699_999,
                },
                b"# IDENTITY.md\n\n- **Name:** instance-memoryful",
            )
            .await
            .unwrap();
        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "memory/SOUL.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_700_000,
                },
                b"remember me",
            )
            .await
            .unwrap();
        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "skills/review/SKILL.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_700_001,
                },
                b"# Review skill",
            )
            .await
            .unwrap();
        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "chats",
                    path: "c-1/transcript.json",
                    mime: Some("application/json"),
                    updated_at: 1_777_700_002,
                },
                br#"[{"role":"user","content":"hi"}]"#,
            )
            .await
            .unwrap();
        let unreadable = state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "chats",
                    path: "c-0001/artefacts/a1.body",
                    mime: Some("application/octet-stream"),
                    updated_at: 1_777_700_003,
                },
                b"sealed then corrupted",
            )
            .await
            .unwrap();
        tokio::fs::write(
            state_files.body_path_for(&unreadable),
            b"legacy plaintext body",
        )
        .await
        .unwrap();

        let row = isvc
            .reset_in_place_from_state(&owner, &src.id, "tpl-v2", &state_files)
            .await
            .unwrap();
        assert_eq!(row.id, src.id);
        assert_eq!(row.template_id, "tpl-v2");

        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-v2");
        assert!(captured.from_snapshot.is_none());
        assert!(
            !captured.env.contains_key(ENV_STATE_SYNC_URL),
            "reset create env must keep state sync disabled until replay finishes"
        );
        assert!(!captured.env.contains_key(ENV_STATE_SYNC_TOKEN));

        let restored = recorder.restored.lock().unwrap();
        assert_eq!(restored.len(), 4);
        assert!(
            restored
                .iter()
                .any(|(_, _, b)| b.namespace == "workspace" && b.path == "IDENTITY.md"),
            "identity must be replayed from the sealed mirror"
        );
        assert!(
            restored
                .iter()
                .all(|(_, _, b)| b.path != "c-0001/artefacts/a1.body"),
            "reset should skip unreadable legacy mirror rows without aborting"
        );
        assert!(
            restored.iter().any(|(_, _, b)| b.namespace == "workspace"
                && b.path == "skills/review/SKILL.md"
                && b.body_b64.as_deref() == Some("IyBSZXZpZXcgc2tpbGw=")),
            "skills must be replayed from the sealed mirror"
        );
        assert!(
            restored
                .iter()
                .any(|(_, _, b)| b.namespace == "chats" && b.path == "c-1/transcript.json"),
            "chat transcript must be replayed from the sealed mirror"
        );
        drop(restored);

        let pushed = recorder.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1);
        assert!(
            pushed[0].2.state_sync_url.is_some() && pushed[0].2.state_sync_token.is_some(),
            "state sync should be enabled by the post-replay configure push"
        );
        assert!(
            pushed[0].2.name.is_none() && pushed[0].2.task.is_none(),
            "post-replay configure must not overwrite mirrored IDENTITY.md with row metadata"
        );
        drop(pushed);

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.last().map(String::as_str), Some("push"));
        assert!(
            events[..events.len() - 1]
                .iter()
                .all(|event| event.starts_with("restore:")),
            "all replay calls must happen before configure enables state sync: {events:?}"
        );
    }

    #[tokio::test]
    async fn binary_rotation_replays_sealed_chats_before_enabling_sync() {
        let pool = open_in_memory().await.unwrap();
        let owner = "facefeed".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();

        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let state_root = tempfile::tempdir().unwrap();
        let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let state_files = Arc::new(crate::state_files::StateFileService::new(
            pool.clone(),
            state_root.path().into(),
            ciphers.clone(),
        ));
        let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(UserSecretsService::new(user_secrets_store, ciphers));
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone())
            .with_state_files(state_files.clone())
            .with_mcp_secrets(user_secrets.clone()),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let ssvc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps,
            backup,
            isvc.clone(),
        ));

        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl-v1".into(),
                    name: Some("redeploy-safe".into()),
                    task: Some("keep chats".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        crate::mcp_servers::put_all(
            &user_secrets,
            &owner,
            &src.id,
            vec![crate::mcp_servers::McpServerSpec {
                name: "mcp_massive".into(),
                url: "https://8.8.8.8/mcp".into(),
                auth: crate::mcp_servers::McpAuthSpec::Bearer {
                    token: "massive_secret".into(),
                },
                enabled_tools: None,
            }],
        )
        .await
        .unwrap();
        recorder.pushed.lock().unwrap().clear();
        recorder.restored.lock().unwrap().clear();
        recorder.events.lock().unwrap().clear();

        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "IDENTITY.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_709_999,
                },
                b"# IDENTITY.md\n\n- **Name:** instance-redeploy-safe",
            )
            .await
            .unwrap();
        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "memory/SOUL.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_710_000,
                },
                b"still here",
            )
            .await
            .unwrap();
        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "chats",
                    path: "c-99/transcript.json",
                    mime: Some("application/json"),
                    updated_at: 1_777_710_001,
                },
                br#"[{"role":"user","content":"please persist me"}]"#,
            )
            .await
            .unwrap();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-v2").await.unwrap();
        assert_eq!(report.visited, 1);
        assert_eq!(report.rotated, 1);
        assert!(report.failed.is_empty());

        let row = instances
            .get_for_owner(&owner, &src.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.id, src.id);
        assert_eq!(row.template_id, "tpl-v2");

        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-v2");
        assert!(
            captured.from_snapshot.is_some(),
            "redeploy rotation should still use the cube snapshot"
        );
        assert!(
            !captured.env.contains_key(ENV_STATE_SYNC_URL),
            "rotation create env must keep state sync disabled until replay finishes"
        );
        assert!(!captured.env.contains_key(ENV_STATE_SYNC_TOKEN));

        let restored = recorder.restored.lock().unwrap();
        assert_eq!(restored.len(), 3);
        assert!(
            restored
                .iter()
                .any(|(_, _, b)| b.namespace == "workspace" && b.path == "IDENTITY.md"),
            "identity must be replayed during redeploy rotation"
        );
        assert!(
            restored
                .iter()
                .any(|(_, _, b)| b.namespace == "chats" && b.path == "c-99/transcript.json"),
            "chat transcript must be replayed during redeploy rotation"
        );
        drop(restored);

        let pushed = recorder.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1);
        assert!(
            pushed[0].2.state_sync_url.is_some() && pushed[0].2.state_sync_token.is_some(),
            "state sync should be re-enabled only by the post-replay configure push"
        );
        assert!(
            pushed[0].2.name.is_none() && pushed[0].2.task.is_none(),
            "redeploy configure must not overwrite mirrored IDENTITY.md with row metadata"
        );
        let mcp_block = pushed[0]
            .2
            .mcp_servers
            .as_ref()
            .expect("post-replay configure must preserve attached MCP servers");
        assert!(
            mcp_block.contains_key("mcp_massive"),
            "rendered mcp_servers block must include attached MCP servers, got keys {:?}",
            mcp_block.keys().collect::<Vec<_>>()
        );
        let mcp_url = mcp_block["mcp_massive"]["url"].as_str().unwrap();
        assert!(
            mcp_url.contains(&src.id),
            "mcp proxy URL must reference the rotated instance id, got {mcp_url}"
        );
        drop(pushed);

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.last().map(String::as_str), Some("push"));
        assert!(
            events[..events.len() - 1]
                .iter()
                .all(|event| event.starts_with("restore:")),
            "all state replay calls must happen before configure enables state sync: {events:?}"
        );
    }

    #[tokio::test]
    async fn binary_rotation_tolerates_unreadable_mirror_rows_from_snapshot() {
        let pool = open_in_memory().await.unwrap();
        let owner = "deadcafe".repeat(4);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&owner)
        .bind(&owner)
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();

        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool.clone(),
            crate::db::test_system_cipher(),
        ));
        let snaps: Arc<dyn SnapshotStore> = Arc::new(SqliteSnapshotStore::new(pool.clone()));
        let recorder = Arc::new(RecordingReconfigurer::default());
        let state_root = tempfile::tempdir().unwrap();
        let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let state_files = Arc::new(crate::state_files::StateFileService::new(
            pool.clone(),
            state_root.path().into(),
            ciphers,
        ));
        let isvc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances.clone(),
                tokens,
                "https://swarm.test/llm",
            )
            .with_reconfigurer(recorder.clone())
            .with_state_files(state_files.clone()),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let ssvc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances.clone(),
            snaps,
            backup,
            isvc.clone(),
        ));

        let src = isvc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl-v1".into(),
                    name: Some("legacy-mirror".into()),
                    task: Some("keep sandbox state".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::Open,
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        recorder.pushed.lock().unwrap().clear();
        recorder.restored.lock().unwrap().clear();
        recorder.events.lock().unwrap().clear();

        state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "workspace",
                    path: "memory/SOUL.md",
                    mime: Some("text/markdown"),
                    updated_at: 1_777_720_000,
                },
                b"restored from mirror",
            )
            .await
            .unwrap();
        let unreadable = state_files
            .ingest(
                crate::state_files::StateFileMeta {
                    instance_id: &src.id,
                    owner_id: &owner,
                    namespace: "chats",
                    path: "c-legacy/activity.jsonl",
                    mime: Some("application/jsonl"),
                    updated_at: 1_777_720_001,
                },
                br#"{"event":"legacy"}"#,
            )
            .await
            .unwrap();
        std::fs::write(
            state_files.body_path_for(&unreadable),
            b"legacy plaintext cache row",
        )
        .unwrap();

        let report = isvc.rotate_binary_all(&ssvc, "tpl-v2").await.unwrap();
        assert_eq!(report.visited, 1);
        assert_eq!(report.rotated, 1);
        assert!(
            report.failed.is_empty(),
            "snapshot-backed rotation must not fail on unreadable mirror rows: {:?}",
            report.failed
        );

        let row = instances
            .get_for_owner(&owner, &src.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.id, src.id);
        assert_eq!(row.template_id, "tpl-v2");

        let captured = cube.last_create();
        assert!(
            captured.from_snapshot.is_some(),
            "rotation must keep using the cube snapshot as the authoritative state source"
        );

        let restored = recorder.restored.lock().unwrap();
        assert_eq!(restored.len(), 1);
        assert!(
            restored
                .iter()
                .any(|(_, _, b)| b.namespace == "workspace" && b.path == "memory/SOUL.md"),
            "readable mirror rows should still be replayed"
        );
        assert!(
            restored
                .iter()
                .all(|(_, _, b)| b.path != "c-legacy/activity.jsonl"),
            "unreadable mirror rows should be skipped because the snapshot carries their state"
        );
    }

    #[tokio::test]
    async fn update_tools_pushes_allowlist_and_persists_on_row() {
        // Regression for the SPA's "uncheck a tool, save, nothing
        // changes" bug.  Front-end side is covered by
        // edit_form.test.jsx; this is the server-side guarantee that
        // when update_tools IS called with a trimmed list, it fires
        // a configure push with `tools: Some(<list>)` AND persists
        // the list on the row so the list endpoint reflects it.
        let (svc, _cube, _tokens, _instances, recorder, _user_secrets, owner) =
            build_with_mcp_secrets().await;

        let created = svc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("axelrod".into()),
                    task: Some("triage".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushes_before = recorder.pushed.lock().unwrap().len();

        let trimmed = vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "edit_file".to_string(),
            "list_files".to_string(),
            "search_files".to_string(),
            "send_file".to_string(),
        ];
        svc.update_tools(&owner, &created.id, trimmed.clone())
            .await
            .unwrap();

        // 1. A new configure push fired carrying exactly the trimmed
        //    list under `tools: Some(...)`.  Identity / models are
        //    untouched on this branch — the body should look like
        //    "tools-only".
        let pushed = recorder.pushed.lock().unwrap();
        assert!(
            pushed.len() > pushes_before,
            "update_tools must fire at least one configure push"
        );
        let (target_id, _, body) = pushed.last().unwrap();
        assert_eq!(target_id, &created.id);
        assert_eq!(body.tools.as_deref(), Some(trimmed.as_slice()));
        assert!(
            body.name.is_none() && body.task.is_none() && body.models.is_empty(),
            "tools-only push must not carry identity or models"
        );

        // 2. The row's `tools` column reflects the new list, so
        //    GET /v1/instances/:id surfaces the trimmed allowlist
        //    on the next read.
        drop(pushed);
        let row = _instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.tools, trimmed);
    }

    #[tokio::test]
    async fn update_tools_empty_list_resets_to_dyson_defaults() {
        // PatchInstanceBody promises `tools: []` resets to defaults.
        // Implementation must translate that to `reset_skills: true,
        // tools: None` — sending `tools: Some([])` instead would hit
        // dyson's allowlist branch and register zero builtins (the
        // bash-stops-working bug).  Mirrors the create + recreate
        // paths that already do this correctly.
        let (svc, _cube, _tokens, _instances, recorder, _user_secrets, owner) =
            build_with_mcp_secrets().await;

        let created = svc
            .create(
                &owner,
                CreateRequest {
                    template_id: "tpl".into(),
                    name: Some("tars".into()),
                    task: Some("triage".into()),
                    env: env_with_model(),
                    ttl_seconds: None,
                    network_policy: NetworkPolicy::default(),
                    mcp_servers: Vec::new(),
                },
            )
            .await
            .unwrap();
        wait_for_pushes(&recorder, 1).await;
        let pushes_before = recorder.pushed.lock().unwrap().len();

        svc.update_tools(&owner, &created.id, Vec::new())
            .await
            .unwrap();

        let pushed = recorder.pushed.lock().unwrap();
        assert!(
            pushed.len() > pushes_before,
            "update_tools must fire a configure push even on the empty-list path"
        );
        let (_, _, body) = pushed.last().unwrap();
        assert!(
            body.reset_skills,
            "empty tools must set reset_skills=true so dyson re-registers all builtins"
        );
        assert!(
            body.tools.is_none(),
            "empty tools must NOT send tools=Some([]) — that registers zero builtins on dyson"
        );
    }

    #[tokio::test]
    async fn clone_unknown_source_returns_not_found() {
        let (isvc, ssvc, _cube, _instances, _user_secrets, _recorder, owner) =
            build_with_snapshot_and_mcp().await;
        let err = isvc
            .clone_instance(&owner, "no-such-instance", &ssvc, "tpl-v2", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SwarmError::NotFound));
    }
}
