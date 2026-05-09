use std::collections::BTreeMap;

use crate::error::SwarmError;
use crate::network_policy::{self, NetworkPolicy};
use crate::secrets::compose_env;

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
/// Distinct prefix (`st_`) and generation-scoped provider
/// (`state_sync:<generation>`) from chat and artefact ingest tokens.
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
pub(super) fn managed_env(
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

pub(super) fn is_reserved_env_name(name: &str) -> bool {
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

pub(super) fn validate_caller_env(env: &BTreeMap<String, String>) -> Result<(), SwarmError> {
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

pub(super) fn compose_sandbox_env(
    managed: &BTreeMap<String, String>,
    caller: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, SwarmError> {
    validate_caller_env(caller)?;
    Ok(compose_env(&BTreeMap::new(), managed, caller))
}

pub(super) fn models_with_primary(existing: Vec<String>, selected: &str) -> Vec<String> {
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
pub(super) fn build_ingest_url(proxy_base: &str) -> String {
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

pub(super) fn build_state_sync_url(proxy_base: &str) -> String {
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
pub(super) fn policy_permits_generic_egress(p: &NetworkPolicy) -> bool {
    matches!(
        p,
        NetworkPolicy::Open | NetworkPolicy::NoLocalNet | NetworkPolicy::Denylist { .. }
    )
}

/// CIDRs persisted on the instance row for operator inspection and
/// for the host egress-policy generator.  Allow-style policies need
/// the resolved allow set; denylist needs the resolved deny set so the
/// host proxy can enforce the same frozen DNS decision as Cube.
pub(super) fn row_policy_cidrs(
    policy: &NetworkPolicy,
    resolved: &network_policy::ResolvedPolicy,
) -> Vec<String> {
    match policy {
        NetworkPolicy::Denylist { .. } => resolved.deny_out.clone(),
        _ => resolved.allow_out.clone(),
    }
}
