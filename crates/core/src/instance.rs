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
use uuid::Uuid;

use crate::channels::TELEGRAM_KIND;
use crate::egress_policy_sync::{EgressPolicySync, NoopEgressPolicySync};
use crate::error::{CubeError, SwarmError};
use crate::mcp_servers::{self, McpAuthSpec, McpServerSpec};
use crate::upstream_policy::{OutboundUrlPolicy, validate_outbound_url};

use crate::network_policy::{self, DnsHostResolver, HostResolver, NetworkPolicy};
use crate::now_secs;
use crate::sandbox_backend::CubeSandboxBackend;
use crate::secrets::UserSecretsService;
use crate::traits::{
    AgentSecretStore, CreateSandboxArgs, CubeClient, HealthProber, InstanceChannelStore,
    InstanceRow, InstanceStatus, InstanceStore, ListFilter, ProbeResult, SandboxBackend,
    SandboxInfo, TokenStore,
};

mod env;
mod mcp_reconcile;
mod types;

#[cfg(test)]
use env::validate_caller_env;
pub use env::{
    CUBE_HTTP_PROXY_URL, CUBE_NO_PROXY, ENV_BEARER_TOKEN, ENV_HTTP_PROXY, ENV_HTTP_PROXY_LC,
    ENV_HTTPS_PROXY, ENV_HTTPS_PROXY_LC, ENV_IMAGE_GENERATION_MODEL, ENV_INGEST_TOKEN,
    ENV_INGEST_URL, ENV_INSTANCE_ID, ENV_MODEL, ENV_MODELS, ENV_NAME, ENV_NO_PROXY,
    ENV_NO_PROXY_LC, ENV_PROXY_TOKEN, ENV_PROXY_URL, ENV_STATE_SYNC_TOKEN, ENV_STATE_SYNC_URL,
    ENV_TASK, ENV_TOOLS, SHARED_PROVIDER, SYSTEM_OWNER,
};
use env::{
    build_ingest_url, build_state_sync_url, compose_sandbox_env, managed_env, models_with_primary,
    row_policy_cidrs,
};
use mcp_reconcile::{auth_shape_matches, keep_existing_secrets};
pub use types::{
    CreateRequest, CreatedInstance, DeletedMcpServer, ImageGenDefaults, InstallSkillBody,
    InstallSkillResponse, ReconfigureBody, RestoreRequest, RestoreStateFileBody, RotateReport,
    TelegramProxyReconfigure, UninstallSkillResponse,
};
use types::{InPlaceSwapPlan, RuntimeTokens};

const MAX_ACTIVE_INSTANCES_PER_OWNER: u64 = 20;

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
                if is_non_retryable_reconfigure_error(&last_err) {
                    return Err(last_err);
                }
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

fn is_non_retryable_reconfigure_error(error: &str) -> bool {
    error.contains("configure secret mismatch")
        || error.contains("did not apply requested")
        || error.contains("configure response had ok=false")
        || error.contains("/api/admin/configure response parse")
}

fn is_snapshot_endpoint_unavailable(error: &SwarmError) -> bool {
    let SwarmError::Cube(CubeError::Status { status, body }) = error else {
        return false;
    };
    *status == 404
        || body.contains("CubeMaster returned error code 404")
        || body.contains("404 page not found")
        || body.contains("snapshot unavailable")
}

fn looks_like_full_identity_doc(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with("# IDENTITY.md") || trimmed.starts_with("# Identity")
}

fn reconfigure_task_fields(task: Option<String>) -> (Option<String>, Option<String>) {
    match task {
        Some(task) if looks_like_full_identity_doc(&task) => (None, Some(task)),
        other => (other, None),
    }
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
    sandbox: Arc<dyn SandboxBackend>,
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
    /// Per-instance channel rows used to render Telegram proxy config
    /// into dyson's runtime configure body. Bot tokens themselves
    /// remain sealed in `UserSecretsService`.
    channels: Option<Arc<dyn InstanceChannelStore>>,
    /// Agent-visible instance secrets. Destroy wipes these so
    /// credentials do not outlive the instance that could read them.
    agent_secrets: Option<Arc<dyn AgentSecretStore>>,
    /// Swarm-side sealed workspace/chat state.  Rebuild paths replay
    /// this into the fresh sandbox before granting that sandbox write
    /// authority, so redeploys do not surface empty state or accept
    /// stale writes from an older cube.
    state_files: Option<crate::state_files::StateFiles>,
    /// Pushes the DB-backed egress policy map to the host proxy after
    /// sandbox ids or policies change.  The implementation is
    /// best-effort: the systemd timer remains the safety net, but UI
    /// edits should take effect immediately on the happy path.
    egress_sync: Arc<dyn EgressPolicySync>,
    /// Operator gate for network profiles that punch through the
    /// default-deny LAN/link-local set.
    network_config: crate::config::NetworkConfig,
}

fn mint_state_generation() -> String {
    Uuid::new_v4().simple().to_string()
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

    /// Install a validated marketplace skill into a running dyson's
    /// workspace. Default error keeps tests and deployments without
    /// runtime reconfiguration from silently claiming success.
    async fn install_skill(
        &self,
        _instance_id: &str,
        _sandbox_id: &str,
        _body: &InstallSkillBody,
    ) -> Result<InstallSkillResponse, String> {
        Err("dyson skill install reconfigurer is not configured".into())
    }

    /// Remove a marketplace-installed skill from a running dyson's
    /// workspace. Default error keeps callers from silently updating
    /// only swarm's mirror when runtime reconfiguration is unavailable.
    async fn uninstall_skill(
        &self,
        _instance_id: &str,
        _sandbox_id: &str,
        _skill: &str,
    ) -> Result<UninstallSkillResponse, String> {
        Err("dyson skill uninstall reconfigurer is not configured".into())
    }
}

impl InstanceService {
    pub fn new(
        cube: Arc<dyn CubeClient>,
        instances: Arc<dyn InstanceStore>,
        tokens: Arc<dyn TokenStore>,
        proxy_base: impl Into<String>,
    ) -> Self {
        Self::with_backend(
            Arc::new(CubeSandboxBackend::new(cube)),
            instances,
            tokens,
            proxy_base,
        )
    }

    pub fn with_backend(
        sandbox: Arc<dyn SandboxBackend>,
        instances: Arc<dyn InstanceStore>,
        tokens: Arc<dyn TokenStore>,
        proxy_base: impl Into<String>,
    ) -> Self {
        Self {
            sandbox,
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
            channels: None,
            agent_secrets: None,
            state_files: None,
            egress_sync: Arc::new(NoopEgressPolicySync::new()),
            network_config: crate::config::NetworkConfig::default(),
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

    /// Builder-style: plug in channel storage so create/sync paths can
    /// push Telegram proxy settings into the running dyson.
    pub fn with_channels(mut self, channels: Arc<dyn InstanceChannelStore>) -> Self {
        self.channels = Some(channels);
        self
    }

    /// Builder-style: plug in agent-visible secret storage so destroy
    /// can clean up rows for the instance.
    pub fn with_agent_secrets(mut self, secrets: Arc<dyn AgentSecretStore>) -> Self {
        self.agent_secrets = Some(secrets);
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

    /// Builder-style: plug in the production egress policy synchronizer.
    /// Tests keep the default no-op counter.
    pub fn with_egress_policy_sync(mut self, sync: Arc<dyn EgressPolicySync>) -> Self {
        self.egress_sync = sync;
        self
    }

    pub fn with_network_config(mut self, cfg: crate::config::NetworkConfig) -> Self {
        self.network_config = cfg;
        self
    }

    /// Build the `<proxy_base>/openrouter` URL the image-gen provider
    /// uses for its `base_url`.  Same shape as `swarm_provider_base_url`
    /// on the dyson-binary side — the trailing `/v1` is added by
    /// dyson's `OpenRouterImageProvider` when it builds the request.
    fn image_proxy_base(&self) -> String {
        format!("{}/openrouter", self.proxy_base.trim_end_matches('/'))
    }

    fn public_proxy_origin(&self) -> String {
        let base = self.proxy_base.trim_end_matches('/');
        base.strip_suffix("/llm").unwrap_or(base).to_owned()
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

    async fn runtime_tokens_for_instance(
        &self,
        instance_id: &str,
        state_generation: &str,
    ) -> Result<RuntimeTokens, SwarmError> {
        let state_generation = state_generation.trim();
        if state_generation.is_empty() {
            return Err(SwarmError::Internal(format!(
                "instance {instance_id} is missing a state generation; recreate it as a swarm-backed workspace"
            )));
        }
        let proxy = match self.tokens.lookup_by_instance(instance_id).await? {
            Some(t) => t,
            None => self.tokens.mint(instance_id, SHARED_PROVIDER).await?,
        };
        let ingest = match self
            .tokens
            .lookup_by_instance_for_provider(instance_id, crate::db::INGEST_PROVIDER)
            .await?
        {
            Some(t) => t,
            None => self.tokens.mint_ingest(instance_id).await?,
        };
        let state_provider = crate::db::state_sync_provider(state_generation);
        let state_sync = match self
            .tokens
            .lookup_by_instance_for_provider(instance_id, &state_provider)
            .await?
        {
            Some(t) => t,
            None => {
                self.tokens
                    .mint_state_sync_for_generation(instance_id, state_generation)
                    .await?
            }
        };
        Ok(RuntimeTokens {
            proxy,
            ingest,
            state_sync,
            state_generation: state_generation.to_owned(),
        })
    }

    async fn build_in_place_swap_plan(
        &self,
        owner_id: &str,
        instance_id: &str,
        new_template_id: &str,
        new_network_policy: Option<NetworkPolicy>,
        destroyed_error: &'static str,
        missing_sandbox_error: &'static str,
    ) -> Result<InPlaceSwapPlan, SwarmError> {
        let target_template_id = new_template_id.trim();
        if target_template_id.is_empty() {
            return Err(SwarmError::BadRequest("template_id is required".into()));
        }
        let source = self
            .instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(SwarmError::NotFound)?;
        if source.status == InstanceStatus::Destroyed {
            return Err(SwarmError::BadRequest(destroyed_error.into()));
        }
        let old_sandbox_id = source
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SwarmError::BadRequest(missing_sandbox_error.into()))?
            .to_owned();
        if let Some(policy) = new_network_policy.as_ref() {
            policy.assert_allowed_by_config(&self.network_config)?;
        }
        let target_policy = new_network_policy.unwrap_or_else(|| source.network_policy.clone());
        let resolved_policy =
            network_policy::resolve(&target_policy, self.llm_cidr.as_deref(), &*self.resolver)
                .await?;
        Ok(InPlaceSwapPlan {
            source,
            old_sandbox_id,
            target_template_id: target_template_id.to_owned(),
            target_policy,
            resolved_policy,
            target_state_generation: mint_state_generation(),
        })
    }

    async fn create_in_place_swap_sandbox(
        &self,
        plan: &InPlaceSwapPlan,
        runtime_tokens: &RuntimeTokens,
        from_snapshot_path: Option<std::path::PathBuf>,
        disable_state_sync_until_configure: bool,
    ) -> Result<SandboxInfo, SwarmError> {
        let source = &plan.source;
        let mut managed = managed_env(
            &self.proxy_base,
            &runtime_tokens.proxy,
            &runtime_tokens.ingest,
            &runtime_tokens.state_sync,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &plan.target_policy,
        );
        if disable_state_sync_until_configure {
            managed.remove(ENV_STATE_SYNC_URL);
            managed.remove(ENV_STATE_SYNC_TOKEN);
        }
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;
        let info = self
            .sandbox
            .create_sandbox(CreateSandboxArgs {
                template_id: plan.target_template_id.clone(),
                env,
                from_snapshot_path,
                resolved_policy: plan.resolved_policy.clone(),
            })
            .await?;
        self.bind_runtime_tokens_to_sandbox_source(&source.id, &info)
            .await?;
        Ok(info)
    }

    async fn bind_runtime_tokens_to_sandbox_source(
        &self,
        instance_id: &str,
        info: &SandboxInfo,
    ) -> Result<(), SwarmError> {
        let source_ip = info.host_ip.trim();
        if source_ip.is_empty() {
            return Ok(());
        }
        self.tokens
            .bind_expected_src_ip(instance_id, source_ip)
            .await?;
        Ok(())
    }

    async fn refresh_egress_policy_best_effort(&self, instance_id: &str, operation: &'static str) {
        if let Err(err) = self.egress_sync.refresh().await {
            tracing::warn!(
                instance = %instance_id,
                operation,
                error = %err,
                "egress-policy-sync: refresh failed; timer remains safety net"
            );
        }
    }

    async fn replay_state_files_and_configure(
        &self,
        owner_id: &str,
        source: &InstanceRow,
        runtime_tokens: &RuntimeTokens,
        sandbox_id: &str,
        state_files: &crate::state_files::StateFileService,
        allow_unreadable_rows: bool,
        configure_before_replay: bool,
        operation: &'static str,
    ) -> Result<(), SwarmError> {
        if configure_before_replay {
            self.configure_existing_sandbox_for_state_replay(
                owner_id,
                source,
                runtime_tokens,
                sandbox_id,
                state_files,
                false,
                operation,
                "before state replay",
            )
            .await?;
        }
        self.replay_state_files_to_sandbox(
            owner_id,
            &source.id,
            sandbox_id,
            state_files,
            allow_unreadable_rows,
        )
        .await?;
        self.configure_existing_sandbox_for_state_replay(
            owner_id,
            source,
            runtime_tokens,
            sandbox_id,
            state_files,
            true,
            operation,
            "after state replay",
        )
        .await
    }

    async fn configure_existing_sandbox_for_state_replay(
        &self,
        owner_id: &str,
        source: &InstanceRow,
        runtime_tokens: &RuntimeTokens,
        sandbox_id: &str,
        state_files: &crate::state_files::StateFileService,
        enable_state_sync: bool,
        operation: &'static str,
        phase: &'static str,
    ) -> Result<(), SwarmError> {
        let reconfigurer = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        let mut body = self
            .configure_body_for_existing_row(
                owner_id,
                source,
                &runtime_tokens.proxy,
                &runtime_tokens.ingest,
                &runtime_tokens.state_sync,
            )
            .await;
        self.clear_identity_fields_when_mirror_is_authoritative(
            &mut body,
            owner_id,
            &source.id,
            state_files,
        )
        .await?;
        if !enable_state_sync {
            body.state_sync_url = None;
            body.state_sync_token = None;
        }
        push_with_retry(reconfigurer.as_ref(), &source.id, sandbox_id, &body)
            .await
            .map_err(|err| {
                SwarmError::Internal(format!("{operation} configure-push failed {phase}: {err}"))
            })
    }

    async fn push_configure_after_swap(
        &self,
        owner_id: &str,
        source: &InstanceRow,
        runtime_tokens: &RuntimeTokens,
        sandbox_id: &str,
        operation: &'static str,
    ) -> Result<(), SwarmError> {
        let reconfigurer = self
            .reconfigurer
            .as_ref()
            .ok_or_else(|| SwarmError::PolicyDenied("dyson reconfigurer not configured".into()))?;
        let body = self
            .configure_body_for_existing_row(
                owner_id,
                source,
                &runtime_tokens.proxy,
                &runtime_tokens.ingest,
                &runtime_tokens.state_sync,
            )
            .await;
        push_with_retry(reconfigurer.as_ref(), &source.id, sandbox_id, &body)
            .await
            .map_err(|err| {
                SwarmError::Internal(format!(
                    "{operation} configure-push failed after swap: {err}"
                ))
            })
    }

    async fn destroy_old_sandbox_after_in_place_swap(
        &self,
        source: &InstanceRow,
        old_sandbox_id: &str,
        operation: &'static str,
    ) {
        if let Err(err) = self.sandbox.destroy_sandbox(old_sandbox_id).await {
            tracing::warn!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                error = %err,
                operation,
                "in-place swap: old cube destroy failed (orphan cube — janitor will sweep)"
            );
        } else {
            tracing::info!(
                instance = %source.id,
                old_sandbox = %old_sandbox_id,
                operation,
                "in-place swap: old cube destroyed"
            );
        }
    }

    fn configure_body_from_parts(
        &self,
        source: &InstanceRow,
        proxy_token: &str,
        ingest_token: &str,
        state_sync_token: &str,
        image_gen_defaults: Option<&ImageGenDefaults>,
        mcp_servers: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> ReconfigureBody {
        let (task, identity_doc) =
            reconfigure_task_fields(Some(source.task.clone()).filter(|s| !s.is_empty()));
        ReconfigureBody {
            name: Some(source.name.clone()).filter(|s| !s.is_empty()),
            task,
            identity_doc,
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
            image_provider_name: image_gen_defaults.map(|d| d.provider_name.clone()),
            image_provider_block: image_gen_defaults
                .map(|d| d.provider_block(&self.image_proxy_base(), proxy_token)),
            image_generation_provider: image_gen_defaults.map(|d| d.provider_name.clone()),
            image_generation_model: image_gen_defaults.map(|d| d.model.clone()),
            reset_skills: source.tools.is_empty(),
            tools: (!source.tools.is_empty()).then(|| source.tools.clone()),
            mcp_servers,
            telegram_proxy: None,
        }
    }

    async fn configure_body_for_existing_row(
        &self,
        owner_id: &str,
        source: &InstanceRow,
        proxy_token: &str,
        ingest_token: &str,
        state_sync_token: &str,
    ) -> ReconfigureBody {
        let mcp_servers = self
            .mcp_servers_block_for_instance(owner_id, &source.id, proxy_token, true)
            .await;
        let mut body = self.configure_body_from_parts(
            source,
            proxy_token,
            ingest_token,
            state_sync_token,
            self.image_gen_defaults.as_ref(),
            mcp_servers,
        );
        body.telegram_proxy = self
            .telegram_proxy_block_for_instance(&source.id, proxy_token)
            .await;
        body
    }

    async fn telegram_proxy_block_for_instance(
        &self,
        instance_id: &str,
        proxy_token: &str,
    ) -> Option<TelegramProxyReconfigure> {
        let channels = self.channels.as_ref()?;
        let row = match channels.get(instance_id, TELEGRAM_KIND).await {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(err) => {
                tracing::warn!(
                    instance = %instance_id,
                    error = %err,
                    "telegram channel sync: lookup failed; skipping configure block"
                );
                return None;
            }
        };
        let origin = self.public_proxy_origin();
        if origin.trim().is_empty() {
            return None;
        }
        let origin = origin.trim_end_matches('/');
        Some(TelegramProxyReconfigure {
            base_url: format!("{origin}/v1/proxy/telegram/{instance_id}"),
            file_base_url: format!("{origin}/v1/proxy/telegram/{instance_id}/file"),
            bearer: proxy_token.to_owned(),
            enabled: row.enabled,
        })
    }

    async fn mcp_servers_block_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
        proxy_token: &str,
        clear_when_empty: bool,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let secrets = self.mcp_secrets.as_ref()?;
        let names = match mcp_servers::list_names(secrets, owner_id, instance_id).await {
            Ok(names) if !names.is_empty() => names,
            Ok(_) if clear_when_empty => return Some(serde_json::Map::new()),
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
        if row.deleted_at.is_some() || row.body_ciphertext.is_none() {
            tracing::warn!(
                instance = %instance_id,
                namespace = %row.namespace,
                path = %row.path,
                deleted = row.deleted_at.is_some(),
                "state identity mirror is not readable; keeping row identity fields"
            );
            return Ok(());
        }
        match state_files.read_body_for_replay(&row) {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(
                    instance = %instance_id,
                    namespace = %row.namespace,
                    path = %row.path,
                    "state identity mirror body missing; keeping row identity fields"
                );
                return Ok(());
            }
            Err(err) => {
                tracing::warn!(
                    instance = %instance_id,
                    namespace = %row.namespace,
                    path = %row.path,
                    error = %err,
                    "state identity mirror body unreadable; keeping row identity fields"
                );
                return Ok(());
            }
        }
        body.name = None;
        body.task = None;
        Ok(())
    }

    async fn has_durable_mirrored_state_files(
        &self,
        instance_id: &str,
        state_files: &crate::state_files::StateFileService,
    ) -> Result<bool, SwarmError> {
        let rows = state_files
            .list_for_instance(instance_id)
            .await
            .map_err(|e| SwarmError::Internal(format!("list state files: {e}")))?;
        for row in rows {
            if !crate::state_files::is_durable_state_file_path(&row.namespace, &row.path) {
                continue;
            }
            if row.deleted_at.is_some() {
                return Ok(true);
            }
            if row.body_ciphertext.is_none() {
                tracing::warn!(
                    instance = %instance_id,
                    namespace = %row.namespace,
                    path = %row.path,
                    "state mirror row has no sealed body; ignoring it for state-replay decisions"
                );
                continue;
            }
            match state_files.read_body_for_replay(&row) {
                Ok(Some(body))
                    if !crate::state_files::is_zero_byte_chat_transcript(
                        &row.namespace,
                        &row.path,
                        &body,
                    ) =>
                {
                    return Ok(true);
                }
                Ok(Some(_)) | Ok(None) => {
                    tracing::warn!(
                        instance = %instance_id,
                        namespace = %row.namespace,
                        path = %row.path,
                        "state mirror row is not replayable; ignoring it for state-replay decisions"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        instance = %instance_id,
                        namespace = %row.namespace,
                        path = %row.path,
                        error = %err,
                        "state mirror row is unreadable; ignoring it for state-replay decisions"
                    );
                }
            }
        }
        Ok(false)
    }

    /// Re-push the canonical desired runtime config to every Live
    /// instance. Idempotent: a dyson that already has the right values
    /// gets the same JSON written back. Best-effort: a sandbox that's
    /// asleep / mid-restore will fail the push and be retried on the
    /// next sweep. Returns `(visited, succeeded)` so the caller can log
    /// a one-line summary.
    pub async fn sync_runtime_config_all(&self) -> Result<(usize, usize), SwarmError> {
        let Some(reconfigurer) = self.reconfigurer.as_ref() else {
            return Ok((0, 0));
        };
        let mut rows = self
            .instances
            .list(
                SYSTEM_OWNER,
                ListFilter {
                    status: Some(InstanceStatus::Live),
                    include_destroyed: false,
                },
            )
            .await?;
        rows.extend(
            self.instances
                .list(
                    SYSTEM_OWNER,
                    ListFilter {
                        status: Some(InstanceStatus::Configuring),
                        include_destroyed: false,
                    },
                )
                .await?,
        );
        let mut succeeded = 0usize;
        for row in &rows {
            let Some(sandbox_id) = &row.cube_sandbox_id else {
                tracing::debug!(
                    instance = %row.id,
                    "runtime-config-sync: skipping; no cube_sandbox_id on row"
                );
                continue;
            };
            let tokens = match self
                .runtime_tokens_for_instance(&row.id, &row.state_generation)
                .await
            {
                Ok(tokens) => tokens,
                Err(e) => {
                    tracing::warn!(
                        instance = %row.id,
                        error = %e,
                        "runtime-config-sync: token repair failed; skipping"
                    );
                    let _ = self
                        .instances
                        .record_probe(
                            &row.id,
                            crate::traits::ProbeResult::Degraded {
                                reason: format!("runtime-config token repair failed: {e}"),
                            },
                        )
                        .await;
                    continue;
                }
            };
            let result = async {
                if row.status == InstanceStatus::Configuring
                    && let Some(state_files) = self.state_files.as_ref()
                    && self
                        .has_durable_mirrored_state_files(&row.id, state_files)
                        .await?
                {
                    return self
                        .replay_state_files_and_configure(
                            &row.owner_id,
                            row,
                            &tokens,
                            sandbox_id,
                            state_files,
                            true,
                            true,
                            "runtime-config-sync",
                        )
                        .await;
                }
                let mut body = self
                    .configure_body_for_existing_row(
                        &row.owner_id,
                        row,
                        &tokens.proxy,
                        &tokens.ingest,
                        &tokens.state_sync,
                    )
                    .await;
                if let Some(state_files) = self.state_files.as_ref() {
                    self.clear_identity_fields_when_mirror_is_authoritative(
                        &mut body,
                        &row.owner_id,
                        &row.id,
                        state_files,
                    )
                    .await?;
                }
                push_with_retry(reconfigurer.as_ref(), &row.id, sandbox_id, &body)
                    .await
                    .map_err(SwarmError::Internal)
            }
            .await;
            match result {
                Ok(()) => {
                    if row.status == InstanceStatus::Configuring {
                        self.instances
                            .update_status(&row.id, InstanceStatus::Live)
                            .await?;
                        self.refresh_egress_policy_best_effort(&row.id, "runtime-config-sync")
                            .await;
                    }
                    succeeded += 1;
                    tracing::debug!(instance = %row.id, "runtime-config-sync: pushed");
                }
                Err(e) => {
                    if row.status == InstanceStatus::Configuring {
                        tracing::warn!(
                            instance = %row.id,
                            sandbox = %sandbox_id,
                            error = %e,
                            "runtime-config-sync: Configuring recovery failed; destroying sandbox"
                        );
                        let _ = self.tokens.revoke_for_instance(&row.id).await;
                        if let Err(destroy_err) = self.sandbox.destroy_sandbox(sandbox_id).await {
                            tracing::warn!(
                                instance = %row.id,
                                sandbox = %sandbox_id,
                                error = %destroy_err,
                                "runtime-config-sync: failed to destroy unrecoverable Configuring sandbox"
                            );
                        }
                        self.instances
                            .update_status(&row.id, InstanceStatus::Destroyed)
                            .await?;
                        continue;
                    }
                    tracing::warn!(
                        instance = %row.id,
                        error = %e,
                        "runtime-config-sync: push failed (will retry next sweep)"
                    );
                    let _ = self
                        .instances
                        .record_probe(
                            &row.id,
                            crate::traits::ProbeResult::Degraded {
                                reason: format!("runtime-config push failed: {e}"),
                            },
                        )
                        .await;
                }
            }
        }
        let visited = rows.len();
        tracing::info!(visited, succeeded, "runtime-config-sync: sweep complete");
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
    /// webhook URLs all survive.  Workspace state normally survives
    /// via the snapshot; hosts on Cube builds without snapshot
    /// endpoints fall back to the snapshotless recreate path where
    /// swarm's sealed state mirror is authoritative.
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
        new_policy.assert_allowed_by_config(&self.network_config)?;
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
        let rotated = self
            .rotate_in_place(
                owner_id,
                instance_id,
                snapshot_svc,
                &target_template,
                Some(new_policy.clone()),
            )
            .await;
        match rotated {
            Ok(row) => Ok(row),
            Err(err) if is_snapshot_endpoint_unavailable(&err) => {
                tracing::warn!(
                    instance = %instance_id,
                    error = %err,
                    "change-network: cube snapshot endpoint unavailable; falling back to snapshotless recreate"
                );
                self.recreate_in_place(owner_id, instance_id, &target_template, Some(new_policy))
                    .await
            }
            Err(err) => Err(err),
        }
    }

    /// In-place rotation: pivot a Live row onto a new template (and
    /// optionally a new network policy) WITHOUT changing the row's
    /// swarm id.  Always snapshot the live cube as the base so local
    /// files that are outside, or not yet present in, the swarm mirror
    /// survive. When swarm has durable mirrored state, replay that
    /// mirror on top of the snapshot before enabling sync. Then swap
    /// `cube_sandbox_id` + `template_id` (+ policy when supplied) on
    /// the row, push the configure envelope, and destroy the old cube.
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
        let plan = self
            .build_in_place_swap_plan(
                owner_id,
                instance_id,
                new_template_id,
                new_network_policy,
                "cannot rotate a destroyed instance",
                "instance has no live cube sandbox; rotation requires a Live row",
            )
            .await?;
        let source = &plan.source;
        let old_sandbox_id = &plan.old_sandbox_id;
        let target_policy = &plan.target_policy;
        let resolved = &plan.resolved_policy;

        let no_op_template = source.template_id == plan.target_template_id;
        let no_op_policy = source.network_policy == *target_policy;
        if no_op_template && no_op_policy {
            return Err(SwarmError::BadRequest(
                "rotation is a no-op (same template, same network policy)".into(),
            ));
        }

        tracing::info!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %plan.target_template_id,
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
                match reconfigurer.is_idle(&source.id, old_sandbox_id).await {
                    Ok((true, _)) => match reconfigurer.quiesce(&source.id, old_sandbox_id).await {
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
                    },
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

        let replay_state_files = self.state_files.clone();
        let use_state_mirror = if let Some(state_files) = replay_state_files.as_ref() {
            match self
                .has_durable_mirrored_state_files(&source.id, state_files)
                .await
            {
                Ok(has_rows) => has_rows,
                Err(e) => {
                    if quiesced {
                        if let Some(rc) = self.reconfigurer.as_ref() {
                            unquiesce_on_drop("state mirror listing failed", &e);
                            let _ = rc.unquiesce(&source.id, old_sandbox_id).await;
                        }
                    }
                    return Err(e);
                }
            }
        } else {
            false
        };

        // Phase 1: snapshot the live cube as the base.  The swarm
        // mirror, when present, is replayed on top in Phase 3 so it
        // remains authoritative for paths it knows about, while the
        // snapshot preserves local workspace files that have not made
        // it into the mirror yet.
        if use_state_mirror {
            tracing::info!(
                instance = %source.id,
                sandbox = %old_sandbox_id,
                "rotate-in-place: durable state mirror present; snapshot will be used as base and mirror replayed"
            );
        }
        let snap = match snapshot_svc.snapshot(SYSTEM_OWNER, &source.id).await {
            Ok(s) => s,
            Err(e) => {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("snapshot failed", &e);
                        let _ = rc.unquiesce(&source.id, old_sandbox_id).await;
                    }
                }
                return Err(e);
            }
        };
        tracing::info!(
            instance = %source.id,
            snapshot = %snap.id,
            sandbox = %old_sandbox_id,
            state_mirror_overlay = use_state_mirror,
            "rotate-in-place: snapshot taken"
        );
        let from_snapshot_path = Some(std::path::PathBuf::from(snap.path));

        // Phase 2: build env envelope using the EXISTING bearer + id.
        // Runtime tokens are repaired here so legacy rows missing any
        // sibling token self-heal during rotation.
        let runtime_tokens = self
            .runtime_tokens_for_instance(&source.id, &plan.target_state_generation)
            .await?;

        // Phase 3: spin up a fresh cube under the new template using
        // the legacy snapshot, or clean when swarm already owns durable
        // state.
        let info = match self
            .create_in_place_swap_sandbox(
                &plan,
                &runtime_tokens,
                from_snapshot_path,
                use_state_mirror,
            )
            .await
        {
            Ok(i) => i,
            Err(e) => {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("cube create failed", &e);
                        let _ = rc.unquiesce(&source.id, old_sandbox_id).await;
                    }
                }
                return Err(e);
            }
        };
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "rotate-in-place: new cube live"
        );

        if let Some(state_files) = replay_state_files.as_ref().filter(|_| use_state_mirror) {
            if let Err(err) = self
                .replay_state_files_and_configure(
                    owner_id,
                    source,
                    &runtime_tokens,
                    &info.sandbox_id,
                    state_files,
                    true,
                    false,
                    "rotate",
                )
                .await
            {
                if quiesced {
                    if let Some(rc) = self.reconfigurer.as_ref() {
                        unquiesce_on_drop("state replay failed", &err);
                        let _ = rc.unquiesce(&source.id, old_sandbox_id).await;
                    }
                }
                let _ = self.sandbox.destroy_sandbox(&info.sandbox_id).await;
                return Err(err);
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
                &runtime_tokens.state_generation,
                &plan.target_template_id,
                target_policy,
                &row_policy_cidrs(target_policy, resolved),
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
                    let _ = rc.unquiesce(&source.id, old_sandbox_id).await;
                }
            }
            if let Err(d) = self.sandbox.destroy_sandbox(&info.sandbox_id).await {
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
        // boots out of warmup-placeholder mode.  The replacement row
        // is still Configuring; only a successful configure push can
        // promote it to Live.
        if !use_state_mirror {
            self.push_configure_after_swap(
                owner_id,
                source,
                &runtime_tokens,
                &info.sandbox_id,
                "rotate",
            )
            .await?;
        }
        self.instances
            .update_status(&source.id, InstanceStatus::Live)
            .await?;
        self.refresh_egress_policy_best_effort(&source.id, "rotate")
            .await;

        // Phase 6: destroy the old cube.  Force=true so a stuck
        // cube doesn't leave the row half-live.  This is the only
        // step where a failure has lasting effect — but the swarm
        // row already points to the new sandbox, so subsequent
        // reads are correct; a leaked cube is a janitor problem,
        // not a correctness problem.
        self.destroy_old_sandbox_after_in_place_swap(source, old_sandbox_id, "rotate")
            .await;

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
        let replay_state_files = self.state_files.clone();
        let use_state_mirror = if let Some(state_files) = replay_state_files.as_ref() {
            self.has_durable_mirrored_state_files(&source.id, state_files)
                .await?
        } else {
            false
        };

        tracing::warn!(
            instance = %source.id,
            old_sandbox = ?old_sandbox_id,
            to_template = %target_template,
            snapshot_path = %snapshot_path.display(),
            state_mirror_overlay = use_state_mirror,
            "restore-snapshot-in-place: creating replacement cube"
        );

        let target_state_generation = mint_state_generation();
        let runtime_tokens = self
            .runtime_tokens_for_instance(&source.id, &target_state_generation)
            .await?;
        let mut managed = managed_env(
            &self.proxy_base,
            &runtime_tokens.proxy,
            &runtime_tokens.ingest,
            &runtime_tokens.state_sync,
            &source.id,
            &source.bearer_token,
            &source.name,
            &source.task,
            &source.network_policy,
        );
        if use_state_mirror {
            managed.remove(ENV_STATE_SYNC_URL);
            managed.remove(ENV_STATE_SYNC_TOKEN);
        }
        let env = compose_sandbox_env(&managed, &BTreeMap::new())?;
        let from_snapshot_path = Some(snapshot_path);

        let info = self
            .sandbox
            .create_sandbox(CreateSandboxArgs {
                template_id: target_template.clone(),
                env,
                from_snapshot_path,
                resolved_policy: resolved.clone(),
            })
            .await?;
        self.bind_runtime_tokens_to_sandbox_source(&source.id, &info)
            .await?;
        tracing::info!(
            instance = %source.id,
            new_sandbox = %info.sandbox_id,
            "restore-snapshot-in-place: replacement cube live"
        );

        if let Some(state_files) = replay_state_files.as_ref().filter(|_| use_state_mirror)
            && let Err(err) = self
                .replay_state_files_and_configure(
                    owner_id,
                    &source,
                    &runtime_tokens,
                    &info.sandbox_id,
                    state_files,
                    true,
                    true,
                    "restore-snapshot",
                )
                .await
        {
            let _ = self.sandbox.destroy_sandbox(&info.sandbox_id).await;
            return Err(err);
        }

        if let Err(e) = self
            .instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                &runtime_tokens.state_generation,
                &target_template,
                &source.network_policy,
                &row_policy_cidrs(&source.network_policy, &resolved),
                now_secs(),
            )
            .await
        {
            if let Err(d) = self.sandbox.destroy_sandbox(&info.sandbox_id).await {
                tracing::warn!(
                    instance = %source.id,
                    new_sandbox = %info.sandbox_id,
                    error = %d,
                    "restore-snapshot-in-place: orphan cube destroy after DB swap failure"
                );
            }
            return Err(e.into());
        }

        if !use_state_mirror {
            self.push_configure_after_swap(
                owner_id,
                &source,
                &runtime_tokens,
                &info.sandbox_id,
                "restore-snapshot",
            )
            .await?;
        }
        self.instances
            .update_status(&source.id, InstanceStatus::Live)
            .await?;
        self.refresh_egress_policy_best_effort(&source.id, "restore-snapshot")
            .await;

        if let Some(old) = old_sandbox_id.filter(|old| old != &info.sandbox_id)
            && let Err(err) = self.sandbox.destroy_sandbox(&old).await
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
        let plan = self
            .build_in_place_swap_plan(
                owner_id,
                instance_id,
                new_template_id,
                new_network_policy,
                "cannot recreate a destroyed instance",
                "instance has no live cube sandbox; recreate requires a Live row",
            )
            .await?;
        let source = &plan.source;
        let old_sandbox_id = &plan.old_sandbox_id;

        tracing::warn!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %plan.target_template_id,
            state_replay = self.state_files.is_some(),
            "recreate-in-place: starting clean swap"
        );

        let runtime_tokens = self
            .runtime_tokens_for_instance(&source.id, &plan.target_state_generation)
            .await?;
        let replay_state_files = self.state_files.clone();
        let info = self
            .create_in_place_swap_sandbox(
                &plan,
                &runtime_tokens,
                None,
                replay_state_files.is_some(),
            )
            .await?;
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "recreate-in-place: new cube live"
        );

        if let Some(state_files) = replay_state_files.as_ref() {
            if let Err(err) = self
                .replay_state_files_and_configure(
                    owner_id,
                    source,
                    &runtime_tokens,
                    &info.sandbox_id,
                    state_files,
                    false,
                    true,
                    "recreate",
                )
                .await
            {
                let _ = self.sandbox.destroy_sandbox(&info.sandbox_id).await;
                return Err(err);
            }
        }

        self.instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                &runtime_tokens.state_generation,
                &plan.target_template_id,
                &plan.target_policy,
                &row_policy_cidrs(&plan.target_policy, &plan.resolved_policy),
                now_secs(),
            )
            .await?;

        if replay_state_files.is_none() {
            self.push_configure_after_swap(
                owner_id,
                source,
                &runtime_tokens,
                &info.sandbox_id,
                "recreate",
            )
            .await?;
        }
        self.instances
            .update_status(&source.id, InstanceStatus::Live)
            .await?;
        self.refresh_egress_policy_best_effort(&source.id, "recreate")
            .await;

        self.destroy_old_sandbox_after_in_place_swap(source, old_sandbox_id, "recreate")
            .await;

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
        let plan = self
            .build_in_place_swap_plan(
                owner_id,
                instance_id,
                new_template_id,
                None,
                "cannot reset a destroyed instance",
                "instance has no live cube sandbox; reset requires a Live row",
            )
            .await?;
        let source = &plan.source;
        let old_sandbox_id = &plan.old_sandbox_id;

        tracing::info!(
            instance = %source.id,
            from_template = %source.template_id,
            to_template = %plan.target_template_id,
            "reset-in-place: starting clean rebuild with sealed state replay"
        );

        let runtime_tokens = self
            .runtime_tokens_for_instance(&source.id, &plan.target_state_generation)
            .await?;
        let info = self
            .create_in_place_swap_sandbox(&plan, &runtime_tokens, None, true)
            .await?;
        tracing::info!(
            instance = %source.id,
            old_sandbox = %old_sandbox_id,
            new_sandbox = %info.sandbox_id,
            "reset-in-place: clean cube live; replaying state"
        );

        if let Err(err) = self
            .replay_state_files_and_configure(
                owner_id,
                source,
                &runtime_tokens,
                &info.sandbox_id,
                state_files,
                true,
                true,
                "reset",
            )
            .await
        {
            let _ = self.sandbox.destroy_sandbox(&info.sandbox_id).await;
            return Err(err);
        }

        if let Err(err) = self
            .instances
            .replace_cube_sandbox(
                &source.id,
                &info.sandbox_id,
                &runtime_tokens.state_generation,
                &plan.target_template_id,
                &plan.target_policy,
                &row_policy_cidrs(&plan.target_policy, &plan.resolved_policy),
                now_secs(),
            )
            .await
        {
            let _ = self.sandbox.destroy_sandbox(&info.sandbox_id).await;
            return Err(err.into());
        }
        self.instances
            .update_status(&source.id, InstanceStatus::Live)
            .await?;
        self.refresh_egress_policy_best_effort(&source.id, "reset")
            .await;

        self.destroy_old_sandbox_after_in_place_swap(source, old_sandbox_id, "reset")
            .await;

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
            if !crate::state_files::is_durable_state_file_path(&row.namespace, &row.path) {
                tracing::warn!(
                    instance = %instance_id,
                    namespace = %row.namespace,
                    path = %row.path,
                    "state-replay: skipping legacy mirror row outside durable state allowlist"
                );
                continue;
            }
            let (deleted, body_b64) = if row.deleted_at.is_some() {
                (true, None)
            } else {
                if row.body_ciphertext.is_none() {
                    if allow_unreadable_rows {
                        tracing::warn!(
                            instance = %instance_id,
                            namespace = %row.namespace,
                            path = %row.path,
                            "state-replay: skipping metadata-only mirror row with no sealed body"
                        );
                        continue;
                    }
                    return Err(SwarmError::Internal(format!(
                        "state file body missing for {}:{}",
                        row.namespace, row.path
                    )));
                }
                let plain = match state_files.read_body_for_replay(&row) {
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
                if crate::state_files::is_zero_byte_chat_transcript(
                    &row.namespace,
                    &row.path,
                    &plain,
                ) {
                    tracing::warn!(
                        instance = %instance_id,
                        namespace = %row.namespace,
                        path = %row.path,
                        "state-replay: skipping zero-byte chat transcript mirror row"
                    );
                    continue;
                }
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
                            "clone-empty: mcp sync push failed; the runtime config sync sweep will retry on next swarm restart"
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
        // Best-effort: a failure here is logged; the runtime config
        // sync sweep retries on next swarm restart.
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
                            "clone: mcp sync push failed; the runtime config sync sweep will retry on next swarm restart"
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
        req.network_policy
            .assert_allowed_by_config(&self.network_config)?;
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
        let state_generation = mint_state_generation();
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
            state_generation: state_generation.clone(),
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
        if !self
            .instances
            .create_with_owner_limit(row, MAX_ACTIVE_INSTANCES_PER_OWNER)
            .await?
        {
            return Err(SwarmError::InstanceQuotaExceeded {
                limit: MAX_ACTIVE_INSTANCES_PER_OWNER,
            });
        }

        let proxy_token = self.tokens.mint(&id, SHARED_PROVIDER).await?;
        // Per-instance ingest token, sibling of the chat proxy token
        // in `proxy_tokens`.  Same revoke path (`revoke_for_instance`
        // at destroy) so we don't need a parallel cleanup hook.
        let ingest_token = self.tokens.mint_ingest(&id).await?;
        let state_sync_token = self
            .tokens
            .mint_state_sync_for_generation(&id, &state_generation)
            .await?;

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
            .sandbox
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
        self.bind_runtime_tokens_to_sandbox_source(&id, &info)
            .await?;
        self.instances
            .set_cube_sandbox_id(&id, &info.sandbox_id)
            .await?;
        self.instances
            .update_status(
                &id,
                if self.reconfigurer.is_some() {
                    InstanceStatus::Configuring
                } else {
                    InstanceStatus::Live
                },
            )
            .await?;
        if self.reconfigurer.is_none() {
            self.refresh_egress_policy_best_effort(&id, "create").await;
        }

        // Caddy's on_demand TLS for `<id>.<hostname>` is warmed by the
        // SPA in the background (no-cors fetch + <link rel="preconnect">
        // when the detail page mounts).  Doing it here would add 5–15s
        // of synchronous wait to every create, which the user feels.

        // Stage 8: push the env envelope (name, task, models) into the
        // running dyson via /api/admin/configure.  Cube's snapshot/
        // restore freezes the warmup-mode dyson process's env; without
        // this push, every instance shows "warmup-placeholder" forever
        // and IDENTITY.md is empty.  Best-effort with retries — the
        // sandbox is Configuring by here but the dyson HTTP server inside
        // can take a beat to settle, especially on cold cubeproxy.
        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            let (task, identity_doc) =
                reconfigure_task_fields(req.task.clone().filter(|s| !s.is_empty()));
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
                task,
                identity_doc,
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
                telegram_proxy: None,
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
            if let Err(err) =
                push_with_retry(reconfigurer.as_ref(), &id, &info.sandbox_id, &body).await
            {
                tracing::warn!(
                    error = %err,
                    instance = %id,
                    sandbox = %info.sandbox_id,
                    "reconfigure: failed during create — destroying half-configured sandbox"
                );
                let _ = self.tokens.revoke_for_instance(&id).await;
                if let Err(destroy_err) = self.sandbox.destroy_sandbox(&info.sandbox_id).await {
                    tracing::warn!(
                        error = %destroy_err,
                        instance = %id,
                        sandbox = %info.sandbox_id,
                        "reconfigure: failed-create sandbox cleanup failed"
                    );
                }
                if let Err(status_err) = self
                    .instances
                    .update_status(&id, InstanceStatus::Destroyed)
                    .await
                {
                    tracing::warn!(
                        error = %status_err,
                        instance = %id,
                        "reconfigure: failed-create row cleanup failed"
                    );
                }
                return Err(SwarmError::Internal(format!(
                    "configure-push failed: {err}"
                )));
            }
            self.instances
                .update_status(&id, InstanceStatus::Live)
                .await?;
            self.refresh_egress_policy_best_effort(&id, "create").await;
        }

        Ok(CreatedInstance {
            id,
            url: info.url,
            bearer_token: bearer,
            proxy_token,
        })
    }

    pub async fn warn_live_internal_network_policies_if_disabled(&self) -> Result<(), SwarmError> {
        if self.network_config.allow_internal_network_policy {
            return Ok(());
        }
        let rows = self
            .instances
            .list(
                SYSTEM_OWNER,
                ListFilter {
                    status: Some(InstanceStatus::Live),
                    include_destroyed: false,
                },
            )
            .await?;
        for row in rows {
            if row.network_policy.is_internal_network() {
                tracing::warn!(
                    instance = %row.id,
                    "instance {} still on Open policy after gating; will not be re-selectable on edit.",
                    row.id
                );
            }
        }
        Ok(())
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

    /// Push a validated marketplace skill install into a Live dyson.
    /// Ownership is enforced by the caller-provided row lookup; this
    /// method only checks runtime viability before crossing into dyson.
    pub async fn install_skill_on_live(
        &self,
        row: &InstanceRow,
        marketplace: &str,
        skill: &str,
        package: crate::skill_marketplace::SkillPackageBody,
        force: bool,
    ) -> Result<InstallSkillResponse, SwarmError> {
        if !matches!(row.status, InstanceStatus::Live) {
            return Err(SwarmError::BadRequest("instance_not_live".into()));
        }
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| SwarmError::BadRequest("instance_not_live".into()))?;
        let Some(reconfigurer) = self.reconfigurer.as_ref() else {
            return Err(SwarmError::Internal(
                "dyson skill install reconfigurer is not configured".into(),
            ));
        };
        let body = InstallSkillBody {
            marketplace: marketplace.to_owned(),
            skill: skill.to_owned(),
            force,
            package,
        };
        reconfigurer
            .install_skill(&row.id, sandbox_id, &body)
            .await
            .map_err(|err| SwarmError::Internal(format!("agent_unreachable: {err}")))
    }

    /// Remove an installed skill from a Live dyson. Swarm's mirrored
    /// state-file tombstones are applied by the HTTP handler after the
    /// live runtime accepts the removal.
    pub async fn uninstall_skill_on_live(
        &self,
        row: &InstanceRow,
        skill: &str,
    ) -> Result<UninstallSkillResponse, SwarmError> {
        if !matches!(row.status, InstanceStatus::Live) {
            return Err(SwarmError::BadRequest("instance_not_live".into()));
        }
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| SwarmError::BadRequest("instance_not_live".into()))?;
        let Some(reconfigurer) = self.reconfigurer.as_ref() else {
            return Err(SwarmError::Internal(
                "dyson skill uninstall reconfigurer is not configured".into(),
            ));
        };
        reconfigurer
            .uninstall_skill(&row.id, sandbox_id, skill)
            .await
            .map_err(|err| SwarmError::Internal(format!("agent_unreachable: {err}")))
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
            let (task, identity_doc) =
                reconfigure_task_fields(Some(task.to_owned()).filter(|s| !s.is_empty()));
            let body = ReconfigureBody {
                name: Some(name.to_owned()).filter(|s| !s.is_empty()),
                task,
                identity_doc,
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

    /// Push Telegram channel proxy settings to the running dyson.
    /// The body carries only swarm proxy URLs and the existing
    /// per-instance bearer; bot tokens remain in swarm's secret store.
    pub async fn sync_channels_to_dyson(&self, owner_id: &str, id: &str) -> Result<(), SwarmError> {
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
        let proxy_token = self.tokens.lookup_by_instance(id).await?.ok_or_else(|| {
            SwarmError::PolicyDenied("instance has no active proxy_token (pre-Stage-8 row)".into())
        })?;

        let body = ReconfigureBody {
            instance_id: Some(id.to_owned()),
            telegram_proxy: self
                .telegram_proxy_block_for_instance(id, &proxy_token)
                .await,
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
                last_check_error: None,
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
            if entry
                .as_ref()
                .and_then(|e| e.raw_vscode_config.as_ref())
                .is_some()
            {
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
            owner_id: owner_id.to_owned(),
            instance_id: id.to_owned(),
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
            owner_id: owner_id.to_owned(),
            instance_id: id.to_owned(),
            name: name.to_owned(),
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
            match self.sandbox.destroy_sandbox(sb).await {
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
        if let Some(secrets) = self.agent_secrets.as_ref()
            && let Err(err) = secrets.delete_for_instance(id).await
        {
            tracing::warn!(
                error = %err,
                instance = %id,
                "destroy: agent secret cleanup failed; sealed plaintext lingers"
            );
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
        req.network_policy
            .assert_allowed_by_config(&self.network_config)?;
        let id = self.mint_unique_instance_id(owner_id).await?;
        let bearer = Uuid::new_v4().simple().to_string();
        let state_generation = mint_state_generation();
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
            state_generation: state_generation.clone(),
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
        let state_sync_token = self
            .tokens
            .mint_state_sync_for_generation(&id, &state_generation)
            .await?;

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
            .sandbox
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
        self.bind_runtime_tokens_to_sandbox_source(&id, &info)
            .await?;

        self.instances
            .set_cube_sandbox_id(&id, &info.sandbox_id)
            .await?;
        self.instances
            .update_status(
                &id,
                if self.reconfigurer.is_some() {
                    InstanceStatus::Configuring
                } else {
                    InstanceStatus::Live
                },
            )
            .await?;
        if self.reconfigurer.is_none() {
            self.refresh_egress_policy_best_effort(&id, "restore").await;
        }

        // A restored sandbox may inherit dyson.json from the snapshot
        // it booted from. Re-project the fresh swarm id, bearer-side
        // runtime tokens, models, tools, and any desired MCP block so a
        // clone/restore never keeps pointing at the source instance's
        // config.
        if let Some(reconfigurer) = self.reconfigurer.as_ref() {
            let row = self
                .instances
                .get_for_owner(owner_id, &id)
                .await?
                .ok_or(SwarmError::NotFound)?;
            let body = self
                .configure_body_for_existing_row(
                    owner_id,
                    &row,
                    &proxy_token,
                    &ingest_token,
                    &state_sync_token,
                )
                .await;
            push_with_retry(reconfigurer.as_ref(), &id, &info.sandbox_id, &body)
                .await
                .map_err(|err| {
                    tracing::warn!(
                        error = %err,
                        instance = %id,
                        sandbox = %info.sandbox_id,
                        "restore: configure-push failed after snapshot restore"
                    );
                    SwarmError::Internal(format!("restore configure-push failed: {err}"))
                })?;
            self.instances
                .update_status(&id, InstanceStatus::Live)
                .await?;
            self.refresh_egress_policy_best_effort(&id, "restore").await;
        }

        Ok(CreatedInstance {
            id,
            url: info.url,
            bearer_token: bearer,
            proxy_token,
        })
    }
}

#[cfg(test)]
mod tests;
