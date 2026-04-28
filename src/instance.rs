//! Instance lifecycle: create, destroy, restore.
//!
//! Wires `CubeClient` + `InstanceStore` + `SecretStore` + `TokenStore`. The
//! env map handed to the sandbox is composed via [`crate::secrets::compose_env`]
//! using the brief's priority (template → managed → caller → existing rows).
//!
//! One **proxy token per instance** is minted at create time; the
//! `provider` column is set to `"*"` to indicate the same token authorises
//! the instance against any provider permitted by its policy. The proxy
//! (step 14) consults the URL path to decide which adapter to use.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::WardenError;
use crate::now_secs;
use crate::secrets::compose_env;
use crate::traits::{
    CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus, InstanceStore,
    ListFilter, ProbeResult, SecretStore, TokenStore,
};

/// Sentinel `provider` value used for the per-instance shared proxy token.
/// The proxy resolves the token, sees `"*"`, and accepts any provider that
/// the instance's policy allows.
pub const SHARED_PROVIDER: &str = "*";

/// Env-var names injected by the orchestrator into every sandbox.
pub const ENV_PROXY_URL: &str = "WARDEN_PROXY_URL";
pub const ENV_PROXY_TOKEN: &str = "WARDEN_PROXY_TOKEN";
pub const ENV_INSTANCE_ID: &str = "WARDEN_INSTANCE_ID";
/// Bearer token the agent's HTTP server must accept. The host-based
/// dyson_proxy stamps `Authorization: Bearer <bearer_token>` on every
/// forwarded request — without this env, the agent has no way to know
/// the secret it's being challenged with.
pub const ENV_BEARER_TOKEN: &str = "WARDEN_BEARER_TOKEN";
/// Human-readable label, e.g. "PR reviewer for foo/bar".
pub const ENV_NAME: &str = "WARDEN_NAME";
/// Free-text mission statement. The agent reads this on first boot to
/// seed its self-knowledge files; warden does not push subsequent
/// edits to a running sandbox.
pub const ENV_TASK: &str = "WARDEN_TASK";
/// LLM model id the agent talks to via warden's `/llm` proxy
/// (e.g. `"anthropic/claude-sonnet-4-5"`, `"openai/gpt-4o"`). Required
/// at create time — there is intentionally no server-side default,
/// since the right model is task-specific and a stale default leaks
/// into deployments long after it was the right call.
pub const ENV_MODEL: &str = "WARDEN_MODEL";

/// Comma-separated ordered fallback list of model ids.  First entry
/// matches `WARDEN_MODEL`; trailing entries let agents that support
/// failover/rotation try alternate models in order.  Optional —
/// agents that only read `WARDEN_MODEL` ignore this.
pub const ENV_MODELS: &str = "WARDEN_MODELS";

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
/// server inside can take a beat to settle (especially when cubeproxy
/// is itself cold-starting).  Total budget: ~15s.  Backoff: 0.5s,
/// 1s, 2s, 4s, 8s.
pub async fn push_with_retry(
    r: &dyn DysonReconfigurer,
    instance_id: &str,
    sandbox_id: &str,
    body: &ReconfigureBody,
) -> Result<(), String> {
    let mut delay = std::time::Duration::from_millis(500);
    let mut last_err = String::new();
    for attempt in 0..5 {
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

#[derive(Clone)]
pub struct InstanceService {
    cube: Arc<dyn CubeClient>,
    instances: Arc<dyn InstanceStore>,
    secrets: Arc<dyn SecretStore>,
    tokens: Arc<dyn TokenStore>,
    /// Public base URL of the warden's `/llm/` proxy mount, e.g.
    /// `http://warden:8080/llm`.
    proxy_base: String,
    default_ttl_seconds: i64,
    /// Dyson reconfigurer — lets us push WARDEN_MODEL / WARDEN_TASK /
    /// WARDEN_NAME into a freshly-created sandbox via Dyson's
    /// `/api/admin/configure` endpoint.  Stage 8 fix for cube's
    /// snapshot/restore freezing the dyson process's env at warmup
    /// time (when WARDEN_* are unset → "warmup-placeholder" model).
    /// `None` skips reconfigure entirely (test/local-dev).
    reconfigurer: Option<Arc<dyn DysonReconfigurer>>,
}

/// Anything that can push warden-side identity/task/model state to a
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
}

/// Build the orchestrator-managed env envelope that gets handed to the
/// sandbox at create + restore time. Centralised so the two paths can't
/// drift on which keys they inject.
fn managed_env(
    proxy_base: &str,
    proxy_token: &str,
    instance_id: &str,
    bearer: &str,
    name: &str,
    task: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(ENV_PROXY_URL.into(), proxy_base.to_owned());
    out.insert(ENV_PROXY_TOKEN.into(), proxy_token.to_owned());
    out.insert(ENV_INSTANCE_ID.into(), instance_id.to_owned());
    out.insert(ENV_BEARER_TOKEN.into(), bearer.to_owned());
    out.insert(ENV_NAME.into(), name.to_owned());
    out.insert(ENV_TASK.into(), task.to_owned());
    out
}

/// Body sent to dyson's `/api/admin/configure`.  Mirrors the dyson
/// side's `ConfigureBody` — the two structs are intentionally
/// duplicated rather than shared because warden + dyson are two
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
}

impl InstanceService {
    pub fn new(
        cube: Arc<dyn CubeClient>,
        instances: Arc<dyn InstanceStore>,
        secrets: Arc<dyn SecretStore>,
        tokens: Arc<dyn TokenStore>,
        proxy_base: impl Into<String>,
        default_ttl_seconds: i64,
    ) -> Self {
        Self {
            cube,
            instances,
            secrets,
            tokens,
            proxy_base: proxy_base.into(),
            default_ttl_seconds,
            reconfigurer: None,
        }
    }

    /// Builder-style: plug in the dyson reconfigurer so post-create
    /// pushes the env envelope through dyson's runtime endpoint.
    pub fn with_reconfigurer(mut self, r: Arc<dyn DysonReconfigurer>) -> Self {
        self.reconfigurer = Some(r);
        self
    }

    pub async fn create(
        &self,
        owner_id: &str,
        req: CreateRequest,
    ) -> Result<CreatedInstance, WardenError> {
        // The agent boot config refuses to start without a model id, so
        // catch the missing-model case here with a clean error instead
        // of letting the cube start a doomed sandbox we then have to
        // garbage-collect. Trim-empty counts as missing.
        if !req.env.get(ENV_MODEL).is_some_and(|s| !s.trim().is_empty()) {
            return Err(WardenError::PolicyDenied(format!(
                "{ENV_MODEL} is required in the create request's `env` \
                 (e.g. \"anthropic/claude-sonnet-4-5\"); there is no default"
            )));
        }

        let id = Uuid::new_v4().simple().to_string();
        let bearer = Uuid::new_v4().simple().to_string();
        let now = now_secs();
        let ttl = req.ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let name = req.name.clone().unwrap_or_default();
        let task = req.task.clone().unwrap_or_default();

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
            expires_at: Some(now + ttl),
            last_active_at: now,
            last_probe_at: None,
            last_probe_status: None,
            created_at: now,
            destroyed_at: None,
        };
        self.instances.create(row).await?;

        let proxy_token = self.tokens.mint(&id, SHARED_PROVIDER).await?;

        // Identity envelope. The agent reads these on first boot to seed
        // its own self-knowledge files (SOUL.md and friends in Dyson's
        // case); subsequent edits to the warden row don't propagate to a
        // running sandbox, by design.
        let managed = managed_env(&self.proxy_base, &proxy_token, &id, &bearer, &name, &task);

        // Templates aren't materialised inside warden — they live in Cube.
        // The "template" half of the merge is empty here; operators set per-
        // instance values via PUT /secrets and they win as `existing`.
        let env = compose_env(&BTreeMap::new(), &managed, &req.env, &[]);

        let info = match self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: req.template_id,
                env,
                from_snapshot_path: None,
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
            let mut models: Vec<String> = req
                .env
                .get(ENV_MODELS)
                .map(|s| s.split(',').map(|m| m.trim().to_owned()).filter(|m| !m.is_empty()).collect())
                .unwrap_or_default();
            // Fall back to the single WARDEN_MODEL if WARDEN_MODELS
            // wasn't supplied — older clients might still only pass
            // the legacy env.
            if models.is_empty()
                && let Some(m) = req.env.get(ENV_MODEL).map(|s| s.trim().to_owned())
                && !m.is_empty()
            {
                models.push(m);
            }
            let body = ReconfigureBody {
                name: req.name.clone().filter(|s| !s.is_empty()),
                task: req.task.clone().filter(|s| !s.is_empty()),
                models,
                instance_id: Some(id.clone()),
            };
            let r = reconfigurer.clone();
            let id_for_log = id.clone();
            let sandbox_id = info.sandbox_id.clone();
            // Spawn so we can return CreatedInstance immediately —
            // the SPA's create flow already shows a "provisioning"
            // spinner that the dispatch layer drives via the
            // detail-page useEffect.  If the push fails we log;
            // the user can retry by editing the dyson, which lands
            // on the same /api/admin/configure code path.
            tokio::spawn(async move {
                if let Err(err) = push_with_retry(&*r, &id_for_log, &sandbox_id, &body).await {
                    tracing::warn!(
                        error = %err,
                        instance = %id_for_log,
                        sandbox = %sandbox_id,
                        "reconfigure: failed; dyson may stay on warmup-placeholder"
                    );
                }
            });
        }

        Ok(CreatedInstance {
            id,
            url: info.url,
            bearer_token: bearer,
            proxy_token,
        })
    }

    /// Owner-scoped lookup: returns NotFound for rows the user doesn't own.
    pub async fn get(&self, owner_id: &str, id: &str) -> Result<InstanceRow, WardenError> {
        self.instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(WardenError::NotFound)
    }

    /// System lookup: returns the row regardless of owner.  Used by
    /// the anonymous `/healthz` probe carve-out in `dyson_proxy::dispatch`
    /// (the prober has no user identity) and by background sweepers
    /// like the TTL loop.  Caller is responsible for not exposing the
    /// row across tenant boundaries — this skips the normal
    /// owner-filter that the per-handler `get` enforces.
    pub async fn get_unscoped(&self, id: &str) -> Result<InstanceRow, WardenError> {
        self.instances.get(id).await?.ok_or(WardenError::NotFound)
    }

    pub async fn list(
        &self,
        owner_id: &str,
        filter: ListFilter,
    ) -> Result<Vec<InstanceRow>, WardenError> {
        Ok(self.instances.list(owner_id, filter).await?)
    }

    /// Run a single probe synchronously, persist the result on the row, and
    /// hand it back to the caller. Used by `POST /v1/instances/:id/probe`.
    pub async fn probe(
        &self,
        owner_id: &str,
        prober: &dyn HealthProber,
        id: &str,
    ) -> Result<ProbeResult, WardenError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(WardenError::NotFound)?;
        let result = prober.probe(&row).await;
        self.instances.record_probe(id, result.clone()).await?;
        Ok(result)
    }

    /// Owner-scoped identity update.  Updates warden's row AND pushes
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
    ) -> Result<InstanceRow, WardenError> {
        self.instances.update_identity(owner_id, id, name, task).await?;
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(WardenError::NotFound)?;
        if let (Some(r), Some(sb)) = (
            self.reconfigurer.as_ref(),
            row.cube_sandbox_id.as_deref().filter(|s| !s.is_empty()),
        ) {
            let body = ReconfigureBody {
                name: Some(name.to_owned()).filter(|s| !s.is_empty()),
                task: Some(task.to_owned()).filter(|s| !s.is_empty()),
                models: Vec::new(), // identity-only update; leave models alone
                instance_id: Some(id.to_owned()),
            };
            let r = r.clone();
            let id_owned = id.to_owned();
            let sb_owned = sb.to_owned();
            tokio::spawn(async move {
                if let Err(err) = push_with_retry(&*r, &id_owned, &sb_owned, &body).await {
                    tracing::warn!(error = %err, instance = %id_owned, "rename: reconfigure push failed");
                }
            });
        }
        Ok(row)
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
    pub async fn update_models(
        &self,
        owner_id: &str,
        id: &str,
        models: Vec<String>,
    ) -> Result<(), WardenError> {
        if models.is_empty() {
            return Err(WardenError::PolicyDenied(
                "models list must contain at least one entry".into(),
            ));
        }
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(WardenError::NotFound)?;
        let sandbox_id = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WardenError::PolicyDenied("instance has no live sandbox to reconfigure".into())
            })?;
        let r = self.reconfigurer.as_ref().ok_or_else(|| {
            WardenError::PolicyDenied("dyson reconfigurer not configured".into())
        })?;
        let body = ReconfigureBody {
            name: None,
            task: None,
            models,
            instance_id: Some(id.to_owned()),
        };
        push_with_retry(&**r, id, sandbox_id, &body)
            .await
            .map_err(WardenError::PolicyDenied)?;
        Ok(())
    }

    pub async fn destroy(&self, owner_id: &str, id: &str) -> Result<(), WardenError> {
        let row = self
            .instances
            .get_for_owner(owner_id, id)
            .await?
            .ok_or(WardenError::NotFound)?;
        if let Some(sb) = &row.cube_sandbox_id {
            self.cube.destroy_sandbox(sb).await?;
        }
        self.tokens.revoke_for_instance(id).await?;
        self.instances
            .update_status(id, InstanceStatus::Destroyed)
            .await?;
        Ok(())
    }

    /// Restore a new instance from a snapshot's bytes on the Cube host.
    /// Carries `source` instance secrets across by writing them into the new
    /// instance's `instance_secrets` rows. The caller may override or add via
    /// `req.env`.
    pub async fn restore(
        &self,
        owner_id: &str,
        req: RestoreRequest,
    ) -> Result<CreatedInstance, WardenError> {
        let id = Uuid::new_v4().simple().to_string();
        let bearer = Uuid::new_v4().simple().to_string();
        let now = now_secs();
        let ttl = req.ttl_seconds.unwrap_or(self.default_ttl_seconds);

        let existing = if let Some(src) = &req.source_instance_id {
            self.secrets.list(src).await?
        } else {
            Vec::new()
        };

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
            expires_at: Some(now + ttl),
            last_active_at: now,
            last_probe_at: None,
            last_probe_status: None,
            created_at: now,
            destroyed_at: None,
        };
        self.instances.create(row).await?;

        let proxy_token = self.tokens.mint(&id, SHARED_PROVIDER).await?;

        // Persist carried-over secrets early so they appear in the new
        // instance's `existing` rows on subsequent restarts. They also feed
        // the env map below directly (cheaper than re-reading).
        for (name, value) in &existing {
            self.secrets.put(&id, name, value).await?;
        }

        // Identity envelope. Re-injected on restore so a fresh sandbox
        // (no SOUL.md) can seed itself; an inherited image with prior
        // self-knowledge will simply ignore them.
        let managed = managed_env(
            &self.proxy_base,
            &proxy_token,
            &id,
            &bearer,
            &restored_name,
            &restored_task,
        );

        let env = compose_env(&BTreeMap::new(), &managed, &req.env, &existing);

        let info = match self
            .cube
            .create_sandbox(CreateSandboxArgs {
                template_id: req.template_id,
                env,
                from_snapshot_path: Some(req.snapshot_path),
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

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRequest {
    pub template_id: String,
    /// Human-readable label for the employee. Optional — defaults to the
    /// short id when unset. Surfaced as `WARDEN_NAME` in the sandbox env.
    #[serde(default)]
    pub name: Option<String>,
    /// Free-text task / mission. Optional but strongly recommended;
    /// surfaced as `WARDEN_TASK` so the agent reads its job description
    /// at boot.
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedInstance {
    pub id: String,
    pub url: String,
    pub bearer_token: String,
    pub proxy_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::error::CubeError;
    use crate::traits::{CubeClient, SandboxInfo, SnapshotInfo};

    #[derive(Default)]
    struct CapturedCreate {
        template_id: String,
        env: BTreeMap<String, String>,
        from_snapshot: Option<std::path::PathBuf>,
    }

    #[derive(Default)]
    struct MockCube {
        last_create: Mutex<Option<CapturedCreate>>,
        destroyed: Mutex<Vec<String>>,
        next_sandbox_id: Mutex<u32>,
    }

    impl MockCube {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn last_create(&self) -> CapturedCreate {
            self.last_create.lock().unwrap().take().unwrap()
        }
    }

    #[async_trait]
    impl CubeClient for MockCube {
        async fn create_sandbox(
            &self,
            args: CreateSandboxArgs,
        ) -> Result<SandboxInfo, CubeError> {
            let mut n = self.next_sandbox_id.lock().unwrap();
            *n += 1;
            let sid = format!("sb-{}", *n);
            *self.last_create.lock().unwrap() = Some(CapturedCreate {
                template_id: args.template_id.clone(),
                env: args.env,
                from_snapshot: args.from_snapshot_path,
            });
            Ok(SandboxInfo {
                sandbox_id: sid.clone(),
                host_ip: "10.0.0.1".into(),
                url: format!("https://{sid}.cube.test"),
            })
        }

        async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), CubeError> {
            self.destroyed.lock().unwrap().push(sandbox_id.into());
            Ok(())
        }

        async fn snapshot_sandbox(
            &self,
            _: &str,
            _: &str,
        ) -> Result<SnapshotInfo, CubeError> {
            unimplemented!("not used in instance tests")
        }

        async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), CubeError> {
            unimplemented!("not used in instance tests")
        }
    }

    async fn build() -> (
        InstanceService,
        Arc<MockCube>,
        Arc<dyn TokenStore>,
        Arc<dyn SecretStore>,
        Arc<dyn InstanceStore>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let cube = MockCube::new();
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool));
        let svc = InstanceService::new(
            cube.clone(),
            instances.clone(),
            secrets.clone(),
            tokens.clone(),
            "http://warden.test:8080/llm",
            3600,
        );
        (svc, cube, tokens, secrets, instances)
    }

    /// Tests share this helper so the WARDEN_MODEL requirement isn't
    /// re-stated everywhere. Returns an env map with just the model set
    /// to a placeholder; callers add their own keys on top.
    fn env_with_model() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(ENV_MODEL.into(), "anthropic/claude-sonnet-4-5".into());
        m
    }

    #[tokio::test]
    async fn create_with_name_and_task_stamps_row_and_env() {
        let (svc, cube, _tokens, _secrets, instances) = build().await;
        let created = svc
            .create("legacy", CreateRequest {
                template_id: "tpl".into(),
                name: Some("PR reviewer".into()),
                task: Some("Watch foo/bar PRs and comment on style".into()),
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();

        let captured = cube.last_create();
        assert_eq!(captured.env[ENV_NAME], "PR reviewer");
        assert_eq!(captured.env[ENV_TASK], "Watch foo/bar PRs and comment on style");

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.name, "PR reviewer");
        assert_eq!(row.task, "Watch foo/bar PRs and comment on style");
    }

    #[tokio::test]
    async fn rename_updates_row_but_does_not_re_emit_env() {
        // Per the design, edits in warden don't propagate to a running
        // sandbox.  This test is the contract: rename mutates the row,
        // but the cube was only invoked at create time, so its captured
        // env snapshot still has the original (empty) values.
        let (svc, cube, _tokens, _secrets, _instances) = build().await;
        let created = svc
            .create("legacy", CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();

        let renamed = svc.rename("legacy", &created.id, "renamed", "new task").await.unwrap();
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
        let (svc, cube, tokens, _secrets, instances) = build().await;
        let mut caller = env_with_model();
        caller.insert("EXTRA".into(), "yes".into());
        let created = svc
            .create("legacy", CreateRequest {
                template_id: "tpl-x".into(),
                name: None,
                task: None,
                env: caller,
                ttl_seconds: Some(60),
            })
            .await
            .unwrap();
        assert!(created.url.starts_with("https://sb-1."));
        assert_eq!(created.bearer_token.len(), 32);
        assert_eq!(created.proxy_token.len(), 32);

        let captured = cube.last_create();
        assert_eq!(captured.template_id, "tpl-x");
        assert_eq!(captured.env[ENV_PROXY_URL], "http://warden.test:8080/llm");
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

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Live);
    }

    #[tokio::test]
    async fn caller_env_overrides_managed_when_keys_collide() {
        // Per the brief's priority: template < managed < caller < existing.
        // The caller can override managed values (we trust the operator).
        let (svc, cube, _tokens, _secrets, _instances) = build().await;
        let mut caller = env_with_model();
        caller.insert(ENV_PROXY_URL.into(), "http://override".into());
        svc.create("legacy", CreateRequest {
            template_id: "tpl".into(),
                name: None,
                task: None,
            env: caller,
            ttl_seconds: None,
        })
        .await
        .unwrap();
        let captured = cube.last_create();
        assert_eq!(captured.env[ENV_PROXY_URL], "http://override");
    }

    #[tokio::test]
    async fn destroy_revokes_proxy_tokens_and_marks_destroyed() {
        let (svc, cube, tokens, _secrets, instances) = build().await;
        let created = svc
            .create("legacy", CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        assert!(tokens.resolve(&created.proxy_token).await.unwrap().is_some());

        svc.destroy("legacy", &created.id).await.unwrap();
        assert!(tokens.resolve(&created.proxy_token).await.unwrap().is_none());

        let row = instances.get(&created.id).await.unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Destroyed);
        assert!(row.destroyed_at.is_some());

        assert_eq!(cube.destroyed.lock().unwrap().as_slice(), ["sb-1"]);
    }

    #[tokio::test]
    async fn destroy_unknown_returns_not_found() {
        let (svc, _cube, _tokens, _secrets, _instances) = build().await;
        let err = svc.destroy("legacy", "nope").await.expect_err("must error");
        matches!(err, WardenError::NotFound);
    }

    #[tokio::test]
    async fn restore_carries_existing_secrets_and_uses_snapshot_path() {
        let (svc, cube, _tokens, secrets, _instances) = build().await;
        let src = svc
            .create("legacy", CreateRequest {
                template_id: "tpl".into(),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        secrets.put(&src.id, "K", "v-existing").await.unwrap();

        let restored = svc
            .restore("legacy", RestoreRequest {
                template_id: "tpl".into(),
                snapshot_path: "/var/snaps/snap-1".into(),
                source_instance_id: Some(src.id.clone()),
                name: None,
                task: None,
                env: env_with_model(),
                ttl_seconds: None,
            })
            .await
            .unwrap();
        assert_ne!(restored.id, src.id);

        let captured = cube.last_create();
        assert_eq!(
            captured.from_snapshot.as_deref(),
            Some(std::path::Path::new("/var/snaps/snap-1"))
        );
        assert_eq!(captured.env["K"], "v-existing");

        // Existing secrets are persisted under the new instance id too.
        let copied = secrets.list(&restored.id).await.unwrap();
        assert_eq!(copied, vec![("K".into(), "v-existing".into())]);
    }
}
