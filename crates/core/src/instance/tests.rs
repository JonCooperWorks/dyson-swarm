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
    let row = instances.get(&created.id).await.unwrap().unwrap();
    assert_eq!(
        state_resolved.provider,
        crate::db::tokens::state_sync_provider(&row.state_generation)
    );

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
        self.restored
            .lock()
            .unwrap()
            .push((instance_id.into(), sandbox_id.into(), body.clone()));
        self.events
            .lock()
            .unwrap()
            .push(format!("restore:{}:{}", body.namespace, body.path));
        Ok(())
    }
}

struct FailingPushReconfigurer;

#[async_trait]
impl DysonReconfigurer for FailingPushReconfigurer {
    async fn push(
        &self,
        _instance_id: &str,
        _sandbox_id: &str,
        _body: &ReconfigureBody,
    ) -> Result<(), String> {
        Err("dyson configure did not apply requested mcp_servers block".into())
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
/// recording reconfigurer. Used by runtime config sync tests
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
async fn startup_runtime_config_sync_visits_each_live_instance_with_its_token() {
    // Hire two dysons.  After the create-time pushes drain, run
    // the sweep: it must visit each one and stamp the same
    // desired runtime config the recreate/restore paths use.
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
        .sync_runtime_config_all()
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
        assert_eq!(
            body.proxy_token.as_deref(),
            Some(expect_token.as_str()),
            "startup sync must repair the chat proxy token too"
        );
        assert_eq!(
            body.proxy_base.as_deref(),
            Some("https://dyson.example.com/llm/openrouter")
        );
        assert_eq!(
            body.models,
            vec!["anthropic/claude-sonnet-4-5".to_string()],
            "startup sync must replay the DB's model source of truth"
        );
        assert!(body.ingest_url.is_some(), "ingest URL must be repaired");
        assert!(body.ingest_token.is_some(), "ingest token must be repaired");
        assert!(
            body.state_sync_url.is_some() && body.state_sync_token.is_some(),
            "state sync must be repaired"
        );
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
async fn runtime_config_sync_failure_is_visible_on_instance_probe_status() {
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

    let failing = InstanceService::new(
        cube.clone(),
        instances.clone(),
        tokens.clone(),
        "https://dyson.example.com/llm",
    )
    .with_reconfigurer(Arc::new(FailingPushReconfigurer));

    let (visited, succeeded) = failing.sync_runtime_config_all().await.unwrap();
    assert_eq!(visited, 1);
    assert_eq!(succeeded, 0);

    let row = instances.get(&created.id).await.unwrap().unwrap();
    match row.last_probe_status {
        Some(crate::traits::ProbeResult::Degraded { reason }) => {
            assert!(reason.contains("runtime-config push failed"));
            assert!(reason.contains("did not apply requested mcp_servers"));
        }
        other => panic!("runtime config failure must be visible, got {other:?}"),
    }
}

#[test]
fn semantic_reconfigure_errors_are_not_retried() {
    assert!(is_non_retryable_reconfigure_error(
        "dyson configure did not apply requested mcp_servers block"
    ));
    assert!(is_non_retryable_reconfigure_error(
        "dyson configure secret mismatch for instance i-1"
    ));
    assert!(!is_non_retryable_reconfigure_error(
        "dyson /api/admin/configure 502: bad gateway"
    ));
}

#[tokio::test]
async fn runtime_config_sync_still_runs_when_image_defaults_disabled() {
    // Disabling image defaults only suppresses the image provider
    // fields. The startup sync still re-projects the rest of the
    // durable desired config so redeploys repair drift.
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

    let (visited, succeeded) = svc.sync_runtime_config_all().await.unwrap();
    assert_eq!(visited, 1);
    assert_eq!(succeeded, 1);
    let pushed = recorder.pushed.lock().unwrap();
    assert_eq!(pushed.len(), 1);
    let body = &pushed[0].2;
    assert!(body.image_provider_name.is_none());
    assert!(body.image_provider_block.is_none());
    assert!(body.image_generation_provider.is_none());
    assert!(body.image_generation_model.is_none());
    assert!(body.proxy_token.is_some());
    assert_eq!(body.models, vec!["anthropic/claude-sonnet-4-5".to_string()]);
}

#[tokio::test]
async fn recreate_in_place_reprojects_mcp_from_canonical_runtime_config() {
    let (svc, cube, _tokens, instances, recorder, _user_secrets, owner) =
        build_with_mcp_secrets().await;
    let created = hire_minimal(&svc, &owner).await;
    wait_for_pushes(&recorder, 1).await;

    svc.put_mcp_server(
        &owner,
        &created.id,
        McpServerSpec {
            name: "mcp_massive".into(),
            url: "https://8.8.8.8/mcp".into(),
            auth: crate::mcp_servers::McpAuthSpec::Bearer {
                token: "massive_secret".into(),
            },
            enabled_tools: None,
        },
    )
    .await
    .unwrap();
    recorder.pushed.lock().unwrap().clear();

    let row = svc
        .recreate_in_place(&owner, &created.id, "tpl-v2", None)
        .await
        .unwrap();
    assert_eq!(row.id, created.id);
    assert_eq!(row.template_id, "tpl-v2");
    assert_eq!(cube.last_create().template_id, "tpl-v2");
    assert_eq!(
        instances
            .get_for_owner(&owner, &created.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InstanceStatus::Live
    );

    let pushed = recorder.pushed.lock().unwrap();
    assert_eq!(pushed.len(), 1);
    let body = &pushed[0].2;
    assert_eq!(body.instance_id.as_deref(), Some(created.id.as_str()));
    let mcp_block = body
        .mcp_servers
        .as_ref()
        .expect("recreate configure must preserve attached MCP servers");
    assert!(
        mcp_block.contains_key("mcp_massive"),
        "rendered mcp_servers block must include attached MCP servers, got keys {:?}",
        mcp_block.keys().collect::<Vec<_>>()
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
        self.map
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .ok_or_else(|| crate::network_policy::PolicyError::HostUnresolvable(host.to_owned()))
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
        state_generation: "sg-ancient".into(),
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
    let (isvc, ssvc, cube, instances, user_secrets, recorder, owner) =
        build_with_snapshot_and_mcp().await;
    let created = isvc
        .create(
            &owner,
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
    crate::mcp_servers::put_all(
        &user_secrets,
        &owner,
        &created.id,
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
    let before = instances.get(&created.id).await.unwrap().unwrap();
    let old_sandbox = before.cube_sandbox_id.clone().unwrap();
    let snap = ssvc.snapshot(&owner, &created.id).await.unwrap();

    let recovered = ssvc
        .restore_in_place(&owner, &created.id, &snap.id, None)
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
    let pushed = recorder.pushed.lock().unwrap();
    assert_eq!(pushed.len(), 1);
    let mcp_block = pushed[0]
        .2
        .mcp_servers
        .as_ref()
        .expect("restore-in-place configure must preserve attached MCP servers");
    assert!(
        mcp_block.contains_key("mcp_massive"),
        "rendered mcp_servers block must include attached MCP servers, got keys {:?}",
        mcp_block.keys().collect::<Vec<_>>()
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
        last_check_error: None,
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
        last_check_error: None,
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
    let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
    let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> =
        Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
    let user_secrets = Arc::new(UserSecretsService::new(user_secrets_store, ciphers.clone()));
    let state_files = crate::state_files::StateFileService::new(pool.clone(), ciphers);
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
    crate::db::state_files::upsert(
        &pool,
        crate::db::state_files::UpsertSpec {
            instance_id: &src.id,
            owner_id: &owner,
            namespace: "chats",
            path: "c-0001/artefacts/a1.body",
            mime: Some("application/octet-stream"),
            bytes: 23,
            body_ciphertext: b"-----BEGIN AGE ENCRYPTED FILE-----\nnot a valid sealed body\n",
            updated_at: 1_777_700_003,
            synced_at: 1_777_700_003,
        },
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
    assert_eq!(pushed.len(), 2);
    assert!(
        pushed[0].2.state_sync_url.is_none() && pushed[0].2.state_sync_token.is_none(),
        "reset must configure paths before replay while state sync is still disabled"
    );
    assert!(
        pushed[1].2.state_sync_url.is_some() && pushed[1].2.state_sync_token.is_some(),
        "state sync should be enabled by the post-replay configure push"
    );
    assert!(
        pushed
            .iter()
            .all(|(_, _, body)| body.name.is_none() && body.task.is_none()),
        "post-replay configure must not overwrite mirrored IDENTITY.md with row metadata"
    );
    for (_, _, body) in pushed.iter() {
        let mcp_block = body
            .mcp_servers
            .as_ref()
            .expect("reset configure must preserve attached MCP servers");
        assert!(
            mcp_block.contains_key("mcp_massive"),
            "rendered mcp_servers block must include attached MCP servers, got keys {:?}",
            mcp_block.keys().collect::<Vec<_>>()
        );
    }
    drop(pushed);

    let events = recorder.events.lock().unwrap();
    assert_eq!(events.first().map(String::as_str), Some("push"));
    assert_eq!(events.last().map(String::as_str), Some("push"));
    assert!(
        events[1..events.len() - 1]
            .iter()
            .all(|event| event.starts_with("restore:")),
        "reset must configure paths, replay state, then configure again to enable state sync: {events:?}"
    );
}

#[tokio::test]
async fn runtime_config_sync_replays_sealed_chats_before_enabling_sync() {
    let pool = open_in_memory().await.unwrap();
    let owner = "abbafeed".repeat(4);
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
    let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
    let ciphers_for_zero = ciphers.clone();
    let state_files = Arc::new(crate::state_files::StateFileService::new(
        pool.clone(),
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
        .with_mcp_secrets(user_secrets),
    );

    let src = isvc
        .create(
            &owner,
            CreateRequest {
                template_id: "tpl-v1".into(),
                name: Some("live-mirror".into()),
                task: Some("keep chat history".into()),
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
                updated_at: 1_777_730_000,
            },
            b"# IDENTITY.md\n\n- **Name:** live-mirror",
        )
        .await
        .unwrap();
    state_files
        .ingest(
            crate::state_files::StateFileMeta {
                instance_id: &src.id,
                owner_id: &owner,
                namespace: "chats",
                path: "c-7/transcript.json",
                mime: Some("application/json"),
                updated_at: 1_777_730_001,
            },
            br#"[{"role":"user","content":"do not vanish"}]"#,
        )
        .await
        .unwrap();
    let zero_path = "c-empty/transcript.json";
    let sealed_zero = ciphers_for_zero
        .for_user(&owner)
        .unwrap()
        .seal(b"")
        .unwrap();
    crate::db::state_files::upsert(
        &pool,
        crate::db::state_files::UpsertSpec {
            instance_id: &src.id,
            owner_id: &owner,
            namespace: "chats",
            path: zero_path,
            mime: Some("application/json"),
            bytes: 0,
            body_ciphertext: &sealed_zero,
            updated_at: 1_777_730_002,
            synced_at: 1_777_730_002,
        },
    )
    .await
    .unwrap();

    let (visited, succeeded) = isvc.sync_runtime_config_all().await.unwrap();
    assert_eq!((visited, succeeded), (1, 1));

    let restored = recorder.restored.lock().unwrap();
    assert!(
        restored
            .iter()
            .any(|(_, _, b)| b.namespace == "chats" && b.path == "c-7/transcript.json"),
        "startup/runtime sync must replay mirrored chat transcripts into the live sandbox"
    );
    assert!(
        !restored
            .iter()
            .any(|(_, _, b)| b.namespace == "chats" && b.path == zero_path),
        "runtime sync must not replay invalid zero-byte chat transcripts"
    );
    drop(restored);

    let pushed = recorder.pushed.lock().unwrap();
    assert_eq!(pushed.len(), 1);
    assert!(
        pushed[0].2.state_sync_url.is_some() && pushed[0].2.state_sync_token.is_some(),
        "state sync should be enabled only after replay finishes"
    );
    assert!(
        pushed[0].2.name.is_none() && pushed[0].2.task.is_none(),
        "post-replay sync configure must not overwrite mirrored IDENTITY.md"
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
    let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
    let state_files = Arc::new(crate::state_files::StateFileService::new(
        pool.clone(),
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
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
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
    let keys = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let ciphers: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
    let state_files = Arc::new(crate::state_files::StateFileService::new(
        pool.clone(),
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
    crate::db::state_files::upsert(
        &pool,
        crate::db::state_files::UpsertSpec {
            instance_id: &src.id,
            owner_id: &owner,
            namespace: "chats",
            path: "c-legacy/activity.jsonl",
            mime: Some("application/jsonl"),
            bytes: 18,
            body_ciphertext: b"-----BEGIN AGE ENCRYPTED FILE-----\nnot a valid sealed body\n",
            updated_at: 1_777_720_001,
            synced_at: 1_777_720_001,
        },
    )
    .await
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
