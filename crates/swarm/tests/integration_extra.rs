#![allow(clippy::disallowed_methods)]

//! Integration tests for surfaces that the original `e2e_mock_cube`
//! walkthrough doesn't cover.  Each test stands up its own swarm using
//! the same in-process mocks, then exercises one focused behaviour:
//!
//! - **tenancy isolation** — alice creates an instance; bob can't see,
//!   destroy, secret-edit, or restore from it.  Cross-tenant routes
//!   return 404 (not 403) so the existence of foreign rows doesn't leak.
//! - **api key bearer auth** — admin mints a bearer for a user, the
//!   user authenticates with it through the chain authenticator,
//!   admin revokes, the next call 401s.
//! - **admin user lifecycle** — create → activate → suspend → reactivate.
//!   Suspend triggers the upstream OR delete and wipes the local
//!   plaintext + key id.
//! - **openrouter user-key minting via /llm/openrouter/** — first call
//!   lazy-mints a key upstream and seals it; the upstream sees the
//!   minted plaintext (not the global fallback); a second call from the
//!   same user reuses the sealed plaintext (no second mint).
//! - **per-instance secrets isolation** — alice's secret on her instance
//!   isn't visible to bob via the secret list endpoint.
//! - **proxy_base shape** — full-stack regression for the `/openrouter/v1`
//!   double-suffix bug.  Drives a turn-shaped LLM call through swarm's
//!   proxy and confirms the URL the upstream sees has exactly one `/v1`.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{any, delete, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::stream;
use serde_json::json;

use dyson_swarm::{
    auth::{AuthState, Authenticator, UserAuthState, chain::ChainAuthenticator},
    backup::local::LocalDiskBackupSink,
    config::{ProviderConfig, Providers},
    cube_client::HttpCubeClient,
    db,
    db::sqlite::{instances::SqlxInstanceStore, tokens::SqlxTokenStore},
    envelope::{AgeCipherDirectory, CipherDirectory},
    http,
    instance::{
        DysonReconfigurer, InstallSkillBody, InstallSkillResponse, InstanceService, ReconfigureBody,
    },
    openrouter::{MintedKey, OpenRouterError, Provisioning, UserOrKeyResolver},
    proxy::{self, ProxyService, policy_check::InstancePolicy},
    secrets::{SystemSecretsService, UserSecretsService},
    skill_marketplace::{SkillMarketplaceService, SkillMarketplaceSourceConfig, skill_body_sha256},
    snapshot::SnapshotService,
    traits::{
        AuditStore, BackupSink, CubeClient, HealthProber, InstanceRow, InstanceStore, PolicyStore,
        ProbeResult, SnapshotStore, SystemSecretStore, TokenStore, UserSecretStore, UserStore,
    },
    webhooks::WebhookDispatcher,
};

// ---------------------------------------------------------------------
// Mocks shared by every test
// ---------------------------------------------------------------------

/// Mock Cube — assigns sequential sandbox ids and records every call.
#[derive(Clone, Default)]
struct CubeState {
    next_id: Arc<AtomicU32>,
    created: Arc<Mutex<Vec<String>>>,
    destroyed: Arc<Mutex<Vec<String>>>,
}

async fn cube_create(
    State(s): State<CubeState>,
    Json(_): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let n = s.next_id.fetch_add(1, Ordering::SeqCst) + 1;
    let id = format!("sb-{n}");
    s.created.lock().unwrap().push(id.clone());
    Json(json!({ "sandboxID": id, "hostIP": "127.0.0.1" }))
}

async fn cube_destroy(State(s): State<CubeState>, Path(id): Path<String>) -> StatusCode {
    s.destroyed.lock().unwrap().push(id);
    StatusCode::NO_CONTENT
}

fn cube_router(state: CubeState) -> Router {
    Router::new()
        .route("/sandboxes", post(cube_create))
        .route("/sandboxes/:id", delete(cube_destroy))
        .with_state(state)
}

/// Mock LLM upstream — captures the auth header and last-seen path so
/// tests can assert what swarm forwarded.  Returns a tiny SSE stream so
/// the response bytes are realistic-shaped.
#[derive(Clone, Default)]
struct LlmState {
    last_auth: Arc<Mutex<Option<String>>>,
    last_path: Arc<Mutex<Option<String>>>,
    calls: Arc<AtomicU32>,
}

async fn llm_chat(
    State(s): State<LlmState>,
    headers: HeaderMap,
    Path(rest): Path<String>,
    _body: Bytes,
) -> Response<Body> {
    s.calls.fetch_add(1, Ordering::SeqCst);
    *s.last_auth.lock().unwrap() = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    *s.last_path.lock().unwrap() = Some(format!("/{rest}"));
    let chunk = Bytes::from_static(b"data: {\"ok\":true}\n\n");
    let body = stream::iter(std::iter::once(Ok::<Bytes, std::io::Error>(chunk)));
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body))
        .unwrap()
}

fn llm_router(state: LlmState) -> Router {
    Router::new()
        .route("/*rest", any(llm_chat))
        .with_state(state)
}

/// Always-healthy prober.
struct StubProber;

#[async_trait::async_trait]
impl HealthProber for StubProber {
    async fn probe(&self, _: &InstanceRow) -> ProbeResult {
        ProbeResult::Healthy
    }
}

#[derive(Clone, Default)]
struct RecordingReconfigurer {
    installs: Arc<Mutex<Vec<(String, String, InstallSkillBody)>>>,
}

#[async_trait::async_trait]
impl DysonReconfigurer for RecordingReconfigurer {
    async fn push(&self, _: &str, _: &str, _: &ReconfigureBody) -> Result<(), String> {
        Ok(())
    }

    async fn install_skill(
        &self,
        instance_id: &str,
        sandbox_id: &str,
        body: &InstallSkillBody,
    ) -> Result<InstallSkillResponse, String> {
        self.installs.lock().unwrap().push((
            instance_id.to_owned(),
            sandbox_id.to_owned(),
            body.clone(),
        ));
        Ok(InstallSkillResponse {
            installed: true,
            version: body.package.version.clone(),
            sha256: body.package.computed_sha256.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingWebhookDispatcher {
    calls: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl WebhookDispatcher for RecordingWebhookDispatcher {
    async fn dispatch(
        &self,
        _: &InstanceRow,
        _: &str,
        _: &str,
        _: &[(String, String)],
        _: &[u8],
    ) -> Result<u16, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(204)
    }
}

/// `(name, label, limit_usd)` recorded for every mint call.
type MintCall = (String, Option<String>, f64);

/// Recording OpenRouter Provisioning client.  Every mint returns a
/// per-call deterministic plaintext so the test can prove the proxy
/// substituted it on the way upstream.
#[derive(Clone, Default)]
struct RecordingProvisioning {
    minted: Arc<Mutex<Vec<MintCall>>>,
    deleted: Arc<Mutex<Vec<String>>>,
    next_seq: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl Provisioning for RecordingProvisioning {
    async fn mint(
        &self,
        name: &str,
        label: Option<&str>,
        limit_usd: f64,
    ) -> Result<MintedKey, OpenRouterError> {
        let n = self.next_seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.minted
            .lock()
            .unwrap()
            .push((name.into(), label.map(String::from), limit_usd));
        Ok(MintedKey {
            id: format!("or-id-{n}"),
            key: format!("sk-or-mock-{n}"),
            name: Some(name.into()),
            label: label.map(String::from),
            limit: Some(limit_usd),
        })
    }
    async fn update_limit(&self, _: &str, _: f64) -> Result<(), OpenRouterError> {
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<(), OpenRouterError> {
        self.deleted.lock().unwrap().push(id.into());
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Stack assembly
// ---------------------------------------------------------------------

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{addr}")
}

/// Build everything a swarm router needs.  Returns the URL the test
/// hits + handles to mocks the test will assert against.
struct Stack {
    base: String,
    pool: sqlx::SqlitePool,
    cube: CubeState,
    llm: LlmState,
    or_prov: Arc<RecordingProvisioning>,
    webhook_dispatches: Arc<AtomicU32>,
    users: Arc<dyn UserStore>,
    instances: Arc<dyn InstanceStore>,
    instance_svc: Arc<InstanceService>,
    skill_marketplace: Arc<SkillMarketplaceService>,
    state_files: Arc<dyson_swarm::state_files::StateFileService>,
    reconfigurer: Arc<RecordingReconfigurer>,
}

/// Build a swarm whose user-auth chain is the production wiring: a
/// bearer authenticator backed by `users.api_keys` plus a fixed-OIDC
/// fallback for `subject_for_no_bearer`.  Tests that want pure-bearer
/// auth can pass any garbage subject — they'll never hit the OIDC link.
async fn build_stack(subject_for_no_bearer: &str) -> Stack {
    let cube_state = CubeState::default();
    let cube_url = spawn(cube_router(cube_state.clone())).await;

    let llm_state = LlmState::default();
    let llm_url = spawn(llm_router(llm_state.clone())).await;

    let pool = db::sqlite::open_in_memory().await.unwrap();
    let cube_cfg = dyson_swarm::config::CubeConfig {
        url: cube_url,
        api_key: "k".into(),
        sandbox_domain: "cube.test".into(),
    };
    let cube: Arc<dyn CubeClient> = Arc::new(HttpCubeClient::new(&cube_cfg).unwrap());
    let keys_tmp = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let cipher_dir: Arc<dyn CipherDirectory> =
        Arc::new(AgeCipherDirectory::new(keys_tmp.path()).unwrap());
    let system_cipher = cipher_dir.system().unwrap();
    let instances_store: Arc<dyn InstanceStore> =
        Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
    let tokens_store: Arc<dyn TokenStore> =
        Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher));
    let user_secrets_store: Arc<dyn UserSecretStore> = Arc::new(
        dyson_swarm::db::sqlite::secrets::SqlxUserSecretStore::new(pool.clone()),
    );
    let system_secrets_store: Arc<dyn SystemSecretStore> =
        Arc::new(dyson_swarm::db::sqlite::secrets::SqlxSystemSecretStore::new(pool.clone()));
    let user_secrets_svc = Arc::new(UserSecretsService::new(
        user_secrets_store,
        cipher_dir.clone(),
    ));
    let system_secrets_svc = Arc::new(SystemSecretsService::new(
        system_secrets_store,
        cipher_dir.clone(),
    ));
    let reconfigurer = Arc::new(RecordingReconfigurer::default());
    let instance_svc = Arc::new(
        InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            tokens_store.clone(),
            "http://swarm.test/llm",
        )
        .with_reconfigurer(reconfigurer.clone()),
    );
    let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
    let snapshots_store: Arc<dyn SnapshotStore> =
        dyson_swarm::db::sqlite::snapshot_store(pool.clone());
    let policies_store: Arc<dyn PolicyStore> = dyson_swarm::db::sqlite::policy_store(pool.clone());
    let audit_store: Arc<dyn AuditStore> = dyson_swarm::db::sqlite::audit_store(pool.clone());
    let snapshot_svc = Arc::new(SnapshotService::new(
        cube.clone(),
        instances_store.clone(),
        snapshots_store,
        backup,
        instance_svc.clone(),
    ));

    // Permissive default policy so the proxy passes through every
    // request shape the tests throw at it.
    let default_policy = InstancePolicy {
        allowed_providers: vec!["*".into()],
        allowed_models: vec!["*".into()],
        daily_token_budget: None,
        monthly_usd_budget: None,
        rps_limit: None,
    };

    // OpenRouter is the provider the lazy-mint test exercises; openai
    // is included so generic-proxy tests have an upstream too.
    let mut providers = Providers::default();
    providers.insert(
        "openai",
        ProviderConfig {
            api_key: Some("sk-openai-global".into()),
            upstream: llm_url.clone(),
            anthropic_version: None,
        },
    );
    providers.insert(
        "openrouter",
        ProviderConfig {
            api_key: Some("sk-or-global-fallback".into()),
            upstream: llm_url.clone(),
            anthropic_version: None,
        },
    );

    let users_store: Arc<dyn UserStore> = Arc::new(
        dyson_swarm::db::sqlite::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
    );

    let or_prov = Arc::new(RecordingProvisioning::default());
    let user_or_keys = Arc::new(UserOrKeyResolver::new(
        users_store.clone(),
        user_secrets_svc.clone(),
        or_prov.clone() as Arc<dyn Provisioning>,
    ));

    let proxy_svc = Arc::new(
        ProxyService::new(
            tokens_store.clone(),
            instances_store.clone(),
            policies_store,
            audit_store,
            providers,
            default_policy,
        )
        .unwrap()
        .with_user_or_keys(user_or_keys.clone()),
    );
    let llm_router_inner = proxy::http::router(proxy_svc);

    let prober: Arc<dyn HealthProber> = Arc::new(StubProber);

    // User auth: bearer chain + fixed-fallback.  The bearer link does a
    // real DB resolve so the api-key tests exercise the production
    // path; the fallback covers cookie-less endpoints (admin pages
    // hitting the bearer check).
    let bearer_link: Arc<dyn Authenticator> = Arc::new(
        dyson_swarm::auth::bearer::BearerAuthenticator::new(users_store.clone()),
    );
    let (fixed_auth, _fixed_id) = dyson_swarm::auth::user::fixed_user_auth_with_roles(
        users_store.clone(),
        subject_for_no_bearer,
        Some(("https://test/roles", &["rol_admin"])),
    )
    .await;
    let chain: Arc<dyn Authenticator> = Arc::new(ChainAuthenticator::new(vec![
        bearer_link,
        fixed_auth.authenticator.clone(),
    ]));
    let user_auth = UserAuthState::new(chain, users_store.clone());

    let webhook_store: Arc<dyn dyson_swarm::traits::WebhookStore> = Arc::new(
        dyson_swarm::db::sqlite::webhooks::SqlxWebhookStore::new(pool.clone()),
    );
    let delivery_store: Arc<dyn dyson_swarm::traits::DeliveryStore> = Arc::new(
        dyson_swarm::db::sqlite::webhooks::SqlxDeliveryStore::new(pool.clone()),
    );
    let webhook_dispatcher = RecordingWebhookDispatcher::default();
    let webhook_dispatches = webhook_dispatcher.calls.clone();
    let webhooks_svc = Arc::new(dyson_swarm::webhooks::WebhookService::new(
        webhook_store,
        delivery_store,
        user_secrets_svc.clone(),
        instance_svc.clone(),
        Arc::new(webhook_dispatcher),
        cipher_dir.clone(),
    ));
    let artefact_cache = Arc::new(dyson_swarm::artefacts::ArtefactCacheService::new(
        dyson_swarm::db::sqlite::artefact_cache_store(pool.clone()),
        cipher_dir.clone(),
    ));
    let shares_svc = Arc::new(dyson_swarm::shares::ShareService::new(
        dyson_swarm::db::sqlite::share_store(pool.clone()),
        user_secrets_svc.clone(),
        instance_svc.clone(),
        artefact_cache.clone(),
        dyson_swarm::shares::ShareMetrics::new(),
        None,
    ));
    let state_files = Arc::new(dyson_swarm::state_files::StateFileService::new(
        dyson_swarm::db::sqlite::state_file_store(pool.clone()),
        cipher_dir.clone(),
    ));
    let skill_marketplace_store = Arc::new(
        dyson_swarm::db::sqlite::skill_marketplace::SqlxSkillMarketplaceSourceStore::new(
            pool.clone(),
        ),
    );
    let skill_marketplace = Arc::new(SkillMarketplaceService::new(skill_marketplace_store));
    let app_state = http::AppState {
        user_secrets: user_secrets_svc,
        system_secrets: system_secrets_svc,
        ciphers: cipher_dir.clone(),
        instances: instance_svc.clone(),
        snapshots: snapshot_svc.clone(),
        prober,
        tokens: tokens_store.clone(),
        users: users_store.clone(),
        sessions: dyson_swarm::db::sqlite::session_store(pool.clone()),
        admin_audit: dyson_swarm::db::sqlite::admin_audit_store(pool.clone()),
        llm_tool_calls: dyson_swarm::db::sqlite::llm_tool_call_store(pool.clone()),
        egress_sync: Arc::new(dyson_swarm::egress_policy_sync::NoopEgressPolicySync::new()),
        sandbox_domain: "cube.test".into(),
        hostname: None,
        auth_config: std::sync::Arc::new(http::auth_config::AuthConfig::none()),
        dyson_http: http::dyson_proxy::build_client().expect("dyson http client init"),
        models_upstream: None,
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: Some(or_prov.clone() as Arc<dyn Provisioning>),
        user_or_keys: Some(user_or_keys.clone()),
        providers: Arc::new(dyson_swarm::config::Providers::default()),
        byo: Arc::new(dyson_swarm::config::ByoConfig::default()),
        external_http: Arc::new(dyson_swarm_core::http::ExternalHttpClient::new(Arc::new(
            dyson_swarm_core::upstream_policy::OutboundUrlPolicy::default(),
        ))),
        webhooks: webhooks_svc,
        shares: shares_svc,
        artefact_cache,
        state_files: state_files.clone(),
        skill_marketplace: skill_marketplace.clone(),
        agent_skill_publications: dyson_swarm::db::sqlite::agent_skill_publication_store(
            pool.clone(),
        ),
        mcp_runtime_socket: None,
    };
    let app = http::router(
        app_state,
        AuthState::enforced(dyson_swarm::config::OidcRoles {
            claim: "https://test/roles".into(),
            admin: "rol_admin".into(),
        }),
        user_auth,
        llm_router_inner,
        axum::Router::new(),
        axum::Router::new(),
    );
    let base = spawn(app).await;

    Stack {
        base,
        pool,
        cube: cube_state,
        llm: llm_state,
        or_prov,
        webhook_dispatches,
        users: users_store,
        instances: instances_store,
        instance_svc,
        skill_marketplace,
        state_files,
        reconfigurer,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[derive(Clone, Default)]
struct SharedLog(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLog {
    type Writer = SharedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Write for SharedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn startup_warns_when_live_open_rows_exist_and_flag_disabled() {
    let stack = build_stack("alice").await;
    stack
        .instances
        .create(InstanceRow {
            id: "open-live".into(),
            owner_id: "legacy".into(),
            name: "legacy open".into(),
            task: "still running".into(),
            cube_sandbox_id: Some("sb-open".into()),
            state_generation: "gen-open".into(),
            template_id: "tpl".into(),
            status: dyson_swarm::traits::InstanceStatus::Live,
            bearer_token: "bearer".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: dyson_swarm::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        })
        .await
        .unwrap();
    let logs = SharedLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .finish();

    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    stack
        .instance_svc
        .warn_live_internal_network_policies_if_disabled()
        .await
        .unwrap();

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains(
            "instance open-live still on Open policy after gating; will not be re-selectable on edit."
        ),
        "startup warning missing from logs: {text}"
    );
}

#[tokio::test]
async fn post_verify_only_returns_structured_verify_error() {
    let stack = build_stack("alice-webhook-verify").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-verify-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/standard/verify-only",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .json(&json!({
            "headers": {
                "webhook-id": "msg_123",
                "webhook-timestamp": "1700000000",
                "webhook-signature": "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            },
            "body_b64": B64.encode(include_bytes!("../../core/tests/fixtures/webhooks/standard/request.txt")),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["type"], "all_signatures_mismatched");
}

#[tokio::test]
async fn webhook_with_preset_id_rejects_mismatched_verifier_config_on_save() {
    let stack = build_stack("alice-webhook-preset-mismatch").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-preset-mismatch-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .json(&json!({
            "name": "half-stripe",
            "description": "bad preset",
            "preset_id": "stripe",
            "auth_scheme": "hmac_sha256",
            "verifier_mode": "hmac_v2",
            "signature_header": "x-hub-signature-256",
            "signature_algo": "sha256",
            "signature_encoding": "hex",
            "signature_prefix": "sha256=",
            "signature_separator": "",
            "signature_value_split": "=",
            "timestamp_header": "",
            "timestamp_skew_secs": 300,
            "payload_template": "{{body}}",
            "idempotency_header": "x-github-delivery",
            "secret": "top-secret",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("preset_id") && body.contains("stripe") && body.contains("verifier config"),
        "bad preset response should name the mismatch, got: {body}"
    );
}

#[tokio::test]
async fn webhook_preset_id_null_when_custom() {
    let stack = build_stack("alice-webhook-custom-preset").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-custom-preset-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .json(&json!({
            "name": "custom-standard",
            "description": "custom even if matching standard",
            "auth_scheme": "hmac_sha256",
            "verifier_mode": "hmac_v2",
            "signature_header": "webhook-signature",
            "signature_algo": "sha256",
            "signature_encoding": "base64",
            "signature_prefix": "v1,",
            "signature_separator": " ",
            "signature_value_split": ",",
            "timestamp_header": "webhook-timestamp",
            "timestamp_skew_secs": 300,
            "payload_template": "{{id}}.{{timestamp}}.{{body}}",
            "idempotency_header": "webhook-id",
            "secret": "top-secret",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body["preset_id"].is_null());
}

#[tokio::test]
async fn get_webhook_presets_returns_stable_vendor_ids() {
    let stack = build_stack("alice-webhook-presets").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-presets-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;

    let r = client
        .get(format!("{}/v1/webhook-presets", stack.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "standard-webhooks",
            "github",
            "stripe",
            "slack",
            "shopify",
            "agentmail",
        ]
    );
}

#[tokio::test]
async fn verify_only_from_last_failed_returns_404_when_no_failed_deliveries_exist() {
    let stack = build_stack("alice-webhook-last-failed-empty").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-last-failed-empty-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/standard/verify-only?from=last-failed",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn verify_only_from_last_failed_replays_most_recent_failed_delivery() {
    let stack = build_stack("alice-webhook-last-failed").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-last-failed-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!("{}/webhooks/{}/standard", stack.base, instance_id))
        .header("webhook-id", "msg_bad")
        .header("webhook-timestamp", "1700000000")
        .header(
            "webhook-signature",
            "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .body(
            include_bytes!("../../core/tests/fixtures/webhooks/standard/request.txt")
                .as_slice()
                .to_vec(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let replay = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/standard/verify-only?from=last-failed",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 200);
    let body: serde_json::Value = replay.json().await.unwrap();
    assert_eq!(body["type"], "all_signatures_mismatched");
}

#[tokio::test]
async fn post_verify_only_does_not_write_delivery_row() {
    let stack = build_stack("alice-webhook-verify-row").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-verify-row-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/standard/verify-only",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .json(&json!({
            "headers": {
                "webhook-id": "msg_123",
                "webhook-timestamp": "1700000000",
                "webhook-signature": "v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs="
            },
            "body_b64": B64.encode(include_bytes!("../../core/tests/fixtures/webhooks/standard/request.txt")),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let rows: serde_json::Value = client
        .get(format!(
            "{}/v1/instances/{}/webhooks/standard/deliveries",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn post_verify_only_does_not_dispatch() {
    let stack = build_stack("alice-webhook-verify-dispatch").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-verify-dispatch-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/standard/verify-only",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .json(&json!({
            "headers": {
                "webhook-id": "msg_123",
                "webhook-timestamp": "1700000000",
                "webhook-signature": "v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs="
            },
            "body_b64": B64.encode(include_bytes!("../../core/tests/fixtures/webhooks/standard/request.txt")),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(stack.webhook_dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_hmac_v2_delivery_persists_structured_verify_error() {
    let stack = build_stack("alice-webhook-verify-error-row").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-verify-error-row-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_standard_webhook(&client, &stack.base, &token, &instance_id, "standard").await;

    let r = client
        .post(format!("{}/webhooks/{}/standard", stack.base, instance_id))
        .header("webhook-id", "msg_bad")
        .header("webhook-timestamp", "1700000000")
        .header(
            "webhook-signature",
            "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .body(
            include_bytes!("../../core/tests/fixtures/webhooks/standard/request.txt")
                .as_slice()
                .to_vec(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let rows: serde_json::Value = client
        .get(format!(
            "{}/v1/instances/{}/webhooks/standard/deliveries",
            stack.base, instance_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rows[0]["verify_error"], "AllSignaturesMismatched");
}

#[tokio::test]
async fn post_replay_redispatches_without_reverifying() {
    let stack = build_stack("alice-webhook-replay").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-replay-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_legacy_hmac_webhook(&client, &stack.base, &token, &instance_id, "github").await;

    let bad = client
        .post(format!("{}/webhooks/{}/github", stack.base, instance_id))
        .header(
            "x-hub-signature-256",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(
            include_bytes!("../../core/tests/fixtures/webhooks/github/request.txt")
                .as_slice()
                .to_vec(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
    assert_eq!(stack.webhook_dispatches.load(Ordering::SeqCst), 0);
    let delivery_id =
        latest_delivery_id(&client, &stack.base, &token, &instance_id, "github").await;

    let replay = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/github/replay/{}",
            stack.base, instance_id, delivery_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 200);
    assert_eq!(stack.webhook_dispatches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn replay_is_audited_with_user_id() {
    let stack = build_stack("alice-webhook-replay-audit").await;
    let client = reqwest::Client::new();
    let user_id = create_user(
        &client,
        &stack.base,
        "alice-webhook-replay-audit-user",
        true,
    )
    .await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_legacy_hmac_webhook(&client, &stack.base, &token, &instance_id, "github").await;
    let bad = client
        .post(format!("{}/webhooks/{}/github", stack.base, instance_id))
        .header(
            "x-hub-signature-256",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(
            include_bytes!("../../core/tests/fixtures/webhooks/github/request.txt")
                .as_slice()
                .to_vec(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
    let delivery_id =
        latest_delivery_id(&client, &stack.base, &token, &instance_id, "github").await;

    let replay = client
        .post(format!(
            "{}/v1/instances/{}/webhooks/github/replay/{}",
            stack.base, instance_id, delivery_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 200);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM admin_audit WHERE action = 'webhook.replay' AND target_user = ?",
    )
    .bind(&user_id)
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn bearer_v2_path_token_required_on_ingest_url() {
    let stack = build_stack("alice-webhook-bearer-v2").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-bearer-v2-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    let row =
        create_bearer_v2_webhook(&client, &stack.base, &token, &instance_id, "agentmail").await;
    let path = row["path"].as_str().unwrap();
    let path_token = path.rsplit('/').next().unwrap();

    let without = client
        .post(format!("{}/webhooks/{}/agentmail", stack.base, instance_id))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(without.status(), 401);

    let with = client
        .post(format!(
            "{}/webhooks/{}/agentmail/{}",
            stack.base, instance_id, path_token
        ))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(with.status(), 204);
}

#[tokio::test]
async fn legacy_hmac_endpoint_still_accepts_github_fixture() {
    let stack = build_stack("alice-webhook-legacy").await;
    let client = reqwest::Client::new();
    let user_id = create_user(&client, &stack.base, "alice-webhook-legacy-user", true).await;
    let token = mint_api_key(&client, &stack.base, &user_id).await;
    let instance_id = create_live_instance(&client, &stack.base, &token).await;
    create_legacy_hmac_webhook(&client, &stack.base, &token, &instance_id, "github").await;

    let r = client
        .post(format!("{}/webhooks/{}/github", stack.base, instance_id))
        .header(
            "x-hub-signature-256",
            "sha256=1ae84c7f758faa88395f24d75a762947277389c2071f1c3c478492f6a2112d0d",
        )
        .body(
            include_bytes!("../../core/tests/fixtures/webhooks/github/request.txt")
                .as_slice()
                .to_vec(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(stack.webhook_dispatches.load(Ordering::SeqCst), 1);
}

/// Tenancy isolation — alice's instance is invisible to bob via every
/// owner-scoped surface (get, secrets, destroy).  All foreign-id reads
/// return 404; the routes intentionally do not distinguish "no such id"
/// from "exists but not yours" so a probe can't enumerate.
#[tokio::test]
async fn tenancy_isolation_blocks_cross_user_access() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();

    // Provision two users via the admin API.  `activate=true` so they
    // skip the inactive landing state.
    let alice_id = create_user(&admin, &stack.base, "alice", true).await;
    let bob_id = create_user(&admin, &stack.base, "bob", true).await;

    // Mint api keys for each.
    let alice_token = mint_api_key(&admin, &stack.base, &alice_id).await;
    let bob_token = mint_api_key(&admin, &stack.base, &bob_id).await;

    // Alice creates an instance.
    let inst = admin
        .post(format!("{}/v1/instances", stack.base))
        .bearer_auth(&alice_token)
        .json(&json!({"template_id": "tpl", "env": {"SWARM_MODEL": "m"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(inst.status(), 201);
    let inst: serde_json::Value = inst.json().await.unwrap();
    let inst_id = inst["id"].as_str().unwrap().to_string();

    // Bob's list omits alice's instance.
    let r = admin
        .get(format!("{}/v1/instances", stack.base))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let bob_list: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        bob_list.is_empty(),
        "bob should see no instances; got {bob_list:?}"
    );

    // Bob trying to GET alice's instance gets 404 — same observable
    // outcome as a non-existent id.  No oracle.
    let r = admin
        .get(format!("{}/v1/instances/{inst_id}", stack.base))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Bob trying to destroy alice's instance: 404; cube was never
    // called for a destroy.
    let r = admin
        .delete(format!("{}/v1/instances/{inst_id}", stack.base))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert!(stack.cube.destroyed.lock().unwrap().is_empty());

    // Alice can still see her instance.
    let r = admin
        .get(format!("{}/v1/instances/{inst_id}", stack.base))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// Bearer api keys: mint via admin route, use it to access tenant
/// routes, revoke it, next call 401s.  Exercises the production
/// `BearerAuthenticator` end to end (sealed envelope, prefix lookup,
/// constant-time compare).
#[tokio::test]
async fn api_key_bearer_auth_round_trip() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();

    let alice_id = create_user(&admin, &stack.base, "alice", true).await;
    let token = mint_api_key(&admin, &stack.base, &alice_id).await;
    assert!(token.starts_with("dy_"), "token must carry the dy_ prefix");
    assert_eq!(token.len(), 35, "dy_<32 hex> = 35 chars");

    // Tenant route: 200 with the freshly-minted bearer.
    let r = reqwest::Client::new()
        .get(format!("{}/v1/instances", stack.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Revoke.
    let r = reqwest::Client::new()
        .delete(format!("{}/v1/admin/users/keys/{token}", stack.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // Same call now 401s — the bearer authenticator's resolve returns
    // None for a revoked row, the chain falls through, and the
    // tenant middleware refuses.
    let r = reqwest::Client::new()
        .get(format!("{}/v1/instances", stack.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

/// User lifecycle: create inactive, activate, suspend (which delete-s
/// upstream OR key + clears local plaintext), reactivate.  Each suspend
/// must show up on the recording provisioning client.
#[tokio::test]
async fn admin_user_suspend_revokes_openrouter_key_upstream() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();

    let alice_id = create_user(&admin, &stack.base, "alice", true).await;
    let token = mint_api_key(&admin, &stack.base, &alice_id).await;

    // Force-mint to populate openrouter_key_id + sealed plaintext so
    // suspend has something upstream to revoke.
    let r = admin
        .post(format!(
            "{}/v1/admin/users/{alice_id}/openrouter_key/mint",
            stack.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let mint: serde_json::Value = r.json().await.unwrap();
    let or_key_id = mint["or_key_id"].as_str().unwrap().to_string();
    assert_eq!(stack.or_prov.minted.lock().unwrap().len(), 1);

    // Suspend → upstream delete fires + local view cleared.
    let r = admin
        .post(format!("{}/v1/admin/users/{alice_id}/suspend", stack.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let deleted = stack.or_prov.deleted.lock().unwrap().clone();
    assert_eq!(deleted, vec![or_key_id]);
    let user = stack.users.get(&alice_id).await.unwrap().unwrap();
    assert!(user.openrouter_key_id.is_none(), "key id wiped on suspend");

    // Bearer for a suspended user is 403 (account suspended) on tenant
    // routes — not 401.  Distinct so the SPA can show "your account
    // was suspended" rather than "you logged out".
    let r = reqwest::Client::new()
        .get(format!("{}/v1/instances", stack.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Reactivate → tenant route works again.
    let r = admin
        .post(format!("{}/v1/admin/users/{alice_id}/activate", stack.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = reqwest::Client::new()
        .get(format!("{}/v1/instances", stack.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// `/llm/openrouter/...` lazy-mints on first call and reuses on the
/// second.  The upstream sees the *minted* bearer, never the global
/// fallback — proves the resolver substituted in place of the
/// `[providers.openrouter].api_key`.
#[tokio::test]
async fn openrouter_proxy_lazy_mints_then_reuses() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();

    let alice_id = create_user(&admin, &stack.base, "alice", true).await;
    let alice_bearer = mint_api_key(&admin, &stack.base, &alice_id).await;

    // Alice creates an instance so the proxy_token path has a row.
    let r = admin
        .post(format!("{}/v1/instances", stack.base))
        .bearer_auth(&alice_bearer)
        .json(&json!({"template_id": "tpl", "env": {"SWARM_MODEL": "m"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let proxy_token = r.json::<serde_json::Value>().await.unwrap()["proxy_token"]
        .as_str()
        .unwrap()
        .to_string();

    // First /llm/openrouter call.
    let r = reqwest::Client::new()
        .post(format!("{}/llm/openrouter/v1/chat/completions", stack.base))
        .bearer_auth(&proxy_token)
        .json(&json!({"model": "deepseek/deepseek-v3", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Upstream saw the minted plaintext, NOT the global fallback.
    let auth_seen = stack
        .llm
        .last_auth
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_default();
    assert_eq!(
        auth_seen, "Bearer sk-or-mock-1",
        "first call must substitute the lazy-minted user key (not the global fallback)"
    );
    assert_eq!(stack.or_prov.minted.lock().unwrap().len(), 1);

    // Second call: no fresh mint, same bearer.
    let r = reqwest::Client::new()
        .post(format!("{}/llm/openrouter/v1/chat/completions", stack.base))
        .bearer_auth(&proxy_token)
        .json(&json!({"model": "deepseek/deepseek-v3", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let auth_seen = stack
        .llm
        .last_auth
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_default();
    assert_eq!(
        auth_seen, "Bearer sk-or-mock-1",
        "second call must reuse the sealed plaintext (no second mint)"
    );
    assert_eq!(
        stack.or_prov.minted.lock().unwrap().len(),
        1,
        "exactly one upstream mint for a stable user"
    );
}

/// Full-stack regression for the chat-hang `/openrouter/v1/v1/...` bug.
/// `/llm/<provider>/<rest>` must forward to `<upstream>/<rest>` with
/// exactly one `/v1` segment — anything else routes to OR's marketing
/// site and surfaces in dyson as "upstream HTTP error".
#[tokio::test]
async fn llm_proxy_forwards_path_with_single_v1() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();
    let alice_id = create_user(&admin, &stack.base, "alice", true).await;
    let alice_bearer = mint_api_key(&admin, &stack.base, &alice_id).await;
    let r = admin
        .post(format!("{}/v1/instances", stack.base))
        .bearer_auth(&alice_bearer)
        .json(&json!({"template_id": "tpl", "env": {"SWARM_MODEL": "m"}}))
        .send()
        .await
        .unwrap();
    let proxy_token = r.json::<serde_json::Value>().await.unwrap()["proxy_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Dyson (post-fix) hits `<swarm>/llm/openrouter/v1/chat/completions`
    // — single `/v1`.  Swarm must forward to `<upstream>/v1/chat/completions`.
    let r = reqwest::Client::new()
        .post(format!("{}/llm/openrouter/v1/chat/completions", stack.base))
        .bearer_auth(&proxy_token)
        .json(&json!({"model": "x", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let path = stack
        .llm
        .last_path
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_default();
    assert_eq!(
        path, "/v1/chat/completions",
        "swarm must strip the /llm/<provider> prefix, leaving the upstream path with exactly one /v1"
    );
}

#[tokio::test]
async fn skill_install_endpoint_validates_ownership_status_and_collisions() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();
    add_test_marketplace(&stack, "team-skills", "code-review", "1.0.0").await;

    let alice_id = create_user(&admin, &stack.base, "alice-skill", true).await;
    let bob_id = create_user(&admin, &stack.base, "bob-skill", true).await;
    let alice_token = mint_api_key(&admin, &stack.base, &alice_id).await;
    let bob_token = mint_api_key(&admin, &stack.base, &bob_id).await;
    let instance_id = create_live_instance(&admin, &stack.base, &alice_token).await;

    let install_body = json!({
        "marketplace": "team-skills",
        "skill": "code-review",
        "force": false,
    });
    let r = admin
        .post(format!(
            "{}/v1/instances/{instance_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .json(&install_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let installed: serde_json::Value = r.json().await.unwrap();
    assert_eq!(installed["installed"], true);
    assert_eq!(installed["version"], "1.0.0");
    assert!(installed["sha256"].as_str().unwrap().len() == 64);
    assert_eq!(stack.reconfigurer.installs.lock().unwrap().len(), 1);

    let skills = admin
        .get(format!("{}/v1/instances/{instance_id}/skills", stack.base))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(skills.status(), 200);
    let skills: Vec<serde_json::Value> = skills.json().await.unwrap();
    assert!(skills.iter().any(|row| row["skill"] == "code-review"));

    let r = admin
        .post(format!(
            "{}/v1/instances/{instance_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .json(&install_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let conflict: serde_json::Value = r.json().await.unwrap();
    assert_eq!(conflict["error"], "already_installed");
    assert_eq!(conflict["current_version"], "1.0.0");

    let r = admin
        .post(format!(
            "{}/v1/instances/{instance_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .json(&json!({
            "marketplace": "team-skills",
            "skill": "code-review",
            "force": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(stack.reconfigurer.installs.lock().unwrap().len(), 2);

    let r = admin
        .post(format!(
            "{}/v1/instances/{instance_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .json(&json!({
            "marketplace": "team-skills",
            "skill": "missing-skill",
            "force": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let missing: serde_json::Value = r.json().await.unwrap();
    assert_eq!(missing["error"], "skill_not_found");

    let r = admin
        .post(format!(
            "{}/v1/instances/{instance_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&bob_token)
        .json(&install_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let destroyed_id = create_live_instance(&admin, &stack.base, &alice_token).await;
    let r = admin
        .delete(format!("{}/v1/instances/{destroyed_id}", stack.base))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = admin
        .post(format!(
            "{}/v1/instances/{destroyed_id}/skills/install",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .json(&install_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    let not_live: serde_json::Value = r.json().await.unwrap();
    assert_eq!(not_live["error"], "instance_not_live");
}

#[tokio::test]
async fn agent_skills_enter_marketplace_only_after_explicit_publication() {
    let stack = build_stack("system-admin").await;
    let admin = reqwest::Client::new();

    let alice_id = create_user(&admin, &stack.base, "alice-pub", true).await;
    let bob_id = create_user(&admin, &stack.base, "bob-pub", true).await;
    let alice_token = mint_api_key(&admin, &stack.base, &alice_id).await;
    let bob_token = mint_api_key(&admin, &stack.base, &bob_id).await;
    let instance_id = create_live_instance(&admin, &stack.base, &alice_token).await;
    ingest_agent_skill(&stack, &instance_id, &alice_id, "debug-logs").await;
    let marketplace = format!("agent-{instance_id}");

    let catalog = marketplace_catalog(&admin, &stack.base, &bob_token).await;
    assert!(
        !catalog_has_skill(&catalog, &marketplace, "debug-logs"),
        "unpublished agent skills must not be projected into marketplace"
    );

    let denied = admin
        .put(format!(
            "{}/v1/instances/{instance_id}/skills/debug-logs/publication",
            stack.base
        ))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);

    let published = admin
        .put(format!(
            "{}/v1/instances/{instance_id}/skills/debug-logs/publication",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 200);
    let published: serde_json::Value = published.json().await.unwrap();
    assert_eq!(published["public"], true);
    assert_eq!(published["marketplace_id"], marketplace);

    let skills = admin
        .get(format!("{}/v1/instances/{instance_id}/skills", stack.base))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(skills.status(), 200);
    let skills: Vec<serde_json::Value> = skills.json().await.unwrap();
    assert!(skills.iter().any(|row| {
        row["skill"] == "debug-logs"
            && row["public"] == true
            && row["public_marketplace_id"] == marketplace
    }));

    let catalog = marketplace_catalog(&admin, &stack.base, &bob_token).await;
    assert!(catalog_has_skill(&catalog, &marketplace, "debug-logs"));
    let content = admin
        .get(format!(
            "{}/v1/skill-marketplaces/{marketplace}/skills/debug-logs/content",
            stack.base
        ))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(content.status(), 200);

    let unpublished = admin
        .delete(format!(
            "{}/v1/instances/{instance_id}/skills/debug-logs/publication",
            stack.base
        ))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(unpublished.status(), 200);
    let catalog = marketplace_catalog(&admin, &stack.base, &bob_token).await;
    assert!(!catalog_has_skill(&catalog, &marketplace, "debug-logs"));

    let admin_published = admin
        .put(format!(
            "{}/v1/admin/instances/{instance_id}/skills/debug-logs/publication",
            stack.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(admin_published.status(), 200);
    let catalog = marketplace_catalog(&admin, &stack.base, &bob_token).await;
    assert!(catalog_has_skill(&catalog, &marketplace, "debug-logs"));
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

async fn add_test_marketplace(stack: &Stack, id: &str, skill: &str, version: &str) {
    let skill_md =
        "---\ndescription: Review code changes.\n---\n# Code Review\n\nUse this skill to review patches.\n"
            .to_string();
    let sha256 = skill_body_sha256(&skill_md);
    let index = json!({
        "schema_version": 1,
        "marketplace": {
            "id": id,
            "name": "Team Skills"
        },
        "skills": [{
            "name": skill,
            "version": version,
            "description": "Review code changes.",
            "tags": ["review", "code"],
            "license": "MIT",
            "sha256": sha256,
            "content": {
                "type": "inline",
                "skill_md": skill_md
            }
        }]
    });
    stack
        .skill_marketplace
        .upsert_source(
            SkillMarketplaceSourceConfig::Inline {
                id: id.to_owned(),
                index_json: serde_json::to_string_pretty(&index).unwrap(),
            },
            true,
        )
        .await
        .unwrap();
}

async fn ingest_agent_skill(stack: &Stack, instance_id: &str, owner_id: &str, skill: &str) {
    let path = format!("skills/{skill}/SKILL.md");
    let body = format!(
        "---\ndescription: Read logs before guessing.\n---\n# Debug Logs\n\nUse this skill to inspect runtime logs for {instance_id}.\n"
    );
    stack
        .state_files
        .ingest(
            dyson_swarm::state_files::StateFileMeta {
                instance_id,
                owner_id,
                namespace: "workspace",
                path: &path,
                mime: Some("text/markdown"),
                updated_at: 1_800_000_000,
            },
            body.as_bytes(),
        )
        .await
        .unwrap();
}

async fn marketplace_catalog(
    client: &reqwest::Client,
    base: &str,
    token: &str,
) -> serde_json::Value {
    let r = client
        .get(format!("{base}/v1/skill-marketplaces/skills"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

fn catalog_has_skill(catalog: &serde_json::Value, marketplace: &str, skill: &str) -> bool {
    catalog["skills"].as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row["marketplace_id"] == marketplace && row["name"] == skill)
    })
}

async fn create_live_instance(client: &reqwest::Client, base: &str, token: &str) -> String {
    let r = client
        .post(format!("{base}/v1/instances"))
        .bearer_auth(token)
        .json(&json!({"template_id": "tpl", "env": {"SWARM_MODEL": "m"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "create_live_instance failed");
    let v: serde_json::Value = r.json().await.unwrap();
    v["id"].as_str().unwrap().to_string()
}

async fn create_legacy_hmac_webhook(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    instance_id: &str,
    name: &str,
) -> serde_json::Value {
    let r = client
        .post(format!("{base}/v1/instances/{instance_id}/webhooks"))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "description": "test legacy webhook",
            "auth_scheme": "hmac_sha256",
            "signature_header": "x-hub-signature-256",
            "secret": "top-secret",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "create_legacy_hmac_webhook failed");
    r.json().await.unwrap()
}

async fn create_standard_webhook(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    instance_id: &str,
    name: &str,
) -> serde_json::Value {
    let r = client
        .post(format!("{base}/v1/instances/{instance_id}/webhooks"))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "description": "test standard webhook",
            "auth_scheme": "hmac_sha256",
            "verifier_mode": "hmac_v2",
            "signature_header": "webhook-signature",
            "signature_algo": "sha256",
            "signature_encoding": "base64",
            "signature_prefix": "v1,",
            "signature_separator": " ",
            "signature_value_split": ",",
            "timestamp_header": "webhook-timestamp",
            "timestamp_skew_secs": 999999999,
            "payload_template": "{{id}}.{{timestamp}}.{{body}}",
            "idempotency_header": "webhook-id",
            "secret": "top-secret",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "create_standard_webhook failed");
    r.json().await.unwrap()
}

async fn create_bearer_v2_webhook(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    instance_id: &str,
    name: &str,
) -> serde_json::Value {
    let r = client
        .post(format!("{base}/v1/instances/{instance_id}/webhooks"))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "description": "test bearer v2 webhook",
            "auth_scheme": "bearer",
            "verifier_mode": "bearer_v2",
            "secret": "legacy-unused",
            "enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "create_bearer_v2_webhook failed");
    r.json().await.unwrap()
}

async fn latest_delivery_id(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    instance_id: &str,
    name: &str,
) -> String {
    let rows: serde_json::Value = client
        .get(format!(
            "{base}/v1/instances/{instance_id}/webhooks/{name}/deliveries"
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    rows.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn create_user(
    client: &reqwest::Client,
    base: &str,
    subject: &str,
    activate: bool,
) -> String {
    let r = client
        .post(format!("{base}/v1/admin/users"))
        .json(&json!({"subject": subject, "activate": activate}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "create_user({subject}) failed");
    let v: serde_json::Value = r.json().await.unwrap();
    v["id"].as_str().unwrap().to_string()
}

async fn mint_api_key(client: &reqwest::Client, base: &str, user_id: &str) -> String {
    let r = client
        .post(format!("{base}/v1/admin/users/{user_id}/keys"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "mint_api_key({user_id}) failed");
    let v: serde_json::Value = r.json().await.unwrap();
    v["token"].as_str().unwrap().to_string()
}
