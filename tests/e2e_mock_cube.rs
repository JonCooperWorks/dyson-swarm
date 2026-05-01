//! End-to-end walkthrough of the whole orchestration flow against in-process
//! mocks for Cube and an LLM upstream.
//!
//! Walk:
//! 1. Create an instance.
//! 2. Take a manual snapshot.
//! 3. Take a backup (local sink, since MinIO isn't required here).
//! 4. Destroy the instance.
//! 5. Restore a fresh instance from the snapshot.
//! 6. Make a streaming LLM call through the proxy and assert the bytes are
//!    delivered intact.
//! 7. Send a request with a disallowed model — expect 403 with the closed
//!    enum code.
//! 8. Revoke the proxy token via the admin endpoint and confirm the next
//!    call returns 401.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{any, delete, post};
use axum::{Json, Router};
use futures::stream;
use serde_json::json;

use dyson_swarm::{
    auth::AuthState,
    backup::local::LocalDiskBackupSink,
    config::{ProviderConfig, Providers},
    cube_client::HttpCubeClient,
    db,
    db::{instances::SqlxInstanceStore, secrets::SqlxSecretStore, tokens::SqlxTokenStore},
    envelope::{AgeCipherDirectory, CipherDirectory},
    http,
    instance::InstanceService,
    proxy::{self, policy_check::InstancePolicy, ProxyService},
    secrets::{SecretsService, SystemSecretsService, UserSecretsService},
    snapshot::SnapshotService,
    traits::{
        AuditStore, BackupSink, CubeClient, HealthProber, InstanceRow, InstanceStore, PolicyStore,
        ProbeResult, SecretStore, SnapshotStore, SystemSecretStore, TokenStore, UserSecretStore,
    },
};

/// Mock Cube. Tracks created sandboxes by id and lets the test assert calls.
#[derive(Clone, Default)]
struct CubeState {
    next_id: Arc<AtomicU32>,
    created: Arc<std::sync::Mutex<Vec<String>>>,
    destroyed: Arc<std::sync::Mutex<Vec<String>>>,
    snapshots: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn cube_create(
    State(s): State<CubeState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let n = s.next_id.fetch_add(1, Ordering::SeqCst) + 1;
    let id = format!("sb-{n}");
    s.created.lock().unwrap().push(id.clone());
    // Echo a few fields for assertions.
    let _ = body;
    Json(json!({ "sandboxID": id, "hostIP": "10.0.0.1" }))
}

async fn cube_destroy(State(s): State<CubeState>, Path(id): Path<String>) -> StatusCode {
    s.destroyed.lock().unwrap().push(id);
    StatusCode::NO_CONTENT
}

async fn cube_snapshot(
    State(s): State<CubeState>,
    Path(sandbox): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("snap").to_string();
    let id = format!("snap-{sandbox}-{name}");
    s.snapshots.lock().unwrap().push(id.clone());
    let dir = std::env::temp_dir().join(format!("swarm-e2e-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("metadata.json"), b"{\"v\":1}").unwrap();
    Json(json!({
        "snapshotID": id,
        "path": dir.display().to_string(),
        "hostIP": "10.0.0.1",
    }))
}

async fn cube_delete_snap(State(_): State<CubeState>, Path(_): Path<String>) -> StatusCode {
    StatusCode::NO_CONTENT
}

fn cube_router(state: CubeState) -> Router {
    Router::new()
        .route("/sandboxes", post(cube_create))
        .route("/sandboxes/:id", delete(cube_destroy))
        .route("/sandboxes/:id/snapshots", post(cube_snapshot))
        .route("/sandboxes/snapshots/:id", delete(cube_delete_snap))
        .with_state(state)
}

/// Mock LLM upstream. Records the inbound auth header so the test can prove
/// the adapter swap happened, and emits a streamed SSE response.
#[derive(Clone, Default)]
struct LlmState {
    last_auth: Arc<std::sync::Mutex<Option<String>>>,
    calls: Arc<AtomicU32>,
}

async fn llm_chat(
    State(s): State<LlmState>,
    headers: HeaderMap,
    _path: Path<String>,
    _body: Bytes,
) -> Response<Body> {
    s.calls.fetch_add(1, Ordering::SeqCst);
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    *s.last_auth.lock().unwrap() = auth;
    let chunks: Vec<Bytes> = vec![
        Bytes::from_static(b"data: {\"chunk\":1}\n\n"),
        Bytes::from_static(b"data: {\"chunk\":2}\n\n"),
        Bytes::from_static(b"data: [DONE]\n\n"),
    ];
    let body_stream = stream::iter(chunks.into_iter().map(Ok::<Bytes, std::io::Error>));
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body_stream))
        .unwrap()
}

fn llm_router(state: LlmState) -> Router {
    Router::new()
        .route("/*rest", any(llm_chat))
        .with_state(state)
}

struct StubProber;

#[async_trait::async_trait]
impl HealthProber for StubProber {
    async fn probe(&self, _: &InstanceRow) -> ProbeResult {
        ProbeResult::Healthy
    }
}

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn full_walkthrough() {
    // 1. Mocks first so swarm can be configured against them.
    let cube_state = CubeState::default();
    let cube_url = spawn(cube_router(cube_state.clone())).await;

    let llm_state = LlmState::default();
    let llm_url = spawn(llm_router(llm_state.clone())).await;

    // 2. Swarm assembly. In-memory DB, real HttpCubeClient pointing at the
    // mock Cube, local backup sink (sufficient for the e2e — no S3 leg).
    let pool = db::open_in_memory().await.unwrap();
    let cube_cfg = dyson_swarm::config::CubeConfig {
        url: cube_url.clone(),
        api_key: "k".into(),
        sandbox_domain: "cube.test".into(),
    };
    let cube: Arc<dyn CubeClient> = Arc::new(HttpCubeClient::new(&cube_cfg).unwrap());
    let instances_store: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
    let secrets_store: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
    let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
    let keys_tmp = tempfile::tempdir().unwrap();
    let cipher_dir: Arc<dyn CipherDirectory> =
        Arc::new(AgeCipherDirectory::new(keys_tmp.path()).unwrap());
    let user_secrets_store: Arc<dyn UserSecretStore> = Arc::new(
        dyson_swarm::db::secrets::SqlxUserSecretStore::new(pool.clone()),
    );
    let system_secrets_store: Arc<dyn SystemSecretStore> = Arc::new(
        dyson_swarm::db::secrets::SqlxSystemSecretStore::new(pool.clone()),
    );
    let user_secrets_svc = Arc::new(UserSecretsService::new(user_secrets_store, cipher_dir.clone()));
    let system_secrets_svc = Arc::new(SystemSecretsService::new(system_secrets_store, cipher_dir.clone()));
    let instance_svc = Arc::new(InstanceService::new(
        cube.clone(),
        instances_store.clone(),
        secrets_store.clone(),
        tokens_store.clone(),
        "http://swarm.test/llm",
    ));
    let secrets_svc = Arc::new(SecretsService::new(
        secrets_store.clone(),
        instances_store.clone(),
        cipher_dir.clone(),
    ));
    let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
    let snapshots_store: Arc<dyn SnapshotStore> =
        Arc::new(dyson_swarm::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
    let policies_store: Arc<dyn PolicyStore> =
        Arc::new(dyson_swarm::db::policies::SqlitePolicyStore::new(pool.clone()));
    let audit_store: Arc<dyn AuditStore> =
        Arc::new(dyson_swarm::db::audit::SqliteAuditStore::new(pool.clone()));
    let snapshot_svc = Arc::new(SnapshotService::new(
        cube.clone(),
        instances_store.clone(),
        snapshots_store,
        backup,
        instance_svc.clone(),
    ));

    // Default policy: permissive on providers, restrictive on models so the
    // denial assertion has a clean failure mode.
    let default_policy = InstancePolicy {
        allowed_providers: vec!["openai".into()],
        allowed_models: vec!["allowed-model".into()],
        daily_token_budget: None,
        monthly_usd_budget: None,
        rps_limit: None,
    };
    let mut providers = Providers::default();
    providers.insert(
        "openai",
        ProviderConfig {
            api_key: Some("sk-real".into()),
            upstream: llm_url.clone(),
            anthropic_version: None,
        },
    );
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
        .with_user_secrets(user_secrets_svc.clone()),
    );
    let llm_router_inner = proxy::http::router(proxy_svc);

    let prober: Arc<dyn HealthProber> = Arc::new(StubProber);
    let users_store: Arc<dyn dyson_swarm::traits::UserStore> = Arc::new(
        dyson_swarm::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
    );
    let (user_auth, user_id) =
        dyson_swarm::auth::user::fixed_user_auth(users_store.clone(), "alice").await;
    // Stage 7: non-OR providers are BYOK-or-503.  This e2e exercises
    // a streaming `/llm/openai/...` call after a snapshot+restore;
    // pre-seed a BYOK row on alice so resolve() succeeds and the
    // upstream actually receives the swapped Authorization header.
    user_secrets_svc
        .put(&user_id, "byok_openai", b"sk-real")
        .await
        .expect("seed byok_openai for e2e");
    let webhook_store: Arc<dyn dyson_swarm::traits::WebhookStore> = Arc::new(
        dyson_swarm::db::webhooks::SqlxWebhookStore::new(pool.clone()),
    );
    let delivery_store: Arc<dyn dyson_swarm::traits::DeliveryStore> = Arc::new(
        dyson_swarm::db::webhooks::SqlxDeliveryStore::new(pool.clone()),
    );
    let webhooks_svc = Arc::new(dyson_swarm::webhooks::WebhookService::new(
        webhook_store,
        delivery_store,
        secrets_svc.clone(),
        instance_svc.clone(),
        Arc::new(dyson_swarm::webhooks::NullWebhookDispatcher),
        cipher_dir.clone(),
    ));
    let shares_svc = Arc::new(dyson_swarm::shares::ShareService::new(
        pool.clone(),
        user_secrets_svc.clone(),
        instance_svc.clone(),
        dyson_swarm::shares::ShareMetrics::new(),
        None,
    ));
    let cache_dir = tempfile::tempdir().unwrap();
    let artefact_cache = Arc::new(dyson_swarm::artefacts::ArtefactCacheService::new(
        pool.clone(),
        cache_dir.path().to_path_buf(),
        cipher_dir.clone(),
    ));
    std::mem::forget(cache_dir);
    let app_state = http::AppState {
        secrets: secrets_svc,
        user_secrets: user_secrets_svc,
        system_secrets: system_secrets_svc,
        ciphers: cipher_dir.clone(),
        instances: instance_svc.clone(),
        snapshots: snapshot_svc.clone(),
        prober,
        tokens: tokens_store.clone(),
        users: users_store,
        sandbox_domain: "cube.test".into(),
        hostname: None,
        auth_config: std::sync::Arc::new(http::auth_config::AuthConfig::none()),
        dyson_http: http::dyson_proxy::build_client().expect("dyson http client init"),
        models_upstream: None,
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: None,
        user_or_keys: None,
        providers: std::sync::Arc::new(dyson_swarm::config::Providers::default()),
        webhooks: webhooks_svc,
        shares: shares_svc,
        artefact_cache,
    };
    // Stage 5 retired the legacy `admin-token` shared bearer; this e2e
    // exercises admin endpoints via `--dangerous-no-auth`, the same
    // bypass path the local-dev CLI uses.  Production deployments rely
    // on the OIDC role check (`AuthState::enforced(OidcRoles {...})`)
    // exercised in the unit tests under `src/http/mod.rs`.
    let app = http::router(
        app_state,
        AuthState::dangerous_no_auth(),
        user_auth,
        llm_router_inner,
        axum::Router::new(),
    );
    let swarm_url = spawn(app).await;

    let admin = reqwest::Client::new();

    // 3. Create an instance.
    let resp = admin
        .post(format!("{swarm_url}/v1/instances"))
        .bearer_auth("admin-token")
        .json(&json!({"template_id": "tpl-x", "env": {"SWARM_MODEL": "anthropic/claude-sonnet-4-5"}, "ttl_seconds": 600}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let inst_id = created["id"].as_str().unwrap().to_string();
    let _proxy_token = created["proxy_token"].as_str().unwrap().to_string();
    assert_eq!(cube_state.created.lock().unwrap().len(), 1);

    // Optional: secret put/delete round-trip.
    let r = admin
        .put(format!("{swarm_url}/v1/instances/{inst_id}/secrets/SECRET_K"))
        .bearer_auth("admin-token")
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // 4. Snapshot.
    let r = admin
        .post(format!("{swarm_url}/v1/instances/{inst_id}/snapshot"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let snap: serde_json::Value = r.json().await.unwrap();
    let snap_id = snap["id"].as_str().unwrap().to_string();
    assert_eq!(snap["kind"], "manual");
    assert!(cube_state.snapshots.lock().unwrap().iter().any(|x| x == &snap_id));

    // 5. Backup (local sink, kind=backup).
    let r = admin
        .post(format!("{swarm_url}/v1/instances/{inst_id}/backup"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let backup_snap: serde_json::Value = r.json().await.unwrap();
    assert_eq!(backup_snap["kind"], "backup");

    // 6. Destroy.
    let r = admin
        .delete(format!("{swarm_url}/v1/instances/{inst_id}"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(cube_state.destroyed.lock().unwrap().len(), 1);

    // 7. Restore from the manual snapshot.
    let r = admin
        .post(format!("{swarm_url}/v1/instances/{inst_id}/restore"))
        .bearer_auth("admin-token")
        .json(&json!({"snapshot_id": snap_id, "env": {}, "ttl_seconds": 600}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let restored: serde_json::Value = r.json().await.unwrap();
    let restored_id = restored["id"].as_str().unwrap().to_string();
    let restored_token = restored["proxy_token"].as_str().unwrap().to_string();
    assert_ne!(restored_id, inst_id);

    // 8. Streaming LLM call through the proxy with the restored instance's
    // token. Use the allowed model so policy passes.
    let resp = reqwest::Client::new()
        .post(format!("{swarm_url}/llm/openai/v1/chat/completions"))
        .bearer_auth(&restored_token)
        .json(&json!({"model": "allowed-model", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let expected: &[u8] =
        b"data: {\"chunk\":1}\n\ndata: {\"chunk\":2}\n\ndata: [DONE]\n\n";
    assert_eq!(body.as_ref(), expected);
    let auth_seen = llm_state.last_auth.lock().unwrap().clone().unwrap_or_default();
    assert_eq!(auth_seen, "Bearer sk-real", "adapter must swap to real key");
    assert_eq!(llm_state.calls.load(Ordering::SeqCst), 1);

    // 9. Policy denial: model not in allowed_models.
    let resp = reqwest::Client::new()
        .post(format!("{swarm_url}/llm/openai/v1/chat/completions"))
        .bearer_auth(&restored_token)
        .json(&json!({"model": "nope", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let denial: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(denial["code"], "model_not_allowed");

    // 10. Token revocation via admin endpoint → next call 401.
    let r = admin
        .post(format!(
            "{swarm_url}/v1/admin/proxy_tokens/{restored_token}/revoke"
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let resp = reqwest::Client::new()
        .post(format!("{swarm_url}/llm/openai/v1/chat/completions"))
        .bearer_auth(&restored_token)
        .json(&json!({"model": "allowed-model", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 11. /healthz remains open — quick sanity that the unauth path still
    // works under the assembled stack.
    let resp = reqwest::get(format!("{swarm_url}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Probe loop sanity (synchronous): ask the swarm to probe the restored
    // instance directly. The mock prober always reports Healthy.
    let r = admin
        .post(format!("{swarm_url}/v1/instances/{restored_id}/probe"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pr: serde_json::Value = r.json().await.unwrap();
    assert_eq!(pr["status"], "healthy");

}
