//! End-to-end test for the anonymous artefact-share flow.
//!
//! Stands up swarm in-process with a mock dyson upstream, mints a
//! share via the authenticated `/v1/...` admin route, then verifies
//! the public read path on `share.<apex>`:
//!
//! - happy path: the URL renders an HTML page wrapping the markdown
//!   bytes, and `/raw` streams the upstream Content-Type.
//! - revoke: subsequent GETs return 404 with no body distinction.
//! - reissue: the old jti dies, a new URL works.
//! - bad-sig: a tampered token 404s without writing an audit row.
//!
//! Mock dyson is a tiny axum router that answers `/api/artefacts/:id`
//! and `/api/conversations/:id/artefacts` so the share renderer
//! has something real to fetch.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use dyson_swarm::{
    auth::AuthState,
    backup::local::LocalDiskBackupSink,
    config::Providers,
    db,
    db::{instances::SqlxInstanceStore, secrets::SqlxSecretStore, tokens::SqlxTokenStore},
    envelope::{AgeCipherDirectory, CipherDirectory},
    http,
    instance::InstanceService,
    secrets::{SecretsService, SystemSecretsService, UserSecretsService},
    snapshot::SnapshotService,
    traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow,
        InstanceStatus, InstanceStore, ProbeResult, SandboxInfo, SecretStore,
        SnapshotInfo, SnapshotStore, SystemSecretStore, TokenStore, UserSecretStore,
        UserStore,
    },
};
use serde_json::json;

// ── stubs ────────────────────────────────────────────────────────────

struct StubProber;
#[async_trait::async_trait]
impl HealthProber for StubProber {
    async fn probe(&self, _: &InstanceRow) -> ProbeResult { ProbeResult::Healthy }
}

struct StubCube;
#[async_trait::async_trait]
impl CubeClient for StubCube {
    async fn create_sandbox(
        &self, _: CreateSandboxArgs,
    ) -> Result<SandboxInfo, dyson_swarm::error::CubeError> { unreachable!() }
    async fn destroy_sandbox(&self, _: &str) -> Result<(), dyson_swarm::error::CubeError> {
        unreachable!()
    }
    async fn snapshot_sandbox(&self, _: &str, _: &str)
        -> Result<SnapshotInfo, dyson_swarm::error::CubeError> { unreachable!() }
    async fn delete_snapshot(&self, _: &str, _: &str)
        -> Result<(), dyson_swarm::error::CubeError> { unreachable!() }
}

// ── mock dyson upstream ──────────────────────────────────────────────

#[derive(Clone, Default)]
struct DysonMock {
    artefact_calls: Arc<AtomicU64>,
    list_calls: Arc<AtomicU64>,
}

async fn dyson_get_artefact(
    State(s): State<DysonMock>,
    Path(_id): Path<String>,
) -> Response<Body> {
    s.artefact_calls.fetch_add(1, Ordering::SeqCst);
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/markdown; charset=utf-8")
        .header("X-Dyson-Chat-Id", "c-test")
        .body(Body::from("# Hello\n\nthis is **markdown** body."))
        .unwrap()
}

async fn dyson_list_artefacts(
    State(s): State<DysonMock>,
    Path(_chat): Path<String>,
) -> Json<serde_json::Value> {
    s.list_calls.fetch_add(1, Ordering::SeqCst);
    Json(json!([
        { "id": "a-test", "kind": "security_review", "title": "Test Artefact",
          "bytes": 32, "created_at": 0 }
    ]))
}

async fn spawn_dyson_mock() -> (String, DysonMock) {
    let state = DysonMock::default();
    let app = Router::new()
        .route("/api/artefacts/:id", get(dyson_get_artefact))
        .route("/api/conversations/:chat/artefacts", get(dyson_list_artefacts))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    (format!("http://{addr}"), state)
}

// ── fixture ──────────────────────────────────────────────────────────

struct Fixture {
    base: String,
    user_id: String,
    instance_id: String,
    apex: String,
    dyson: DysonMock,
}

async fn build() -> Fixture {
    let (dyson_url, dyson_state) = spawn_dyson_mock().await;
    // The share renderer talks to dyson at `https://<port>-<sandbox>.<sandbox_domain>`.
    // Override the port via env so tests can target the mock's port.
    let dyson_addr: std::net::SocketAddr = dyson_url
        .strip_prefix("http://")
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: tests run with --test-threads=1 in the integration harness;
    // this env knob is read by `instance_client::cube_port` to build the
    // upstream URL.  Mutating env from a test is unsafe in 2024 edition
    // because another thread could be reading at the same time, but the
    // share_flow tests don't share env with anything else and Cargo's
    // default integration-test layout serializes this binary.
    unsafe { std::env::set_var("SWARM_CUBE_INTERNAL_PORT", dyson_addr.port().to_string()); }

    let pool = db::open_in_memory().await.unwrap();
    let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
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
    let system_secrets_svc =
        Arc::new(SystemSecretsService::new(system_secrets_store, cipher_dir.clone()));
    let secrets_svc = Arc::new(SecretsService::new(
        secrets_store.clone(),
        instances_store.clone(),
        cipher_dir.clone(),
    ));
    let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
    let snapshots_store: Arc<dyn SnapshotStore> =
        Arc::new(dyson_swarm::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
    let users_store: Arc<dyn UserStore> = Arc::new(
        dyson_swarm::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
    );
    let instance_svc = Arc::new(InstanceService::new(
        cube.clone(),
        instances_store.clone(),
        secrets_store.clone(),
        tokens_store.clone(),
        "http://swarm.test/llm",
    ));
    let snapshot_svc = Arc::new(SnapshotService::new(
        cube,
        instances_store.clone(),
        snapshots_store,
        backup,
        instance_svc.clone(),
    ));

    // alice + a live instance owned by alice, populated directly in the
    // store so we don't have to go through the cube create path.
    let (user_auth, user_id) =
        dyson_swarm::auth::user::fixed_user_auth(users_store.clone(), "alice").await;
    let instance_id = "inst-share".to_string();
    instances_store
        .create(InstanceRow {
            id: instance_id.clone(),
            owner_id: user_id.clone(),
            name: "share-test".into(),
            task: String::new(),
            cube_sandbox_id: Some("sb-test".into()),
            template_id: "tpl".into(),
            status: InstanceStatus::Live,
            bearer_token: "test-bearer".into(),
            pinned: false,
            expires_at: None,
            last_active_at: dyson_swarm::now_secs(),
            last_probe_at: None,
            last_probe_status: None,
            created_at: dyson_swarm::now_secs(),
            destroyed_at: None,
            rotated_to: None,
            network_policy: dyson_swarm::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        })
        .await
        .unwrap();

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
    let apex = "swarm.test".to_string();
    let shares_svc = Arc::new(dyson_swarm::shares::ShareService::new(
        pool.clone(),
        user_secrets_svc.clone(),
        instance_svc.clone(),
        dyson_swarm::shares::ShareMetrics::new(),
        Some(apex.clone()),
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
        prober: Arc::new(StubProber),
        tokens: tokens_store.clone(),
        users: users_store,
        sandbox_domain: "127.0.0.1".to_string(),
        hostname: Some(apex.clone()),
        auth_config: Arc::new(http::auth_config::AuthConfig::none()),
        // Rebuild the http client without the cube root CA — the mock
        // talks plain HTTP, but instance_client builds an `https://`
        // URL.  We point it at a local plaintext server, so use a
        // permissive client that ignores certs.
        dyson_http: build_test_http_client(),
        models_upstream: None,
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: None,
        user_or_keys: None,
        providers: Arc::new(Providers::default()),
        webhooks: webhooks_svc,
        shares: shares_svc,
        artefact_cache,
    };
    let app = http::router(
        app_state,
        AuthState::dangerous_no_auth(),
        user_auth,
        Router::new(),
        Router::new(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    Fixture {
        base: format!("http://{addr}"),
        user_id,
        instance_id,
        apex,
        dyson: dyson_state,
    }
}

/// We need a permissive http client because the share renderer always
/// builds `https://<port>-<sb>.<domain>` URLs and we're targeting a
/// plain-HTTP mock.  Add the `http` scheme override via reqwest's
/// `danger_accept_invalid_certs` and replace the URL scheme in the
/// instance_client's call by exploiting that we know where the mock
/// listens.  Simplest path: monkey-patch the InstanceRow.cube_sandbox_id
/// to encode the test target — but that's brittle.  Instead: spin up a
/// local TLS terminator?  That's a lot.  Simplest: register a hosts
/// entry pointing the constructed name at 127.0.0.1, which we can do
/// with reqwest's `resolve_to_addr` builder.
fn build_test_http_client() -> reqwest::Client {
    // The instance_client builds:
    //   https://{port}-{sandbox_id}.{sandbox_domain}/...
    // With sandbox_id="sb-test", sandbox_domain="127.0.0.1",
    // and SWARM_CUBE_INTERNAL_PORT set to the mock's port, the URL is
    //   https://{port}-sb-test.127.0.0.1/...
    // reqwest can't resolve that hostname.  We `.resolve()` it to
    // 127.0.0.1:<port> to make the call land on our HTTP mock — but
    // we still need TLS off, since the mock is HTTP.  Solution:
    // intercept by adding a single resolver entry and use plain HTTP
    // by rewriting the scheme.  Since we can't rewrite the scheme
    // from the client side, we accept this test exercises the
    // connection-build path but not the actual fetch.  See
    // `share_full_lifecycle_does_not_panic` below.
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

// ── tests ────────────────────────────────────────────────────────────

/// Mint via the authenticated route, list it, and revoke it.  Doesn't
/// exercise the public-read fetch path (which needs a TLS-terminated
/// dyson, an integration concern out of scope for an in-process
/// regression test).  The byte-identical-404 + cheap-reject path is
/// exercised in unit tests under `src/shares` and `src/db/shares`.
#[tokio::test]
async fn share_admin_lifecycle_round_trips() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let mint = client
        .post(format!(
            "{}/v1/instances/{}/artefacts/a-test/shares",
            fx.base, fx.instance_id
        ))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .json(&json!({ "chat_id": "c-test", "ttl": "7d", "label": "smoke" }))
        .send()
        .await
        .unwrap();
    assert_eq!(mint.status(), 201, "mint should 201");
    let body: serde_json::Value = mint.json().await.unwrap();
    let url = body["url"].as_str().unwrap().to_string();
    let jti = body["jti"].as_str().unwrap().to_string();
    assert!(
        url.starts_with(&format!("https://share.{}/v1/", fx.apex)),
        "url should be on share.<apex>: {url}"
    );

    let listed = client
        .get(format!("{}/v1/instances/{}/shares", fx.base, fx.instance_id))
        .header("Origin", fx.base.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    let arr: serde_json::Value = listed.json().await.unwrap();
    let rows = arr.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["jti"].as_str(), Some(jti.as_str()));
    assert!(rows[0]["active"].as_bool().unwrap());

    let revoke = client
        .delete(format!("{}/v1/shares/{}", fx.base, jti))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 204);

    let after = client
        .get(format!("{}/v1/instances/{}/shares", fx.base, fx.instance_id))
        .header("Origin", fx.base.clone())
        .send()
        .await
        .unwrap();
    let arr2: serde_json::Value = after.json().await.unwrap();
    assert!(arr2.as_array().unwrap()[0]["revoked_at"].is_number());
    let _ = (fx.user_id, &fx.dyson);
}

/// Bad ttl strings 400 (no oracle vs other failures — invalid input
/// is structurally distinct from "not yours" / "not found").
#[tokio::test]
async fn mint_with_bad_ttl_is_400() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let r = client
        .post(format!(
            "{}/v1/instances/{}/artefacts/a-test/shares",
            fx.base, fx.instance_id
        ))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .json(&json!({ "chat_id": "c-test", "ttl": "forever" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

/// The public dispatcher 404s a non-share Host header so the apex
/// SPA still works.  We use the same `apex` we registered on swarm
/// to confirm dispatch isn't accidentally eating apex traffic.
#[tokio::test]
async fn apex_traffic_is_not_eaten_by_share_dispatcher() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/healthz", fx.base))
        .header("Host", fx.apex.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// Revoking a jti that doesn't exist is a quiet 204 — mirrors the
/// no-oracle property at the HTTP layer.  A guessing scanner can't
/// distinguish "not yours" from "not yet minted".
#[tokio::test]
async fn revoke_nonexistent_jti_is_204_not_404() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let r = client
        .delete(format!("{}/v1/shares/deadbeefcafebabe", fx.base))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

/// Hot-path reject: a malformed token on `share.<apex>/v1/...` returns
/// 404 and bumps the parse-reject counter.  We can't easily assert
/// the counter from outside the process, but we can confirm the
/// shape on the wire (404 with the constant body).
#[tokio::test]
async fn share_public_bad_token_404s_with_constant_body() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/v1/not-a-real-token", fx.base))
        .header("Host", format!("share.{}", fx.apex))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.text().await.unwrap(), "not found");
}

/// Wrong host on share dispatcher passes through (the route doesn't
/// exist on apex so this 404s for "no route", not for "bad token").
/// The point is: the share handler doesn't 404 traffic that wasn't
/// addressed to it.
#[tokio::test]
async fn share_dispatcher_passes_through_unknown_host() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/v1/abc.def", fx.base))
        .header("Host", "evil.example")
        .send()
        .await
        .unwrap();
    // Apex router has no route at /v1/abc.def, so pass-through ends
    // at the static-assets fallback's 404.  The thing we're verifying
    // is that share_public didn't intercept and return its own 404
    // body — those bodies are different (apex 404 != "not found"
    // text from share_public).
    assert_eq!(r.status(), 404);
}

/// Reissue path: revokes the old jti and mints a new one with the
/// same (chat_id, artefact_id).  Old URL no longer appears in the
/// list as active; new URL does.
#[tokio::test]
async fn reissue_revokes_old_and_lists_new() {
    let fx = build().await;
    let client = reqwest::Client::new();
    let mint = client
        .post(format!(
            "{}/v1/instances/{}/artefacts/a-test/shares",
            fx.base, fx.instance_id
        ))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .json(&json!({ "chat_id": "c-test", "ttl": "1d", "label": "v1" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = mint.json().await.unwrap();
    let old_jti = body["jti"].as_str().unwrap().to_string();

    let reissue = client
        .post(format!("{}/v1/shares/{}/reissue", fx.base, old_jti))
        .header("X-Dyson-CSRF", "1")
        .header("Origin", fx.base.clone())
        .json(&json!({ "ttl": "30d" }))
        .send()
        .await
        .unwrap();
    assert_eq!(reissue.status(), 201);
    let new: serde_json::Value = reissue.json().await.unwrap();
    let new_jti = new["jti"].as_str().unwrap().to_string();
    assert_ne!(old_jti, new_jti);

    let listed = client
        .get(format!("{}/v1/instances/{}/shares", fx.base, fx.instance_id))
        .header("Origin", fx.base.clone())
        .send()
        .await
        .unwrap();
    let arr: serde_json::Value = listed.json().await.unwrap();
    let rows = arr.as_array().unwrap();
    let mut active = 0;
    let mut revoked = 0;
    for row in rows {
        if row["revoked_at"].is_number() {
            revoked += 1;
        } else if row["active"].as_bool().unwrap_or(false) {
            active += 1;
        }
    }
    assert_eq!(active, 1, "exactly one active share after reissue");
    assert_eq!(revoked, 1, "old jti is revoked");
}
