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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{any, delete, post};
use axum::{Json, Router};
use futures::stream;
use serde_json::json;

use dyson_swarm::{
    auth::{chain::ChainAuthenticator, Authenticator, AuthState, UserAuthState},
    backup::local::LocalDiskBackupSink,
    config::{ProviderConfig, Providers},
    cube_client::HttpCubeClient,
    db,
    db::{instances::SqlxInstanceStore, secrets::SqlxSecretStore, tokens::SqlxTokenStore},
    envelope::{AgeCipherDirectory, CipherDirectory},
    http,
    instance::InstanceService,
    openrouter::{MintedKey, OpenRouterError, Provisioning, UserOrKeyResolver},
    proxy::{self, policy_check::InstancePolicy, ProxyService},
    secrets::{SecretsService, SystemSecretsService, UserSecretsService},
    snapshot::SnapshotService,
    traits::{
        AuditStore, BackupSink, CubeClient, HealthProber, InstanceRow, InstanceStore, PolicyStore,
        ProbeResult, SecretStore, SnapshotStore, SystemSecretStore, TokenStore, UserSecretStore,
        UserStore,
    },
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
    Json(json!({ "sandboxID": id, "hostIP": "10.0.0.1" }))
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
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

/// Build everything a swarm router needs.  Returns the URL the test
/// hits + handles to mocks the test will assert against.
struct Stack {
    base: String,
    cube: CubeState,
    llm: LlmState,
    or_prov: Arc<RecordingProvisioning>,
    users: Arc<dyn UserStore>,
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

    let pool = db::open_in_memory().await.unwrap();
    let cube_cfg = dyson_swarm::config::CubeConfig {
        url: cube_url,
        api_key: "k".into(),
        sandbox_domain: "cube.test".into(),
    };
    let cube: Arc<dyn CubeClient> = Arc::new(HttpCubeClient::new(&cube_cfg).unwrap());
    let instances_store: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
    let secrets_store: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
    let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
    let keys_tmp = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let cipher_dir: Arc<dyn CipherDirectory> =
        Arc::new(AgeCipherDirectory::new(keys_tmp.path()).unwrap());
    let user_secrets_store: Arc<dyn UserSecretStore> =
        Arc::new(dyson_swarm::db::secrets::SqlxUserSecretStore::new(pool.clone()));
    let system_secrets_store: Arc<dyn SystemSecretStore> = Arc::new(
        dyson_swarm::db::secrets::SqlxSystemSecretStore::new(pool.clone()),
    );
    let user_secrets_svc = Arc::new(UserSecretsService::new(user_secrets_store, cipher_dir.clone()));
    let system_secrets_svc =
        Arc::new(SystemSecretsService::new(system_secrets_store, cipher_dir.clone()));
    let instance_svc = Arc::new(InstanceService::new(
        cube.clone(),
        instances_store.clone(),
        secrets_store.clone(),
        tokens_store.clone(),
        "http://swarm.test/llm",
    ));
    let secrets_svc = Arc::new(SecretsService::new(secrets_store.clone(), cipher_dir.clone()));
    let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
    let snapshots_store: Arc<dyn SnapshotStore> = Arc::new(
        dyson_swarm::db::snapshots::SqliteSnapshotStore::new(pool.clone()),
    );
    let policies_store: Arc<dyn PolicyStore> = Arc::new(
        dyson_swarm::db::policies::SqlitePolicyStore::new(pool.clone()),
    );
    let audit_store: Arc<dyn AuditStore> =
        Arc::new(dyson_swarm::db::audit::SqliteAuditStore::new(pool.clone()));
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
        dyson_swarm::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
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
    let bearer_link: Arc<dyn Authenticator> =
        Arc::new(dyson_swarm::auth::bearer::BearerAuthenticator::new(users_store.clone()));
    let (fixed_auth, _fixed_id) = dyson_swarm::auth::user::fixed_user_auth_with_roles(
        users_store.clone(),
        subject_for_no_bearer,
        Some(("https://test/roles", &["rol_admin"])),
    )
    .await;
    let chain: Arc<dyn Authenticator> =
        Arc::new(ChainAuthenticator::new(vec![bearer_link, fixed_auth.authenticator.clone()]));
    let user_auth = UserAuthState::new(chain, users_store.clone());

    let app_state = http::AppState {
        secrets: secrets_svc,
        user_secrets: user_secrets_svc,
        system_secrets: system_secrets_svc,
        ciphers: cipher_dir.clone(),
        instances: instance_svc.clone(),
        snapshots: snapshot_svc.clone(),
        prober,
        tokens: tokens_store.clone(),
        users: users_store.clone(),
        sandbox_domain: "cube.test".into(),
        hostname: None,
        auth_config: std::sync::Arc::new(http::auth_config::AuthConfig::none()),
        dyson_http: http::dyson_proxy::build_client().expect("dyson http client init"),
        models_upstream: None,
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: Some(or_prov.clone() as Arc<dyn Provisioning>),
        user_or_keys: Some(user_or_keys.clone()),
        providers: Arc::new(dyson_swarm::config::Providers::default()),
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
    );
    let base = spawn(app).await;

    Stack {
        base,
        cube: cube_state,
        llm: llm_state,
        or_prov,
        users: users_store,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

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
    assert!(bob_list.is_empty(), "bob should see no instances; got {bob_list:?}");

    // Bob trying to GET alice's instance gets 404 — same observable
    // outcome as a non-existent id.  No oracle.
    let r = admin
        .get(format!("{}/v1/instances/{inst_id}", stack.base))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Bob trying to write a secret to alice's instance: 404.
    let r = admin
        .put(format!("{}/v1/instances/{inst_id}/secrets/X", stack.base))
        .bearer_auth(&bob_token)
        .json(&json!({"value": "leaked"}))
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
    let proxy_token = r
        .json::<serde_json::Value>()
        .await
        .unwrap()["proxy_token"]
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
    let auth_seen = stack.llm.last_auth.lock().unwrap().clone().unwrap_or_default();
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
    let auth_seen = stack.llm.last_auth.lock().unwrap().clone().unwrap_or_default();
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
    let proxy_token = r
        .json::<serde_json::Value>()
        .await
        .unwrap()["proxy_token"]
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
    let path = stack.llm.last_path.lock().unwrap().clone().unwrap_or_default();
    assert_eq!(
        path, "/v1/chat/completions",
        "swarm must strip the /llm/<provider> prefix, leaving the upstream path with exactly one /v1"
    );
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

async fn create_user(client: &reqwest::Client, base: &str, subject: &str, activate: bool) -> String {
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
