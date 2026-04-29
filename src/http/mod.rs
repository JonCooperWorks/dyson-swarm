//! HTTP server assembly.
//!
//! - `/healthz` is unauthenticated (load balancers must reach it without a
//!   bearer).
//! - `/v1/*` (instances, snapshots, secrets, admin) is wrapped in the
//!   admin-bearer middleware.
//! - `/llm/*` (the LLM proxy, step 14) is mounted with its own
//!   per-instance-bearer middleware in [`crate::proxy::http`].
//! - `/` and other unmatched paths fall through to the embedded React
//!   bundle (the SPA, served from [`static_assets`]).
//!
//! Each sub-module exports a `router(state)` factory; this module decides
//! which auth layer wraps which subtree.

pub mod admin_users;
pub mod assets;
pub mod auth_config;
pub mod byok;
pub mod dyson_proxy;
pub mod healthz;
pub mod instances;
pub mod models;
pub mod proxy_admin;
pub mod secrets;
pub mod snapshots;
pub mod static_assets;

use std::sync::Arc;

use axum::{middleware, Router};

use crate::auth::{require_admin_role, user_middleware, AuthState, UserAuthState};
use crate::instance::InstanceService;
use crate::secrets::SecretsService;
use crate::snapshot::SnapshotService;
use crate::traits::{HealthProber, TokenStore};

/// Shared state handed to every route handler. Cheap to clone — every field
/// is an `Arc` or scalar `String`.
#[derive(Clone)]
pub struct AppState {
    pub secrets: Arc<SecretsService>,
    /// Per-user opaque blobs, encrypted with the user's own age key.
    /// Stages 3 + 6 use this for OpenRouter keys and (in future) any
    /// other per-user secret material.
    pub user_secrets: Arc<crate::secrets::UserSecretsService>,
    /// Global blobs (provider api_keys, OpenRouter provisioning key),
    /// encrypted with the system-scope cipher.
    pub system_secrets: Arc<crate::secrets::SystemSecretsService>,
    /// Per-user envelope cipher directory.  Held here so handlers can
    /// drop down to raw seal/open if needed (e.g. minting an OR key
    /// before there's a UserSecretsService entry).
    pub ciphers: Arc<dyn crate::envelope::CipherDirectory>,
    pub instances: Arc<InstanceService>,
    pub snapshots: Arc<SnapshotService>,
    pub prober: Arc<dyn HealthProber>,
    pub tokens: Arc<dyn TokenStore>,
    pub users: Arc<dyn crate::traits::UserStore>,
    pub sandbox_domain: String,
    /// Public hostname swarm serves on, e.g. `"swarm.example.com"`.
    /// Drives the host-based dispatcher in
    /// [`dyson_proxy`] (each Dyson is reachable at
    /// `<instance_id>.<hostname>`) and `InstanceView::open_url` (the
    /// SPA's "open ↗" link).  `None` disables the per-Dyson UI path.
    pub hostname: Option<String>,
    /// Auth-mode descriptor surfaced via `GET /auth/config`. Built from
    /// [`crate::config::Config`] at startup; the SPA hits this endpoint
    /// before mounting React to decide whether to start a PKCE flow.
    pub auth_config: Arc<auth_config::AuthConfig>,
    /// Shared `reqwest::Client` for the host-based reverse proxy.  One
    /// per process so connection pooling survives across requests.
    pub dyson_http: reqwest::Client,
    /// Upstream URL (e.g. `https://openrouter.ai/api`) for the LLM
    /// provider the agents talk through.  `GET /v1/models` proxies to
    /// `<upstream>/v1/models` and exposes the catalogue to the SPA's
    /// create-form picker. `None` disables the endpoint (returns 503).
    pub models_upstream: Option<String>,
    /// Per-process cache for `/v1/models`.  TTL'd inside the handler.
    pub models_cache: models::ModelsCache,
    /// OpenRouter Provisioning-API client.  Some when the operator
    /// supplies a provisioning key (Stage 6); None disables per-user
    /// minting.
    pub openrouter_provisioning: Option<Arc<dyn crate::openrouter::Provisioning>>,
    /// Resolves user_id → plaintext OR bearer.  Same as the proxy's,
    /// surfaced here so admin endpoints can mint/rotate without
    /// duplicating the lazy logic.
    pub user_or_keys: Option<Arc<crate::openrouter::UserOrKeyResolver>>,
    /// Provider configs from `[providers.*]` TOML.  Mirror of the value
    /// inside `ProxyService` — surfaced here so the BYOK routes can
    /// list configured providers (`GET /v1/providers`) and run the
    /// upstream validator against the right URL on PUT.
    pub providers: Arc<crate::config::Providers>,
}

/// Build the public `Router`.
///
/// `auth` decides whether `/v1/*` requires an admin bearer (legacy admin
/// path used by `--dangerous-no-auth` and ops bearers) or runs in
/// pass-through. `user_auth` configures the user-identity middleware that
/// resolves OIDC/bearer credentials to a `users` row and stamps it on the
/// request extensions.
///
/// Routing tiers (outermost first):
/// - `/healthz` — open
/// - `/v1/admin/*` — admin-bearer only (god-mode for ops)
/// - `/v1/*` (non-admin) — user-identity middleware required
/// - `/llm/*` (the proxy) — its own per-instance proxy_token gate, mounted
///   via `extra`
pub fn router(
    state: AppState,
    auth: AuthState,
    user_auth: UserAuthState,
    extra: Router,
) -> Router {
    // Admin-only routes — Stage 5 layered:
    // 1. user_middleware resolves the caller's CallerIdentity (OIDC
    //    JWT or user api-key).  Stamps it on extensions.
    // 2. require_admin_role inspects the caller's claims for the
    //    configured admin role.  Bearer-only callers (no claims) and
    //    OIDC users without the admin role get 404 (admin surface
    //    is privileged; we don't advertise its existence).
    //
    // Layers apply outside-in: the LAST `.layer()` runs FIRST.  So we
    // add user_middleware last to make it the outermost.
    //
    // `--dangerous-no-auth` mode skips user_middleware entirely —
    // require_admin_role's pass-through branch then stamps the
    // X-Swarm-Insecure header.  Otherwise local-dev would 401 on
    // every admin endpoint and the marker header would never fire.
    let admin_handlers =
        proxy_admin::router(state.clone()).merge(crate::http::admin_users::router(state.clone()));
    let admin = if auth.dangerous_no_auth {
        admin_handlers
            .layer(middleware::from_fn_with_state(auth.clone(), require_admin_role))
    } else {
        admin_handlers
            .layer(middleware::from_fn_with_state(auth.clone(), require_admin_role))
            .layer(middleware::from_fn_with_state(user_auth.clone(), user_middleware))
    };

    // Tenant routes — every request resolves to a CallerIdentity.
    let tenant = Router::new()
        .merge(instances::router(state.clone()))
        .merge(snapshots::router(state.clone()))
        .merge(secrets::router(state.clone()))
        .merge(byok::router(state.clone()))
        .merge(models::router(state.clone()))
        .layer(middleware::from_fn_with_state(user_auth.clone(), user_middleware));

    // Static assets (SPA bundle) are merged last so the API routes win
    // every match.  The static router owns the fallback, which serves
    // `/`, `/assets/*`, and 404s anything else — no auth, no logging.
    let normal = Router::new()
        .merge(healthz::router())
        .merge(auth_config::router(state.clone()))
        .merge(admin)
        .merge(tenant)
        .merge(extra)
        .merge(static_assets::router());

    // Outer layer: host-based dispatcher.  When a request's Host header
    // is `<instance_id>.<hostname>`, forward to the matching Dyson
    // sandbox.  Otherwise fall through to `normal`.  Hostname comes
    // from config; when unset, the dispatcher is a pass-through.
    let dispatch_state = dyson_proxy::DispatchState::new(
        state.clone(),
        user_auth.authenticator.clone(),
        state.hostname.clone(),
    );
    normal.layer(middleware::from_fn_with_state(
        dispatch_state,
        dyson_proxy::dispatch,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStore,
        ProbeResult, SandboxInfo, SecretStore, SnapshotInfo, SnapshotStore, TokenStore,
    };

    struct StubProber;

    #[async_trait::async_trait]
    impl HealthProber for StubProber {
        async fn probe(&self, _: &InstanceRow) -> ProbeResult {
            ProbeResult::Healthy
        }
    }

    struct StubCube;

    #[async_trait::async_trait]
    impl CubeClient for StubCube {
        async fn create_sandbox(
            &self,
            _: CreateSandboxArgs,
        ) -> Result<SandboxInfo, crate::error::CubeError> {
            unreachable!()
        }
        async fn destroy_sandbox(&self, _: &str) -> Result<(), crate::error::CubeError> {
            unreachable!()
        }
        async fn snapshot_sandbox(
            &self,
            _: &str,
            _: &str,
        ) -> Result<SnapshotInfo, crate::error::CubeError> {
            unreachable!()
        }
        async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), crate::error::CubeError> {
            unreachable!()
        }
    }

    async fn build_state() -> (AppState, Arc<dyn crate::traits::UserStore>) {
        let pool = open_in_memory().await.unwrap();
        let raw: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let svc = Arc::new(SecretsService::new(raw.clone(), cipher_dir.clone()));
        let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let system_secrets_store: Arc<dyn crate::traits::SystemSecretStore> =
            Arc::new(crate::db::secrets::SqlxSystemSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(crate::secrets::UserSecretsService::new(
            user_secrets_store,
            cipher_dir.clone(),
        ));
        let system_secrets = Arc::new(crate::secrets::SystemSecretsService::new(
            system_secrets_store,
            cipher_dir.clone(),
        ));
        let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone()));
        let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let users_store: Arc<dyn crate::traits::UserStore> = Arc::new(
            crate::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
        );
        let instance_svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            raw.clone(),
            tokens_store.clone(),
            "http://test/llm",
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn SnapshotStore> =
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store,
            snapshots_store,
            backup,
            instance_svc.clone(),
        ));
        let state = AppState {
            secrets: svc,
            user_secrets,
            system_secrets,
            ciphers: cipher_dir,
            instances: instance_svc,
            snapshots: snapshot_svc,
            prober: Arc::new(StubProber),
            tokens: tokens_store,
            users: users_store.clone(),
            sandbox_domain: "cube.test".into(),
            hostname: None,
            auth_config: Arc::new(auth_config::AuthConfig::none()),
            dyson_http: dyson_proxy::build_client().expect("dyson http client init"),
            models_upstream: None,
            models_cache: models::ModelsCache::new(),
            openrouter_provisioning: None,
            user_or_keys: None,
            providers: Arc::new(crate::config::Providers::default()),
        };
        (state, users_store)
    }

    async fn spawn(state: AppState, auth: AuthState, user_auth: UserAuthState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state, auth, user_auth, Router::new());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn build_with_user(subject: &str) -> (AppState, UserAuthState, String) {
        let (state, users) = build_state().await;
        let (user_auth, user_id) = crate::auth::user::fixed_user_auth(users, subject).await;
        (state, user_auth, user_id)
    }

    fn deny_user_auth(users: Arc<dyn crate::traits::UserStore>) -> UserAuthState {
        // Authenticator that always returns Missing — used to verify the
        // tenant routes 401 when the resolver finds no credential.
        struct AlwaysMissing;
        #[async_trait::async_trait]
        impl crate::auth::Authenticator for AlwaysMissing {
            async fn authenticate(
                &self,
                _: &axum::http::HeaderMap,
            ) -> Result<crate::auth::UserIdentity, crate::auth::AuthError> {
                Err(crate::auth::AuthError::Missing)
            }
        }
        UserAuthState::new(Arc::new(AlwaysMissing), users)
    }

    #[tokio::test]
    async fn healthz_is_open() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn tenant_route_without_credential_is_401() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn tenant_route_with_active_user_is_200() {
        let (state, user_auth, _user_id) = build_with_user("alice").await;
        let base = spawn(state, AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }), user_auth).await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn admin_route_without_admin_bearer_is_401() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/admin/users")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn admin_route_with_admin_role_is_200() {
        // Stage 5: admin gate is now an OIDC role check, not a shared
        // bearer.  Construct a UserAuthState whose authenticator
        // returns an identity carrying the admin role in the
        // configured claim, then any Authorization header value will
        // pass (the Fixed authenticator ignores header content).
        let (state, users) = build_state().await;
        let (user_auth, _id) = crate::auth::user::fixed_user_auth_with_roles(
            users,
            "alice",
            Some(("https://test/roles", &["rol_admin"])),
        )
        .await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/admin/users"))
            .bearer_auth("not-checked-by-fixed-authenticator")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn admin_route_with_non_admin_role_is_404() {
        let (state, users) = build_state().await;
        let (user_auth, _id) = crate::auth::user::fixed_user_auth_with_roles(
            users,
            "bob",
            Some(("https://test/roles", &["rol_free"])),
        )
        .await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/admin/users"))
            .bearer_auth("ignored")
            .send()
            .await
            .unwrap();
        // Denied admin requests return 404, not 403 — see the
        // require_admin_role docstring for the rationale (privileged
        // surface, deny-by-omission rather than deny-by-permission).
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn host_dispatcher_passes_through_when_host_does_not_match() {
        // hostname configured, but request Host = base host (swarm's
        // own UI, not a sandbox subdomain).  The dispatcher must not
        // intercept; the request flows through to the normal router
        // and we get the regular 401 from user_middleware.
        let (mut state, users) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let base = spawn(state, AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }), deny_user_auth(users)).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/instances"))
            .header("host", "swarm.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn host_dispatcher_404s_unknown_subdomain() {
        // Sandbox subdomain shape, but no row with that id exists.
        // The dispatcher authenticates the user (alice), looks up the
        // instance, and returns 404.
        let (mut state, _) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let users = state.users.clone();
        let (alice_auth, _alice_id) =
            crate::auth::user::fixed_user_auth(users, "alice").await;
        let base = spawn(state, AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }), alice_auth).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/anything"))
            .header("host", "no-such-id.swarm.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn dangerous_no_auth_marker_header_on_admin_routes() {
        let (state, users) = build_state().await;
        let base = spawn(state, AuthState::dangerous_no_auth(), deny_user_auth(users)).await;
        let r = reqwest::get(format!("{base}/v1/admin/users")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers().get("x-swarm-insecure").map(|v| v.to_str().unwrap()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn auth_config_is_unauthenticated_and_reports_none_by_default() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        // No bearer — must succeed.
        let r = reqwest::get(format!("{base}/auth/config")).await.unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["mode"], "none");
    }

    #[tokio::test]
    async fn root_serves_embedded_spa_index_html() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/")).await.unwrap();
        assert_eq!(r.status(), 200);
        let ct = r
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
        let body = r.text().await.unwrap();
        assert!(
            body.contains("<div id=\"root\">"),
            "expected SPA shell, got: {}",
            body.chars().take(200).collect::<String>()
        );
    }

    #[tokio::test]
    async fn unknown_static_path_is_404() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles { claim: "https://test/roles".into(), admin: "rol_admin".into() }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/no-such-asset")).await.unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn healthz_does_not_emit_insecure_header() {
        // The marker header is scoped to admin routes — /healthz must not
        // advertise an auth posture (it wasn't subject to the auth layer in
        // the first place).
        let (state, users) = build_state().await;
        let base = spawn(state, AuthState::dangerous_no_auth(), deny_user_auth(users)).await;
        let r = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("x-swarm-insecure").is_none());
    }
}
