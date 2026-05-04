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
pub mod instance_artefacts;
pub mod instances;
pub mod internal_ingest;
pub mod internal_state;
pub mod models;
pub mod proxy_admin;
pub mod secrets;
pub mod share_public;
pub mod shares;
pub mod snapshots;
pub mod static_assets;
pub mod webhooks;

use std::path::PathBuf;
use std::sync::Arc;

use axum::{Router, middleware};

use crate::auth::{AuthState, UserAuthState, require_admin_role, user_middleware};
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
    /// Operator startup gate for user-selected `byo` upstream hosts.
    pub byo: Arc<crate::config::ByoConfig>,
    /// Per-instance webhook ("tasks") service — backs both the
    /// management routes under `/v1/instances/:id/webhooks` and the
    /// public delivery endpoint `/webhooks/:id/:name`.
    pub webhooks: Arc<crate::webhooks::WebhookService>,
    /// Anonymous artefact-share service — backs `/v1/instances/:id/...`
    /// admin CRUD and the public read path on `share.<apex>`.  Holds
    /// the SQLite pool, the per-user-secrets handle, and the metrics
    /// counters; stateless across requests.
    pub shares: Arc<crate::shares::ShareService>,
    /// Swarm-side cache of dyson-emitted artefacts.  Read-through and
    /// write-through: the share public path consults this before
    /// hitting the live cube, and ingests every cube response into it,
    /// so destroyed/reset cubes don't break still-active share URLs
    /// or the swarm UI's artefact list.
    pub artefact_cache: crate::artefacts::ArtefactCache,
    /// Sealed mirror of selected dyson workspace/chat state files.
    /// Written by the internal state-sync endpoint with an `st_`
    /// per-instance bearer; bodies are encrypted before disk.
    pub state_files: crate::state_files::StateFiles,
    /// Unix socket for the MCP runtime helper. Instance destroy uses
    /// it to tell the helper to stop any Docker/stdout sessions keyed
    /// to the instance before the sealed MCP rows disappear.
    pub mcp_runtime_socket: Option<PathBuf>,
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
    mcp_user_router: Router,
    mcp_admin_router: Router,
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
    let admin_handlers = proxy_admin::router(state.clone())
        .merge(crate::http::admin_users::router(state.clone()))
        .merge(instances::admin_router(state.clone()))
        .merge(mcp_admin_router);
    let admin = if auth.dangerous_no_auth {
        admin_handlers.layer(middleware::from_fn_with_state(
            auth.clone(),
            require_admin_role,
        ))
    } else {
        admin_handlers
            .layer(middleware::from_fn_with_state(
                auth.clone(),
                require_admin_role,
            ))
            .layer(middleware::from_fn_with_state(
                user_auth.clone(),
                user_middleware,
            ))
    };

    // Tenant routes — every request resolves to a CallerIdentity.
    let tenant = Router::new()
        .merge(instances::router(state.clone()))
        .merge(snapshots::router(state.clone()))
        .merge(secrets::router(state.clone()))
        .merge(byok::router(state.clone()))
        .merge(models::router(state.clone()))
        .merge(webhooks::router(state.clone()))
        .merge(shares::router(state.clone()))
        .merge(instance_artefacts::router(state.clone()))
        .merge(mcp_user_router)
        .layer(middleware::from_fn_with_state(
            user_auth.clone(),
            user_middleware,
        ));

    // Static assets (SPA bundle) are merged last so the API routes win
    // every match.  The static router owns the fallback, which serves
    // `/`, `/assets/*`, and 404s anything else — no auth, no logging.
    //
    // `instances::internal_router` mounts `/v1/internal/tls-allowlist`
    // unauthenticated for Caddy's `on_demand_tls.ask` probe.  Caddy
    // calls this endpoint at TLS-issuance time and can't carry a
    // bearer; the only information the endpoint reveals is whether
    // a given hostname maps to a known instance, which the public
    // wildcard DNS + cert SAN list already implicitly expose.
    let normal = Router::new()
        .merge(healthz::router())
        .merge(auth_config::router(state.clone()))
        .merge(instances::internal_router(state.clone()))
        .merge(internal_ingest::router(state.clone()))
        .merge(internal_state::router(state.clone()))
        .merge(webhooks::public_router(state.clone()))
        .merge(admin)
        .merge(tenant)
        .merge(extra)
        .merge(static_assets::router());

    // Outer layers: two host-based dispatchers in sequence.  Layers
    // apply outside-in — the LAST `.layer()` is the OUTERMOST one
    // and runs FIRST on inbound traffic.  share_public must run
    // before dyson_proxy because `share.<hostname>` is technically
    // a one-label subdomain of the apex and `extract_instance_subdomain`
    // would otherwise treat it as instance_id="share" and 404.
    // dyson_proxy then runs second, catching legitimate
    // `<id>.<hostname>` traffic, and finally `normal` handles
    // everything for the apex host.
    let dispatch_state = dyson_proxy::DispatchState::new(
        state.clone(),
        user_auth.authenticator.clone(),
        state.hostname.clone(),
    );
    normal
        .layer(middleware::from_fn_with_state(
            dispatch_state,
            dyson_proxy::dispatch,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            share_public::dispatch,
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
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
        let svc = Arc::new(SecretsService::new(
            raw.clone(),
            instances_store.clone(),
            cipher_dir.clone(),
        ));
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
        let tokens_store: Arc<dyn TokenStore> =
            Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher));
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
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store,
            snapshots_store,
            backup,
            instance_svc.clone(),
        ));
        let webhook_store: Arc<dyn crate::traits::WebhookStore> =
            Arc::new(crate::db::webhooks::SqlxWebhookStore::new(pool.clone()));
        let delivery_store: Arc<dyn crate::traits::DeliveryStore> =
            Arc::new(crate::db::webhooks::SqlxDeliveryStore::new(pool.clone()));
        let webhooks_svc = Arc::new(crate::webhooks::WebhookService::new(
            webhook_store,
            delivery_store,
            user_secrets.clone(),
            instance_svc.clone(),
            Arc::new(crate::webhooks::NullWebhookDispatcher),
            cipher_dir.clone(),
        ));
        let shares_svc = Arc::new(crate::shares::ShareService::new(
            pool.clone(),
            user_secrets.clone(),
            instance_svc.clone(),
            crate::shares::ShareMetrics::new(),
            None,
        ));
        let cache_dir = tempfile::tempdir().unwrap();
        let artefact_cache = Arc::new(crate::artefacts::ArtefactCacheService::new(
            pool.clone(),
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));
        let state_files = Arc::new(crate::state_files::StateFileService::new(
            pool.clone(),
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));
        // Leak the tempdir so the body files outlive the test scope —
        // the test harness exits soon after either way.
        std::mem::forget(cache_dir);
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
            byo: Arc::new(crate::config::ByoConfig::default()),
            webhooks: webhooks_svc,
            shares: shares_svc,
            artefact_cache,
            state_files,
            mcp_runtime_socket: None,
        };
        (state, users_store)
    }

    async fn spawn(state: AppState, auth: AuthState, user_auth: UserAuthState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(
            state,
            auth,
            user_auth,
            Router::new(),
            Router::new(),
            Router::new(),
        );
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
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
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
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn tenant_route_with_active_user_is_200() {
        let (state, user_auth, _user_id) = build_with_user("alice").await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn admin_route_without_admin_bearer_is_401() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/admin/users"))
            .await
            .unwrap();
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
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/instances"))
            .header("host", "swarm.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn host_dispatcher_403s_post_without_origin() {
        // Stage: F2 — Origin/Referer enforcement on dyson_proxy.
        // POST hits a sandbox subdomain with no Origin or Referer.  The
        // dispatcher must short-circuit before authentication and return
        // 403 with the canonical JSON shape.  This is what blocks the
        // classic CSRF vector even when SameSite enforcement is missing
        // or buggy.
        let (mut state, _) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let users = state.users.clone();
        let (alice_auth, _alice_id) = crate::auth::user::fixed_user_auth(users, "alice").await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let r = reqwest::Client::new()
            .post(format!("{base}/anything"))
            .header("host", "abc.swarm.test")
            .body("payload")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let body = r.text().await.unwrap();
        assert!(
            body.contains("cross-origin request rejected"),
            "expected canonical error body, got {body:?}"
        );
    }

    #[tokio::test]
    async fn host_dispatcher_passes_post_with_matching_origin() {
        // Same shape as above but with a matching Origin header.  The
        // CSRF gate lets it through — we then hit the auth path, which
        // 401s because no Authorization header is present.  The point of
        // the test is that the request reached auth (i.e. was NOT
        // rejected as cross-origin).
        let (mut state, users) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::Client::new()
            .post(format!("{base}/anything"))
            .header("host", "abc.swarm.test")
            .header("origin", "https://abc.swarm.test")
            .body("payload")
            .send()
            .await
            .unwrap();
        // Not 403 (cross-origin).  401 from the auth layer is the
        // expected next-step rejection.
        assert_ne!(
            r.status(),
            403,
            "request was incorrectly cross-origin-rejected"
        );
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn host_dispatcher_redirects_browser_get_to_login() {
        // Logged-out browser opens https://abc.swarm.test/some/path.
        // dyson_proxy can't satisfy the request, but a bare 401 on a
        // top-level navigation is a dead end — the user has no way to
        // recover.  Bounce them to the apex with `?return_to=<url>`
        // so the SPA can run the OIDC flow and navigate back.
        let (mut state, users) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = client
            .get(format!("{base}/some/path?x=1"))
            .header("host", "abc.swarm.test")
            .header("accept", "text/html,application/xhtml+xml")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 302);
        let loc = r.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            loc.starts_with("https://swarm.test/?return_to="),
            "unexpected Location: {loc}"
        );
        assert!(
            loc.contains("https%3A%2F%2Fabc.swarm.test%2Fsome%2Fpath%3Fx%3D1"),
            "Location did not preserve original URL: {loc}"
        );
    }

    #[tokio::test]
    async fn host_dispatcher_keeps_401_for_xhr() {
        // Same shape as above but `Accept: application/json` — the SPA's
        // fetch wrapper handles 401 explicitly, so a 302 here would be
        // silently followed by reqwest/fetch and confuse the caller.
        let (mut state, users) = build_state().await;
        state.hostname = Some("swarm.test".into());
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = client
            .get(format!("{base}/api/whatever"))
            .header("host", "abc.swarm.test")
            .header("accept", "application/json")
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
        let (alice_auth, _alice_id) = crate::auth::user::fixed_user_auth(users, "alice").await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
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
        let r = reqwest::get(format!("{base}/v1/admin/users"))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers()
                .get("x-swarm-insecure")
                .map(|v| v.to_str().unwrap()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn auth_config_is_unauthenticated_and_reports_none_by_default() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
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
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
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
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
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
