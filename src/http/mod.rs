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
pub mod healthz;
pub mod instances;
pub mod proxy_admin;
pub mod secrets;
pub mod snapshots;
pub mod static_assets;

use std::sync::Arc;

use axum::{middleware, Router};

use crate::auth::{admin_bearer, user_middleware, AuthState, UserAuthState};
use crate::instance::InstanceService;
use crate::secrets::SecretsService;
use crate::snapshot::SnapshotService;
use crate::traits::{HealthProber, TokenStore};

/// Shared state handed to every route handler. Cheap to clone — every field
/// is an `Arc` or scalar `String`.
#[derive(Clone)]
pub struct AppState {
    pub secrets: Arc<SecretsService>,
    pub instances: Arc<InstanceService>,
    pub snapshots: Arc<SnapshotService>,
    pub prober: Arc<dyn HealthProber>,
    pub tokens: Arc<dyn TokenStore>,
    pub users: Arc<dyn crate::traits::UserStore>,
    pub sandbox_domain: String,
    /// Auth-mode descriptor surfaced via `GET /auth/config`. Built from
    /// [`crate::config::Config`] at startup; the SPA hits this endpoint
    /// before mounting React to decide whether to start a PKCE flow.
    pub auth_config: Arc<auth_config::AuthConfig>,
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
    // Admin-only routes — keep the admin-bearer layer and skip user_middleware
    // so ops can manage users without an account themselves.
    let admin = proxy_admin::router(state.clone())
        .merge(crate::http::admin_users::router(state.clone()))
        .layer(middleware::from_fn_with_state(auth.clone(), admin_bearer));

    // Tenant routes — every request resolves to a CallerIdentity.
    let tenant = Router::new()
        .merge(instances::router(state.clone()))
        .merge(snapshots::router(state.clone()))
        .merge(secrets::router(state.clone()))
        .layer(middleware::from_fn_with_state(user_auth, user_middleware));

    // Static assets (SPA bundle) are merged last so the API routes win
    // every match.  The static router owns the fallback, which serves
    // `/`, `/assets/*`, and 404s anything else — no auth, no logging.
    Router::new()
        .merge(healthz::router())
        .merge(auth_config::router(state))
        .merge(admin)
        .merge(tenant)
        .merge(extra)
        .merge(static_assets::router())
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
        let svc = Arc::new(SecretsService::new(raw.clone()));
        let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone()));
        let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let users_store: Arc<dyn crate::traits::UserStore> =
            Arc::new(crate::db::users::SqlxUserStore::new(pool.clone()));
        let instance_svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            raw.clone(),
            tokens_store.clone(),
            "http://test/llm",
            3600,
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
            instances: instance_svc,
            snapshots: snapshot_svc,
            prober: Arc::new(StubProber),
            tokens: tokens_store,
            users: users_store.clone(),
            sandbox_domain: "cube.test".into(),
            auth_config: Arc::new(auth_config::AuthConfig::None),
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
            AuthState::enforced("admin-token"),
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
            AuthState::enforced("admin-token"),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn tenant_route_with_active_user_is_200() {
        let (state, user_auth, _user_id) = build_with_user("alice").await;
        let base = spawn(state, AuthState::enforced("admin-token"), user_auth).await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn admin_route_without_admin_bearer_is_401() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced("admin-token"),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::get(format!("{base}/v1/admin/users")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn admin_route_with_admin_bearer_is_200() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced("admin-token"),
            deny_user_auth(users),
        )
        .await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/admin/users"))
            .bearer_auth("admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn dangerous_no_auth_marker_header_on_admin_routes() {
        let (state, users) = build_state().await;
        let base = spawn(state, AuthState::dangerous_no_auth(), deny_user_auth(users)).await;
        let r = reqwest::get(format!("{base}/v1/admin/users")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers().get("x-warden-insecure").map(|v| v.to_str().unwrap()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn auth_config_is_unauthenticated_and_reports_none_by_default() {
        let (state, users) = build_state().await;
        let base = spawn(
            state,
            AuthState::enforced("admin-token"),
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
            AuthState::enforced("admin-token"),
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
            AuthState::enforced("admin-token"),
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
        assert!(r.headers().get("x-warden-insecure").is_none());
    }
}
