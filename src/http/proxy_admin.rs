//! Admin endpoints for the LLM proxy.
//!
//! - `POST /v1/admin/proxy_tokens/:token/revoke` — emergency revocation by
//!   token value. Useful when a leaked token must be invalidated without
//!   destroying the instance.
//!
//! Mounted under `/v1/*` so the admin-bearer middleware applies.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;

use crate::http::{secrets::store_err_to_status, AppState};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/proxy_tokens/:token/revoke", post(revoke))
        .with_state(state)
}

async fn revoke(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> StatusCode {
    let resolved = match state.tokens.resolve(&token).await {
        Ok(r) => r,
        Err(e) => return store_err_to_status(e),
    };
    let Some(rec) = resolved else {
        // Either the token never existed or it's already revoked. Both are
        // observably the same to the admin: the token cannot be used. 404
        // distinguishes "no such token row" from a successful revoke.
        return StatusCode::NOT_FOUND;
    };
    match state.tokens.revoke_for_instance(&rec.instance_id).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::auth::AuthState;
    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::http::AppState;
    use crate::instance::InstanceService;
    use crate::secrets::SecretsService;
    use crate::snapshot::SnapshotService;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus,
        InstanceStore, ProbeResult, SandboxInfo, SecretStore, SnapshotInfo, TokenStore,
    };

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

    struct StubProber;

    #[async_trait::async_trait]
    impl HealthProber for StubProber {
        async fn probe(&self, _: &InstanceRow) -> ProbeResult {
            ProbeResult::Healthy
        }
    }

    async fn build() -> (AppState, Arc<dyn TokenStore>, String) {
        let pool = open_in_memory().await.unwrap();
        let raw: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let svc = Arc::new(SecretsService::new(raw.clone()));
        let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone()));
        let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let instance_svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            raw.clone(),
            tokens_store.clone(),
            "http://test/llm",
            3600,
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn crate::traits::SnapshotStore> =
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store.clone(),
            snapshots_store,
            backup,
            instance_svc.clone(),
        ));
        let id = "i1".to_string();
        instances_store
            .create(InstanceRow {
                id: id.clone(),
                owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
                cube_sandbox_id: None,
                template_id: "t".into(),
                status: InstanceStatus::Live,
                bearer_token: "b".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: None,
            })
            .await
            .unwrap();
        let token = tokens_store.mint(&id, "*").await.unwrap();
        let users_store: Arc<dyn crate::traits::UserStore> =
            Arc::new(crate::db::users::SqlxUserStore::new(pool));
        let state = AppState {
            secrets: svc,
            instances: instance_svc,
            snapshots: snapshot_svc,
            users: users_store,
            prober: Arc::new(StubProber),
            tokens: tokens_store.clone(),
            sandbox_domain: "cube.test".into(),
            hostname: None,
            auth_config: Arc::new(crate::http::auth_config::AuthConfig::None),
            dyson_http: crate::http::dyson_proxy::build_client().expect("dyson http client init"),
        };
        (state, tokens_store, token)
    }

    async fn spawn(state: AppState) -> String {
        // proxy_admin endpoints are admin-bearer-gated, so we only need a
        // permissive admin posture. The user middleware never runs on admin
        // routes, so any UserAuthState works here.
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
        let user_auth =
            crate::auth::UserAuthState::new(Arc::new(AlwaysMissing), state.users.clone());
        let app = crate::http::router(
            state,
            AuthState::dangerous_no_auth(),
            user_auth,
            axum::Router::new(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn revoke_known_token_returns_204_and_token_no_longer_resolves() {
        let (state, tokens, token) = build().await;
        let base = spawn(state).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/proxy_tokens/{token}/revoke"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert!(tokens.resolve(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_unknown_token_returns_404() {
        let (state, _tokens, _token) = build().await;
        let base = spawn(state).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/proxy_tokens/nope/revoke"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }
}
