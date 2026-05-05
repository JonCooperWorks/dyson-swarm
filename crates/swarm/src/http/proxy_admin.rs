//! Admin endpoints for the LLM proxy.
//!
//! - `POST /v1/admin/proxy_tokens/:token/revoke` — emergency revocation by
//!   token value. Useful when a leaked token must be invalidated without
//!   destroying the instance.
//!
//! Mounted under `/v1/*` so the admin-bearer middleware applies.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;

use crate::http::{AppState, store_err_to_status};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/proxy_tokens/:token/revoke", post(revoke))
        .with_state(state)
}

async fn revoke(State(state): State<AppState>, Path(token): Path<String>) -> StatusCode {
    // Resolve first so we can 404 cleanly on unknown / already-revoked
    // tokens.  `resolve` returns None for both "never existed" and
    // "revoked", which is what we want: an admin retrying a revoke on
    // a token that's already gone gets 404, not a confusing 204.
    let resolved = match state.tokens.resolve(&token).await {
        Ok(r) => r,
        Err(e) => return store_err_to_status(e),
    };
    if resolved.is_none() {
        return StatusCode::NOT_FOUND;
    }
    // Surgical revoke: only this token row, not every token tied to
    // the instance.  The previous `revoke_for_instance` shape blew
    // away unrelated active tokens (e.g. a freshly-minted one issued
    // moments before the admin reacted to a leak alert); the per-
    // token revoke avoids that collateral damage.
    match state.tokens.revoke_token(&token).await {
        Ok(true) => StatusCode::NO_CONTENT,
        // The token was unrevoked when we resolved it but a concurrent
        // revoke beat us to it.  Treat as success-equivalent: the
        // post-condition (token unusable) holds either way, but 404
        // matches the "revoke called on absent token" path so admin
        // tooling can use a single response check.
        Ok(false) => StatusCode::NOT_FOUND,
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
    use crate::db::tokens::SqlxTokenStore;
    use crate::http::AppState;
    use crate::instance::InstanceService;
    use crate::snapshot::SnapshotService;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus,
        InstanceStore, ProbeResult, SandboxInfo, SnapshotInfo, TokenStore,
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
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
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
        let instance_svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            tokens_store.clone(),
            "http://test/llm",
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
                rotated_to: None,
                network_policy: crate::network_policy::NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
        let token = tokens_store.mint(&id, "*").await.unwrap();
        let users_store: Arc<dyn crate::traits::UserStore> = Arc::new(
            crate::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
        );
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
        let cache_dir = tempfile::tempdir().unwrap();
        let artefact_cache = Arc::new(crate::artefacts::ArtefactCacheService::new(
            pool.clone(),
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));
        let shares_svc = Arc::new(crate::shares::ShareService::new(
            pool.clone(),
            user_secrets.clone(),
            instance_svc.clone(),
            artefact_cache.clone(),
            crate::shares::ShareMetrics::new(),
            None,
        ));
        let state_files = Arc::new(crate::state_files::StateFileService::new(
            pool,
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));
        std::mem::forget(cache_dir);
        let state = AppState {
            user_secrets,
            system_secrets,
            ciphers: cipher_dir,
            instances: instance_svc,
            snapshots: snapshot_svc,
            users: users_store,
            prober: Arc::new(StubProber),
            tokens: tokens_store.clone(),
            sandbox_domain: "cube.test".into(),
            hostname: None,
            auth_config: Arc::new(crate::http::auth_config::AuthConfig::none()),
            dyson_http: crate::http::dyson_proxy::build_client().expect("dyson http client init"),
            models_upstream: None,
            models_cache: crate::http::models::ModelsCache::new(),
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
            axum::Router::new(),
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
