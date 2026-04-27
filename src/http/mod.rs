//! HTTP server assembly.
//!
//! - `/healthz` is unauthenticated (load balancers must reach it without a
//!   bearer).
//! - `/v1/*` (instances, snapshots, secrets, admin) is wrapped in the
//!   admin-bearer middleware.
//! - `/llm/*` (the LLM proxy, step 14) is mounted with its own
//!   per-instance-bearer middleware in [`crate::proxy::http`].
//!
//! Each sub-module exports a `router(state)` factory; this module decides
//! which auth layer wraps which subtree.

pub mod healthz;
pub mod instances;
pub mod secrets;
pub mod snapshots;

use std::sync::Arc;

use axum::{middleware, Router};

use crate::auth::{admin_bearer, AuthState};
use crate::instance::InstanceService;
use crate::secrets::SecretsService;
use crate::snapshot::SnapshotService;

/// Shared state handed to every route handler. Cheap to clone — every field
/// is an `Arc` or scalar `String`.
#[derive(Clone)]
pub struct AppState {
    pub secrets: Arc<SecretsService>,
    pub instances: Arc<InstanceService>,
    pub snapshots: Arc<SnapshotService>,
    pub sandbox_domain: String,
}

/// Build the public `Router`.
///
/// `auth` decides whether `/v1/*` requires an admin bearer or runs in
/// `--dangerous-no-auth` pass-through mode. `extra` lets the caller mount
/// additional subtrees (e.g. the LLM proxy at `/llm/*`) outside the admin
/// auth layer; pass `Router::new()` if there are none.
pub fn router(state: AppState, auth: AuthState, extra: Router) -> Router {
    let v1 = Router::new()
        .merge(instances::router(state.clone()))
        .merge(snapshots::router(state.clone()))
        .merge(secrets::router(state))
        .layer(middleware::from_fn_with_state(auth, admin_bearer));

    Router::new().merge(healthz::router()).merge(v1).merge(extra)
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
        BackupSink, CreateSandboxArgs, CubeClient, InstanceStore, SandboxInfo, SecretStore,
        SnapshotInfo, TokenStore,
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

    async fn build_state() -> AppState {
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
            tokens_store,
            "http://test/llm",
            3600,
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store,
            backup,
            instance_svc.clone(),
            pool,
        ));
        AppState {
            secrets: svc,
            instances: instance_svc,
            snapshots: snapshot_svc,
            sandbox_domain: "cube.test".into(),
        }
    }

    async fn spawn(state: AppState, auth: AuthState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state, auth, Router::new());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn healthz_is_open() {
        let state = build_state().await;
        let base = spawn(state, AuthState::enforced("s3cr3t")).await;
        let r = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn v1_without_bearer_is_401() {
        let state = build_state().await;
        let base = spawn(state, AuthState::enforced("s3cr3t")).await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn v1_with_correct_bearer_is_200() {
        let state = build_state().await;
        let base = spawn(state, AuthState::enforced("s3cr3t")).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/v1/instances"))
            .bearer_auth("s3cr3t")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("x-warden-insecure").is_none());
    }

    #[tokio::test]
    async fn dangerous_no_auth_passes_with_marker_header() {
        let state = build_state().await;
        let base = spawn(state, AuthState::dangerous_no_auth()).await;
        let r = reqwest::get(format!("{base}/v1/instances")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers().get("x-warden-insecure").map(|v| v.to_str().unwrap()),
            Some("1")
        );
    }

    #[tokio::test]
    async fn healthz_does_not_emit_insecure_header() {
        // The marker header is scoped to /v1/* — /healthz must not advertise
        // an auth posture (it wasn't subject to the auth layer in the first
        // place).
        let state = build_state().await;
        let base = spawn(state, AuthState::dangerous_no_auth()).await;
        let r = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("x-warden-insecure").is_none());
    }
}
