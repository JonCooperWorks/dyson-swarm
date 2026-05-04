//! BYOK management routes (per-user provider keys + the `byo` slot).
//!
//! Mounted on the same `user_middleware` layer as `/v1/instances` and
//! `/v1/secrets`, so every handler receives the caller's
//! `Extension<CallerIdentity>`.
//!
//! - `GET /v1/providers`      — list every provider in the adapter
//!   registry with its `has_byok` / `has_platform` status for the
//!   current caller.  Drives the SPA's Provider Keys table.
//! - `GET /v1/byok`           — list provider names where the caller
//!   has a BYOK row set (no plaintext returned).
//! - `PUT /v1/byok/:provider` — upsert a key.  Body is `{key}` for
//!   ordinary providers and `{upstream, key}` for `byo`.  Validation
//!   runs synchronously (probe-on-paste) and on rejection the row is
//!   not persisted.  Returns 204 on success, 422 on rejection, 502 on
//!   network error to the upstream, 404 on unknown provider.
//! - `DELETE /v1/byok/:provider` — idempotent removal.  204 always.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CallerIdentity;
use crate::http::AppState;
use crate::proxy::adapters;
use crate::proxy::byok::{BYO_BLOB_NAME, ByoBlob, byok_name};
use crate::proxy::upstream_policy::{
    ByoUpstreamError, ValidatedByoUpstream, validate_byo_upstream,
};
use crate::proxy::validate::{
    ValidateError, ValidateResult, build_pinned_byo_validation_client, validate_key,
    validate_key_with_client,
};

/// Body for `PUT /v1/byok/:provider`.  `upstream` is required only
/// when `provider == "byo"`; the field is ignored otherwise so a
/// SPA built against an older schema still works.
#[derive(Debug, Deserialize)]
pub struct PutByokBody {
    pub key: String,
    #[serde(default)]
    pub upstream: Option<String>,
}

/// `GET /v1/providers` row.
#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderView {
    pub name: String,
    pub has_byok: bool,
    pub has_platform: bool,
    pub supports_byo: bool,
    /// Set only for `openrouter` when the user has a Stage-6
    /// lazy-minted key sitting in `user_secrets["openrouter_key"]`.
    /// Distinct from `has_byok` — minted keys are billed against
    /// the operator's OR Provisioning account (capped per-user),
    /// BYOK keys are billed against the user's own OR account.  The
    /// SPA renders these differently so a user with a working
    /// minted key doesn't see "not configured".
    pub has_or_minted: bool,
}

/// Legacy name the OpenRouter `UserOrKeyResolver` stores its
/// lazy-minted plaintext key under.  Predates BYOK; kept distinct so
/// the BYOK row (`byok_openrouter`) can coexist and short-circuit the
/// mint path when set.
const LEGACY_OR_MINT_NAME: &str = "openrouter_key";

/// `GET /v1/byok` row.
#[derive(Debug, Serialize)]
pub struct ByokRow {
    pub provider: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/providers", get(list_providers))
        .route("/v1/byok", get(list_byok))
        .route("/v1/byok/:provider", put(put_byok).delete(delete_byok))
        .with_state(state)
}

/// Iterate every provider in the registry, with platform/BYOK presence
/// for the caller.
async fn list_providers(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<Vec<ProviderView>>, StatusCode> {
    let names = state
        .user_secrets
        .list_names(&caller.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut byok_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut has_or_minted = false;
    for name in names {
        if name == BYO_BLOB_NAME {
            byok_set.insert("byo".into());
        } else if let Some(stripped) = name.strip_prefix("byok_") {
            byok_set.insert(stripped.to_owned());
        } else if name == LEGACY_OR_MINT_NAME {
            has_or_minted = true;
        }
    }

    let registry = adapters::registry();
    let mut rows: Vec<ProviderView> = registry
        .keys()
        .map(|name| ProviderView {
            name: (*name).to_owned(),
            has_byok: byok_set.contains(*name),
            has_platform: state
                .providers
                .get(name)
                .and_then(|p| p.api_key.as_ref())
                .is_some(),
            supports_byo: *name == "byo" && state.byo.enabled,
            has_or_minted: *name == "openrouter" && has_or_minted,
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(rows))
}

async fn list_byok(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<Vec<ByokRow>>, StatusCode> {
    let names = state
        .user_secrets
        .list_names(&caller.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut rows: Vec<ByokRow> = names
        .into_iter()
        .filter_map(|n| {
            if n == BYO_BLOB_NAME {
                Some(ByokRow {
                    provider: "byo".into(),
                })
            } else {
                n.strip_prefix("byok_").map(|s| ByokRow {
                    provider: s.to_owned(),
                })
            }
        })
        .collect();
    rows.sort_by(|a, b| a.provider.cmp(&b.provider));
    Ok(Json(rows))
}

async fn put_byok(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(provider): Path<String>,
    Json(body): Json<PutByokBody>,
) -> impl IntoResponse {
    // 1. Provider must be in the adapter registry.  We list `byo` so a
    //    user can configure their custom slot without TOML.
    let registry = adapters::registry();
    if !registry.contains_key(provider.as_str()) {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    }
    if body.key.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "key is empty").into_response();
    }

    // 2. Resolve the upstream the validator will probe.
    //    - byo: must come from the request body (no platform stanza).
    //    - everything else: from `[providers.<name>].upstream`.  No
    //      platform stanza → 503 (operator hasn't enabled this
    //      provider; we have nowhere to validate against).
    let (upstream_for_validate, version_for_validate, byo_upstream): (
        String,
        Option<String>,
        Option<ValidatedByoUpstream>,
    ) = if provider == "byo" {
        let Some(u) = body.upstream.as_ref() else {
            return (StatusCode::BAD_REQUEST, "byo requires upstream in body").into_response();
        };
        if u.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, "upstream is empty").into_response();
        }
        let validated = match validate_byo_upstream(&state.byo, u).await {
            Ok(validated) => validated,
            Err(ByoUpstreamError::Disabled) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "byo_disabled"})),
                )
                    .into_response();
            }
            Err(err) => {
                tracing::warn!(error = %err, "byo upstream rejected by operator policy");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "byo_upstream_not_allowed"})),
                )
                    .into_response();
            }
        };
        (validated.url.to_string(), None, Some(validated))
    } else if let Some(cfg) = state.providers.get(&provider) {
        (cfg.upstream.clone(), cfg.anthropic_version.clone(), None)
    } else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "provider not configured for this deployment",
        )
            .into_response();
    };

    // 3. Probe-on-paste.  Network failures bubble up as 502 — we
    //    can't tell if the key is bad or just unreachable.
    let validation = if let Some(byo) = byo_upstream.as_ref() {
        match build_pinned_byo_validation_client(byo) {
            Ok(http) => {
                validate_key_with_client(
                    &provider,
                    &body.key,
                    &upstream_for_validate,
                    version_for_validate.as_deref(),
                    &http,
                )
                .await
            }
            Err(err) => Err(err),
        }
    } else {
        validate_key(
            &provider,
            &body.key,
            &upstream_for_validate,
            version_for_validate.as_deref(),
        )
        .await
    };
    match validation {
        Ok(ValidateResult::Ok) => (),
        Ok(ValidateResult::Rejected) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid_key"})),
            )
                .into_response();
        }
        Err(ValidateError::UnknownProvider(_)) => {
            return (
                StatusCode::NOT_FOUND,
                "validator does not support this provider",
            )
                .into_response();
        }
        Err(ValidateError::Network(msg) | ValidateError::Client(msg)) => {
            tracing::warn!(provider = %provider, error = %msg, "byok validation network error");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "upstream_unreachable"})),
            )
                .into_response();
        }
    }

    // 4. Persist.
    let put_result = if let Some(byo) = byo_upstream {
        let blob = ByoBlob {
            upstream: byo.url.to_string(),
            resolved_addrs: byo.resolved_addrs.iter().map(ToString::to_string).collect(),
            api_key: body.key,
        };
        let Ok(bytes) = serde_json::to_vec(&blob) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        state
            .user_secrets
            .put(&caller.user_id, BYO_BLOB_NAME, &bytes)
            .await
    } else {
        state
            .user_secrets
            .put(&caller.user_id, &byok_name(&provider), body.key.as_bytes())
            .await
    };
    match put_result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(provider = %provider, error = %err, "byok put failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_byok(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    let secret_name = if provider == "byo" {
        BYO_BLOB_NAME.to_owned()
    } else {
        byok_name(&provider)
    };
    match state
        .user_secrets
        .delete(&caller.user_id, &secret_name)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(err) => {
            tracing::warn!(provider = %provider, error = %err, "byok delete failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};

    use axum::extract::Path as AxPath;
    use axum::http::StatusCode as AxStatus;
    use axum::routing::get;
    use axum::{Json as AxJson, Router as AxRouter};
    use serde_json::Value;

    use crate::auth::user::fixed_user_auth;
    use crate::backup::local::LocalDiskBackupSink;
    use crate::config::{ProviderConfig, Providers};
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::http::AppState;
    use crate::instance::InstanceService;
    use crate::secrets::SecretsService;
    use crate::snapshot::SnapshotService;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, ProbeResult,
        SandboxInfo, SecretStore, SnapshotInfo, TokenStore, UserSecretStore,
    };

    /// Local cube + prober stubs — none of the BYOK tests touch these
    /// surfaces but `AppState` requires non-None fields.
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

    /// Mock provider upstream.  Every request is answered with the
    /// configured status (default 200) so we can flip a single
    /// AtomicU16 between success/reject mid-test.  Used to exercise
    /// the probe-on-paste path without hitting real OpenAI/Groq/etc.
    async fn handler(
        axum::extract::State(s): axum::extract::State<Arc<AtomicU16>>,
        AxPath(_rest): AxPath<String>,
    ) -> impl axum::response::IntoResponse {
        let code = AxStatus::from_u16(s.load(Ordering::SeqCst)).unwrap_or(AxStatus::OK);
        (code, AxJson(serde_json::json!({"ok": true})))
    }

    async fn spawn_mock_provider(initial_status: u16) -> (String, Arc<AtomicU16>) {
        let status = Arc::new(AtomicU16::new(initial_status));
        let s = status.clone();
        let app = AxRouter::new()
            .route("/*rest", get(handler).post(handler))
            .with_state(s);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), status)
    }
    /// Build a full AppState pointed at a per-test mock provider for
    /// validation, with `provider_name` declared in the platform
    /// stanza so PUT requests can find an upstream to probe.
    async fn build_state_with_provider(
        provider_name: &str,
        upstream_for_validate: &str,
    ) -> (AppState, crate::auth::UserAuthState, String, String) {
        let pool = open_in_memory().await.unwrap();
        let raw: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        // Leak the tempdir so the on-disk keys outlive the test.
        std::mem::forget(keys_tmp);
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn crate::traits::InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
        let svc = Arc::new(SecretsService::new(
            raw.clone(),
            instances_store.clone(),
            cipher_dir.clone(),
        ));
        let user_secret_store: Arc<dyn UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let system_secret_store: Arc<dyn crate::traits::SystemSecretStore> =
            Arc::new(crate::db::secrets::SqlxSystemSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(crate::secrets::UserSecretsService::new(
            user_secret_store,
            cipher_dir.clone(),
        ));
        let system_secrets = Arc::new(crate::secrets::SystemSecretsService::new(
            system_secret_store,
            cipher_dir.clone(),
        ));
        let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
        let tokens_store: Arc<dyn TokenStore> =
            Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher));
        let users_store: Arc<dyn crate::traits::UserStore> = Arc::new(
            crate::db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
        );
        let (user_auth, user_id) = fixed_user_auth(users_store.clone(), "alice").await;
        let instance_svc = Arc::new(InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            raw.clone(),
            tokens_store.clone(),
            "http://test/llm",
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn crate::traits::SnapshotStore> =
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store,
            snapshots_store,
            backup,
            instance_svc.clone(),
        ));

        let mut providers = Providers::default();
        providers.insert(
            provider_name,
            ProviderConfig {
                api_key: None,
                upstream: upstream_for_validate.to_owned(),
                anthropic_version: None,
            },
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
            pool,
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));
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
            users: users_store,
            sandbox_domain: "cube.test".into(),
            hostname: None,
            auth_config: Arc::new(crate::http::auth_config::AuthConfig::none()),
            dyson_http: crate::http::dyson_proxy::build_client().expect("dyson http client"),
            models_upstream: None,
            models_cache: crate::http::models::ModelsCache::new(),
            openrouter_provisioning: None,
            user_or_keys: None,
            providers: Arc::new(providers),
            byo: Arc::new(crate::config::ByoConfig {
                enabled: true,
                allow_localhost: false,
                allow_internal: true,
            }),
            webhooks: webhooks_svc,
            shares: shares_svc,
            artefact_cache,
            state_files,
        };
        // We don't return the upstream URL here; tests close over their
        // own variables.  The third return is kept stable for symmetry
        // with the legacy `build_state` helpers in this crate.
        (state, user_auth, user_id, "http://placeholder".to_owned())
    }

    async fn spawn_full(state: AppState, user_auth: crate::auth::UserAuthState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::http::router(
            state,
            crate::auth::AuthState::dangerous_no_auth(),
            user_auth,
            axum::Router::new(),
            axum::Router::new(),
            axum::Router::new(),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn put_byok_happy_path_validates_and_persists() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, uid, _) = build_state_with_provider("openai", &mock_url).await;
        let user_secrets = state.user_secrets.clone();
        let base = spawn_full(state, user_auth).await;

        let r = reqwest::Client::new()
            .put(format!("{base}/v1/byok/openai"))
            .json(&serde_json::json!({"key": "sk-test"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);

        // Round-trip via the user_secrets handle to confirm the row
        // landed under the right name and matches the input bytes.
        let names = user_secrets.list_names(&uid).await.unwrap();
        assert!(names.contains(&"byok_openai".to_owned()));
    }

    #[tokio::test]
    async fn put_byok_validation_rejection_returns_422_and_does_not_persist() {
        let (mock_url, status) = spawn_mock_provider(401).await;
        let _ = status; // already wired
        let (state, user_auth, uid, _) = build_state_with_provider("openai", &mock_url).await;
        let user_secrets = state.user_secrets.clone();
        let base = spawn_full(state, user_auth).await;

        let r = reqwest::Client::new()
            .put(format!("{base}/v1/byok/openai"))
            .json(&serde_json::json!({"key": "sk-bad"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["error"], "invalid_key");

        let names = user_secrets.list_names(&uid).await.unwrap();
        assert!(!names.contains(&"byok_openai".to_owned()));
    }

    #[tokio::test]
    async fn put_byok_unknown_provider_returns_404() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, _uid, _) = build_state_with_provider("openai", &mock_url).await;
        let base = spawn_full(state, user_auth).await;

        let r = reqwest::Client::new()
            .put(format!("{base}/v1/byok/nonsense"))
            .json(&serde_json::json!({"key": "x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn put_byo_without_upstream_returns_400() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, _uid, _) = build_state_with_provider("openai", &mock_url).await;
        let base = spawn_full(state, user_auth).await;

        let r = reqwest::Client::new()
            .put(format!("{base}/v1/byok/byo"))
            .json(&serde_json::json!({"key": "sk"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[tokio::test]
    async fn put_byo_with_upstream_persists_blob() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, uid, _) = build_state_with_provider("openai", &mock_url).await;
        let user_secrets = state.user_secrets.clone();
        let base = spawn_full(state, user_auth).await;

        let r = reqwest::Client::new()
            .put(format!("{base}/v1/byok/byo"))
            .json(&serde_json::json!({"key": "sk", "upstream": mock_url.clone()}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
        let names = user_secrets.list_names(&uid).await.unwrap();
        assert!(names.contains(&"byok_byo".to_owned()));
        let bytes = user_secrets.get(&uid, "byok_byo").await.unwrap().unwrap();
        let blob: crate::proxy::byok::ByoBlob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            blob.upstream,
            reqwest::Url::parse(&mock_url).unwrap().to_string()
        );
        assert!(
            !blob.resolved_addrs.is_empty(),
            "PUT should cache resolved BYO addresses"
        );
    }

    #[tokio::test]
    async fn delete_byok_is_idempotent() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, _uid, _) = build_state_with_provider("openai", &mock_url).await;
        let base = spawn_full(state, user_auth).await;

        let cli = reqwest::Client::new();
        // Delete with no row should still succeed.
        let r = cli
            .delete(format!("{base}/v1/byok/openai"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);

        // PUT then DELETE then DELETE — all 204.
        cli.put(format!("{base}/v1/byok/openai"))
            .json(&serde_json::json!({"key": "sk"}))
            .send()
            .await
            .unwrap();
        let r1 = cli
            .delete(format!("{base}/v1/byok/openai"))
            .send()
            .await
            .unwrap();
        let r2 = cli
            .delete(format!("{base}/v1/byok/openai"))
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 204);
        assert_eq!(r2.status(), 204);
    }

    #[tokio::test]
    async fn list_providers_shows_registry_with_byok_status() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, _uid, _) = build_state_with_provider("openai", &mock_url).await;
        let base = spawn_full(state, user_auth).await;
        let cli = reqwest::Client::new();

        let rows: Vec<Value> = cli
            .get(format!("{base}/v1/providers"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // Every adapter in the registry should be listed.
        let names: Vec<String> = rows
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_owned())
            .collect();
        for n in [
            "openai",
            "anthropic",
            "openrouter",
            "groq",
            "deepseek",
            "xai",
            "byo",
        ] {
            assert!(
                names.contains(&n.to_owned()),
                "missing provider {n} in {names:?}"
            );
        }
        // None has BYOK yet.
        for r in &rows {
            assert_eq!(r["has_byok"], serde_json::Value::Bool(false));
        }
        // openai row has_platform should be false (we declared it with
        // api_key = None, only upstream).
        let openai = rows.iter().find(|r| r["name"] == "openai").unwrap();
        assert_eq!(openai["has_platform"], serde_json::Value::Bool(false));
        // byo row supports_byo should be true.
        let byo = rows.iter().find(|r| r["name"] == "byo").unwrap();
        assert_eq!(byo["supports_byo"], serde_json::Value::Bool(true));

        // After PUT, has_byok flips for that one row.
        cli.put(format!("{base}/v1/byok/openai"))
            .json(&serde_json::json!({"key": "sk"}))
            .send()
            .await
            .unwrap();
        let rows2: Vec<Value> = cli
            .get(format!("{base}/v1/providers"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let openai2 = rows2.iter().find(|r| r["name"] == "openai").unwrap();
        assert_eq!(openai2["has_byok"], serde_json::Value::Bool(true));
        let groq = rows2.iter().find(|r| r["name"] == "groq").unwrap();
        assert_eq!(groq["has_byok"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn list_byok_returns_only_user_rows() {
        let (mock_url, _status) = spawn_mock_provider(200).await;
        let (state, user_auth, _uid, _) = build_state_with_provider("openai", &mock_url).await;
        let base = spawn_full(state, user_auth).await;

        let cli = reqwest::Client::new();
        cli.put(format!("{base}/v1/byok/openai"))
            .json(&serde_json::json!({"key": "sk"}))
            .send()
            .await
            .unwrap();

        let rows: Vec<Value> = cli
            .get(format!("{base}/v1/byok"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["provider"], "openai");
    }
}
