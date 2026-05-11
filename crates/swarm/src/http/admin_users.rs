//! Admin-only user management. Mounted under `/v1/admin/*` so the
//! admin-role middleware gates these calls.
//!
//! - `GET    /v1/admin/users` — list all users (auto-created + provisioned)
//! - `POST   /v1/admin/users/:id/activate` — flip status to `active`
//! - `POST   /v1/admin/users/:id/suspend` — flip status to `suspended`,
//!   revoke OR key upstream
//! - `POST   /v1/admin/users/:id/keys` — mint an opaque bearer for the user
//! - `DELETE /v1/admin/users/keys/:token` — revoke an api key by value
//! - `PATCH  /v1/admin/users/:id/openrouter_limit` — set OR USD cap
//! - `POST   /v1/admin/users/:id/openrouter_key/mint` — force a fresh
//!   mint, returns the plaintext once

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::http::{AppState, store_err_to_status};
use crate::openrouter::USER_OR_KEY_SECRET_NAME;
use crate::traits::{UserRow, UserStatus};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/users", get(list_users).post(create_user))
        .route("/v1/admin/users/:id/activate", post(activate))
        .route("/v1/admin/users/:id/suspend", post(suspend))
        .route("/v1/admin/users/:id/keys", post(mint_key))
        .route("/v1/admin/users/keys/:token", delete(revoke_key))
        .route("/v1/admin/users/:id/openrouter_limit", patch(set_or_limit))
        .route(
            "/v1/admin/users/:id/openrouter_key/mint",
            post(force_mint_or_key),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    /// Stable identity string. With OIDC this is the `sub` claim; for
    /// admin-bootstrapped users it can be anything unique (e.g. an
    /// email or a label).
    subject: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    /// Skip the inactive->active step when true. Equivalent to posting
    /// `/v1/admin/users/:id/activate` immediately after.
    #[serde(default)]
    activate: bool,
}

async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUserBody>,
) -> Result<(StatusCode, Json<UserView>), StatusCode> {
    let now = crate::now_secs();
    let initial_status = if body.activate {
        UserStatus::Active
    } else {
        UserStatus::Inactive
    };
    let row = UserRow {
        id: uuid::Uuid::new_v4().simple().to_string(),
        subject: body.subject,
        email: body.email,
        display_name: body.display_name,
        status: initial_status,
        created_at: now,
        activated_at: if body.activate { Some(now) } else { None },
        last_seen_at: None,
        openrouter_key_id: None,
        openrouter_key_limit_usd: 10.0,
    };
    match state.users.create(row.clone()).await {
        Ok(()) => Ok((StatusCode::CREATED, Json(UserView::from(row)))),
        Err(e) => Err(store_err_to_status(e)),
    }
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    /// True when swarm has minted an OR key for this user.  We don't
    /// surface the id itself — operators don't need it, and exposing
    /// it through the SPA's admin pane would invite copy-paste leaks.
    pub openrouter_key_present: bool,
    pub openrouter_key_limit_usd: f64,
}

impl From<UserRow> for UserView {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            subject: r.subject,
            email: r.email.as_deref().map(mask_email),
            display_name: r.display_name,
            status: r.status.as_str().into(),
            created_at: r.created_at,
            activated_at: r.activated_at,
            last_seen_at: r.last_seen_at,
            openrouter_key_present: r.openrouter_key_id.is_some(),
            openrouter_key_limit_usd: r.openrouter_key_limit_usd,
        }
    }
}

/// Render `alice@gmail.com` as `a***@gmail.com` for the admin
/// list view — operators can recognise their tenants without the
/// SPA pulling the full address over the wire.  Single-char locals
/// collapse to `***@domain` (no information leak from a one-letter
/// preview).  No-`@` strings collapse to a flat `***`; the input
/// shouldn't reach here but masking-not-asserting keeps the route
/// safe under malformed data.
fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_owned();
    };
    let mut chars = local.chars();
    match chars.next() {
        Some(first) if chars.next().is_some() => format!("{first}***@{domain}"),
        _ => format!("***@{domain}"),
    }
}

async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<UserView>>, StatusCode> {
    match state.users.list().await {
        Ok(rows) => Ok(Json(rows.into_iter().map(UserView::from).collect())),
        Err(e) => Err(store_err_to_status(e)),
    }
}

async fn activate(State(state): State<AppState>, Path(id): Path<String>) -> StatusCode {
    match state.users.set_status(&id, UserStatus::Active).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

async fn suspend(State(state): State<AppState>, Path(id): Path<String>) -> StatusCode {
    // Stage 6.5: revoke the user's OpenRouter key upstream BEFORE
    // flipping local status, so a leaked plaintext stops accruing
    // charges even if the local DB write fails.  Best-effort — we
    // log on failure and continue, since suspending a tenant whose
    // key is already gone (manual rotation, OR-side revoke) shouldn't
    // be blocked by the upstream call.
    if let Some(prov) = state.openrouter_provisioning.as_ref() {
        if let Ok(Some(user)) = state.users.get(&id).await
            && let Some(key_id) = user.openrouter_key_id.as_deref()
        {
            if let Err(err) = prov.delete(key_id).await {
                tracing::warn!(
                    error = %err,
                    user = %id,
                    or_key_id = %key_id,
                    "suspend: openrouter delete failed; continuing"
                );
            }
            // Wipe the local plaintext + id regardless of upstream
            // outcome.  If upstream still has the key, the operator
            // can reconcile via the OR dashboard.
            let _ = state
                .user_secrets
                .delete(&id, USER_OR_KEY_SECRET_NAME)
                .await;
            let _ = state.users.set_openrouter_key_id(&id, None).await;
        }
    }
    match state.users.set_status(&id, UserStatus::Suspended).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

#[derive(Debug, Deserialize)]
struct MintKeyBody {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct MintKeyResp {
    token: String,
}

async fn mint_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<MintKeyBody>,
) -> Result<(StatusCode, Json<MintKeyResp>), StatusCode> {
    match state.users.mint_api_key(&id, body.label.as_deref()).await {
        Ok(token) => Ok((StatusCode::CREATED, Json(MintKeyResp { token }))),
        Err(e) => Err(store_err_to_status(e)),
    }
}

async fn revoke_key(State(state): State<AppState>, Path(token): Path<String>) -> StatusCode {
    match state.users.revoke_api_key(&token).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => store_err_to_status(e),
    }
}

#[derive(Debug, Deserialize)]
struct SetLimitBody {
    /// New USD spend cap on the user's OR key.  Mirrored upstream
    /// when the user already has a key minted; otherwise just
    /// persisted (next lazy mint will use it).
    limit_usd: f64,
}

async fn set_or_limit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SetLimitBody>,
) -> StatusCode {
    if !body.limit_usd.is_finite() || body.limit_usd < 0.0 {
        return StatusCode::BAD_REQUEST;
    }
    let user = match state.users.get(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(e) => return store_err_to_status(e),
    };
    if let Err(e) = state.users.set_openrouter_limit(&id, body.limit_usd).await {
        return store_err_to_status(e);
    }
    if let (Some(prov), Some(key_id)) = (
        state.openrouter_provisioning.as_ref(),
        user.openrouter_key_id.as_deref(),
    ) {
        if let Err(err) = prov.update_limit(key_id, body.limit_usd).await {
            tracing::warn!(
                error = %err,
                user = %id,
                or_key_id = %key_id,
                "set_or_limit: openrouter PATCH failed; local row is updated"
            );
            // Don't fail the request — the local view is the source
            // of truth and the next mint/rotate will reconcile.
        }
    }
    StatusCode::NO_CONTENT
}

#[derive(Debug, Serialize)]
struct ForceMintResp {
    /// Plaintext key.  Surfaced once; the next call to this endpoint
    /// returns a different value because the previous one is wiped
    /// upstream.
    token: String,
    or_key_id: String,
}

async fn force_mint_or_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ForceMintResp>), StatusCode> {
    let resolver = state
        .user_or_keys
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Force a fresh mint by clearing the existing one (if any) first,
    // so the lazy-mint path picks "new key needed".  Upstream revoke
    // is best-effort.
    let user = match state.users.get(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => return Err(store_err_to_status(e)),
    };
    if let (Some(prov), Some(old_id)) = (
        state.openrouter_provisioning.as_ref(),
        user.openrouter_key_id.as_deref(),
    ) {
        let _ = prov.delete(old_id).await;
        let _ = state
            .user_secrets
            .delete(&id, USER_OR_KEY_SECRET_NAME)
            .await;
        let _ = state.users.set_openrouter_key_id(&id, None).await;
    }
    let plaintext = resolver.resolve_plaintext(&id).await.map_err(|err| {
        tracing::warn!(error = %err, user = %id, "force mint OR key failed");
        StatusCode::BAD_GATEWAY
    })?;
    // Re-read so we surface the new id.
    let new_id = match state.users.get(&id).await {
        Ok(Some(u)) => u.openrouter_key_id.unwrap_or_default(),
        _ => String::new(),
    };
    Ok((
        StatusCode::CREATED,
        Json(ForceMintResp {
            token: plaintext,
            or_key_id: new_id,
        }),
    ))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::tokens::SqlxTokenStore;
    use crate::openrouter::{MintedKey, OpenRouterError, Provisioning, UserOrKeyResolver};
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStore,
        ProbeResult, SandboxInfo, SnapshotInfo, SnapshotStore, TokenStore, UserStore,
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

    #[derive(Default)]
    struct StubProvisioning;

    #[async_trait::async_trait]
    impl Provisioning for StubProvisioning {
        async fn mint(
            &self,
            name: &str,
            _label: Option<&str>,
            limit_usd: f64,
        ) -> Result<MintedKey, OpenRouterError> {
            Ok(MintedKey {
                id: format!("or-{name}"),
                key: "sk-or-plaintext-admin-test".into(),
                name: Some(name.into()),
                label: None,
                limit: Some(limit_usd),
            })
        }

        async fn update_limit(&self, _id: &str, _limit_usd: f64) -> Result<(), OpenRouterError> {
            Ok(())
        }

        async fn delete(&self, _id: &str) -> Result<(), OpenRouterError> {
            Ok(())
        }
    }

    async fn create_admin_audit_fixture(pool: &sqlx::SqlitePool) {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                target_user TEXT NOT NULL,
                params_hash TEXT NOT NULL,
                ts INTEGER NOT NULL
            )",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn build_state() -> (
        AppState,
        Arc<dyn UserStore>,
        sqlx::SqlitePool,
        tempfile::TempDir,
    ) {
        let pool = open_in_memory().await.unwrap();
        create_admin_audit_fixture(&pool).await;
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
        let users_store: Arc<dyn UserStore> = Arc::new(crate::db::users::SqlxUserStore::new(
            pool.clone(),
            cipher_dir.clone(),
        ));
        let instance_svc = Arc::new(crate::instance::InstanceService::new(
            cube.clone(),
            instances_store.clone(),
            tokens_store.clone(),
            "http://test/llm",
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn SnapshotStore> =
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
        let snapshot_svc = Arc::new(crate::snapshot::SnapshotService::new(
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
        let artefact_cache = Arc::new(crate::artefacts::ArtefactCacheService::new(
            pool.clone(),
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
            pool.clone(),
            cipher_dir.clone(),
        ));
        let provisioning: Arc<dyn Provisioning> = Arc::new(StubProvisioning);
        let user_or_keys = Arc::new(UserOrKeyResolver::new(
            users_store.clone(),
            user_secrets.clone(),
            provisioning.clone(),
        ));
        let state = AppState {
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
            auth_config: Arc::new(crate::http::auth_config::AuthConfig::none()),
            dyson_http: crate::http::dyson_proxy::build_client()
                .expect("dyson http client init"),
            models_upstream: None,
            models_cache: crate::http::models::ModelsCache::new(),
            openrouter_provisioning: Some(provisioning),
            user_or_keys: Some(user_or_keys),
            providers: Arc::new(crate::config::Providers::default()),
            byo: Arc::new(crate::config::ByoConfig::default()),
            external_http: Arc::new(dyson_swarm_core::http::ExternalHttpClient::new(Arc::new(
                dyson_swarm_core::upstream_policy::OutboundUrlPolicy::default(),
            ))),
            webhooks: webhooks_svc,
            shares: shares_svc,
            artefact_cache,
            state_files,
            skill_marketplace: Arc::new(crate::skill_marketplace::SkillMarketplaceService::empty()),
            mcp_runtime_socket: None,
        };
        (state, users_store, pool, keys_tmp)
    }

    async fn spawn_admin(state: AppState, users: Arc<dyn UserStore>) -> String {
        let (user_auth, _) = crate::auth::user::fixed_user_auth_with_roles(
            users,
            "admin-subject",
            Some(("roles", &["admin"])),
        )
        .await;
        let app = crate::http::router(
            state,
            crate::auth::AuthState::enforced(crate::config::OidcRoles {
                claim: "roles".into(),
                admin: "admin".into(),
            }),
            user_auth,
            axum::Router::new(),
            axum::Router::new(),
            axum::Router::new(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn create_target_user(users: &dyn UserStore) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        users
            .create(UserRow {
                id: id.clone(),
                subject: format!("subject-{id}"),
                email: None,
                display_name: None,
                status: UserStatus::Inactive,
                created_at: 0,
                activated_at: None,
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
            })
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn mutating_admin_user_routes_write_hashed_audit_rows() {
        let (state, users, pool, _keys) = build_state().await;
        let target_user = create_target_user(users.as_ref()).await;
        let base = spawn_admin(state, users).await;
        let client = reqwest::Client::new();

        let activate_resp = client
            .post(format!("{base}/v1/admin/users/{target_user}/activate"))
            .send()
            .await
            .unwrap();
        assert_eq!(activate_resp.status(), StatusCode::NO_CONTENT);

        let mint_resp: serde_json::Value = client
            .post(format!("{base}/v1/admin/users/{target_user}/keys"))
            .json(&serde_json::json!({"label": "break-glass"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let api_token = mint_resp["token"].as_str().unwrap();

        let limit_resp = client
            .patch(format!(
                "{base}/v1/admin/users/{target_user}/openrouter_limit"
            ))
            .json(&serde_json::json!({"limit_usd": 42.0}))
            .send()
            .await
            .unwrap();
        assert_eq!(limit_resp.status(), StatusCode::NO_CONTENT);

        let force_resp = client
            .post(format!(
                "{base}/v1/admin/users/{target_user}/openrouter_key/mint"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(force_resp.status(), StatusCode::CREATED);

        let revoke_resp = client
            .delete(format!("{base}/v1/admin/users/keys/{api_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(revoke_resp.status(), StatusCode::NO_CONTENT);

        let suspend_resp = client
            .post(format!("{base}/v1/admin/users/{target_user}/suspend"))
            .send()
            .await
            .unwrap();
        assert_eq!(suspend_resp.status(), StatusCode::NO_CONTENT);

        let rows = sqlx::query(
            "SELECT actor_subject, action, target_user, params_hash, ts \
             FROM admin_audit ORDER BY id ASC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows.len(),
            6,
            "mutating admin user routes must write one admin_audit row each"
        );
        let actions: Vec<String> = rows
            .iter()
            .map(|row| sqlx::Row::try_get(row, "action").unwrap())
            .collect();
        assert_eq!(
            actions,
            vec![
                "activate",
                "mint_key",
                "set_openrouter_limit",
                "force_mint_or_key",
                "revoke_key",
                "suspend",
            ],
            "admin_audit actions must identify the mutating route"
        );
        for row in rows {
            let actor: String = sqlx::Row::try_get(&row, "actor_subject").unwrap();
            let target: String = sqlx::Row::try_get(&row, "target_user").unwrap();
            let params_hash: String = sqlx::Row::try_get(&row, "params_hash").unwrap();
            let ts: i64 = sqlx::Row::try_get(&row, "ts").unwrap();
            assert_eq!(
                actor, "admin-subject",
                "admin_audit actor_subject mismatch"
            );
            assert!(
                target == target_user || target == "<api-key>",
                "admin_audit target_user mismatch"
            );
            assert_eq!(
                params_hash.len(),
                64,
                "admin_audit params_hash must be a SHA-256 hex digest"
            );
            assert!(
                !params_hash.contains(api_token),
                "admin_audit params_hash must not contain plaintext parameters"
            );
            assert!(ts > 0, "admin_audit timestamp must be populated");
        }
    }

    #[tokio::test]
    async fn force_mint_openrouter_key_does_not_return_plaintext() {
        let (state, users, _pool, _keys) = build_state().await;
        let target_user = create_target_user(users.as_ref()).await;
        let base = spawn_admin(state, users).await;

        let body: serde_json::Value = reqwest::Client::new()
            .post(format!(
                "{base}/v1/admin/users/{target_user}/openrouter_key/mint"
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(
            body.get("token").is_none(),
            "force_mint_or_key must not return the plaintext OpenRouter key"
        );
        assert_eq!(
            body["or_key_id"].as_str(),
            Some(format!("or-{target_user}").as_str()),
            "force_mint_or_key should return only the OpenRouter key id"
        );
    }
}
