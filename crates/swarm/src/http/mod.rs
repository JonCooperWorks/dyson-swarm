//! HTTP server assembly.
//!
//! - `/healthz` is unauthenticated (load balancers must reach it without a
//!   bearer).
//! - `/v1/*` (instances, snapshots, admin) is wrapped in the
//!   admin-bearer middleware.
//! - `/llm/*` (the LLM proxy, step 14) is mounted with its own
//!   per-instance-bearer middleware in [`crate::proxy::http`].
//! - `/` and other unmatched paths fall through to the embedded React
//!   bundle (the SPA, served from [`static_assets`]).
//!
//! Each sub-module exports a `router(state)` factory; this module decides
//! which auth layer wraps which subtree.

pub mod admin_users;
pub mod agent_secrets;
pub mod assets;
pub mod auth_config;
pub mod auth_session;
pub mod byok;
pub mod channels;
pub mod dyson_proxy;
pub mod egress_admin;
pub mod healthz;
pub mod instance_artefacts;
pub mod instances;
pub mod internal_ingest;
pub mod internal_state;
pub mod kms_audit;
pub mod models;
pub mod proxy_admin;
pub mod share_public;
pub mod shares;
pub mod skill_marketplace;
pub mod skills;
pub mod snapshots;
pub mod static_assets;
pub mod tool_calls;
pub mod webhooks;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::{Router, middleware};

use crate::auth::{AuthState, UserAuthState, require_admin_role, user_middleware};
use crate::error::StoreError;
use crate::instance::InstanceService;
use crate::snapshot::SnapshotService;
use crate::traits::{HealthProber, TokenStore};

/// Shared state handed to every route handler. Cheap to clone — every field
/// is an `Arc` or scalar `String`.
#[derive(Clone)]
pub struct AppState {
    /// Per-user opaque blobs, encrypted with the user's own age key.
    /// Stages 3 + 6 use this for OpenRouter keys and (in future) any
    /// other per-user secret material.
    pub user_secrets: Arc<crate::secrets::UserSecretsService>,
    /// Agent-visible per-instance secrets. Values are encrypted under
    /// the owning user's envelope key and scoped to one instance.
    pub agent_secrets: Arc<crate::agent_secrets::AgentSecretsService>,
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
    pub sessions: Arc<dyn crate::traits::SessionStore>,
    pub admin_audit: Arc<dyn crate::traits::AdminAuditStore>,
    pub secret_access_audit: Arc<dyn crate::traits::SecretAccessAuditStore>,
    pub llm_tool_calls: Arc<dyn crate::traits::LlmToolCallStore>,
    pub egress_sync: Arc<dyn crate::egress_policy_sync::EgressPolicySync>,
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
    /// Shared internal HTTP client for the host-based reverse proxy. One per
    /// process so connection pooling survives across requests.
    pub dyson_http: dyson_swarm_core::http::InternalHttpClient,
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
    /// Shared constructor for admin/user-controlled outbound URLs. Each
    /// request still gets its own IP-pinned reqwest client.
    pub external_http: Arc<dyson_swarm_core::http::ExternalHttpClient>,
    /// Per-instance webhook ("tasks") service — backs both the
    /// management routes under `/v1/instances/:id/webhooks` and the
    /// public delivery endpoint `/webhooks/:id/:name`.
    pub webhooks: Arc<crate::webhooks::WebhookService>,
    /// Instance chat-surface channels. V1 is Telegram only; secrets stay
    /// in swarm and dyson talks to the bearer-protected Telegram proxy.
    pub channels: Arc<crate::channels::ChannelsService>,
    /// Anonymous artefact-share service — backs `/v1/instances/:id/...`
    /// admin CRUD and the public read path on `share.<apex>`.  Holds
    /// the share store, the per-user-secrets handle, and the metrics
    /// counters; stateless across requests.
    pub shares: Arc<crate::shares::ShareService>,
    /// Swarm-side cache of dyson-emitted artefacts.  Read-through and
    /// write-through: the share public path consults this before
    /// hitting the live cube, and ingests every cube response into it,
    /// so destroyed/reset cubes don't break still-active share URLs
    /// or the swarm UI's artefact list.
    pub artefact_cache: crate::artefacts::ArtefactCache,
    /// Swarm-owned selected dyson workspace/chat state files.
    /// Written by the internal state-sync endpoint with an `st_`
    /// generation-scoped bearer; bodies are encrypted before entering
    /// the store.
    pub state_files: crate::state_files::StateFiles,
    /// Shared skill marketplace catalog. Swarm owns catalog ingestion;
    /// Dyson instances install selected packages into their own workspaces.
    pub skill_marketplace: Arc<crate::skill_marketplace::SkillMarketplaceService>,
    /// Explicit public opt-in rows for agent-authored skills. A mirrored
    /// workspace skill can contain sensitive local instructions, so it only
    /// enters the marketplace after a user/admin publishes it here.
    pub agent_skill_publications: Arc<dyn crate::traits::AgentSkillPublicationStore>,
    /// Unix socket for the MCP runtime helper. Instance destroy uses
    /// it to tell the helper to stop any Docker/stdout sessions keyed
    /// to the instance before the sealed MCP rows disappear.
    pub mcp_runtime_socket: Option<PathBuf>,
}

pub(crate) fn store_err_to_status(e: StoreError) -> StatusCode {
    match e {
        StoreError::NotFound => StatusCode::NOT_FOUND,
        StoreError::Constraint(_) => StatusCode::CONFLICT,
        StoreError::Malformed(_) | StoreError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
        .merge(egress_admin::router(state.clone()))
        .merge(kms_audit::router(state.clone()))
        .merge(skill_marketplace::admin_router(state.clone()))
        .merge(mcp_admin_router);
    let admin = if auth.dangerous_no_auth {
        admin_handlers.layer(middleware::from_fn_with_state(auth, require_admin_role))
    } else {
        admin_handlers
            .layer(middleware::from_fn_with_state(auth, require_admin_role))
            .layer(middleware::from_fn_with_state(
                user_auth.clone(),
                user_middleware,
            ))
    };

    // Tenant routes — every request resolves to a CallerIdentity.
    let tenant = Router::new()
        .merge(instances::router(state.clone()))
        .merge(snapshots::router(state.clone()))
        .merge(byok::router(state.clone()))
        .merge(models::router(state.clone()))
        .merge(webhooks::router(state.clone()))
        .merge(channels::router(state.clone()))
        .merge(agent_secrets::router(state.clone()))
        .merge(shares::router(state.clone()))
        .merge(instance_artefacts::router(state.clone()))
        .merge(skill_marketplace::router(state.clone()))
        .merge(skills::router(state.clone()))
        .merge(tool_calls::router(state.clone()))
        .merge(mcp_user_router)
        .layer(middleware::from_fn_with_state(
            user_auth.clone(),
            user_middleware,
        ));

    // Static assets (SPA bundle) are merged last so the API routes win
    // every concrete match.  Its fallback serves `/`, `/assets/*`, and
    // browser document navigations for SPA deep links while keeping
    // API-like prefixes and missing assets as 404s.
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
        .merge(auth_session::router(state.clone(), user_auth.clone()))
        .merge(instances::internal_router(state.clone()))
        .merge(internal_ingest::router(state.clone()))
        .merge(agent_secrets::internal_router(state.clone()))
        .merge(internal_state::router(state.clone()))
        .merge(skill_marketplace::internal_router(state.clone()))
        .merge(webhooks::public_router(state.clone()))
        .merge(channels::public_router(state.clone()))
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
            state,
            share_public::dispatch,
        ))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::sqlite::instances::SqlxInstanceStore;
    use crate::db::sqlite::open_in_memory;
    use crate::db::sqlite::tokens::SqlxTokenStore;
    use crate::network_policy::NetworkPolicy;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus,
        InstanceStore, LlmToolCallEntry, ProbeResult, SandboxInfo, SnapshotInfo, SnapshotStore,
        TokenStore,
    };
    use futures::StreamExt as _;

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
        let (state, users, _) = build_state_with_instances().await;
        (state, users)
    }

    async fn build_state_with_instances() -> (
        AppState,
        Arc<dyn crate::traits::UserStore>,
        Arc<dyn InstanceStore>,
    ) {
        let pool = open_in_memory().await.unwrap();
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
        let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> = Arc::new(
            crate::db::sqlite::secrets::SqlxUserSecretStore::new(pool.clone()),
        );
        let system_secrets_store: Arc<dyn crate::traits::SystemSecretStore> = Arc::new(
            crate::db::sqlite::secrets::SqlxSystemSecretStore::new(pool.clone()),
        );
        let user_secrets = Arc::new(crate::secrets::UserSecretsService::new(
            user_secrets_store,
            cipher_dir.clone(),
        ));
        let agent_secret_store = crate::db::sqlite::agent_secret_store(pool.clone());
        let agent_secrets = Arc::new(crate::agent_secrets::AgentSecretsService::new(
            agent_secret_store.clone(),
            cipher_dir.clone(),
            crate::db::sqlite::secret_access_audit_store(pool.clone()),
        ));
        let system_secrets = Arc::new(crate::secrets::SystemSecretsService::new(
            system_secrets_store,
            cipher_dir.clone(),
        ));
        let cube: Arc<dyn CubeClient> = Arc::new(StubCube);
        let tokens_store: Arc<dyn TokenStore> =
            Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher));
        let users_store: Arc<dyn crate::traits::UserStore> = Arc::new(
            crate::db::sqlite::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()),
        );
        let sessions_store: Arc<dyn crate::traits::SessionStore> =
            crate::db::sqlite::session_store(pool.clone());
        let instance_svc = Arc::new(
            InstanceService::new(
                cube.clone(),
                instances_store.clone(),
                tokens_store.clone(),
                "http://test/llm",
            )
            .with_agent_secrets(agent_secret_store),
        );
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn SnapshotStore> =
            crate::db::sqlite::snapshot_store(pool.clone());
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube,
            instances_store.clone(),
            snapshots_store,
            backup,
            instance_svc.clone(),
        ));
        let webhook_store: Arc<dyn crate::traits::WebhookStore> = Arc::new(
            crate::db::sqlite::webhooks::SqlxWebhookStore::new(pool.clone()),
        );
        let delivery_store: Arc<dyn crate::traits::DeliveryStore> = Arc::new(
            crate::db::sqlite::webhooks::SqlxDeliveryStore::new(pool.clone()),
        );
        let webhooks_svc = Arc::new(crate::webhooks::WebhookService::new(
            webhook_store,
            delivery_store,
            user_secrets.clone(),
            instance_svc.clone(),
            Arc::new(crate::webhooks::NullWebhookDispatcher),
            cipher_dir.clone(),
        ));
        let artefact_cache = Arc::new(crate::artefacts::ArtefactCacheService::new(
            crate::db::sqlite::artefact_cache_store(pool.clone()),
            cipher_dir.clone(),
        ));
        let shares_svc = Arc::new(crate::shares::ShareService::new(
            crate::db::sqlite::share_store(pool.clone()),
            user_secrets.clone(),
            instance_svc.clone(),
            artefact_cache.clone(),
            crate::shares::ShareMetrics::new(),
            Some("swarm.test".into()),
        ));
        let state_files = Arc::new(crate::state_files::StateFileService::new(
            crate::db::sqlite::state_file_store(pool.clone()),
            cipher_dir.clone(),
        ));
        let state = AppState {
            user_secrets: user_secrets.clone(),
            agent_secrets,
            system_secrets,
            ciphers: cipher_dir,
            instances: instance_svc,
            snapshots: snapshot_svc,
            prober: Arc::new(StubProber),
            tokens: tokens_store,
            users: users_store.clone(),
            sessions: sessions_store,
            admin_audit: crate::db::sqlite::admin_audit_store(pool.clone()),
            secret_access_audit: crate::db::sqlite::secret_access_audit_store(pool.clone()),
            llm_tool_calls: crate::db::sqlite::llm_tool_call_store(pool.clone()),
            egress_sync: Arc::new(crate::egress_policy_sync::NoopEgressPolicySync::new()),
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
            external_http: Arc::new(dyson_swarm_core::http::ExternalHttpClient::new(Arc::new(
                dyson_swarm_core::upstream_policy::OutboundUrlPolicy::default(),
            ))),
            webhooks: webhooks_svc,
            channels: Arc::new(crate::channels::ChannelsService::new(
                crate::db::sqlite::instance_channel_store(pool.clone()),
                instances_store.clone(),
                user_secrets.clone(),
                Arc::new(crate::channels::NoopTelegramApi),
                Some("https://swarm.test".into()),
            )),
            shares: shares_svc,
            artefact_cache,
            state_files,
            skill_marketplace: Arc::new(crate::skill_marketplace::SkillMarketplaceService::empty()),
            agent_skill_publications: crate::db::sqlite::agent_skill_publication_store(
                pool.clone(),
            ),
            mcp_runtime_socket: None,
        };
        (state, users_store, instances_store)
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
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        format!("http://{addr}")
    }

    async fn build_with_user(subject: &str) -> (AppState, UserAuthState, String) {
        let (state, users) = build_state().await;
        let (user_auth, user_id) = crate::auth::user::fixed_user_auth(users, subject).await;
        (state, user_auth, user_id)
    }

    async fn token_bound_user_auth(
        users: Arc<dyn crate::traits::UserStore>,
        subject: &str,
        bearer: &str,
    ) -> (UserAuthState, String) {
        struct BearerOnly {
            bearer: String,
            identity: crate::auth::UserIdentity,
        }

        #[async_trait::async_trait]
        impl crate::auth::Authenticator for BearerOnly {
            async fn authenticate(
                &self,
                headers: &axum::http::HeaderMap,
            ) -> Result<crate::auth::UserIdentity, crate::auth::AuthError> {
                match crate::auth::extract_bearer(headers) {
                    Some(token) if token == self.bearer => Ok(self.identity.clone()),
                    Some(_) => Err(crate::auth::AuthError::Invalid(
                        "unexpected bearer".to_owned(),
                    )),
                    None => Err(crate::auth::AuthError::Missing),
                }
            }
        }

        let id = uuid::Uuid::new_v4().simple().to_string();
        users
            .create(crate::traits::UserRow {
                id: id.clone(),
                subject: subject.into(),
                email: None,
                display_name: None,
                status: crate::traits::UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
            })
            .await
            .expect("create test user");
        let identity = crate::auth::UserIdentity {
            subject: subject.into(),
            email: None,
            display_name: None,
            source: crate::auth::AuthSource::Oidc,
            claims: serde_json::Value::Null,
        };
        (
            UserAuthState::new(
                Arc::new(BearerOnly {
                    bearer: bearer.to_owned(),
                    identity,
                }),
                users,
            ),
            id,
        )
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

    async fn seed_owned_instance(
        instances: &Arc<dyn InstanceStore>,
        owner_id: &str,
        instance_id: &str,
    ) {
        instances
            .create(InstanceRow {
                id: instance_id.into(),
                owner_id: owner_id.into(),
                name: "agent".into(),
                task: "task".into(),
                cube_sandbox_id: Some("cube-1".into()),
                state_generation: "gen-1".into(),
                template_id: "tmpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "bearer".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: None,
                rotated_to: None,
                network_policy: NetworkPolicy::NoLocalNet,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .expect("seed instance");
    }

    fn seal_json_for_test(state: &AppState, owner_id: &str, value: serde_json::Value) -> Vec<u8> {
        let cipher =
            crate::envelope::CipherDirectory::for_user(state.ciphers.as_ref(), owner_id).unwrap();
        cipher.seal(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    async fn seed_tool_call(
        state: &AppState,
        owner_id: &str,
        instance_id: &str,
        use_id: &str,
        tool: &str,
        server: Option<&str>,
        called_at: i64,
        result: Option<(serde_json::Value, bool, i64)>,
    ) -> i64 {
        let id = state
            .llm_tool_calls
            .insert_call(&LlmToolCallEntry {
                llm_audit_id: None,
                owner_id: owner_id.into(),
                instance_id: instance_id.into(),
                tool_use_id: use_id.into(),
                tool_name: tool.into(),
                mcp_server: server.map(str::to_owned),
                input_sealed: Some(seal_json_for_test(
                    state,
                    owner_id,
                    serde_json::json!({"tool": tool, "needle": use_id}),
                )),
                called_at,
            })
            .await
            .unwrap();
        if let Some((value, is_error, resulted_at)) = result {
            let sealed = seal_json_for_test(state, owner_id, value);
            state
                .llm_tool_calls
                .attach_result(use_id, &sealed, is_error, resulted_at)
                .await
                .unwrap();
        }
        id
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
    async fn agent_secrets_user_routes_list_without_values_and_reveal() {
        let (state, users, instances) = build_state_with_instances().await;
        let (user_auth, owner_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &owner_id, "inst-a").await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let client = reqwest::Client::new();

        let put = client
            .put(format!("{base}/v1/instances/inst-a/agent-secrets/api_key"))
            .bearer_auth("alice-token")
            .json(&serde_json::json!({ "value": "super-secret" }))
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), 200);

        let list_body = client
            .get(format!("{base}/v1/instances/inst-a/agent-secrets"))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(list_body.contains("api_key"));
        assert!(!list_body.contains("super-secret"));

        let reveal: serde_json::Value = client
            .get(format!(
                "{base}/v1/instances/inst-a/agent-secrets/api_key/reveal"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reveal["value"], "super-secret");
    }

    #[tokio::test]
    async fn agent_secrets_user_cannot_access_another_owner_instance() {
        let (state, users, instances) = build_state_with_instances().await;
        let (user_auth, alice_id) =
            token_bound_user_auth(users.clone(), "alice", "alice-token").await;
        let (_bob_auth, bob_id) = token_bound_user_auth(users, "bob", "bob-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;
        seed_owned_instance(&instances, &bob_id, "inst-b").await;
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
            .get(format!("{base}/v1/instances/inst-b/agent-secrets"))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn agent_secrets_internal_token_is_scoped_to_its_instance() {
        let (state, users, instances) = build_state_with_instances().await;
        let (user_auth, owner_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &owner_id, "inst-a").await;
        seed_owned_instance(&instances, &owner_id, "inst-b").await;
        state
            .agent_secrets
            .put(
                &owner_id,
                "inst-b",
                "api_key",
                b"other-secret",
                crate::agent_secrets::AgentSecretActor::user(&owner_id),
            )
            .await
            .unwrap();
        let token = state.tokens.mint("inst-a", "*").await.unwrap();
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let client = reqwest::Client::new();

        let missing = client
            .get(format!("{base}/v1/internal/agent-secrets/api_key"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);

        let put = client
            .put(format!("{base}/v1/internal/agent-secrets/api_key"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "value": "own-secret" }))
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), 200);

        let got: serde_json::Value = client
            .get(format!("{base}/v1/internal/agent-secrets/api_key"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(got["value"], "own-secret");

        let list_body = client
            .get(format!("{base}/v1/internal/agent-secrets"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(list_body.contains("api_key"));
        assert!(!list_body.contains("own-secret"));

        let deleted = client
            .delete(format!("{base}/v1/internal/agent-secrets/api_key"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status(), 200);
    }

    #[tokio::test]
    async fn auth_session_sets_httponly_domain_cookie() {
        let (mut state, user_auth, _user_id) = build_with_user("alice").await;
        state.hostname = Some("swarm.example.com".into());
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
            .post(format!("{base}/auth/session"))
            .bearer_auth("access.jwt.token")
            .json(&serde_json::json!({ "expires_at": crate::now_secs() + 3600 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
        let cookie = r
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .expect("session response must set cookie")
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("dyson_swarm_session=ses_"));
        assert!(
            !cookie.contains("access.jwt.token"),
            "session cookie must not contain the OIDC JWT"
        );
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Domain=swarm.example.com"));

        let r = reqwest::Client::new()
            .delete(format!("{base}/auth/session"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
        let cookie = r
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .expect("clear response must clear cookie")
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("dyson_swarm_session=;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn auth_session_logout_revokes_prior_cookie_identity() {
        let (mut state, users, instances) = build_state_with_instances().await;
        state.hostname = Some("swarm.test".into());
        let (user_auth, user_id) = token_bound_user_auth(users, "alice", "future.jwt.token").await;
        let now = crate::now_secs();
        let instance_id = uuid::Uuid::new_v4().simple().to_string();
        instances
            .create(InstanceRow {
                id: instance_id.clone(),
                owner_id: user_id,
                name: "session test".into(),
                task: "session test".into(),
                cube_sandbox_id: Some("sb-test".into()),
                state_generation: uuid::Uuid::new_v4().simple().to_string(),
                template_id: "tpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "instance-bearer".into(),
                pinned: false,
                expires_at: None,
                last_active_at: now,
                last_probe_at: None,
                last_probe_status: None,
                created_at: now,
                destroyed_at: None,
                rotated_to: None,
                network_policy: crate::network_policy::NetworkPolicy::default(),
                network_policy_cidrs: vec![],
                models: vec!["test-model".into()],
                tools: vec![],
            })
            .await
            .expect("insert test instance");
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            user_auth,
        )
        .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let create_resp = client
            .post(format!("{base}/auth/session"))
            .bearer_auth("future.jwt.token")
            .json(&serde_json::json!({ "expires_at": crate::now_secs() + 3600 }))
            .send()
            .await
            .unwrap();
        assert_eq!(create_resp.status(), 204);
        let set_cookie = create_resp
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .expect("session response must set cookie")
            .to_str()
            .unwrap();
        let cookie_pair = set_cookie
            .split(';')
            .next()
            .expect("set-cookie must contain a cookie pair")
            .to_owned();
        let before_logout = client
            .get(format!("{base}/api/conversations"))
            .header("host", format!("{instance_id}.swarm.test"))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .unwrap();
        assert_ne!(
            before_logout.status(),
            401,
            "session cookie should resolve before logout"
        );

        let logout_resp = client
            .delete(format!("{base}/auth/session"))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .send()
            .await
            .unwrap();
        assert_eq!(logout_resp.status(), 204);
        let after_logout = client
            .get(format!("{base}/api/conversations"))
            .header("host", format!("{instance_id}.swarm.test"))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(
            after_logout.status(),
            401,
            "logout must revoke prior session cookie even when the original JWT is unexpired"
        );
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
    async fn admin_kms_audit_returns_runtime_token_owner_id() {
        let (state, users) = build_state().await;
        state
            .secret_access_audit
            .insert(&crate::traits::SecretAccessAuditEntry {
                timestamp: 42,
                actor_kind: "runtime".into(),
                actor_id: Some("inst-a".into()),
                reason: crate::envelope::SecretAccessReason::LlmProviderProxy,
                operation: crate::envelope::SecretAccessOperation::Decrypt,
                scope: crate::envelope::KmsScope::RuntimeToken,
                owner_id: Some("owner-a".into()),
                instance_id: Some("inst-a".into()),
                secret_name: Some("proxy_token:*".into()),
                key_id: Some("system/runtime_tokens".into()),
                key_version: Some(1),
                result: crate::envelope::SecretAccessResult::Success,
                error_class: None,
                error_message: None,
            })
            .await
            .unwrap();
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
            .get(format!("{base}/v1/admin/kms/audit?scope=runtime_token"))
            .bearer_auth("ignored")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["items"][0]["owner_id"], "owner-a");
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
    async fn host_dispatcher_403s_post_with_foreign_origin() {
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
            .header("origin", "https://evil.test")
            .body("payload")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn host_dispatcher_get_skips_csrf_gate() {
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
            .get(format!("{base}/api/whatever"))
            .header("host", "abc.swarm.test")
            .header("accept", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            401,
            "GET without Origin should reach auth, not the CSRF rejection",
        );
    }

    #[tokio::test]
    async fn share_host_runs_before_instance_dispatcher() {
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
            .get(format!("{base}/not-a-share-path"))
            .header("host", "share.swarm.test")
            .header("accept", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            404,
            "share.<apex> must be handled by the public share dispatcher, not instance auth",
        );
        assert_eq!(r.text().await.unwrap(), "not found");
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
    async fn host_dispatcher_healthz_requires_auth() {
        let (mut state, users, instances) = build_state_with_instances().await;
        state.hostname = Some("swarm.test".into());
        let (_unused_auth, user_id) =
            crate::auth::user::fixed_user_auth(users.clone(), "alice").await;
        let now = crate::now_secs();
        instances
            .create(InstanceRow {
                id: "abc".into(),
                owner_id: user_id,
                name: "healthz auth".into(),
                task: "healthz auth".into(),
                cube_sandbox_id: Some("sb-health".into()),
                state_generation: uuid::Uuid::new_v4().simple().to_string(),
                template_id: "tpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "instance-bearer".into(),
                pinned: false,
                expires_at: None,
                last_active_at: now,
                last_probe_at: None,
                last_probe_status: None,
                created_at: now,
                destroyed_at: None,
                rotated_to: None,
                network_policy: crate::network_policy::NetworkPolicy::default(),
                network_policy_cidrs: vec![],
                models: vec!["test-model".into()],
                tools: vec![],
            })
            .await
            .expect("insert test instance");
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
            .get(format!("{base}/healthz"))
            .header("host", "abc.swarm.test")
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            401,
            "dyson subdomain /healthz must require auth instead of forwarding anonymously",
        );
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
    async fn host_dispatcher_enforces_owner_on_instance_subdomain() {
        let (mut state, users, instances) = build_state_with_instances().await;
        state.hostname = Some("swarm.test".into());
        let (alice_auth, alice_id) =
            token_bound_user_auth(users.clone(), "alice", "alice-token").await;
        let (bob_auth, _bob_id) = token_bound_user_auth(users, "bob", "bob-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;

        let client = reqwest::Client::new();
        let bob_base = spawn(
            state.clone(),
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            bob_auth,
        )
        .await;
        let bob = client
            .get(format!("{bob_base}/api/conversations"))
            .header("host", "inst-a.swarm.test")
            .header("accept", "application/json")
            .bearer_auth("bob-token")
            .send()
            .await
            .unwrap();
        assert_eq!(bob.status(), StatusCode::NOT_FOUND);

        let alice_base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let alice = client
            .get(format!("{alice_base}/api/conversations"))
            .header("host", "inst-a.swarm.test")
            .header("accept", "application/json")
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap();
        assert_ne!(
            alice.status(),
            StatusCode::NOT_FOUND,
            "owner should pass the scoped lookup and reach upstream forwarding",
        );
        assert_ne!(alice.status(), StatusCode::UNAUTHORIZED);
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
    async fn hire_with_open_policy_rejected_when_disabled_returns_400() {
        let (state, users) = build_state().await;
        let (user_auth, _user_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        let base = spawn(state, AuthState::dangerous_no_auth(), user_auth).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/v1/instances"))
            .bearer_auth("alice-token")
            .json(&serde_json::json!({
                "template_id": "tpl",
                "env": { "SWARM_MODEL": "openrouter/model" },
                "network_policy": { "kind": "open" }
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            r.text().await.unwrap(),
            crate::network_policy::INTERNAL_NETWORK_POLICY_DISABLED_MESSAGE
        );
    }

    #[tokio::test]
    async fn change_network_endpoint_rejects_open_when_disabled() {
        let (state, users, instances) = build_state_with_instances().await;
        let (user_auth, user_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &user_id, "inst-a").await;
        let base = spawn(state, AuthState::dangerous_no_auth(), user_auth).await;

        let r = reqwest::Client::new()
            .post(format!("{base}/v1/instances/inst-a/change-network"))
            .bearer_auth("alice-token")
            .json(&serde_json::json!({ "network_policy": { "kind": "open" } }))
            .send()
            .await
            .unwrap();

        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            r.text().await.unwrap(),
            crate::network_policy::INTERNAL_NETWORK_POLICY_DISABLED_MESSAGE
        );
        let row = instances.get("inst-a").await.unwrap().unwrap();
        assert_eq!(row.network_policy, NetworkPolicy::NoLocalNet);
    }

    #[tokio::test]
    async fn whoami_or_public_config_exposes_allow_internal_network_policy_flag() {
        let (mut state, users) = build_state().await;
        state.auth_config = Arc::new(auth_config::AuthConfig::from_toml(
            None,
            None,
            vec![],
            vec![],
            crate::config::NetworkConfig {
                allow_internal_network_policy: true,
            },
        ));
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            deny_user_auth(users),
        )
        .await;

        let r = reqwest::get(format!("{base}/auth/config")).await.unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["network"]["allow_internal_network_policy"],
            serde_json::Value::Bool(true)
        );
    }

    #[tokio::test]
    async fn tool_call_audit_list_filters_paginates_and_enforces_owner() {
        let (state, users, instances) = build_state_with_instances().await;
        let (alice_auth, alice_id) =
            token_bound_user_auth(users.clone(), "alice", "alice-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;
        let bash = seed_tool_call(
            &state,
            &alice_id,
            "inst-a",
            "use-bash",
            "bash",
            None,
            10,
            Some((serde_json::json!({"ok": true}), false, 12)),
        )
        .await;
        let _ok = seed_tool_call(
            &state,
            &alice_id,
            "inst-a",
            "use-gh-ok",
            "mcp__github__create_issue",
            Some("github"),
            20,
            Some((serde_json::json!({"number": 1}), false, 24)),
        )
        .await;
        let err = seed_tool_call(
            &state,
            &alice_id,
            "inst-a",
            "use-gh-err",
            "mcp__github__close_issue",
            Some("github"),
            30,
            Some((serde_json::json!({"error": "needle"}), true, 35)),
        )
        .await;
        let base = spawn(
            state.clone(),
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let client = reqwest::Client::new();
        let body: serde_json::Value = client
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls?server=github&status=err&q=needle&limit=1"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], err);
        assert_eq!(body["items"][0]["result"]["error"], "needle");
        assert_eq!(body["next_cursor"], err);

        let body: serde_json::Value = client
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls?before={err}&limit=10"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let ids: Vec<i64> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_i64().unwrap())
            .collect();
        assert!(ids.contains(&bash));

        let facets: serde_json::Value = client
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls/facets"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            facets["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "bash")
        );
        assert!(
            facets["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "mcp__github__create_issue")
        );
        assert!(
            facets["servers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "github")
        );

        let (bob_auth, _bob_id) = token_bound_user_auth(users, "bob", "bob-token").await;
        let bob_base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            bob_auth,
        )
        .await;
        let r = client
            .get(format!("{bob_base}/v1/instances/inst-a/audit/tool-calls"))
            .bearer_auth("bob-token")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), reqwest::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tool_call_audit_sse_sends_initial_event() {
        let (state, users, instances) = build_state_with_instances().await;
        let (alice_auth, alice_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;
        seed_tool_call(
            &state, &alice_id, "inst-a", "use-bash", "bash", None, 10, None,
        )
        .await;
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let resp = reqwest::Client::new()
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls/stream"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let mut stream = resp.bytes_stream();
        let chunk = stream.next().await.unwrap().unwrap();
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("event: tool_call"));
        assert!(text.contains("\"tool_name\":\"bash\""));
    }

    #[tokio::test]
    async fn tool_call_audit_search_scans_past_first_page() {
        let (state, users, instances) = build_state_with_instances().await;
        let (alice_auth, alice_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;
        let target = seed_tool_call(
            &state,
            &alice_id,
            "inst-a",
            "deep-needle",
            "bash",
            None,
            1,
            None,
        )
        .await;
        for i in 0..505 {
            seed_tool_call(
                &state,
                &alice_id,
                "inst-a",
                &format!("ordinary-{i}"),
                "bash",
                None,
                2 + i,
                None,
            )
            .await;
        }
        let base = spawn(
            state,
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let body: serde_json::Value = reqwest::Client::new()
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls?q=deep-needle&limit=1"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], target);
    }

    #[tokio::test]
    async fn tool_call_audit_sse_filters_followed_events() {
        let (state, users, instances) = build_state_with_instances().await;
        let (alice_auth, alice_id) = token_bound_user_auth(users, "alice", "alice-token").await;
        seed_owned_instance(&instances, &alice_id, "inst-a").await;
        let base = spawn(
            state.clone(),
            AuthState::enforced(crate::config::OidcRoles {
                claim: "https://test/roles".into(),
                admin: "rol_admin".into(),
            }),
            alice_auth,
        )
        .await;
        let resp = reqwest::Client::new()
            .get(format!(
                "{base}/v1/instances/inst-a/audit/tool-calls/stream?tool=bash"
            ))
            .bearer_auth("alice-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let mut stream = resp.bytes_stream();

        seed_tool_call(
            &state,
            &alice_id,
            "inst-a",
            "use-python",
            "python",
            None,
            10,
            None,
        )
        .await;
        seed_tool_call(
            &state, &alice_id, "inst-a", "use-bash", "bash", None, 20, None,
        )
        .await;

        let chunk = tokio::time::timeout(std::time::Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(text.contains("\"tool_name\":\"bash\""));
        assert!(!text.contains("\"tool_name\":\"python\""));
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
    async fn browser_deep_link_refresh_serves_spa_index_html() {
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
        let r = reqwest::Client::new()
            .get(format!("{base}/i/fluffy-otter-042/model"))
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let ct = r
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
        let body = r.text().await.unwrap();
        assert!(body.contains("<div id=\"root\">"));
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
