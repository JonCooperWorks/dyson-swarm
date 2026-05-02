//! Internal artefact ingest — `POST /v1/internal/ingest/artefact`.
//!
//! The dyson agent calls this from `Output::send_artefact` to push
//! artefact metadata + body bytes to swarm.  Auth is a per-instance
//! `it_<32hex>` bearer minted at instance create (see
//! `db::tokens::SqlxTokenStore::mint_ingest`); the token's
//! `instance_id` is authoritative for owner scoping, so the caller
//! cannot forge metadata fields to write into another tenant's
//! `artefact_cache` row or another tenant's owner-keyed cipher.
//!
//! Wire shape: JSON body with metadata + base64-encoded body bytes.
//! Same posture as dyson's own `POST /api/conversations/:id/turn`
//! attachment shape — keeps base64 round-tripping consistent across
//! the dyson↔swarm boundary.  Cap at 25 MiB total request size; that
//! mirrors dyson's `MAX_FILE_BYTES` so anything dyson would have
//! refused locally, swarm refuses too.
//!
//! Storage: handed to `ArtefactCacheService::ingest` which seals the
//! body under the owner's age cipher and writes it to disk under
//! `<local_cache_dir>/artefacts/<instance>/<chat>/<artefact_id>.body`.
//! Idempotent on `(instance_id, chat_id, artefact_id)` so a dyson-
//! side retry produces the same on-disk state.
//!
//! Mounted unauthenticated under `/v1/internal/` (alongside
//! `instances::internal_router`).  The bearer-token check in this
//! handler IS the auth.

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use crate::artefacts::IngestMeta;
use crate::http::AppState;

/// Cap on the JSON request body.  Picked to mirror dyson's own
/// `MAX_FILE_BYTES = 25 MiB` so we don't accept a payload dyson would
/// have refused upstream.  Base64 inflates by ~33%, so the actual
/// body-bytes ceiling is roughly 18.7 MiB — fine for every artefact
/// shape we see today (security review reports, generated images,
/// PDFs); larger needs a streaming endpoint we'd add when it's worth it.
pub const MAX_INGEST_BODY: usize = 25 * 1024 * 1024;

/// Required prefix for ingest tokens.  Chat-provider tokens (`pt_`)
/// are rejected at this gate even if they happen to authenticate
/// against the same `proxy_tokens` table — the prefix is the
/// audience-discriminator the route honours.
const INGEST_TOKEN_PREFIX: &str = "it_";

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/internal/ingest/artefact", post(ingest))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct IngestRequest {
    chat_id: String,
    artefact_id: String,
    kind: String,
    title: String,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    /// Plaintext seconds-since-epoch from dyson's clock.  Used to seed
    /// the row's `created_at`; cosmetic for newest-first listings.
    created_at: i64,
    /// Base64-encoded body bytes.  `None` is a metadata-only refresh
    /// (the existing `ArtefactCacheService::ingest` semantics) — the
    /// row's existing on-disk body is preserved.  `Some("")` is a
    /// distinct signal: the artefact's body is known-empty.
    #[serde(default)]
    body_b64: Option<String>,
}

async fn ingest(State(state): State<AppState>, req: Request<Body>) -> StatusCode {
    // 1. Pull and validate the bearer.  Reject anything missing the
    //    `it_` prefix at the door so a stolen chat-provider token
    //    can't be retargeted at the ingest endpoint, even if it
    //    happens to resolve in the shared `proxy_tokens` table.
    let bearer = match extract_bearer(&req) {
        Some(b) if b.starts_with(INGEST_TOKEN_PREFIX) => b.to_owned(),
        _ => return StatusCode::UNAUTHORIZED,
    };
    let token_record = match state.tokens.resolve(&bearer).await {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::UNAUTHORIZED,
        Err(e) => {
            tracing::warn!(error = %e, "ingest: token resolve failed");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    if token_record.provider != crate::db::tokens::INGEST_PROVIDER {
        return StatusCode::UNAUTHORIZED;
    }
    let instance_id = token_record.instance_id;

    // 2. Resolve the instance row (unscoped — caller has no user
    //    identity, the token has already proved instance-bound
    //    possession) so we know the owner_id for the seal.
    let instance = match state.instances.get_unscoped(&instance_id).await {
        Ok(r) => r,
        Err(crate::error::SwarmError::NotFound) => return StatusCode::NOT_FOUND,
        Err(e) => {
            tracing::warn!(error = %e, instance = %instance_id, "ingest: instance lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // 3. Read the body up to the size cap.  `axum::body::to_bytes` with
    //    a limit returns 413-equivalent on overrun; we map that to 413.
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_INGEST_BODY).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE,
    };

    // 4. Parse the JSON envelope.
    let body: IngestRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "ingest: malformed JSON envelope");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 5. Decode body_b64.  None ⇒ metadata-only ingest.  Some(b"") ⇒
    //    known-empty body.
    let decoded = match body.body_b64.as_deref() {
        None => None,
        Some("") => Some(Vec::new()),
        Some(s) => match B64.decode(s) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::debug!(error = %e, "ingest: malformed base64 body");
                return StatusCode::BAD_REQUEST;
            }
        },
    };

    // 6. Build the metadata view + push through the cache.  The cache
    //    handles seal-on-write internally.  `metadata` is opaque JSON —
    //    re-serialise to a stable string for the BLOB column.
    let metadata_json = body.metadata.as_ref().map(|v| v.to_string());
    let meta = IngestMeta {
        instance_id: &instance_id,
        owner_id: &instance.owner_id,
        chat_id: &body.chat_id,
        artefact_id: &body.artefact_id,
        kind: &body.kind,
        title: &body.title,
        mime: body.mime.as_deref(),
        created_at: body.created_at,
        metadata_json: metadata_json.as_deref(),
    };
    match state.artefact_cache.ingest(meta, decoded.as_deref()).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(
                error = %e,
                instance = %instance_id,
                chat = %body.chat_id,
                artefact = %body.artefact_id,
                "ingest: cache write failed",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Extract the `Authorization: Bearer <token>` value, case-insensitive
/// on the scheme.  Returns the trimmed token, or `None` when missing
/// or malformed.
fn extract_bearer(req: &Request<Body>) -> Option<&str> {
    let raw = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artefacts::ArtefactCacheService;
    use crate::backup::local::LocalDiskBackupSink;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSecretStore;
    use crate::db::tokens::SqlxTokenStore;
    use crate::instance::InstanceService;
    use crate::secrets::SecretsService;
    use crate::snapshot::SnapshotService;
    use crate::traits::{
        BackupSink, CreateSandboxArgs, CubeClient, HealthProber, InstanceRow, InstanceStatus,
        InstanceStore, ProbeResult, SandboxInfo, SecretStore, SnapshotInfo, SnapshotStore,
        TokenStore, UserRow, UserStatus,
    };

    use std::sync::Arc;

    /// Stub cube — every call panics; none of these tests exercise
    /// the cube path, but `InstanceService` and `SnapshotService` need
    /// a `CubeClient` to construct.  Mirror of the stub in
    /// `http::tests`.
    struct StubCube;

    #[async_trait::async_trait]
    impl CubeClient for StubCube {
        async fn create_sandbox(
            &self,
            _: CreateSandboxArgs,
        ) -> Result<SandboxInfo, crate::error::CubeError> {
            unreachable!("stub cube — create_sandbox not used in ingest tests")
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

    /// Build an isolated `AppState` (in-memory pool, tempdir-rooted
    /// cipher directory + body cache) plus seed one instance row.
    /// Returns the URL of a server bound on an ephemeral port plus
    /// the ingest token, the sibling chat-provider token, and the
    /// owner / instance ids the seed row landed under.
    async fn fixture() -> Fixture {
        // Owner id must satisfy `validate_user_id` (32-hex or `system`).
        const OWNER: &str = "1111222233334444aaaabbbbccccdddd";
        const INSTANCE: &str = "inst-x";

        let pool = open_in_memory().await.unwrap();

        let raw_secret_store: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
        let keys = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys.path()).unwrap());
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
        let secrets_svc = Arc::new(SecretsService::new(
            raw_secret_store.clone(),
            instances_store.clone(),
            cipher_dir.clone(),
        ));
        let user_secrets_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let system_secrets_store: Arc<dyn crate::traits::SystemSecretStore> =
            Arc::new(crate::db::secrets::SqlxSystemSecretStore::new(pool.clone()));
        let user_secrets_svc = Arc::new(crate::secrets::UserSecretsService::new(
            user_secrets_store,
            cipher_dir.clone(),
        ));
        let system_secrets_svc = Arc::new(crate::secrets::SystemSecretsService::new(
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
            raw_secret_store.clone(),
            tokens_store.clone(),
            "http://test/llm",
        ));
        let backup: Arc<dyn BackupSink> = Arc::new(LocalDiskBackupSink::new(cube.clone()));
        let snapshots_store: Arc<dyn SnapshotStore> =
            Arc::new(crate::db::snapshots::SqliteSnapshotStore::new(pool.clone()));
        let snapshot_svc = Arc::new(SnapshotService::new(
            cube.clone(),
            instances_store.clone(),
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
            secrets_svc.clone(),
            instance_svc.clone(),
            Arc::new(crate::webhooks::NullWebhookDispatcher),
            cipher_dir.clone(),
        ));
        let shares_svc = Arc::new(crate::shares::ShareService::new(
            pool.clone(),
            user_secrets_svc.clone(),
            instance_svc.clone(),
            crate::shares::ShareMetrics::new(),
            None,
        ));
        let cache_dir = tempfile::tempdir().unwrap();
        let artefact_cache = Arc::new(ArtefactCacheService::new(
            pool.clone(),
            cache_dir.path().to_path_buf(),
            cipher_dir.clone(),
        ));

        // Seed the owner user (FK target for instances.owner_id),
        // then the instance row, then mint both token kinds.
        users_store
            .create(UserRow {
                id: OWNER.into(),
                subject: format!("test:{OWNER}"),
                email: None,
                display_name: None,
                status: UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 0.0,
            })
            .await
            .unwrap();
        instances_store
            .create(InstanceRow {
                id: INSTANCE.into(),
                owner_id: OWNER.into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: Some("cube-x".into()),
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
        let ingest_token = tokens_store.mint_ingest(INSTANCE).await.unwrap();
        let chat_token = tokens_store.mint(INSTANCE, "openai").await.unwrap();

        let state = AppState {
            secrets: secrets_svc,
            user_secrets: user_secrets_svc,
            system_secrets: system_secrets_svc,
            ciphers: cipher_dir,
            instances: instance_svc,
            snapshots: snapshot_svc,
            prober: Arc::new(StubProber),
            tokens: tokens_store,
            users: users_store,
            sandbox_domain: "cube.test".into(),
            hostname: None,
            auth_config: Arc::new(crate::http::auth_config::AuthConfig::none()),
            dyson_http: crate::http::dyson_proxy::build_client().unwrap(),
            models_upstream: None,
            models_cache: crate::http::models::ModelsCache::new(),
            openrouter_provisioning: None,
            user_or_keys: None,
            providers: Arc::new(crate::config::Providers::default()),
            byo: Arc::new(crate::config::ByoConfig::default()),
            webhooks: webhooks_svc,
            shares: shares_svc,
            artefact_cache,
        };

        // Spawn the router on an ephemeral port.
        let app = router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{addr}");

        // Leak the tempdirs so the bodies + keys outlive the test —
        // matches the existing http fixture pattern.
        std::mem::forget(keys);
        std::mem::forget(cache_dir);

        Fixture {
            url,
            ingest_token,
            chat_token,
            state,
            owner: OWNER.to_owned(),
            instance: INSTANCE.to_owned(),
        }
    }

    struct Fixture {
        url: String,
        ingest_token: String,
        chat_token: String,
        state: AppState,
        owner: String,
        instance: String,
    }

    fn good_body(chat: &str, art: &str, body: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "chat_id": chat,
            "artefact_id": art,
            "kind": "security_review",
            "title": "Test artefact",
            "mime": "text/markdown",
            "created_at": 1_700_000_000_i64,
            "body_b64": B64.encode(body),
        })
    }

    #[tokio::test]
    async fn rejects_missing_bearer() {
        let f = fixture().await;
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .json(&good_body("c1", "a1", b"hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn rejects_chat_provider_pt_prefix() {
        // pt_ tokens authenticate against the same proxy_tokens table
        // but must NOT be accepted at the ingest endpoint.  The route
        // filters by prefix at the door.
        let f = fixture().await;
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.chat_token)
            .json(&good_body("c1", "a1", b"hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn rejects_unknown_token() {
        let f = fixture().await;
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth("it_deadbeefdeadbeefdeadbeefdeadbeef")
            .json(&good_body("c1", "a1", b"hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn rejects_revoked_token() {
        let f = fixture().await;
        f.state
            .tokens
            .revoke_for_instance(&f.instance)
            .await
            .unwrap();
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&good_body("c1", "a1", b"hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn rejects_oversize_body() {
        // Build a JSON envelope just over the 25 MiB limit.  The base64
        // payload alone is sized so the request body crosses MAX_INGEST_BODY.
        let f = fixture().await;
        // 19 MiB of plaintext base64-inflates to ~25.3 MiB, which puts
        // the JSON envelope over the 25 MiB cap.
        let big_plain = vec![0u8; 19 * 1024 * 1024];
        let payload = good_body("c1", "a1", &big_plain);
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 413);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let f = fixture().await;
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .header("content-type", "application/json")
            .body("{not json")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn rejects_malformed_base64() {
        let f = fixture().await;
        let payload = serde_json::json!({
            "chat_id": "c1",
            "artefact_id": "a1",
            "kind": "security_review",
            "title": "T",
            "created_at": 0_i64,
            "body_b64": "!!!not-base64!!!",
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn happy_path_writes_sealed_row_and_decrypts_back() {
        let f = fixture().await;
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&good_body("c1", "a1", b"# Findings\n\n* a\n"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        // Row landed under the OWNER from the token (not from the
        // request body — there's no owner field on the wire).
        let row = f
            .state
            .artefact_cache
            .find(&f.instance, "c1", "a1")
            .await
            .unwrap()
            .expect("row present");
        assert_eq!(row.owner_id, f.owner);
        assert_eq!(row.title, "Test artefact");
        assert_eq!(row.kind, "security_review");
        assert_eq!(row.mime.as_deref(), Some("text/markdown"));
        assert_eq!(row.bytes, 16);

        // Body decrypts back to the input plaintext.
        let plain = f
            .state
            .artefact_cache
            .read_body(&row)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain, b"# Findings\n\n* a\n");

        // Disk holds ciphertext, not plaintext.
        let on_disk = std::fs::read(f.state.artefact_cache.body_path_for(&row)).unwrap();
        assert!(on_disk.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    }

    #[tokio::test]
    async fn idempotent_double_post_replaces_body() {
        let f = fixture().await;
        let client = reqwest::Client::new();

        let r1 = client
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&good_body("c1", "a1", b"v1"))
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 204);

        let r2 = client
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&good_body("c1", "a1", b"v2-much-longer"))
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), 204);

        let row = f
            .state
            .artefact_cache
            .find(&f.instance, "c1", "a1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.bytes, 14);
        let plain = f
            .state
            .artefact_cache
            .read_body(&row)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain, b"v2-much-longer");
    }

    #[tokio::test]
    async fn metadata_only_post_preserves_body() {
        // POST without `body_b64` after a previous body-bearing POST
        // keeps the body intact (delegates to ArtefactCacheService's
        // existing metadata-only-refresh semantics).
        let f = fixture().await;
        let client = reqwest::Client::new();
        let r1 = client
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&good_body("c1", "a1", b"original"))
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 204);

        let payload = serde_json::json!({
            "chat_id": "c1",
            "artefact_id": "a1",
            "kind": "security_review",
            "title": "Renamed",
            "created_at": 1_700_000_000_i64,
        });
        let r2 = client
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), 204);

        let row = f
            .state
            .artefact_cache
            .find(&f.instance, "c1", "a1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.title, "Renamed");
        assert_eq!(row.bytes, 8);
        let plain = f
            .state
            .artefact_cache
            .read_body(&row)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain, b"original");
    }

    #[tokio::test]
    async fn token_owner_is_authoritative_across_metadata_fields() {
        // Caller can stuff arbitrary chat_id / artefact_id / title into
        // the body, but the row's owner_id comes from the token's
        // instance — there's no way for a body field to override it.
        // (We can't directly assert "no body field exists" — we assert
        // the row landed under the seeded owner regardless of body.)
        let f = fixture().await;
        let payload = serde_json::json!({
            "chat_id": "evil-chat",
            "artefact_id": "evil-art",
            "kind": "spoof",
            "title": "Spoof title",
            "created_at": 0_i64,
            "body_b64": B64.encode(b"hi"),
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let row = f
            .state
            .artefact_cache
            .find(&f.instance, "evil-chat", "evil-art")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.owner_id, f.owner, "owner is from token, never the wire");
    }

    #[tokio::test]
    async fn empty_body_b64_is_known_empty_signal() {
        // body_b64 = "" is distinct from omitted body_b64: the cache
        // writes a zero-length file (vs. preserving an existing body).
        let f = fixture().await;
        let payload = serde_json::json!({
            "chat_id": "c1",
            "artefact_id": "empty",
            "kind": "other",
            "title": "Empty",
            "created_at": 0_i64,
            "body_b64": "",
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/internal/ingest/artefact", f.url))
            .bearer_auth(&f.ingest_token)
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let row = f
            .state
            .artefact_cache
            .find(&f.instance, "c1", "empty")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.bytes, 0);
        let got = f
            .state
            .artefact_cache
            .read_body(&row)
            .await
            .unwrap()
            .unwrap();
        assert!(got.is_empty());
    }
}
