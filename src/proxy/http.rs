//! LLM proxy router.
//!
//! Mounted at `/llm/<provider>/...`. The handler is a single catch-all that:
//! 1. Resolves the proxy bearer via [`TokenStore`] (401 on miss/revoke).
//! 2. Loads the per-instance policy (falling back to the configured default)
//!    and a usage snapshot.
//! 3. Calls [`crate::proxy::policy_check::enforce`] (403 with a closed-enum
//!    code on denial).
//! 4. Picks the adapter for `<provider>`, asks it to rewrite the auth
//!    headers/URL using the real upstream key from config.
//! 5. Forwards the request body via `reqwest::Body::wrap_stream` and streams
//!    the response back via `axum::body::Body::from_stream` — no buffering.
//! 6. Writes an `llm_audit` row regardless of outcome.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use futures::TryStreamExt;
use serde::Serialize;

use crate::auth::extract_bearer;
use crate::now_secs;
use crate::policy::PolicyDenial;
use crate::proxy::adapters::anthropic as anthropic_adapter;
use crate::proxy::policy_check::{enforce, EnforceContext};
use crate::proxy::ProxyService;
use crate::traits::{AuditEntry, TokenRecord};

/// Wallclock duration → audit-row millis.  `Duration::as_millis()` returns
/// `u128`; saturating to `i64::MAX` (~292M years) is safer than wrapping.
fn elapsed_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Build the `/llm/*` router. Carries its own state and per-instance-bearer
/// middleware — the admin auth layer does not apply here.
pub fn router(state: Arc<ProxyService>) -> Router {
    Router::new()
        .route("/llm/:provider/*rest", any(handle))
        .with_state(state)
}

async fn handle(
    State(state): State<Arc<ProxyService>>,
    Path((provider, rest)): Path<(String, String)>,
    req: Request,
) -> Response<Body> {
    let started = Instant::now();
    let method = req.method().clone();
    let (mut parts, body) = req.into_parts();

    // 1. Resolve the proxy bearer. The middleware would normally do this but
    // we keep it inline so the audit row gets the instance id even when
    // resolution fails.
    let Some(token) = extract_bearer(&parts.headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing bearer");
    };
    let record: TokenRecord = match state.tokens.resolve(&token).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "invalid bearer"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "token store error"),
    };

    // 1b. Resolve owner. Per-user budgets need it; per-instance
    // policy/budget were a phase-2 deviation we're correcting here.
    let instance_row = match state.instances.get(&record.instance_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "instance gone"),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance store error")
        }
    };
    let owner_id = instance_row.owner_id;

    // 2. Read the body up front. Forwarding a streaming request body is
    // possible but the JSON body needs to be inspected for `model` to enforce
    // policy *before* forwarding — buffering a single LLM request is cheap
    // (a handful of KB) so we accept that cost. The response is still
    // streamed back unbuffered (step 6).
    let Ok(body_bytes) = axum::body::to_bytes(body, 8 * 1024 * 1024).await else {
        return error_response(StatusCode::BAD_REQUEST, "body too large");
    };
    let body_json: serde_json::Value = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null)
    };

    // 3. Policy + usage are keyed on owner_id, not instance_id, so a user
    // with N instances shares one budget envelope.
    let policy = match state.policies.get(&owner_id).await {
        Ok(Some(p)) => p,
        Ok(None) => state.default_policy.clone(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "policy load error"),
    };
    let usage = state.snapshot(&owner_id).await;
    let ctx = EnforceContext {
        policy: &policy,
        usage: &usage,
        provider: &provider,
    };
    if let Err(denial) = enforce(&ctx, &record, &body_json) {
        let model = body_json
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        write_audit(
            &state,
            AuditEntry {
                owner_id: owner_id.clone(),
                instance_id: record.instance_id.clone(),
                provider: provider.clone(),
                model,
                prompt_tokens: None,
                output_tokens: None,
                status_code: 403,
                duration_ms: elapsed_ms(started),
                occurred_at: now_secs(),
            },
        )
        .await;
        return denial_response(denial);
    }

    // 4. Adapter + provider config.
    let adapter = match state.adapters.get(provider.as_str()) {
        Some(a) => a.clone(),
        None => return error_response(StatusCode::NOT_FOUND, "unknown provider"),
    };
    let Some(provider_cfg) = state.provider_config(&provider) else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "provider not configured");
    };
    // Stage 6: `/llm/openrouter/*` MUST use the caller's own per-user
    // OR bearer.  We never fall back to the global `[providers.openrouter]
    // api_key` — silently doing so would shift the user's spend onto
    // the operator's plan and bypass the per-user budget cap entirely.
    // The resolver lazy-mints on first call (`create if not exists`);
    // anything that prevents that — resolver not configured, OR
    // Provisioning API down, decrypt failure — is a 503 the agent can
    // retry rather than a billing leak the operator catches a month
    // late.
    let real_key: String = if provider == "openrouter" {
        let Some(resolver) = state.user_or_keys.as_ref() else {
            tracing::warn!(
                user = %owner_id,
                "openrouter request but no per-user resolver configured; failing closed",
            );
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "openrouter per-user key unavailable",
            );
        };
        match resolver.resolve_plaintext(&owner_id).await {
            Ok(k) => k,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    user = %owner_id,
                    "openrouter per-user key resolve failed; failing closed",
                );
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "openrouter per-user key unavailable",
                );
            }
        }
    } else {
        provider_cfg.api_key.clone().unwrap_or_default()
    };

    let upstream_base = adapter.upstream_base_url(&provider_cfg);
    let rest_with_query = match parts.uri.query() {
        Some(q) => format!("/{rest}?{q}"),
        None => format!("/{rest}"),
    };
    let upstream_url = format!(
        "{}{}",
        upstream_base.trim_end_matches('/'),
        rest_with_query
    );
    let mut upstream_uri: Uri = match upstream_url.parse() {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "bad upstream url"),
    };

    // Hop-by-hop and proxy-internal headers are stripped before the adapter
    // gets to set its own.
    sanitize_request_headers(&mut parts.headers);
    adapter.rewrite_auth(&mut parts.headers, &mut upstream_uri, &real_key);
    if provider == "anthropic" {
        anthropic_adapter::apply_version(&mut parts.headers, &provider_cfg);
    }

    // 5. Forward.
    let prompt_tokens_in = estimate_prompt_tokens(&body_json);
    let mut req_builder = state
        .http
        .request(method, upstream_uri.to_string())
        .body(body_bytes.clone());
    for (k, v) in &parts.headers {
        if !is_hop_by_hop(k) {
            req_builder = req_builder.header(k.as_str(), v);
        }
    }
    let upstream_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            write_audit(
                &state,
                AuditEntry {
                    owner_id: owner_id.clone(),
                    instance_id: record.instance_id.clone(),
                    provider: provider.clone(),
                    model: body_json.get("model").and_then(|v| v.as_str()).map(str::to_owned),
                    prompt_tokens: prompt_tokens_in,
                    output_tokens: None,
                    status_code: 502,
                    duration_ms: elapsed_ms(started),
                    occurred_at: now_secs(),
                },
            )
            .await;
            // Don't surface `e` to the client.  reqwest's Display includes
            // the upstream URL, which for Gemini carries `?key=<real_key>`
            // (see proxy::adapters::gemini) — echoing the error would leak
            // the platform-wide provider key to the agent on any timeout
            // or TLS hiccup.  Log server-side, return a fixed string.
            tracing::warn!(
                provider = %provider,
                error = %e,
                "upstream request failed",
            );
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    let upstream_status = upstream_resp.status().as_u16();
    let upstream_headers = upstream_resp.headers().clone();

    // 6. Stream response back.
    let body_stream = upstream_resp.bytes_stream().map_err(std::io::Error::other);
    let resp_body = Body::from_stream(body_stream);

    let mut response = Response::builder()
        .status(StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY));
    {
        let headers = response.headers_mut().expect("fresh builder has headers");
        for (k, v) in &upstream_headers {
            if !is_hop_by_hop_str(k.as_str()) {
                headers.insert(k.clone(), v.clone());
            }
        }
    }
    let response = response.body(resp_body).unwrap();

    // 7. Audit row. Note we don't have the response body here (it's
    // streaming); output_tokens is therefore best-effort: only available if
    // the upstream provided a non-streaming JSON response with usage info.
    // A future refinement could wrap the stream in a counter that updates
    // the row on close. For step 14 we record what we know.
    write_audit(
        &state,
        AuditEntry {
            owner_id: owner_id.clone(),
            instance_id: record.instance_id.clone(),
            provider: provider.clone(),
            model: body_json.get("model").and_then(|v| v.as_str()).map(str::to_owned),
            prompt_tokens: prompt_tokens_in,
            output_tokens: None,
            status_code: i64::from(upstream_status),
            duration_ms: elapsed_ms(started),
            occurred_at: now_secs(),
        },
    )
    .await;

    response
}

/// Strip hop-by-hop headers and the inbound proxy bearer before forwarding.
fn sanitize_request_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|k| is_hop_by_hop_str(k.as_str()))
        .cloned()
        .collect();
    for k in to_remove {
        headers.remove(&k);
    }
    headers.remove(axum::http::header::HOST);
    // Authorization is intentionally kept here — adapters rewrite it. They
    // see the proxy bearer and overwrite it before the request goes out.
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    is_hop_by_hop_str(name.as_str())
}

fn is_hop_by_hop_str(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

#[derive(Serialize)]
struct DenialBody {
    code: &'static str,
    message: String,
}

fn denial_response(d: PolicyDenial) -> Response<Body> {
    let body = DenialBody {
        code: d.code(),
        message: format!("policy denial: {}", d.code()),
    };
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .unwrap()
}

fn error_response(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(Body::from(msg.to_owned()))
        .unwrap()
}

async fn write_audit(state: &ProxyService, entry: AuditEntry) {
    if let Err(e) = state.audit.insert(&entry).await {
        tracing::warn!(error = %e, "llm_audit insert failed");
    }
}

/// Best-effort prompt-token estimate. The proxy doesn't tokenize requests
/// itself; we look for `usage.prompt_tokens` on the request body in case the
/// agent supplied it (rare) and otherwise fall back to None.
fn estimate_prompt_tokens(body: &serde_json::Value) -> Option<i64> {
    body.get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(serde_json::Value::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Bytes;
    use axum::extract::Path as AxPath;
    use axum::http::HeaderMap as AxHeaderMap;
    use axum::routing::post;
    use axum::Router as AxRouter;
    use futures::stream;
    use sqlx::SqlitePool;

    use crate::config::{ProviderConfig, Providers};
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::tokens::SqlxTokenStore;
    use crate::proxy::adapters;
    use crate::proxy::policy_check::InstancePolicy;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore, TokenStore};

    async fn seed_instance_with_token(pool: &SqlitePool) -> (String, String) {
        let store = SqlxInstanceStore::new(pool.clone());
        let id = "i-test".to_string();
        store
            .create(InstanceRow {
                id: id.clone(),
                owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
                cube_sandbox_id: Some("sb-1".into()),
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
            })
            .await
            .unwrap();
        let tokens = SqlxTokenStore::new(pool.clone());
        let token = tokens.mint(&id, "*").await.unwrap();
        (id, token)
    }

    fn permissive_policy() -> InstancePolicy {
        InstancePolicy {
            allowed_providers: vec!["*".into()],
            allowed_models: vec!["*".into()],
            daily_token_budget: None,
            monthly_usd_budget: None,
            rps_limit: None,
        }
    }

    #[derive(Clone)]
    struct UpstreamState {
        calls: Arc<std::sync::atomic::AtomicU32>,
        chunks: Arc<Vec<Vec<u8>>>,
        captured_headers: Arc<std::sync::Mutex<Option<AxHeaderMap>>>,
    }

    async fn upstream_handler(
        axum::extract::State(state): axum::extract::State<UpstreamState>,
        AxPath(_rest): AxPath<String>,
        headers: AxHeaderMap,
        _body: Bytes,
    ) -> Response<Body> {
        state.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *state.captured_headers.lock().unwrap() = Some(headers);
        let chunks_owned: Vec<Vec<u8>> = state.chunks.iter().cloned().collect();
        let body_stream = stream::iter(
            chunks_owned
                .into_iter()
                .map(|c| Ok::<Bytes, std::io::Error>(Bytes::from(c))),
        );
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(body_stream))
            .unwrap()
    }

    /// Spin up a mock LLM upstream that emits a real-shaped chunked body.
    /// Returns the URL and a handle to the call counter.
    async fn spawn_streaming_upstream(
        payload: Vec<Vec<u8>>,
    ) -> (String, Arc<std::sync::atomic::AtomicU32>) {
        let state = UpstreamState {
            calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            chunks: Arc::new(payload),
            captured_headers: Arc::new(std::sync::Mutex::new(None)),
        };
        let calls = state.calls.clone();
        let app = AxRouter::new()
            .route("/*rest", post(upstream_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), calls)
    }

    /// Build a `ProxyService` whose only configured provider points at
    /// `upstream_url`, with `policy` as the per-instance policy and a stub
    /// API key.
    fn build_service(pool: SqlitePool, upstream_url: String, policy: InstancePolicy) -> Arc<ProxyService> {
        build_service_for(pool, "openai", upstream_url, "sk-real-server", policy)
    }

    /// Variant of `build_service` that lets the caller pick which provider
    /// is configured + what real_key the upstream rewrite uses.  Used by
    /// the regression test that proves the BAD_GATEWAY body never echoes
    /// the upstream URL (which for Gemini carries the real key as a query
    /// parameter).
    fn build_service_for(
        pool: SqlitePool,
        provider: &str,
        upstream_url: String,
        real_key: &str,
        policy: InstancePolicy,
    ) -> Arc<ProxyService> {
        let cfg = ProviderConfig {
            api_key: Some(real_key.into()),
            upstream: upstream_url,
            anthropic_version: None,
        };
        let providers = match provider {
            "openai" => Providers {
                anthropic: None,
                openai: Some(cfg),
                gemini: None,
                openrouter: None,
                ollama: None,
            },
            "gemini" => Providers {
                anthropic: None,
                openai: None,
                gemini: Some(cfg),
                openrouter: None,
                ollama: None,
            },
            "anthropic" => Providers {
                anthropic: Some(cfg),
                openai: None,
                gemini: None,
                openrouter: None,
                ollama: None,
            },
            "openrouter" => Providers {
                anthropic: None,
                openai: None,
                gemini: None,
                openrouter: Some(cfg),
                ollama: None,
            },
            other => panic!("build_service_for: unsupported provider {other}"),
        };
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> =
            Arc::new(crate::db::instances::SqlxInstanceStore::new(pool.clone()));
        let policies: Arc<dyn crate::traits::PolicyStore> =
            Arc::new(crate::db::policies::SqlitePolicyStore::new(pool.clone()));
        let audit: Arc<dyn crate::traits::AuditStore> =
            Arc::new(crate::db::audit::SqliteAuditStore::new(pool));
        Arc::new(
            ProxyService::new(tokens, instances, policies, audit, providers, policy)
                .expect("build proxy"),
        )
    }

    async fn spawn_proxy(svc: Arc<ProxyService>) -> String {
        let app = router(svc);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn streaming_response_passes_through_byte_for_byte() {
        // Three chunks. The proxy must forward them without buffering — this
        // doesn't strictly verify streaming (the test client may aggregate
        // them) but it does verify byte fidelity.
        let chunks: Vec<Vec<u8>> = vec![
            b"data: {\"hello\":\"world\"}\n\n".to_vec(),
            b"data: {\"more\":1}\n\n".to_vec(),
            b"data: [DONE]\n\n".to_vec(),
        ];
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();

        let (upstream_url, upstream_calls) = spawn_streaming_upstream(chunks.clone()).await;

        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let svc = build_service(pool, upstream_url, permissive_policy());
        let proxy_base = spawn_proxy(svc).await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{proxy_base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o", "messages": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.as_ref(), expected.as_slice());
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_bearer_returns_401() {
        let pool = open_in_memory().await.unwrap();
        let (upstream_url, _) = spawn_streaming_upstream(vec![b"x".to_vec()]).await;
        let svc = build_service(pool, upstream_url, permissive_policy());
        let base = spawn_proxy(svc).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/llm/openai/v1/chat/completions"))
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn revoked_token_returns_401() {
        let pool = open_in_memory().await.unwrap();
        let (id, token) = seed_instance_with_token(&pool).await;
        SqlxTokenStore::new(pool.clone())
            .revoke_for_instance(&id)
            .await
            .unwrap();
        let (upstream_url, _) = spawn_streaming_upstream(vec![b"x".to_vec()]).await;
        let svc = build_service(pool, upstream_url, permissive_policy());
        let base = spawn_proxy(svc).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn policy_denial_returns_403_with_closed_enum_code() {
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;

        let mut policy = permissive_policy();
        policy.allowed_models = vec!["claude-only".into()];

        let (upstream_url, _) = spawn_streaming_upstream(vec![b"x".to_vec()]).await;
        let svc = build_service(pool.clone(), upstream_url, policy);
        let base = spawn_proxy(svc).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "model_not_allowed");

        // Audit row written even on denial.
        let row =
            sqlx::query("SELECT status_code FROM llm_audit ORDER BY id DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        let status: i64 = sqlx::Row::try_get(&row, "status_code").unwrap();
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn unknown_provider_in_url_returns_404() {
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let (upstream_url, _) = spawn_streaming_upstream(vec![b"x".to_vec()]).await;
        let svc = build_service(pool, upstream_url, permissive_policy());
        let base = spawn_proxy(svc).await;
        let resp = reqwest::Client::new()
            .post(format!("{base}/llm/zzz/v1/chat"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn audit_row_written_on_success() {
        let pool = open_in_memory().await.unwrap();
        let (id, token) = seed_instance_with_token(&pool).await;
        let (upstream_url, _) = spawn_streaming_upstream(vec![b"ok".to_vec()]).await;
        let svc = build_service(pool.clone(), upstream_url, permissive_policy());
        let base = spawn_proxy(svc).await;
        reqwest::Client::new()
            .post(format!("{base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();

        let row = sqlx::query(
            "SELECT instance_id, provider, model, status_code FROM llm_audit ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let inst: String = sqlx::Row::try_get(&row, "instance_id").unwrap();
        let prov: String = sqlx::Row::try_get(&row, "provider").unwrap();
        let model: String = sqlx::Row::try_get(&row, "model").unwrap();
        let status: i64 = sqlx::Row::try_get(&row, "status_code").unwrap();
        assert_eq!(inst, id);
        assert_eq!(prov, "openai");
        assert_eq!(model, "gpt-4o");
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn registry_has_five_adapters() {
        let r = adapters::registry();
        assert!(r.contains_key("openrouter"));
        assert!(r.contains_key("openai"));
        assert!(r.contains_key("anthropic"));
        assert!(r.contains_key("gemini"));
        assert!(r.contains_key("ollama"));
        assert_eq!(r.len(), 5);
    }

    /// Regression: `/llm/openrouter/*` must NEVER use the global
    /// `[providers.openrouter].api_key`.  When the deployment has no
    /// per-user resolver configured, a request for OR must 503 — not
    /// fall back to the operator's global key (which would invisibly
    /// shift the user's spend onto the operator's plan and bypass the
    /// per-user budget cap).  This pins fail-closed behaviour at the
    /// integration layer so a future "make it work" patch can't
    /// silently re-introduce the leak.
    #[tokio::test]
    async fn openrouter_with_no_resolver_fails_closed_with_503() {
        let real_global_key = "sk-or-v1-OPERATOR-GLOBAL-NEVER-USE-FOR-USERS";
        // Spawn a counting upstream so we can prove zero traffic was
        // forwarded with the global key.
        let (upstream_url, upstream_calls) = spawn_streaming_upstream(vec![b"x".to_vec()]).await;

        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let svc = build_service_for(
            pool,
            "openrouter",
            upstream_url,
            real_global_key,
            permissive_policy(),
        );
        // user_or_keys deliberately left None — this is the "no
        // resolver configured" path the fix targets.
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/openrouter/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "moonshotai/kimi-k2.6"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no upstream traffic should have been emitted with the global key",
        );
    }

    /// Regression: the 502 surfaced when the upstream connection fails
    /// must not echo `reqwest::Error`'s Display, which embeds the
    /// upstream URL.  For Gemini that URL is `…?key=<real_key>` —
    /// echoing it leaks the platform-wide provider key to whoever can
    /// reach the proxy.  The fix replaces the formatted error with a
    /// fixed string and routes details to the server log.
    #[tokio::test]
    async fn upstream_failure_502_does_not_leak_real_key_in_body() {
        // Bind a TCP port, drop the listener, use the now-free port as
        // the upstream URL.  Any connect attempt fails with
        // "connection refused".
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let upstream_url = format!("http://{dead_addr}");

        let real_key = "AIza-very-secret-real-key-do-not-leak";
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let svc = build_service_for(
            pool,
            "gemini",
            upstream_url.clone(),
            real_key,
            permissive_policy(),
        );
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/gemini/v1beta/models/gemini-pro:generateContent"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gemini-pro"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains(real_key),
            "BAD_GATEWAY body leaked the real upstream key: {body}",
        );
        // Belt-and-braces: the upstream URL itself shouldn't be echoed
        // either (other adapters may grow URL-embedded auth in future).
        assert!(
            !body.contains(&upstream_url),
            "BAD_GATEWAY body echoed the upstream URL: {body}",
        );
    }

}

