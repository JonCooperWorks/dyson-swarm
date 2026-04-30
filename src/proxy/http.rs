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
use crate::config::ProviderConfig;
use crate::now_secs;
use crate::policy::PolicyDenial;
use crate::proxy::adapters::anthropic as anthropic_adapter;
use crate::proxy::byok::{self, KeySource};
use crate::proxy::policy_check::{enforce, EnforceContext};
use crate::proxy::recording_body::RecordingBody;
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
    //
    // Race: between reading `daily_tokens` here and the audit insert at
    // step 6, two concurrent requests can both pass the budget check
    // before either inserts a row.  The atomic version wants:
    //   `tx = pool.begin_immediate()` → `daily_tokens(...)` (inside tx)
    //   → enforce → `tx.insert(audit_entry)` → `tx.commit()`.
    // This is D2 in the security review and requires a new
    // `AuditStore::insert_with_tx` method (trait surgery owned by
    // Agent 1).  Until that's plumbed, the window stays — typical
    // exposure is a single extra request slipping past the cap.
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
                // Policy denial happens before key resolution, so we
                // record `platform` as a placeholder.  The call never
                // hit upstream; the value is informational.
                key_source: KeySource::Platform.as_str().to_owned(),
                // Denials never stream; row is final at insert time.
                completed: true,
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
    // `byo` has no TOML stanza — its upstream comes from the user's
    // `byok_byo` blob.  Use a default ProviderConfig as a placeholder
    // so the adapter trait stays uniform.
    let provider_cfg = state.provider_config(&provider).unwrap_or(ProviderConfig {
        api_key: None,
        upstream: String::new(),
        anthropic_version: None,
    });

    // 4b. Resolve the real upstream key + (for byo) upstream URL.  See
    // `proxy::byok` for the layered lookup: BYOK > OR-mint (legacy) >
    // platform.  Failure is fail-closed 503 — never silently fall back
    // through paths the operator hasn't authorised.
    let resolved = match byok::resolve(&state, &provider, &owner_id).await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                error = %err,
                user = %owner_id,
                provider = %provider,
                "key resolution failed; failing closed",
            );
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "no provider key available",
            );
        }
    };
    let real_key = resolved.key.clone();
    let key_source_str = resolved.source.as_str().to_owned();

    let upstream_base: String = match resolved.upstream_override.as_deref() {
        Some(u) => u.to_owned(),
        None => adapter.upstream_base_url(&provider_cfg).to_owned(),
    };
    if upstream_base.is_empty() {
        // Defensive: every code path above should have populated this
        // (platform stanza or byo override).  An empty string here
        // means the operator declared neither — fail closed rather
        // than ship a request to "/".
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "provider not configured");
    }
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

    // Allowlist request headers (D6).  Switch from blocklist to
    // allowlist: only the headers we explicitly forward survive.  The
    // adapter then gets to set its own auth header on top.  Strips
    // every hop-by-hop, every cookie, every X-* header, every
    // platform-key-bearing `OpenAI-Organization`/`X-Api-Key`/etc.
    sanitize_request_headers(&mut parts.headers, &provider);
    adapter.rewrite_auth(&mut parts.headers, &mut upstream_uri, &real_key);
    if provider == "anthropic" {
        anthropic_adapter::apply_version(&mut parts.headers, &provider_cfg);
        // D5: on the platform-key path we also have to strip
        // prompt-cache hints from both headers and body so a user
        // can't ride another tenant's cache namespace (Anthropic
        // namespaces caches by api-key, so cache_control under our
        // platform key would be a cross-tenant info leak).
        if matches!(resolved.source, KeySource::Platform) {
            strip_anthropic_cache_hints(&mut parts.headers);
        }
    }

    // 5. Forward.  For the Anthropic platform-key path we also strip
    // any `cache_control` keys from the request body — see D5: on the
    // platform key, every user shares one Anthropic cache namespace,
    // so a `cache_control` block could let user A read parts of user
    // B's prompt by hashing collision.  BYOK doesn't have this issue
    // (each user authenticates with their own Anthropic api-key →
    // their own namespace).
    let prompt_tokens_in = estimate_prompt_tokens(&body_json);
    let outbound_body = if provider == "anthropic"
        && matches!(resolved.source, KeySource::Platform)
        && !body_bytes.is_empty()
    {
        let mut v = body_json.clone();
        strip_cache_control_in_body(&mut v);
        match serde_json::to_vec(&v) {
            Ok(b) => bytes_from_vec(b),
            Err(_) => body_bytes.clone(),
        }
    } else {
        body_bytes.clone()
    };
    let mut req_builder = state
        .http
        .request(method, upstream_uri.to_string())
        .body(outbound_body);
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
                    key_source: key_source_str.clone(),
                    // Connect/timeout failure has no body to stream;
                    // the row is final at insert time.
                    completed: true,
                },
            )
            .await;
            // Don't surface `e` to the client OR the log.  reqwest's
            // Display includes the upstream URL, which for Gemini
            // carries `?key=<real_key>` (see proxy::adapters::gemini)
            // — echoing the error would leak the platform-wide
            // provider key on any timeout or TLS hiccup.  Use the
            // structured-fields shape: it captures the failure mode
            // without ever stringifying the URL.  C2 in the security
            // review.
            tracing::warn!(
                provider = %provider,
                is_timeout = e.is_timeout(),
                is_connect = e.is_connect(),
                is_request = e.is_request(),
                status = ?e.status(),
                "upstream request failed",
            );
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    let upstream_status = upstream_resp.status().as_u16();
    let upstream_headers = upstream_resp.headers().clone();

    // 6. Insert the audit row up-front with `completed = false` so a
    // mid-stream crash still leaves a forensic trail.  RecordingBody
    // will stamp `completed = true` + the final `output_tokens` count
    // via `update_completion` once the body finishes.
    let audit_id = match state
        .audit
        .insert(&AuditEntry {
            owner_id: owner_id.clone(),
            instance_id: record.instance_id.clone(),
            provider: provider.clone(),
            model: body_json.get("model").and_then(|v| v.as_str()).map(str::to_owned),
            prompt_tokens: prompt_tokens_in,
            output_tokens: None,
            status_code: i64::from(upstream_status),
            duration_ms: elapsed_ms(started),
            occurred_at: now_secs(),
            key_source: key_source_str,
            completed: false,
        })
        .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            // We've already started the upstream call.  An audit
            // insert failure is a swarm-side bookkeeping issue, not
            // a request failure — we still pass the response back
            // (we just lose the budget-accounting row).  Log loud.
            tracing::warn!(error = %e, "llm_audit insert failed; proceeding without audit row");
            None
        }
    };

    // 7. Stream response back through `RecordingBody` so the audit
    // row gets stamped with `output_tokens` + `completed=true` once
    // the body finishes streaming.  Also caps total response bytes
    // at MAX_RESPONSE_BYTES — past that we close the connection and
    // mark `truncated` (D7 in the security review).
    let raw_stream = upstream_resp.bytes_stream();
    let resp_body = if let Some(id) = audit_id {
        let recorded = RecordingBody::new(raw_stream, state.audit.clone(), id);
        let mapped = futures::TryStreamExt::map_err(recorded, std::io::Error::other);
        Body::from_stream(mapped)
    } else {
        // No audit row → no recording wrapper, just byte-pump.
        let mapped = raw_stream.map_err(std::io::Error::other);
        Body::from_stream(mapped)
    };

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
    response.body(resp_body).unwrap()
}

/// Allowlist incoming headers — the curated set listed in
/// [`is_allowlisted_header`] survives, everything else is dropped.
/// The adapter will then re-insert its own auth header.  Closing this
/// off (D6 in the security review) prevents the agent from passing
/// upstream-bearing headers like `OpenAI-Organization`, `X-Api-Key`,
/// `Cookie`, `X-Forwarded-For`, `Anthropic-Beta`, etc — any of which
/// could either bypass our rate limits / billing routing, leak
/// internal IPs to the upstream, or activate features (`Anthropic-
/// Beta: prompt-caching`) that our cross-tenant strategy assumes off.
fn sanitize_request_headers(headers: &mut HeaderMap, provider: &str) {
    let to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|k| !is_allowlisted_header(k.as_str(), provider))
        .cloned()
        .collect();
    for k in to_remove {
        headers.remove(&k);
    }
    // Authorization stays *only* if the allowlist let it through.
    // We don't allowlist Authorization in the curated set above, so
    // by this point it's gone — the adapter's `rewrite_auth` puts
    // the upstream-correct credential back in.
}

/// Headers we forward verbatim.  Everything else gets stripped.
/// The provider name lets us conditionally allow provider-specific
/// headers (e.g. `anthropic-version` on the Anthropic path).
fn is_allowlisted_header(name: &str, provider: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "content-type" | "accept" | "accept-encoding" | "user-agent"
    ) || (provider == "anthropic" && n == "anthropic-version")
}

/// Drop any `anthropic-beta` header on the platform-key path so the
/// agent can't smuggle `prompt-caching` (and therefore opt into a
/// cross-tenant cache namespace).  See D5.
fn strip_anthropic_cache_hints(headers: &mut HeaderMap) {
    headers.remove("anthropic-beta");
}

/// Walk a JSON value and drop every `cache_control` key.  Used on
/// the Anthropic platform-key path so a user's `cache_control` hint
/// can't pin a cache key under our shared platform-key namespace.
/// Recursive — Anthropic's request shape has `cache_control` nested
/// under `messages[].content[]` and under `system[]`.
fn strip_cache_control_in_body(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            map.remove("cache_control");
            for (_, child) in map.iter_mut() {
                strip_cache_control_in_body(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                strip_cache_control_in_body(item);
            }
        }
        _ => {}
    }
}

/// reqwest::Body::from(Vec<u8>) is fine but `body_bytes.clone()` is
/// `axum::body::Bytes`.  Wrap a Vec<u8> back in Bytes so the request
/// builder's `.body(...)` types line up.  (`axum::body::Bytes` is a
/// re-export of the `bytes` crate's type — we don't take a direct
/// dep on `bytes`.)
fn bytes_from_vec(v: Vec<u8>) -> axum::body::Bytes {
    axum::body::Bytes::from(v)
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
        seed_instance_with_token_for(pool, "legacy").await
    }

    /// 32-char hex owner_id used by tests that seed BYOK rows.  The
    /// `AgeCipherDirectory` rejects anything else — `"legacy"` is fine
    /// for tests that don't touch the cipher (most pre-Stage-7 tests
    /// fall in that bucket and call `seed_instance_with_token`).
    const TEST_OWNER: &str = "00000000000000000000000000000001";

    async fn seed_instance_with_token_for(pool: &SqlitePool, owner: &str) -> (String, String) {
        // Pre-seed the user row so the instances.owner_id FK is
        // satisfied.  "legacy" is migrated in by 0002 so we skip it.
        if owner != "legacy" {
            sqlx::query(
                "INSERT OR IGNORE INTO users (id, subject, status, created_at) \
                 VALUES (?, ?, 'active', 0)",
            )
            .bind(owner)
            .bind(format!("subject-{owner}"))
            .execute(pool)
            .await
            .unwrap();
        }
        let store = SqlxInstanceStore::new(pool.clone());
        let id = "i-test".to_string();
        store
            .create(InstanceRow {
                id: id.clone(),
                owner_id: owner.into(),
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
                network_policy: crate::network_policy::NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
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
        let (url, _, calls) = spawn_streaming_upstream_full(payload).await;
        (url, calls)
    }

    /// Variant of `spawn_streaming_upstream` that also returns the
    /// captured-headers handle so BYOK tests can verify which
    /// `Authorization` header reached the upstream.
    async fn spawn_streaming_upstream_full(
        payload: Vec<Vec<u8>>,
    ) -> (
        String,
        Arc<std::sync::Mutex<Option<AxHeaderMap>>>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let state = UpstreamState {
            calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            chunks: Arc::new(payload),
            captured_headers: captured.clone(),
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
        (format!("http://{addr}"), captured, calls)
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
        let mut providers = Providers::default();
        providers.insert(provider, cfg);
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

    /// Convenience for "happy path" success tests: seed a BYOK row,
    /// an instance/token and build the service, all under `TEST_OWNER`.
    /// Returns the service, the bearer token, and a `_keys` guard the
    /// caller must hold for the test's lifetime.
    ///
    /// The non-OR resolver is now BYOK-or-503, so every test that
    /// expects a 200 from `/llm/<provider>` must seed BYOK first.
    async fn build_byok_seeded(
        pool: SqlitePool,
        provider: &str,
        upstream_url: String,
        byok_key: &str,
        policy: InstancePolicy,
    ) -> (Arc<ProxyService>, String, tempfile::TempDir) {
        let (_id, token) = seed_instance_with_token_for(&pool, TEST_OWNER).await;
        let (svc, user_secrets, keys) = build_service_with_byok(
            pool,
            provider,
            upstream_url,
            None,
            policy,
        );
        user_secrets
            .put(TEST_OWNER, &format!("byok_{provider}"), byok_key.as_bytes())
            .await
            .expect("seed byok");
        (svc, token, keys)
    }

    /// Variant that wires a real `UserSecretsService` into the
    /// `ProxyService` so tests can pre-seed `byok_<provider>` rows
    /// and exercise the BYOK > platform precedence.  Returns the
    /// service and the user_secrets handle so the caller can `put`
    /// rows for `owner_id = "legacy"` (the value
    /// `seed_instance_with_token` uses).  Also returns the keys-dir
    /// guard so it stays alive for the test's lifetime.
    fn build_service_with_byok(
        pool: SqlitePool,
        provider: &str,
        upstream_url: String,
        real_key: Option<&str>,
        policy: InstancePolicy,
    ) -> (
        Arc<ProxyService>,
        Arc<crate::secrets::UserSecretsService>,
        tempfile::TempDir,
    ) {
        let cfg = ProviderConfig {
            api_key: real_key.map(str::to_owned),
            upstream: upstream_url,
            anthropic_version: None,
        };
        let mut providers = Providers::default();
        providers.insert(provider, cfg);
        let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));
        let instances: Arc<dyn InstanceStore> =
            Arc::new(crate::db::instances::SqlxInstanceStore::new(pool.clone()));
        let policies: Arc<dyn crate::traits::PolicyStore> =
            Arc::new(crate::db::policies::SqlitePolicyStore::new(pool.clone()));
        let audit: Arc<dyn crate::traits::AuditStore> =
            Arc::new(crate::db::audit::SqliteAuditStore::new(pool.clone()));

        // Per-test keys directory so encrypted user_secrets work.
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let user_secret_store: Arc<dyn crate::traits::UserSecretStore> =
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone()));
        let user_secrets = Arc::new(crate::secrets::UserSecretsService::new(
            user_secret_store,
            cipher_dir,
        ));

        let svc = Arc::new(
            ProxyService::new(tokens, instances, policies, audit, providers, policy)
                .expect("build proxy")
                .with_user_secrets(user_secrets.clone()),
        );
        (svc, user_secrets, keys_tmp)
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
        let (svc, token, _keys) = build_byok_seeded(
            pool,
            "openai",
            upstream_url,
            "sk-byok-test",
            permissive_policy(),
        ).await;
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
        let (upstream_url, _) = spawn_streaming_upstream(vec![b"ok".to_vec()]).await;
        let (svc, token, _keys) = build_byok_seeded(
            pool.clone(),
            "openai",
            upstream_url,
            "sk-byok-audit",
            permissive_policy(),
        ).await;
        // build_byok_seeded uses a fixed instance id (`i-test`) under
        // TEST_OWNER; recover it for the assertion below.
        let id = "i-test".to_string();
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
    async fn registry_has_all_adapters() {
        let r = adapters::registry();
        for name in [
            "openrouter", "openai", "anthropic", "gemini", "ollama",
            "groq", "deepseek", "xai", "byo",
        ] {
            assert!(r.contains_key(name), "missing adapter `{name}`");
        }
        assert_eq!(r.len(), 9);
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
        let (svc, token, _keys) = build_byok_seeded(
            pool,
            "gemini",
            upstream_url.clone(),
            real_key,
            permissive_policy(),
        ).await;
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

    // ── Stage 7 BYOK tests ───────────────────────────────────────────

    /// Pull the captured `Authorization` header out of the
    /// upstream-spy state.  Panics if no request was captured.
    fn captured_auth(captured: &std::sync::Mutex<Option<AxHeaderMap>>) -> String {
        let guard = captured.lock().unwrap();
        let h = guard
            .as_ref()
            .expect("upstream never received a request");
        h.get(axum::http::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    /// BYOK takes precedence over the platform key: the user's stored
    /// `byok_<provider>` value reaches the upstream, never the global
    /// `[providers.X].api_key`.
    #[tokio::test]
    async fn byok_takes_precedence_over_platform() {
        let (upstream_url, captured, _calls) =
            spawn_streaming_upstream_full(vec![b"ok".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token_for(&pool, TEST_OWNER).await;
        let (svc, user_secrets, _keys) = build_service_with_byok(
            pool,
            "openai",
            upstream_url,
            Some("sk-PLATFORM"),
            permissive_policy(),
        );
        // Seed a BYOK row for the same owner_id the test fixture uses.
        user_secrets
            .put(TEST_OWNER, "byok_openai", b"sk-USER-BYOK")
            .await
            .unwrap();
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(captured_auth(&captured), "Bearer sk-USER-BYOK");
    }

    /// Policy regression: non-OR providers are BYOK-or-503, even
    /// when the operator left a platform `api_key` in TOML.
    /// OpenRouter is the only provider where the operator backstops
    /// spend (its API has reseller-shaped per-key caps via the
    /// Provisioning API); for anything else, silently using the
    /// global key would mean unbounded operator spend on a provider
    /// that has no per-user spend controls.  This test pins that
    /// behaviour at the integration layer so a future "make it
    /// convenient" patch can't regress it without showing up here.
    #[tokio::test]
    async fn non_or_with_no_byok_ignores_platform_key_and_returns_503() {
        let (upstream_url, _captured, calls) =
            spawn_streaming_upstream_full(vec![b"ok".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let (svc, _user_secrets, _keys) = build_service_with_byok(
            pool,
            "openai",
            upstream_url,
            Some("sk-PLATFORM-NEVER-USE"),
            permissive_policy(),
        );
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no upstream traffic should have been emitted with the platform key",
        );
    }

    /// Neither BYOK nor platform → 503, no upstream traffic.
    #[tokio::test]
    async fn no_byok_no_platform_returns_503() {
        let (upstream_url, _captured, calls) =
            spawn_streaming_upstream_full(vec![b"x".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let (svc, _user_secrets, _keys) = build_service_with_byok(
            pool,
            "openai",
            upstream_url,
            None, // no platform key
            permissive_policy(),
        );
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// `byok_openrouter` short-circuits the lazy-mint resolver entirely.
    /// Even when no resolver is configured (the case `openrouter_with_no_
    /// resolver_fails_closed_with_503` pins) BYOK alone is enough.
    #[tokio::test]
    async fn openrouter_byok_skips_lazy_mint_and_overrides_503_path() {
        let (upstream_url, captured, calls) =
            spawn_streaming_upstream_full(vec![b"ok".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token_for(&pool, TEST_OWNER).await;
        let (svc, user_secrets, _keys) = build_service_with_byok(
            pool,
            "openrouter",
            upstream_url,
            Some("sk-OR-PLATFORM-NEVER-USE"), // present but must NOT be used
            permissive_policy(),
        );
        // Note: no UserOrKeyResolver is wired (svc was built without
        // `with_user_or_keys`) — without BYOK this would 503.  With
        // BYOK seeded, the resolver isn't consulted at all.
        user_secrets
            .put(TEST_OWNER, "byok_openrouter", b"sk-or-USER-BYOK")
            .await
            .unwrap();
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/openrouter/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "anthropic/claude-haiku-4.5"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(captured_auth(&captured), "Bearer sk-or-USER-BYOK");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// `byo` with a per-user blob routes the request to the
    /// user-supplied upstream URL with the user-supplied bearer.  The
    /// platform's "openai" upstream must NOT be hit.
    #[tokio::test]
    async fn byo_uses_user_supplied_upstream_and_key() {
        // Two upstreams: A (platform openai) gets nothing; B (byo
        // target) gets the request.
        let (upstream_a, _capa, calls_a) =
            spawn_streaming_upstream_full(vec![b"a".to_vec()]).await;
        let (upstream_b, capb, calls_b) =
            spawn_streaming_upstream_full(vec![b"b".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token_for(&pool, TEST_OWNER).await;
        // We declare openai's platform stanza pointing at A; byo has
        // none (only the user blob can populate it).
        let (svc, user_secrets, _keys) = build_service_with_byok(
            pool,
            "openai",
            upstream_a,
            Some("sk-A"),
            permissive_policy(),
        );
        let blob = serde_json::json!({
            "upstream": upstream_b,
            "api_key": "sk-USER-B",
        });
        user_secrets
            .put(TEST_OWNER, "byok_byo", &serde_json::to_vec(&blob).unwrap())
            .await
            .unwrap();
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/byo/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "any"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(captured_auth(&capb), "Bearer sk-USER-B");
        assert_eq!(calls_a.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(calls_b.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// `byo` without a per-user blob → 503; no upstream is contacted.
    #[tokio::test]
    async fn byo_without_blob_returns_503() {
        let (upstream, _captured, calls) =
            spawn_streaming_upstream_full(vec![b"x".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token(&pool).await;
        let (svc, _user_secrets, _keys) = build_service_with_byok(
            pool,
            "openai", // unrelated stanza; byo has none
            upstream,
            Some("sk-A"),
            permissive_policy(),
        );
        let proxy_base = spawn_proxy(svc).await;

        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/byo/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "any"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Audit row records `key_source = "byok"` when the BYOK row
    /// supplied the credential.  The "platform" path no longer
    /// fires for non-OR providers (see
    /// `non_or_with_no_byok_ignores_platform_key_and_returns_503`)
    /// and a 503 from missing-credential doesn't produce an audit
    /// row, so this test pins only the success-with-BYOK case.
    #[tokio::test]
    async fn audit_row_records_byok_key_source() {
        let (upstream_url, _captured, _) =
            spawn_streaming_upstream_full(vec![b"ok".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (_id, token) = seed_instance_with_token_for(&pool, TEST_OWNER).await;
        let (svc, user_secrets, _keys) = build_service_with_byok(
            pool.clone(),
            "openai",
            upstream_url,
            None,
            permissive_policy(),
        );
        let proxy_base = spawn_proxy(svc).await;
        let cli = reqwest::Client::new();

        user_secrets
            .put(TEST_OWNER, "byok_openai", b"sk-USER")
            .await
            .unwrap();
        cli.post(format!("{proxy_base}/llm/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "gpt-4o"}))
            .send()
            .await
            .unwrap();

        let row = sqlx::query("SELECT key_source FROM llm_audit ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .unwrap();
        let sources: Vec<String> = row
            .iter()
            .map(|r| sqlx::Row::try_get::<String, _>(r, "key_source").unwrap())
            .collect();
        assert_eq!(sources, vec!["byok".to_string()]);
    }

    /// D6: header allowlist drops every cookie / x-* / org-id /
    /// platform-key-bearing field on the inbound side, so an agent
    /// can't smuggle billing-relevant or cross-tenant headers
    /// through to the upstream.  Authorization is dropped here too —
    /// the adapter's `rewrite_auth` re-adds the upstream-correct one.
    #[test]
    fn sanitize_strips_non_allowlisted_headers() {
        use axum::http::HeaderValue;

        let mut h = HeaderMap::new();
        // Allowlisted — survive.
        h.insert("content-type", HeaderValue::from_static("application/json"));
        h.insert("accept", HeaderValue::from_static("text/event-stream"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        h.insert("user-agent", HeaderValue::from_static("ua/1"));
        // Stripped — every one of these is a known leak vector.
        h.insert(
            "openai-organization",
            HeaderValue::from_static("org-evil"),
        );
        h.insert("cookie", HeaderValue::from_static("sess=abc"));
        h.insert("x-api-key", HeaderValue::from_static("sk-leaked"));
        h.insert(
            "anthropic-beta",
            HeaderValue::from_static("prompt-caching-2024-07-31"),
        );
        h.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        h.insert(
            "authorization",
            HeaderValue::from_static("Bearer client-token"),
        );

        sanitize_request_headers(&mut h, "openai");

        assert!(h.get("content-type").is_some());
        assert!(h.get("accept").is_some());
        assert!(h.get("accept-encoding").is_some());
        assert!(h.get("user-agent").is_some());

        for stripped in [
            "openai-organization",
            "cookie",
            "x-api-key",
            "anthropic-beta",
            "x-forwarded-for",
            "authorization",
        ] {
            assert!(
                h.get(stripped).is_none(),
                "header {stripped} should have been stripped",
            );
        }
    }

    /// `anthropic-version` gets through on the Anthropic path but
    /// not on others — pin that the conditional allow is respected.
    #[test]
    fn sanitize_allows_anthropic_version_only_for_anthropic() {
        use axum::http::HeaderValue;
        let mut h = HeaderMap::new();
        h.insert(
            "anthropic-version",
            HeaderValue::from_static("2024-09-01"),
        );
        let mut h2 = h.clone();

        sanitize_request_headers(&mut h, "anthropic");
        assert!(h.get("anthropic-version").is_some());

        sanitize_request_headers(&mut h2, "openai");
        assert!(h2.get("anthropic-version").is_none());
    }

    /// D5: `cache_control` blocks everywhere in the request body
    /// get stripped on the platform-key path, including nested
    /// arrays under `messages[].content[]` and `system[]`.
    #[test]
    fn strip_cache_control_walks_arrays_and_objects() {
        let mut v = serde_json::json!({
            "model": "claude-haiku-4.5",
            "system": [
                {"type": "text", "text": "yo", "cache_control": {"type": "ephemeral"}},
            ],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}},
                        {"type": "image", "source": {"data": "..."}},
                    ],
                    "cache_control": {"type": "ephemeral"},
                },
            ],
            "cache_control": {"type": "ephemeral"},
        });
        strip_cache_control_in_body(&mut v);
        // No `cache_control` survives anywhere.
        let serialised = serde_json::to_string(&v).unwrap();
        assert!(
            !serialised.contains("cache_control"),
            "cache_control still present: {serialised}",
        );
        // Other content survives.
        assert!(serialised.contains("\"role\":\"user\""));
        assert!(serialised.contains("\"text\":\"hi\""));
    }

    /// Round-trip a request through one of the new providers (groq).
    /// Pins the registry wiring + Bearer rewrite for the new
    /// adapters.
    #[tokio::test]
    async fn new_provider_groq_round_trips_with_bearer_rewrite() {
        let (upstream_url, captured, _) =
            spawn_streaming_upstream_full(vec![b"ok".to_vec()]).await;
        let pool = open_in_memory().await.unwrap();
        let (svc, token, _keys) = build_byok_seeded(
            pool,
            "groq",
            upstream_url,
            "gsk-byok-test",
            permissive_policy(),
        ).await;
        let proxy_base = spawn_proxy(svc).await;
        let resp = reqwest::Client::new()
            .post(format!("{proxy_base}/llm/groq/openai/v1/chat/completions"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"model": "llama-3.3-70b"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(captured_auth(&captured), "Bearer gsk-byok-test");
    }
}

