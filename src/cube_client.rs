//! `CubeClient` over HTTP. One `reqwest::Client` is constructed and reused
//! across calls. 5xx responses retry up to three attempts with jittered
//! backoff capped at 5s. 4xx responses are terminal — they map straight to
//! `CubeError::Status`. Transport errors retry the same way as 5xx.
//!
//! No retry loops anywhere else in the codebase; this is the single seam
//! where Cube flakiness is absorbed.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::CubeConfig;
use crate::error::CubeError;
use crate::traits::{CreateSandboxArgs, CubeClient, SandboxInfo, SnapshotInfo};

const MAX_ATTEMPTS: u32 = 3;
const BACKOFF_CAP: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct HttpCubeClient {
    base: String,
    api_key: String,
    sandbox_domain: String,
    http: Client,
}

impl HttpCubeClient {
    pub fn new(cfg: &CubeConfig) -> Result<Self, CubeError> {
        let http = Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()
            .map_err(|e| CubeError::Transport(e.to_string()))?;
        Ok(Self {
            base: cfg.url.trim_end_matches('/').to_owned(),
            api_key: cfg.api_key.clone(),
            sandbox_domain: cfg.sandbox_domain.clone(),
            http,
        })
    }

    /// Override the http client (used by tests with a custom timeout).
    pub fn with_client(mut self, http: Client) -> Self {
        self.http = http;
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn build_sandbox_url(&self, sandbox_id: &str) -> String {
        format!("https://{sandbox_id}.{}", self.sandbox_domain)
    }
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    template_id: &'a str,
    env: &'a std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "fromSnapshot")]
    from_snapshot: Option<FromSnapshot<'a>>,
}

#[derive(Debug, Serialize)]
struct FromSnapshot<'a> {
    path: &'a str,
}

#[derive(Debug, Deserialize)]
struct CreateResp {
    #[serde(rename = "sandboxID")]
    sandbox_id: String,
    #[serde(rename = "hostIP")]
    host_ip: String,
}

#[derive(Debug, Serialize)]
struct SnapshotBody<'a> {
    name: &'a str,
}

#[derive(Debug, Deserialize)]
struct SnapshotResp {
    #[serde(rename = "snapshotID")]
    snapshot_id: String,
    path: String,
    #[serde(rename = "hostIP")]
    host_ip: String,
}

#[async_trait]
impl CubeClient for HttpCubeClient {
    async fn create_sandbox(&self, args: CreateSandboxArgs) -> Result<SandboxInfo, CubeError> {
        let from_snap_path: Option<String> = args
            .from_snapshot_path
            .as_ref()
            .map(|p| p.display().to_string());
        let body = CreateBody {
            template_id: &args.template_id,
            env: &args.env,
            from_snapshot: from_snap_path.as_deref().map(|path| FromSnapshot { path }),
        };
        let url = self.url("/v1/sandboxes");
        let resp: CreateResp = with_retry(MAX_ATTEMPTS, || async {
            send_json(&self.http, reqwest::Method::POST, &url, &self.api_key, Some(&body)).await
        })
        .await?;
        let sandbox_url = self.build_sandbox_url(&resp.sandbox_id);
        Ok(SandboxInfo {
            sandbox_id: resp.sandbox_id,
            host_ip: resp.host_ip,
            url: sandbox_url,
        })
    }

    async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), CubeError> {
        let url = self.url(&format!("/v1/sandboxes/{sandbox_id}"));
        let _: serde_json::Value = with_retry(MAX_ATTEMPTS, || async {
            send_json::<()>(&self.http, reqwest::Method::DELETE, &url, &self.api_key, None).await
        })
        .await?;
        Ok(())
    }

    async fn snapshot_sandbox(
        &self,
        sandbox_id: &str,
        name: &str,
    ) -> Result<SnapshotInfo, CubeError> {
        let url = self.url(&format!("/v1/sandboxes/{sandbox_id}/snapshots"));
        let body = SnapshotBody { name };
        let resp: SnapshotResp = with_retry(MAX_ATTEMPTS, || async {
            send_json(&self.http, reqwest::Method::POST, &url, &self.api_key, Some(&body)).await
        })
        .await?;
        Ok(SnapshotInfo {
            snapshot_id: resp.snapshot_id,
            path: resp.path,
            host_ip: resp.host_ip,
        })
    }

    async fn delete_snapshot(&self, snapshot_id: &str, host_ip: &str) -> Result<(), CubeError> {
        let url = self.url(&format!("/v1/snapshots/{snapshot_id}?hostIP={host_ip}"));
        let _: serde_json::Value = with_retry(MAX_ATTEMPTS, || async {
            send_json::<()>(&self.http, reqwest::Method::DELETE, &url, &self.api_key, None).await
        })
        .await?;
        Ok(())
    }
}

/// One attempt: send the request, decode JSON on 2xx, return a structured
/// `CubeError` otherwise. The boolean tells the retry loop whether the
/// failure is retryable.
async fn send_json<B: Serialize + ?Sized>(
    http: &Client,
    method: reqwest::Method,
    url: &str,
    api_key: &str,
    body: Option<&B>,
) -> AttemptResult {
    let mut req = http
        .request(method, url)
        .bearer_auth(api_key)
        .header("accept", "application/json");
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptResult::Retry(CubeError::Transport(e.to_string()));
        }
    };
    let status = resp.status();
    if status.is_success() {
        // Empty bodies (typical for DELETE) decode as null when we ask for
        // serde_json::Value, so always read raw bytes first.
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return AttemptResult::Terminal(CubeError::Transport(e.to_string())),
        };
        if bytes.is_empty() {
            return AttemptResult::Ok(serde_json::Value::Null);
        }
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) => AttemptResult::Ok(v),
            Err(e) => AttemptResult::Terminal(CubeError::Decode(e.to_string())),
        }
    } else {
        let body_text = resp.text().await.unwrap_or_default();
        let err = CubeError::Status {
            status: status.as_u16(),
            body: body_text,
        };
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            AttemptResult::Retry(err)
        } else {
            AttemptResult::Terminal(err)
        }
    }
}

enum AttemptResult {
    Ok(serde_json::Value),
    Retry(CubeError),
    Terminal(CubeError),
}

/// Run an attempt closure up to `max_attempts` times, retrying only on
/// retryable errors with jittered exponential backoff capped at `BACKOFF_CAP`.
/// On the final attempt the most recent error is returned as-is.
async fn with_retry<F, Fut, T>(max_attempts: u32, mut f: F) -> Result<T, CubeError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = AttemptResult>,
    T: for<'de> Deserialize<'de>,
{
    let mut last_err: Option<CubeError> = None;
    for attempt in 1..=max_attempts {
        match f().await {
            AttemptResult::Ok(v) => {
                return serde_json::from_value::<T>(v).map_err(|e| CubeError::Decode(e.to_string()));
            }
            AttemptResult::Terminal(e) => return Err(e),
            AttemptResult::Retry(e) => {
                last_err = Some(e);
                if attempt == max_attempts {
                    break;
                }
                let delay = backoff(attempt);
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(last_err.unwrap_or(CubeError::Transport("retry loop exhausted".into())))
}

fn backoff(attempt: u32) -> Duration {
    // Base = 100ms * 2^(attempt-1), then add 0..base jitter, then cap.
    let base_ms = 100u64.saturating_mul(1u64 << (attempt - 1).min(6));
    let jitter_ms = pseudo_jitter(attempt) % base_ms.max(1);
    let total = Duration::from_millis(base_ms.saturating_add(jitter_ms));
    total.min(BACKOFF_CAP)
}

/// Cheap deterministic-ish jitter without pulling in `rand`. Sourced from
/// the current monotonic time so consecutive callers don't collide; falls
/// back to the attempt count if the clock isn't monotonic.
fn pseudo_jitter(attempt: u32) -> u64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let s = START.get_or_init(Instant::now);
    s.elapsed().as_nanos() as u64 ^ (attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use axum::extract::{Path, State};
    use axum::http::StatusCode as AxStatus;
    use axum::routing::{delete, post};
    use axum::{Json, Router};

    #[derive(Clone, Default)]
    struct MockState {
        create_calls: Arc<AtomicU32>,
        snapshot_calls: Arc<AtomicU32>,
        delete_calls: Arc<AtomicU32>,
        // Number of 503s to emit before succeeding on /v1/sandboxes.
        create_flake_remaining: Arc<AtomicU32>,
    }

    async fn create_handler(
        State(s): State<MockState>,
        Json(body): Json<serde_json::Value>,
    ) -> Result<Json<serde_json::Value>, AxStatus> {
        s.create_calls.fetch_add(1, Ordering::SeqCst);
        let flake = s.create_flake_remaining.load(Ordering::SeqCst);
        if flake > 0 {
            s.create_flake_remaining.fetch_sub(1, Ordering::SeqCst);
            return Err(AxStatus::SERVICE_UNAVAILABLE);
        }
        // Inspect the env-map round-trip just enough to confirm the body
        // shape matches the brief.
        assert_eq!(body["template_id"], "tpl");
        assert!(body["env"].is_object());
        Ok(Json(serde_json::json!({
            "sandboxID": "sb-1",
            "hostIP": "10.0.0.5",
        })))
    }

    async fn create_bad_request(
        State(s): State<MockState>,
        Json(_): Json<serde_json::Value>,
    ) -> Result<Json<serde_json::Value>, (AxStatus, String)> {
        s.create_calls.fetch_add(1, Ordering::SeqCst);
        Err((AxStatus::BAD_REQUEST, "template not found".into()))
    }

    async fn snapshot_handler(
        State(s): State<MockState>,
        Path(sandbox): Path<String>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        s.snapshot_calls.fetch_add(1, Ordering::SeqCst);
        Json(serde_json::json!({
            "snapshotID": format!("snap-{sandbox}"),
            "path": format!("/var/snaps/{}", body["name"].as_str().unwrap_or("x")),
            "hostIP": "10.0.0.5",
        }))
    }

    async fn delete_handler(State(s): State<MockState>, Path(_): Path<String>) -> AxStatus {
        s.delete_calls.fetch_add(1, Ordering::SeqCst);
        AxStatus::NO_CONTENT
    }

    async fn delete_snap_handler(
        State(s): State<MockState>,
        Path(_): Path<String>,
    ) -> AxStatus {
        s.delete_calls.fetch_add(1, Ordering::SeqCst);
        AxStatus::NO_CONTENT
    }

    fn router(state: MockState, with_bad_create: bool) -> Router {
        let create_route = if with_bad_create {
            post(create_bad_request)
        } else {
            post(create_handler)
        };
        Router::new()
            .route("/v1/sandboxes", create_route)
            .route("/v1/sandboxes/:id", delete(delete_handler))
            .route("/v1/sandboxes/:id/snapshots", post(snapshot_handler))
            .route("/v1/snapshots/:id", delete(delete_snap_handler))
            .with_state(state)
    }

    async fn spawn(state: MockState, with_bad_create: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state, with_bad_create);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn cfg(base: &str) -> CubeConfig {
        CubeConfig {
            url: base.to_owned(),
            api_key: "test-key".into(),
            sandbox_domain: "cube.test".into(),
        }
    }

    #[tokio::test]
    async fn create_happy_path_builds_sandbox_url() {
        let state = MockState::default();
        let base = spawn(state.clone(), false).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        let mut env = BTreeMap::new();
        env.insert("FOO".into(), "bar".into());
        let info = client
            .create_sandbox(CreateSandboxArgs {
                template_id: "tpl".into(),
                env,
                from_snapshot_path: None,
            })
            .await
            .unwrap();
        assert_eq!(info.sandbox_id, "sb-1");
        assert_eq!(info.host_ip, "10.0.0.5");
        assert_eq!(info.url, "https://sb-1.cube.test");
        assert_eq!(state.create_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn create_retries_on_503_then_succeeds() {
        let state = MockState::default();
        state.create_flake_remaining.store(2, Ordering::SeqCst);
        let base = spawn(state.clone(), false).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        let info = client
            .create_sandbox(CreateSandboxArgs {
                template_id: "tpl".into(),
                env: BTreeMap::new(),
                from_snapshot_path: None,
            })
            .await
            .unwrap();
        assert_eq!(info.sandbox_id, "sb-1");
        // 2 flaked + 1 success = 3 calls, the maximum.
        assert_eq!(state.create_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn create_400_is_terminal_no_retry() {
        let state = MockState::default();
        let base = spawn(state.clone(), true).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        let err = client
            .create_sandbox(CreateSandboxArgs {
                template_id: "tpl".into(),
                env: BTreeMap::new(),
                from_snapshot_path: None,
            })
            .await
            .expect_err("400 must error");
        match err {
            CubeError::Status { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("template not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(state.create_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn snapshot_returns_id_path_host() {
        let state = MockState::default();
        let base = spawn(state.clone(), false).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        let snap = client.snapshot_sandbox("sb-1", "ckpt").await.unwrap();
        assert_eq!(snap.snapshot_id, "snap-sb-1");
        assert_eq!(snap.path, "/var/snaps/ckpt");
        assert_eq!(snap.host_ip, "10.0.0.5");
    }

    #[tokio::test]
    async fn destroy_sandbox_204() {
        let state = MockState::default();
        let base = spawn(state.clone(), false).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        client.destroy_sandbox("sb-1").await.unwrap();
        assert_eq!(state.delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn delete_snapshot_204() {
        let state = MockState::default();
        let base = spawn(state.clone(), false).await;
        let client = HttpCubeClient::new(&cfg(&base)).unwrap();
        client.delete_snapshot("snap-1", "10.0.0.5").await.unwrap();
        assert_eq!(state.delete_calls.load(Ordering::SeqCst), 1);
    }
}
