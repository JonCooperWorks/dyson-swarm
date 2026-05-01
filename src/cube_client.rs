//! `CubeClient` over HTTP. One `reqwest::Client` is constructed and reused
//! across calls. 5xx responses retry up to three attempts with jittered
//! backoff capped at 5s. 4xx responses are terminal — they map straight to
//! `CubeError::Status`. Transport errors retry the same way as 5xx.
//!
//! No retry loops anywhere else in the codebase; this is the single seam
//! where Cube flakiness is absorbed.

use std::collections::BTreeMap;
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
    #[serde(rename = "templateID")]
    template_id: &'a str,
    /// Renamed to envVars to match CubeAPI's E2B-style schema. Skipped
    /// when empty so the validator doesn't trip on a `{}` payload.
    #[serde(rename = "envVars", skip_serializing_if = "BTreeMap::is_empty")]
    env: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "fromSnapshot")]
    from_snapshot: Option<FromSnapshot<'a>>,
    /// Force CubeAPI to install an explicit `CubeVSContext` for the
    /// sandbox.  Without `allow_internet_access` *or* a non-empty
    /// `network` block, `build_cubevs_context` returns `None` and the
    /// per-ifindex eBPF policy maps end up in whatever state the
    /// previous occupant of the TAP (or the pool pre-allocation) left
    /// them in — observed as silent egress drops.  Mirrors the shape
    /// used in CubeSandbox's `network_denylist.py` example.
    allow_internet_access: bool,
    network: SandboxNetwork<'a>,
    /// CubeMaster's restore-from-snapshot path
    /// (`handleColdStartCompatibility`) requires either an inbound
    /// `com.netid` annotation OR a populated `cube_box_req_template`
    /// in CubeMaster's conf.yaml.  Stock cube installs leave the
    /// template's annotations block empty, so the snapshot-restore
    /// 500s with `netID is missing in CubeBoxReqTemplate`.  Sending
    /// the annotation from here is harmless on the from-scratch path
    /// (the cold-start branch only fires when restoring) and unblocks
    /// rotation without a host-side cube config patch.  Value is
    /// opaque to CubeMaster — any non-empty string works.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<&'static str, &'static str>,
}

#[derive(Debug, Serialize)]
struct SandboxNetwork<'a> {
    /// Explicit "allow everything not denied below".  Required because
    /// the cube template injects `119.29.29.29/32` (DNSPod) into
    /// allow_out by default, which flips the eBPF policy into
    /// whitelist mode — the cube then can only reach IPs in
    /// allow_out, not the rest of the public internet.  Sending
    /// `0.0.0.0/0` here keeps the policy in blacklist mode (allow
    /// all, subtract deny_out) and is unioned with whatever the
    /// template also adds.  Symptom when missing: cube TCP SYN to
    /// `swarm.myprivate.network:443` stays in `syn_sent` until the
    /// cubevs session reaper kills it.
    ///
    /// Per-instance now: derived from the row's `NetworkPolicy` via
    /// `crate::network_policy::resolve`.  See that module for the
    /// profile → wire-shape table.
    #[serde(rename = "allowOut")]
    allow_out: &'a [String],
    /// Mirrors `alwaysDeniedSandboxCIDRs` in CubeNet (`netpolicy.go`).
    /// The eBPF layer always appends these to the deny trie, but
    /// passing them here forces `build_cubevs_context` to return
    /// `Some(...)` and keeps the policy view auditable from the
    /// orchestrator side.
    #[serde(rename = "denyOut")]
    deny_out: &'a [String],
}

#[derive(Debug, Serialize)]
struct FromSnapshot<'a> {
    path: &'a str,
}

#[derive(Debug, Deserialize)]
struct CreateResp {
    #[serde(rename = "sandboxID")]
    sandbox_id: String,
    /// CubeAPI's create response doesn't carry hostIP (single-host
    /// model). Snapshot create still does — that's the host the snapshot
    /// blob lives on, supplied back on delete. Default here keeps the
    /// SandboxInfo shape stable.
    #[serde(rename = "hostIP", default)]
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
    /// CubeMaster currently returns this as `omitempty` — the
    /// underlying gRPC's `commitRsp.GetSnapshotPath()` is sometimes
    /// blank and CubeAPI then drops the field from the JSON.  Bundle
    /// IS on disk at `<CUBE_SNAPSHOT_ROOT>/<snapshot_id>` regardless,
    /// so we deserialize as Option and the caller derives the path
    /// from the snapshot id when cube didn't supply one.  Tracked
    /// upstream; this defensive shape unblocks rotation in the
    /// meantime.
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "hostIP", default)]
    host_ip: String,
}

/// Filesystem layout the cube uses for snapshot bundles when CubeMaster
/// doesn't echo the path back.  Same root the CubeShim writes to
/// (`/usr/local/services/cubetoolbox/cube-snapshot/cubebox/<name>`)
/// — kept in sync with `deploy/scripts/bring-up.sh`'s install prefix.
/// Override via the `CUBE_SNAPSHOT_ROOT` env var on dev hosts that ran
/// the cube installer with a non-standard `--prefix`.
fn cube_snapshot_root() -> String {
    std::env::var("CUBE_SNAPSHOT_ROOT")
        .unwrap_or_else(|_| "/usr/local/services/cubetoolbox/cube-snapshot/cubebox".to_owned())
}

#[async_trait]
impl CubeClient for HttpCubeClient {
    async fn create_sandbox(&self, args: CreateSandboxArgs) -> Result<SandboxInfo, CubeError> {
        let from_snap_path: Option<String> = args
            .from_snapshot_path
            .as_ref()
            .map(|p| p.display().to_string());
        // See `CreateBody.annotations` doc for why we always send
        // `com.netid` — closes a CubeMaster cold-start path bug
        // without requiring a host config edit.
        let mut annotations = BTreeMap::new();
        annotations.insert("com.netid", "dyson");
        let body = CreateBody {
            template_id: &args.template_id,
            env: &args.env,
            from_snapshot: from_snap_path.as_deref().map(|path| FromSnapshot { path }),
            allow_internet_access: args.resolved_policy.allow_internet_access,
            network: SandboxNetwork {
                allow_out: &args.resolved_policy.allow_out,
                deny_out: &args.resolved_policy.deny_out,
            },
            annotations,
        };
        let url = self.url("/sandboxes");
        let resp: CreateResp = with_retry(MAX_ATTEMPTS, || async {
            send_json(
                &self.http,
                reqwest::Method::POST,
                &url,
                &self.api_key,
                Some(&body),
            )
            .await
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
        let url = self.url(&format!("/sandboxes/{sandbox_id}"));
        let _: serde_json::Value = with_retry(MAX_ATTEMPTS, || async {
            send_json::<()>(
                &self.http,
                reqwest::Method::DELETE,
                &url,
                &self.api_key,
                None,
            )
            .await
        })
        .await?;
        Ok(())
    }

    async fn snapshot_sandbox(
        &self,
        sandbox_id: &str,
        name: &str,
    ) -> Result<SnapshotInfo, CubeError> {
        let url = self.url(&format!("/sandboxes/{sandbox_id}/snapshots"));
        let body = SnapshotBody { name };
        let resp: SnapshotResp = with_retry(MAX_ATTEMPTS, || async {
            send_json(
                &self.http,
                reqwest::Method::POST,
                &url,
                &self.api_key,
                Some(&body),
            )
            .await
        })
        .await?;
        // CubeMaster's response omits `path` when the underlying
        // gRPC didn't fill it in; the bundle is still on disk under
        // `<CUBE_SNAPSHOT_ROOT>/<snapshot_id>`.  Reconstruct the
        // path so the snapshot row carries something
        // restore can later open.
        let path = resp.path.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            let derived = format!("{}/{}", cube_snapshot_root(), resp.snapshot_id);
            tracing::debug!(
                snapshot_id = %resp.snapshot_id,
                derived = %derived,
                "snapshot response missing path; deriving from snapshot_id"
            );
            derived
        });
        Ok(SnapshotInfo {
            snapshot_id: resp.snapshot_id,
            path,
            host_ip: resp.host_ip,
        })
    }

    async fn delete_snapshot(&self, snapshot_id: &str, host_ip: &str) -> Result<(), CubeError> {
        // The fork's delete route is /sandboxes/snapshots/{snapshotID}
        // with hostIP as a required query string — single-host installs
        // use whatever host_ip the snapshot create response carried.
        let url = self.url(&format!(
            "/sandboxes/snapshots/{snapshot_id}?hostIP={host_ip}"
        ));
        let _: serde_json::Value = with_retry(MAX_ATTEMPTS, || async {
            send_json::<()>(
                &self.http,
                reqwest::Method::DELETE,
                &url,
                &self.api_key,
                None,
            )
            .await
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
                return serde_json::from_value::<T>(v)
                    .map_err(|e| CubeError::Decode(e.to_string()));
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
    // Jitter only — truncation to u64 is fine; we don't need the upper bits.
    let nanos = u64::try_from(s.elapsed().as_nanos() & u128::from(u64::MAX)).unwrap_or(0);
    nanos ^ u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15)
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
        // Number of 503s to emit before succeeding on /sandboxes.
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
        // CubeAPI's create payload uses E2B-style camelCase: templateID is
        // always present; envVars is omitted when the map is empty.
        assert_eq!(body["templateID"], "tpl");
        if !body["envVars"].is_null() {
            assert!(body["envVars"].is_object());
        }
        // Egress policy is always sent so CubeVSContext is non-None on
        // the API side — see `network_denylist.py` in CubeSandbox/examples.
        // The default is `NoLocalNet`: empty allowOut (so the BPF
        // default-allow path lets non-private destinations through) and
        // a populated denyOut covering RFC1918 / link-local / metadata.
        assert_eq!(body["allow_internet_access"], true);
        assert!(body["network"]["allowOut"].is_array());
        assert_eq!(body["network"]["allowOut"].as_array().unwrap().len(), 0);
        assert!(body["network"]["denyOut"].is_array());
        assert!(!body["network"]["denyOut"].as_array().unwrap().is_empty());
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

    async fn delete_snap_handler(State(s): State<MockState>, Path(_): Path<String>) -> AxStatus {
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
            .route("/sandboxes", create_route)
            .route("/sandboxes/:id", delete(delete_handler))
            .route("/sandboxes/:id/snapshots", post(snapshot_handler))
            .route("/sandboxes/snapshots/:id", delete(delete_snap_handler))
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

    #[test]
    fn create_body_serialises_egress_policy() {
        // Lock in the wire shape consumed by CubeAPI's
        // `build_cubevs_context`: top-level `allow_internet_access` plus
        // a `network` block carrying `denyOut`.  Without both, the API
        // returns `cubevs_context: None` and the per-ifindex eBPF
        // policy maps are not explicitly populated.
        let env = BTreeMap::new();
        let allow: Vec<String> = crate::network_policy::DEFAULT_OPEN_ALLOW_OUT
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let deny: Vec<String> = crate::network_policy::DEFAULT_DENY_OUT
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let body = CreateBody {
            template_id: "tpl",
            env: &env,
            from_snapshot: None,
            allow_internet_access: true,
            network: SandboxNetwork {
                allow_out: &allow,
                deny_out: &deny,
            },
            annotations: BTreeMap::new(),
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["templateID"], "tpl");
        assert_eq!(v["allow_internet_access"], true);
        // Explicit allow-all keeps the eBPF policy in blacklist mode
        // even when the cube template injects its own allow_out
        // entries (e.g. DNSPod 119.29.29.29/32).  Without this, the
        // template's allow_out flips the policy into whitelist mode
        // and silently drops all egress except the templated CIDRs.
        let allow: Vec<&str> = v["network"]["allowOut"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        // 0.0.0.0/0 keeps the policy in blacklist mode; 192.168.0.1/32
        // punches a /32 hole in the always-denied 192.168.0.0/16 so the
        // cube can reach the host on the cube-dev gateway IP (path 1
        // for the NAT-hairpin: cube reaches Caddy via /etc/hosts entry
        // pointing swarm.myprivate.network at 192.168.0.1).
        assert_eq!(allow, vec!["0.0.0.0/0", "192.168.0.1/32"]);
        let deny: Vec<&str> = v["network"]["denyOut"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        // Single source of truth — the constant in network_policy.rs.
        // Post-A1 the curated set is wider than `alwaysDeniedSandbox
        // CIDRs` (adds 0.0.0.0/8, 100.64/10, multicast, class-E reserved
        // on top of RFC1918+linklocal+loopback).
        let expected: Vec<&str> = crate::network_policy::DEFAULT_DENY_OUT.to_vec();
        assert_eq!(deny, expected);
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
                resolved_policy: crate::network_policy::ResolvedPolicy::default(),
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
                resolved_policy: crate::network_policy::ResolvedPolicy::default(),
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
                resolved_policy: crate::network_policy::ResolvedPolicy::default(),
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
