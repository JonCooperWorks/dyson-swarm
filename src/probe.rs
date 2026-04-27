//! Health probes.
//!
//! Two pieces:
//! - [`HttpHealthProber`] implements [`HealthProber`] over HTTP. It issues a
//!   `GET https://<sandbox_id>.<sandbox_domain>/healthz` with the
//!   per-instance bearer and a hard timeout.
//! - [`spawn_loop`] runs a background task that ticks every
//!   `health_probe_interval_seconds`, lists live instances, probes each
//!   serially, and persists the result. Three consecutive `Unreachable`
//!   results for the same instance emit exactly one `tracing::warn!` —
//!   subsequent unreachable results are silenced until the instance recovers.
//!
//! No automated remediation. The brief is explicit on this: the orchestrator
//! observes, an operator decides.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::Mutex;

use crate::traits::{HealthProber, InstanceRow, InstanceStatus, InstanceStore, ListFilter, ProbeResult};

#[derive(Clone)]
pub struct HttpHealthProber {
    http: Client,
    sandbox_domain: String,
}

impl HttpHealthProber {
    pub fn new(timeout: Duration, sandbox_domain: impl Into<String>) -> Result<Self, reqwest::Error> {
        // Mirror dyson_proxy::build_client — cubeproxy's TLS uses an
        // mkcert root that isn't in the default webpki bundle, so a
        // vanilla reqwest::Client fails with "error sending request"
        // (TLS handshake → unknown issuer) on every probe.
        // WARDEN_CUBE_ROOT_CA points at the PEM the installer drops
        // at /etc/dyson-warden/cube-root-ca.pem; trust it as an
        // additional root.  Verification stays on.
        let mut b = Client::builder().timeout(timeout);
        if let Ok(path) = std::env::var("WARDEN_CUBE_ROOT_CA")
            && !path.is_empty()
        {
            match std::fs::read(&path) {
                Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                    Ok(cert) => {
                        tracing::info!(path = %path, "probe: trusting cube root CA");
                        b = b.add_root_certificate(cert);
                    }
                    Err(e) => tracing::error!(path = %path, error = %e, "probe: WARDEN_CUBE_ROOT_CA: parse failed"),
                },
                Err(e) => tracing::error!(path = %path, error = %e, "probe: WARDEN_CUBE_ROOT_CA: read failed"),
            }
        }
        let http = b.build()?;
        Ok(Self {
            http,
            sandbox_domain: sandbox_domain.into(),
        })
    }

    fn url_for(&self, sandbox_id: &str) -> String {
        format!("https://{sandbox_id}.{}/healthz", self.sandbox_domain)
    }
}

#[async_trait]
impl HealthProber for HttpHealthProber {
    async fn probe(&self, instance: &InstanceRow) -> ProbeResult {
        let Some(sb) = instance.cube_sandbox_id.as_deref() else {
            return ProbeResult::Unreachable {
                reason: "no cube sandbox id".into(),
            };
        };
        let url = self.url_for(sb);
        let resp = match self
            .http
            .get(&url)
            .bearer_auth(&instance.bearer_token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return ProbeResult::Unreachable {
                    reason: e.to_string(),
                }
            }
        };
        let status = resp.status();
        if status.is_success() {
            ProbeResult::Healthy
        } else if status.is_server_error() {
            ProbeResult::Unreachable {
                reason: format!("HTTP {}", status.as_u16()),
            }
        } else {
            // 4xx: the sandbox responded but unhappily. Auth mismatch, wrong
            // path, etc. Treat as degraded so the operator notices without
            // it hitting the unreachable threshold.
            ProbeResult::Degraded {
                reason: format!("HTTP {}", status.as_u16()),
            }
        }
    }
}

/// Per-instance counter of consecutive `Unreachable` results. Threshold for
/// emitting a warning is 3; the warn fires exactly once and is reset on the
/// next non-unreachable probe.
#[derive(Default)]
struct UnreachableCounters {
    counts: HashMap<String, u32>,
    warned: HashMap<String, bool>,
}

impl UnreachableCounters {
    /// Record `result` for `instance_id`. Returns `true` if this call should
    /// emit a `tracing::warn!`.
    fn observe(&mut self, instance_id: &str, result: &ProbeResult) -> bool {
        match result {
            ProbeResult::Unreachable { .. } => {
                let n = self.counts.entry(instance_id.to_string()).or_insert(0);
                *n += 1;
                if *n >= 3 && !self.warned.get(instance_id).copied().unwrap_or(false) {
                    self.warned.insert(instance_id.to_string(), true);
                    return true;
                }
                false
            }
            _ => {
                self.counts.remove(instance_id);
                self.warned.remove(instance_id);
                false
            }
        }
    }
}

/// Run one tick of the probe loop: list live instances, probe each, persist
/// the result, fire warns when the threshold trips. Exposed publicly so a
/// `POST /v1/instances/:id/probe`-style synchronous run can share the same
/// counter state if it wants to.
async fn run_once(
    prober: &dyn HealthProber,
    instances: &dyn InstanceStore,
    counters: &Mutex<UnreachableCounters>,
) {
    let rows = match instances
        .list(
            "*",
            ListFilter {
                status: Some(InstanceStatus::Live),
                include_destroyed: false,
            },
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "probe loop: list failed");
            return;
        }
    };
    for row in rows {
        let result = prober.probe(&row).await;
        if let Err(e) = instances.record_probe(&row.id, result.clone()).await {
            tracing::warn!(error = %e, instance = %row.id, "probe loop: record_probe failed");
        }
        let should_warn = {
            let mut c = counters.lock().await;
            c.observe(&row.id, &result)
        };
        if should_warn {
            tracing::warn!(
                instance = %row.id,
                cube_sandbox_id = ?row.cube_sandbox_id,
                "instance unreachable for 3 consecutive probes"
            );
        }
    }
}

/// Spawn the background probe loop. Returns a `JoinHandle` so the caller can
/// abort it on shutdown if it wants — `axum::serve(...).with_graceful_shutdown`
/// already handles the signal half.
pub fn spawn_loop(
    prober: Arc<dyn HealthProber>,
    instances: Arc<dyn InstanceStore>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let counters = Arc::new(Mutex::new(UnreachableCounters::default()));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so we don't probe before
        // any instance has had a chance to come up.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_once(&*prober, &*instances, &counters).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

    /// Mock prober whose responses are dictated by a queue. Counts how many
    /// times `probe` was invoked.
    #[derive(Clone)]
    struct ScriptedProber {
        results: Arc<Mutex<Vec<ProbeResult>>>,
        calls: Arc<AtomicU32>,
    }

    impl ScriptedProber {
        fn new(results: Vec<ProbeResult>) -> Self {
            Self {
                results: Arc::new(Mutex::new(results)),
                calls: Arc::new(AtomicU32::new(0)),
            }
        }
    }

    #[async_trait]
    impl HealthProber for ScriptedProber {
        async fn probe(&self, _: &InstanceRow) -> ProbeResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut q = self.results.lock().await;
            q.remove(0)
        }
    }

    async fn seed_live(pool: &sqlx::SqlitePool, id: &str) {
        let store = SqlxInstanceStore::new(pool.clone());
        store
            .create(InstanceRow {
                id: id.into(),
                owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
                cube_sandbox_id: Some(format!("sb-{id}")),
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
            })
            .await
            .unwrap();
    }

    #[test]
    fn unreachable_counter_warns_exactly_once_at_three() {
        let mut c = UnreachableCounters::default();
        let unr = || ProbeResult::Unreachable {
            reason: "x".into(),
        };
        assert!(!c.observe("i1", &unr())); // 1
        assert!(!c.observe("i1", &unr())); // 2
        assert!(c.observe("i1", &unr())); // 3 → warn
        assert!(!c.observe("i1", &unr())); // 4 → silenced
        assert!(!c.observe("i1", &unr())); // 5 → silenced
    }

    #[test]
    fn unreachable_counter_resets_on_recovery() {
        let mut c = UnreachableCounters::default();
        let unr = || ProbeResult::Unreachable {
            reason: "x".into(),
        };
        assert!(!c.observe("i1", &unr()));
        assert!(!c.observe("i1", &unr()));
        assert!(!c.observe("i1", &ProbeResult::Healthy));
        // Counter cleared, so we should be able to warn again on the next 3
        // unreachables — confirms `warned` was wiped too.
        assert!(!c.observe("i1", &unr()));
        assert!(!c.observe("i1", &unr()));
        assert!(c.observe("i1", &unr()));
    }

    #[test]
    fn unreachable_counter_is_per_instance() {
        let mut c = UnreachableCounters::default();
        let unr = || ProbeResult::Unreachable {
            reason: "x".into(),
        };
        assert!(!c.observe("a", &unr()));
        assert!(!c.observe("b", &unr()));
        assert!(!c.observe("a", &unr()));
        assert!(!c.observe("b", &unr()));
        assert!(c.observe("a", &unr()));
        assert!(c.observe("b", &unr()));
    }

    #[tokio::test]
    async fn run_once_persists_results_and_skips_destroyed() {
        let pool = open_in_memory().await.unwrap();
        seed_live(&pool, "i1").await;

        // A destroyed instance: should NOT be probed.
        let store = SqlxInstanceStore::new(pool.clone());
        store
            .create(InstanceRow {
                id: "d1".into(),
                owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
                cube_sandbox_id: Some("sb-d1".into()),
                template_id: "t".into(),
                status: InstanceStatus::Destroyed,
                bearer_token: "b".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: Some(0),
            })
            .await
            .unwrap();

        let prober = ScriptedProber::new(vec![ProbeResult::Healthy]);
        let counters = Mutex::new(UnreachableCounters::default());
        let store_dyn: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
        run_once(&prober, &*store_dyn, &counters).await;

        assert_eq!(prober.calls.load(Ordering::SeqCst), 1);
        let i1 = store_dyn.get("i1").await.unwrap().unwrap();
        assert!(matches!(i1.last_probe_status, Some(ProbeResult::Healthy)));
        assert!(i1.last_probe_at.is_some());
        let d1 = store_dyn.get("d1").await.unwrap().unwrap();
        assert!(d1.last_probe_status.is_none());
    }

    #[tokio::test]
    async fn run_once_three_unreachables_warn_once() {
        let pool = open_in_memory().await.unwrap();
        seed_live(&pool, "i1").await;
        let store_dyn: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));

        let unr = || ProbeResult::Unreachable {
            reason: "boom".into(),
        };
        let prober = ScriptedProber::new(vec![unr(), unr(), unr(), unr()]);
        let counters = Mutex::new(UnreachableCounters::default());

        // Tick 1, 2: silent.
        for _ in 0..2 {
            run_once(&prober, &*store_dyn, &counters).await;
            let c = counters.lock().await;
            assert!(!c.warned.get("i1").copied().unwrap_or(false));
        }
        // Tick 3: warn.
        run_once(&prober, &*store_dyn, &counters).await;
        {
            let c = counters.lock().await;
            assert!(c.warned.get("i1").copied().unwrap_or(false));
        }
        // Tick 4: still unreachable but warning is silenced.
        run_once(&prober, &*store_dyn, &counters).await;
        let c = counters.lock().await;
        // Still flagged as warned; no second warn would have fired.
        assert!(c.warned.get("i1").copied().unwrap_or(false));
    }
}
