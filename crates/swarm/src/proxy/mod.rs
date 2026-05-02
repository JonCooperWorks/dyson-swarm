//! LLM proxy.
//!
//! - [`policy_check::enforce`] is the single composed policy gate (step 10).
//! - [`http::router`] mounts `/llm/<provider>/...` with per-instance-bearer
//!   handling baked into the catch-all handler.
//! - [`adapters`] holds the per-provider quirks.
//!
//! The proxy is intentionally a separate module tree from `/v1/*` so it can
//! carry its own auth posture and not touch the admin auth path.

pub mod adapters;
pub mod byok;
pub mod http;
pub mod mcp;
pub mod policy_check;
pub mod recording_body;
pub mod upstream_policy;
pub mod validate;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{ByoConfig, ProviderConfig, Providers};
use crate::proxy::policy_check::{InstancePolicy, UsageSnapshot};
use crate::traits::{AuditStore, InstanceStore, PolicyStore, ProviderAdapter, TokenStore};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Wires the proxy together. Cheap to clone — every field is `Arc` or
/// scalar.
pub struct ProxyService {
    pub tokens: Arc<dyn TokenStore>,
    /// Used to resolve `instance_id → owner_id` on every request so per-user
    /// budgets/policies can be looked up. The proxy bypasses tenant
    /// filtering here (it has already authenticated the caller via the
    /// proxy_token).
    pub instances: Arc<dyn InstanceStore>,
    pub policies: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditStore>,
    pub providers: Providers,
    pub adapters: HashMap<&'static str, Arc<dyn ProviderAdapter>>,
    pub http: reqwest::Client,
    pub default_policy: InstancePolicy,
    /// Optional Stage-6 per-user OpenRouter bearer resolver.  When
    /// set, requests to `/llm/openrouter/...` substitute the user's
    /// own minted OR key for the global `[providers.openrouter]
    /// api_key`.  When `None` the proxy falls back to the global key
    /// (used in tests + deployments without the OR Provisioning API
    /// configured).
    pub user_or_keys: Option<Arc<crate::openrouter::UserOrKeyResolver>>,
    /// Per-user encrypted secret store backing BYOK (`byok_<provider>`
    /// rows).  When `None`, the BYOK lookup branch is skipped and the
    /// resolver falls back to OR lazy-mint / platform key directly —
    /// preserves the pre-BYOK behaviour for tests that don't seed the
    /// store.
    pub user_secrets: Option<Arc<crate::secrets::UserSecretsService>>,
    /// Operator startup gate for user-selected `byo` upstream hosts.
    pub byo: ByoConfig,
    rate: Arc<RateWindow>,
    budget_locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl ProxyService {
    pub fn new(
        tokens: Arc<dyn TokenStore>,
        instances: Arc<dyn InstanceStore>,
        policies: Arc<dyn PolicyStore>,
        audit: Arc<dyn AuditStore>,
        providers: Providers,
        default_policy: InstancePolicy,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            tokens,
            instances,
            policies,
            audit,
            providers,
            adapters: adapters::registry(),
            http,
            default_policy,
            user_or_keys: None,
            user_secrets: None,
            byo: ByoConfig::default(),
            rate: Arc::new(RateWindow::default()),
            budget_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Builder-style setter so main.rs can plug in the resolver
    /// without making it a constructor arg (tests stay clean).
    pub fn with_user_or_keys(
        mut self,
        resolver: Arc<crate::openrouter::UserOrKeyResolver>,
    ) -> Self {
        self.user_or_keys = Some(resolver);
        self
    }

    /// Builder-style setter for the per-user secrets backing BYOK.
    /// Same shape as `with_user_or_keys` so main.rs wires both at once
    /// and tests opt in only when they need BYOK behaviour.
    pub fn with_user_secrets(mut self, secrets: Arc<crate::secrets::UserSecretsService>) -> Self {
        self.user_secrets = Some(secrets);
        self
    }

    pub fn with_byo_config(mut self, byo: ByoConfig) -> Self {
        self.byo = byo;
        self
    }

    /// Resolve a provider name to its config. Returns an owned clone because
    /// the adapter's `upstream_base_url` borrows from it.
    pub fn provider_config(&self, name: &str) -> Option<ProviderConfig> {
        self.providers.get(name).cloned()
    }

    /// Build a [`UsageSnapshot`] for an owner id. RPS comes from an
    /// in-memory rolling window; daily tokens come from the audit store.
    ///
    /// Pricing tables are intentionally not implemented; configured
    /// `monthly_usd_budget` values fail closed until a pricing layer exists.
    /// Daily token budgets ARE enforced via `daily_tokens` (which now
    /// correctly sums `prompt_tokens + output_tokens` after Agent 1's
    /// audit-completion plumbing — `update_completion` stamps the
    /// final `output_tokens` count once the upstream body finishes
    /// streaming, so the daily budget reflects real usage rather than
    /// just the prompt-side estimate).
    pub async fn snapshot(&self, subject: &str) -> UsageSnapshot {
        let recent_rps = self.rate.observe(subject);
        let daily_tokens = self
            .audit
            .daily_tokens(subject, crate::now_secs())
            .await
            .unwrap_or(0);
        UsageSnapshot {
            recent_rps,
            daily_tokens,
            // See doc comment above: pricing intentionally absent.  NaN
            // makes configured USD budgets fail closed instead of silently
            // passing against a fake 0.0 spend total.
            monthly_usd: f64::NAN,
        }
    }

    pub async fn budget_guard(&self, subject: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.budget_locks.lock().expect("budget lock map poisoned");
            locks
                .entry(subject.to_owned())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

/// One-second rolling window of request timestamps. `observe` records `now`
/// and returns the current count (including the just-recorded timestamp).
#[derive(Default)]
struct RateWindow {
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateWindow {
    fn observe(&self, subject: &str) -> u32 {
        let mut m = self.buckets.lock().expect("rate window poisoned");
        let q = m.entry(subject.to_string()).or_default();
        let now = Instant::now();
        q.push_back(now);
        prune(q, now);
        // RPS counter is u32; capping at u32::MAX is fine — anything north of
        // 4 billion entries in the per-second window has already failed open
        // and the policy check will reject regardless.
        u32::try_from(q.len()).unwrap_or(u32::MAX)
    }
}

fn prune(q: &mut VecDeque<Instant>, now: Instant) {
    let cutoff = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
    while let Some(front) = q.front() {
        if *front < cutoff {
            q.pop_front();
        } else {
            break;
        }
    }
}
