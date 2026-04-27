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
pub mod http;
pub mod policy_check;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{ProviderConfig, Providers};
use crate::proxy::policy_check::{InstancePolicy, UsageSnapshot};
use crate::traits::{AuditStore, InstanceStore, PolicyStore, ProviderAdapter, TokenStore};

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
    rate: Arc<RateWindow>,
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
            rate: Arc::new(RateWindow::default()),
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

    /// Resolve a provider name to its config. Returns an owned clone because
    /// the adapter's `upstream_base_url` borrows from it.
    pub fn provider_config(&self, name: &str) -> Option<ProviderConfig> {
        match name {
            "anthropic" => self.providers.anthropic.clone(),
            "openai" => self.providers.openai.clone(),
            "gemini" => self.providers.gemini.clone(),
            "openrouter" => self.providers.openrouter.clone(),
            "ollama" => self.providers.ollama.clone(),
            _ => None,
        }
    }

    /// Build a [`UsageSnapshot`] for `subject` (instance_id today,
    /// owner_id after phase 6). RPS comes from an in-memory rolling window;
    /// daily tokens come from the audit store. Monthly USD is currently
    /// zero — the audit table doesn't carry per-call USD and the brief
    /// defines the policy primitive without prescribing the computation.
    pub async fn snapshot(&self, subject: &str) -> UsageSnapshot {
        let recent_rps = self.rate.observe(subject);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let daily_tokens = self.audit.daily_tokens(subject, now).await.unwrap_or(0);
        UsageSnapshot {
            recent_rps,
            daily_tokens,
            monthly_usd: 0.0,
        }
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
        q.len() as u32
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
