//! Single entrypoint that composes [`crate::policy`] primitives into one
//! check. The brief specifies `enforce(token, body) -> Result<(),
//! PolicyDenial>`. Concretely the check needs more context than the token
//! alone carries (the resolved policy, current usage counters, and which
//! provider the URL path resolved to), so this module also defines
//! `EnforceContext` to bundle them. The proxy router wires the async loads
//! that materialise the context, then this function decides yes/no.

use crate::policy::{
    model_allowed, provider_allowed, within_daily_token_budget, within_monthly_usd_budget,
    within_rps, PolicyDenial,
};
use crate::traits::TokenRecord;

/// Re-export of the canonical policy record. Predates the multi-tenant
/// schema; the trait-level type now lives in [`crate::traits`] so
/// [`crate::traits::PolicyStore`] impls don't need to convert.
pub use crate::traits::PolicyRecord as InstancePolicy;

/// Live counters the caller pre-computes from `llm_audit` (and an in-memory
/// rate window). Passing them in keeps this function pure and trivially
/// table-testable.
#[derive(Debug, Clone, Default)]
pub struct UsageSnapshot {
    pub recent_rps: u32,
    pub daily_tokens: u64,
    pub monthly_usd: f64,
}

/// Bundle handed to [`enforce`].
pub struct EnforceContext<'a> {
    pub policy: &'a InstancePolicy,
    pub usage: &'a UsageSnapshot,
    /// Provider derived from the URL path (`/llm/<provider>/...`), not from
    /// the token (which is a shared per-instance token with provider="*").
    pub provider: &'a str,
}

/// Composed check. Order matches the brief: provider → model → rps →
/// daily-tokens → monthly-usd. The first failure short-circuits.
pub fn enforce(
    ctx: &EnforceContext<'_>,
    _token: &TokenRecord,
    body: &serde_json::Value,
) -> Result<(), PolicyDenial> {
    if !provider_allowed(&ctx.policy.allowed_providers, ctx.provider) {
        return Err(PolicyDenial::ProviderNotAllowed);
    }
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    if !model_allowed(&ctx.policy.allowed_models, model) {
        return Err(PolicyDenial::ModelNotAllowed);
    }
    if !within_rps(ctx.policy.rps_limit, ctx.usage.recent_rps) {
        return Err(PolicyDenial::RpsExceeded);
    }
    if !within_daily_token_budget(ctx.policy.daily_token_budget, ctx.usage.daily_tokens) {
        return Err(PolicyDenial::DailyTokenBudgetExceeded);
    }
    if !within_monthly_usd_budget(ctx.policy.monthly_usd_budget, ctx.usage.monthly_usd) {
        return Err(PolicyDenial::MonthlyUsdBudgetExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    fn token() -> TokenRecord {
        TokenRecord {
            token: "t".into(),
            instance_id: "i".into(),
            provider: "*".into(),
            created_at: 0,
            revoked_at: None,
        }
    }

    fn permissive_policy() -> InstancePolicy {
        InstancePolicy {
            allowed_providers: s(&["*"]),
            allowed_models: s(&["*"]),
            daily_token_budget: None,
            monthly_usd_budget: None,
            rps_limit: None,
        }
    }

    fn cold_usage() -> UsageSnapshot {
        UsageSnapshot::default()
    }

    fn body(model: &str) -> serde_json::Value {
        serde_json::json!({ "model": model, "messages": [] })
    }

    #[test]
    fn fully_permissive_passes() {
        let p = permissive_policy();
        let ctx = EnforceContext {
            policy: &p,
            usage: &cold_usage(),
            provider: "openai",
        };
        enforce(&ctx, &token(), &body("gpt-4o")).expect("ok");
    }

    #[test]
    fn provider_denial_short_circuits() {
        let mut p = permissive_policy();
        p.allowed_providers = s(&["openrouter"]);
        let ctx = EnforceContext {
            policy: &p,
            usage: &cold_usage(),
            provider: "anthropic",
        };
        let err = enforce(&ctx, &token(), &body("claude-opus-4-7")).expect_err("denied");
        assert_eq!(err, PolicyDenial::ProviderNotAllowed);
        assert_eq!(err.code(), "provider_not_allowed");
    }

    #[test]
    fn model_denial_after_provider_passes() {
        let mut p = permissive_policy();
        p.allowed_models = s(&["claude-opus-4-7"]);
        let ctx = EnforceContext {
            policy: &p,
            usage: &cold_usage(),
            provider: "anthropic",
        };
        let err = enforce(&ctx, &token(), &body("gpt-4o")).expect_err("denied");
        assert_eq!(err, PolicyDenial::ModelNotAllowed);
    }

    #[test]
    fn rps_denial() {
        let mut p = permissive_policy();
        p.rps_limit = Some(5);
        let usage = UsageSnapshot {
            recent_rps: 5,
            ..Default::default()
        };
        let ctx = EnforceContext {
            policy: &p,
            usage: &usage,
            provider: "openai",
        };
        let err = enforce(&ctx, &token(), &body("gpt-4o")).expect_err("denied");
        assert_eq!(err, PolicyDenial::RpsExceeded);
    }

    #[test]
    fn daily_token_denial() {
        let mut p = permissive_policy();
        p.daily_token_budget = Some(1000);
        let usage = UsageSnapshot {
            daily_tokens: 1000,
            ..Default::default()
        };
        let ctx = EnforceContext {
            policy: &p,
            usage: &usage,
            provider: "openai",
        };
        let err = enforce(&ctx, &token(), &body("gpt-4o")).expect_err("denied");
        assert_eq!(err, PolicyDenial::DailyTokenBudgetExceeded);
    }

    #[test]
    fn monthly_usd_denial() {
        let mut p = permissive_policy();
        p.monthly_usd_budget = Some(100.0);
        let usage = UsageSnapshot {
            monthly_usd: 100.01,
            ..Default::default()
        };
        let ctx = EnforceContext {
            policy: &p,
            usage: &usage,
            provider: "openai",
        };
        let err = enforce(&ctx, &token(), &body("gpt-4o")).expect_err("denied");
        assert_eq!(err, PolicyDenial::MonthlyUsdBudgetExceeded);
    }

    #[test]
    fn order_is_provider_then_model_then_rate() {
        // Several denials simultaneously satisfied; first hit wins.
        let mut p = permissive_policy();
        p.allowed_providers = s(&["openrouter"]);
        p.allowed_models = s(&["claude-only"]);
        p.rps_limit = Some(0);
        let usage = UsageSnapshot {
            recent_rps: 999,
            daily_tokens: u64::MAX,
            monthly_usd: f64::MAX,
        };
        let ctx = EnforceContext {
            policy: &p,
            usage: &usage,
            provider: "openai",
        };
        let err = enforce(&ctx, &token(), &body("gpt-4o")).expect_err("denied");
        assert_eq!(err, PolicyDenial::ProviderNotAllowed);
    }

    #[test]
    fn missing_model_field_is_empty_string() {
        let mut p = permissive_policy();
        p.allowed_models = s(&["gpt-4o"]);
        let ctx = EnforceContext {
            policy: &p,
            usage: &cold_usage(),
            provider: "openai",
        };
        let err = enforce(&ctx, &token(), &serde_json::json!({"messages": []}))
            .expect_err("denied");
        assert_eq!(err, PolicyDenial::ModelNotAllowed);
    }
}
