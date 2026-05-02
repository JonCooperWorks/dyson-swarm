//! Pure policy primitives. None of these touch the network or DB; the
//! caller is responsible for materialising the policy + current usage and
//! handing them in. The proxy (step 14) wires the async loads to these
//! sync checks.

use serde::{Deserialize, Serialize};

/// Closed-enum denial codes. Returned to callers as the `code` field of a
/// 403 body so the agent can branch on the exact reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDenial {
    ProviderNotAllowed,
    ModelNotAllowed,
    RpsExceeded,
    DailyTokenBudgetExceeded,
    MonthlyUsdBudgetExceeded,
}

impl PolicyDenial {
    pub fn code(self) -> &'static str {
        match self {
            Self::ProviderNotAllowed => "provider_not_allowed",
            Self::ModelNotAllowed => "model_not_allowed",
            Self::RpsExceeded => "rps_exceeded",
            Self::DailyTokenBudgetExceeded => "daily_token_budget_exceeded",
            Self::MonthlyUsdBudgetExceeded => "monthly_usd_budget_exceeded",
        }
    }
}

/// `"*"` is the wildcard. Returns true if either the wildcard or the exact
/// `provider` string is present.
pub fn provider_allowed(allowed: &[String], provider: &str) -> bool {
    allowed.iter().any(|p| p == "*" || p == provider)
}

/// `"*"` is the universal wildcard.  Each entry is exact-match unless
/// it ends with `*`, in which case the prefix matches.  So `"gpt-4o*"`
/// matches `gpt-4o`, `gpt-4o-2024-08-06`, etc.
pub fn model_allowed(allowed: &[String], model: &str) -> bool {
    allowed.iter().any(|m| {
        if m == "*" {
            return true;
        }
        if let Some(prefix) = m.strip_suffix('*') {
            return model.starts_with(prefix);
        }
        m == model
    })
}

/// `recent_rps` is the count of requests in the last whole second.
/// `None` limit means no limit.
pub fn within_rps(limit: Option<u32>, recent_rps: u32) -> bool {
    match limit {
        Some(lim) => recent_rps < lim,
        None => true,
    }
}

/// `used_tokens` is the running total for the rolling-day window.
pub fn within_daily_token_budget(budget: Option<u64>, used_tokens: u64) -> bool {
    match budget {
        Some(b) => used_tokens < b,
        None => true,
    }
}

/// `used_usd` is the running total for the calendar month.
///
/// Pricing is intentionally not implemented in this build.  Callers that
/// cannot compute a real USD total pass `NaN`; any configured budget then
/// fails closed instead of silently allowing spend against a fake `0.0`.
/// Daily token budgets ARE enforced via `within_daily_token_budget` and
/// `audit::daily_tokens`.
pub fn within_monthly_usd_budget(budget: Option<f64>, used_usd: f64) -> bool {
    match budget {
        Some(b) => used_usd.is_finite() && used_usd < b,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn provider_wildcard_allows_anything() {
        assert!(provider_allowed(&s(&["*"]), "anthropic"));
        assert!(provider_allowed(&s(&["*"]), "obscure"));
    }

    #[test]
    fn provider_exact_match() {
        let allowed = s(&["openai", "anthropic"]);
        assert!(provider_allowed(&allowed, "openai"));
        assert!(provider_allowed(&allowed, "anthropic"));
        assert!(!provider_allowed(&allowed, "gemini"));
    }

    #[test]
    fn provider_empty_list_denies() {
        assert!(!provider_allowed(&[], "openai"));
    }

    #[test]
    fn model_wildcard_allows_anything() {
        assert!(model_allowed(&s(&["*"]), "claude-opus-4-7"));
        assert!(model_allowed(&s(&["*"]), "anything-here"));
    }

    #[test]
    fn model_exact_match() {
        let allowed = s(&["gpt-4o", "claude-3-5-sonnet"]);
        assert!(model_allowed(&allowed, "gpt-4o"));
        assert!(!model_allowed(&allowed, "gpt-3.5-turbo"));
    }

    #[test]
    fn model_trailing_star_is_prefix_match() {
        let allowed = s(&["gpt-4o*", "claude-3-5-sonnet"]);
        assert!(model_allowed(&allowed, "gpt-4o"));
        assert!(model_allowed(&allowed, "gpt-4o-2024-08-06"));
        assert!(model_allowed(&allowed, "gpt-4o-mini"));
        assert!(!model_allowed(&allowed, "gpt-3.5-turbo"));
        // Star only matches at the end — a literal `*` mid-string
        // would have to be exact.
        let weird = s(&["foo*bar"]);
        assert!(!model_allowed(&weird, "foobar"));
        assert!(!model_allowed(&weird, "foozbar"));
    }

    #[test]
    fn model_bare_star_still_universal() {
        // `"*"` alone is the universal wildcard (back-compat with the
        // pre-glob behaviour).  `strip_suffix('*')` would leave an
        // empty prefix that matches anything via `starts_with("")` —
        // same outcome, but the explicit branch keeps the intent
        // legible.
        assert!(model_allowed(&s(&["*"]), "anything"));
    }

    #[test]
    fn rps_none_means_unlimited() {
        assert!(within_rps(None, 9_999_999));
    }

    #[test]
    fn rps_strict_under_limit() {
        assert!(within_rps(Some(10), 9));
        assert!(!within_rps(Some(10), 10));
        assert!(!within_rps(Some(10), 11));
    }

    #[test]
    fn daily_tokens_none_unlimited() {
        assert!(within_daily_token_budget(None, u64::MAX));
    }

    #[test]
    fn daily_tokens_strict_under_budget() {
        assert!(within_daily_token_budget(Some(1000), 999));
        assert!(!within_daily_token_budget(Some(1000), 1000));
    }

    #[test]
    fn monthly_usd_none_unlimited() {
        assert!(within_monthly_usd_budget(None, f64::INFINITY));
    }

    #[test]
    fn monthly_usd_strict_under_budget() {
        assert!(within_monthly_usd_budget(Some(100.0), 99.99));
        assert!(!within_monthly_usd_budget(Some(100.0), 100.0));
        assert!(!within_monthly_usd_budget(Some(100.0), 100.01));
        assert!(!within_monthly_usd_budget(Some(100.0), f64::NAN));
    }
}
