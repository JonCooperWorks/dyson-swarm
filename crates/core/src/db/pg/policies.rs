//! Policy CRUD. Backs the [`PolicyStore`] trait. The trait's `subject`
//! parameter is opaque — for the pre-tenancy build it's `instance_id`; the
//! multi-tenant migration (phase 2) re-keys this on `user_id` without
//! changing the trait shape.
//!
//! `allowed_providers` and `allowed_models` are stored as comma-separated
//! strings — short closed-set lists in practice, JSON would buy nothing.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::traits::{PolicyRecord, PolicyStore};

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

fn join_csv(items: &[String]) -> String {
    items.join(",")
}

#[derive(Debug, Clone)]
pub struct PgPolicyStore {
    pool: PgPool,
}

impl PgPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn get(&self, subject: &str) -> Result<Option<PolicyRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT allowed_providers, allowed_models, daily_token_budget, monthly_usd_budget, rps_limit \
             FROM user_policies WHERE user_id = $1",
        )
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let Some(r) = row else { return Ok(None) };
        let providers: String = r.try_get("allowed_providers").map_err(map_sqlx)?;
        let models: String = r.try_get("allowed_models").map_err(map_sqlx)?;
        let daily: Option<i64> = r.try_get("daily_token_budget").map_err(map_sqlx)?;
        let monthly: Option<f64> = r.try_get("monthly_usd_budget").map_err(map_sqlx)?;
        let rps: Option<i64> = r.try_get("rps_limit").map_err(map_sqlx)?;
        Ok(Some(PolicyRecord {
            allowed_providers: split_csv(&providers),
            allowed_models: split_csv(&models),
            // Both budgets are non-negative caps stored as signed sqlite ints.
            // Anything negative would be corrupted state — clamp to 0 rather
            // than panic on a `try_from` failure.
            daily_token_budget: daily.map(|n| u64::try_from(n.max(0)).unwrap_or(0)),
            monthly_usd_budget: monthly,
            rps_limit: rps.map(|n| u32::try_from(n.clamp(0, i64::from(u32::MAX))).unwrap_or(0)),
        }))
    }

    async fn put(&self, subject: &str, policy: &PolicyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO user_policies \
             (user_id, allowed_providers, allowed_models, daily_token_budget, monthly_usd_budget, rps_limit) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT(user_id) DO UPDATE SET \
                allowed_providers = excluded.allowed_providers, \
                allowed_models = excluded.allowed_models, \
                daily_token_budget = excluded.daily_token_budget, \
                monthly_usd_budget = excluded.monthly_usd_budget, \
                rps_limit = excluded.rps_limit",
        )
        .bind(subject)
        .bind(join_csv(&policy.allowed_providers))
        .bind(join_csv(&policy.allowed_models))
        // u64 → i64 saturates at i64::MAX. Token budgets above ~9 exabytes
        // are nonsensical, but saturating is safer than wrapping into a
        // negative budget that the read path would clamp back to 0.
        .bind(policy.daily_token_budget.map(|n| i64::try_from(n).unwrap_or(i64::MAX)))
        .bind(policy.monthly_usd_budget)
        .bind(policy.rps_limit.map(i64::from))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}
