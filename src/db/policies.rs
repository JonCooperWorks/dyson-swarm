//! Policy CRUD. Backs the [`PolicyStore`] trait. The trait's `subject`
//! parameter is opaque — for the pre-tenancy build it's `instance_id`; the
//! multi-tenant migration (phase 2) re-keys this on `user_id` without
//! changing the trait shape.
//!
//! `allowed_providers` and `allowed_models` are stored as comma-separated
//! strings — short closed-set lists in practice, JSON would buy nothing.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
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
pub struct SqlitePolicyStore {
    pool: SqlitePool,
}

impl SqlitePolicyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyStore for SqlitePolicyStore {
    async fn get(&self, subject: &str) -> Result<Option<PolicyRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT allowed_providers, allowed_models, daily_token_budget, monthly_usd_budget, rps_limit \
             FROM user_policies WHERE user_id = ?",
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
             VALUES (?, ?, ?, ?, ?, ?) \
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    /// The migration seeds a `legacy` user; tests key policies on that
    /// existing FK target.
    const TEST_USER: &str = "legacy";

    #[tokio::test]
    async fn round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlitePolicyStore::new(pool);
        let p = PolicyRecord {
            allowed_providers: vec!["openai".into(), "anthropic".into()],
            allowed_models: vec!["*".into()],
            daily_token_budget: Some(100_000),
            monthly_usd_budget: Some(50.0),
            rps_limit: Some(10),
        };
        store.put(TEST_USER, &p).await.unwrap();
        let got = store.get(TEST_USER).await.unwrap().unwrap();
        assert_eq!(
            got.allowed_providers,
            vec!["openai".to_string(), "anthropic".into()]
        );
        assert_eq!(got.allowed_models, vec!["*".to_string()]);
        assert_eq!(got.daily_token_budget, Some(100_000));
        assert_eq!(got.monthly_usd_budget, Some(50.0));
        assert_eq!(got.rps_limit, Some(10));
    }

    #[tokio::test]
    async fn upsert_overwrites() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlitePolicyStore::new(pool);
        let mut p = PolicyRecord {
            allowed_providers: vec!["openai".into()],
            allowed_models: vec!["*".into()],
            daily_token_budget: None,
            monthly_usd_budget: None,
            rps_limit: None,
        };
        store.put(TEST_USER, &p).await.unwrap();
        p.allowed_providers = vec!["anthropic".into()];
        p.rps_limit = Some(5);
        store.put(TEST_USER, &p).await.unwrap();
        let got = store.get(TEST_USER).await.unwrap().unwrap();
        assert_eq!(got.allowed_providers, vec!["anthropic".to_string()]);
        assert_eq!(got.rps_limit, Some(5));
    }

    #[tokio::test]
    async fn missing_returns_none() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlitePolicyStore::new(pool);
        assert!(store.get(TEST_USER).await.unwrap().is_none());
    }
}
