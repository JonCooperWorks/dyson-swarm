//! Policy CRUD. Backs the [`PolicyStore`] trait. The trait's `subject`
//! parameter is opaque — for the pre-tenancy build it's `instance_id`; the
//! multi-tenant migration (phase 2) re-keys this on `user_id` without
//! changing the trait shape.
//!
//! `allowed_providers` and `allowed_models` are stored as comma-separated
//! strings — short closed-set lists in practice, JSON would buy nothing.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::error::StoreError;
use crate::traits::{PolicyRecord, PolicyStore};

fn map_sqlx(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StoreError::Constraint(db.to_string())
        }
        other => StoreError::Io(other.to_string()),
    }
}

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
             FROM instance_policies WHERE instance_id = ?",
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
            daily_token_budget: daily.map(|n| n as u64),
            monthly_usd_budget: monthly,
            rps_limit: rps.map(|n| n as u32),
        }))
    }

    async fn put(&self, subject: &str, policy: &PolicyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO instance_policies \
             (instance_id, allowed_providers, allowed_models, daily_token_budget, monthly_usd_budget, rps_limit) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(instance_id) DO UPDATE SET \
                allowed_providers = excluded.allowed_providers, \
                allowed_models = excluded.allowed_models, \
                daily_token_budget = excluded.daily_token_budget, \
                monthly_usd_budget = excluded.monthly_usd_budget, \
                rps_limit = excluded.rps_limit",
        )
        .bind(subject)
        .bind(join_csv(&policy.allowed_providers))
        .bind(join_csv(&policy.allowed_models))
        .bind(policy.daily_token_budget.map(|n| n as i64))
        .bind(policy.monthly_usd_budget)
        .bind(policy.rps_limit.map(|n| n as i64))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

    async fn seed(pool: &SqlitePool, id: &str) {
        SqlxInstanceStore::new(pool.clone())
            .create(InstanceRow {
                id: id.into(),
                cube_sandbox_id: None,
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

    #[tokio::test]
    async fn round_trip() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlitePolicyStore::new(pool);
        let p = PolicyRecord {
            allowed_providers: vec!["openai".into(), "anthropic".into()],
            allowed_models: vec!["*".into()],
            daily_token_budget: Some(100_000),
            monthly_usd_budget: Some(50.0),
            rps_limit: Some(10),
        };
        store.put("i1", &p).await.unwrap();
        let got = store.get("i1").await.unwrap().unwrap();
        assert_eq!(got.allowed_providers, vec!["openai".to_string(), "anthropic".into()]);
        assert_eq!(got.allowed_models, vec!["*".to_string()]);
        assert_eq!(got.daily_token_budget, Some(100_000));
        assert_eq!(got.monthly_usd_budget, Some(50.0));
        assert_eq!(got.rps_limit, Some(10));
    }

    #[tokio::test]
    async fn upsert_overwrites() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlitePolicyStore::new(pool);
        let mut p = PolicyRecord {
            allowed_providers: vec!["openai".into()],
            allowed_models: vec!["*".into()],
            daily_token_budget: None,
            monthly_usd_budget: None,
            rps_limit: None,
        };
        store.put("i1", &p).await.unwrap();
        p.allowed_providers = vec!["anthropic".into()];
        p.rps_limit = Some(5);
        store.put("i1", &p).await.unwrap();
        let got = store.get("i1").await.unwrap().unwrap();
        assert_eq!(got.allowed_providers, vec!["anthropic".to_string()]);
        assert_eq!(got.rps_limit, Some(5));
    }

    #[tokio::test]
    async fn missing_returns_none() {
        let pool = open_in_memory().await.unwrap();
        seed(&pool, "i1").await;
        let store = SqlitePolicyStore::new(pool);
        assert!(store.get("i1").await.unwrap().is_none());
    }
}
