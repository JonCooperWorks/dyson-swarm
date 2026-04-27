//! SQLite-backed `UserStore`. The `subject` field is the OIDC `sub` claim
//! (or an admin-issued opaque label for non-OIDC api keys). Users start in
//! `inactive` status — JIT provisioning creates the row from a fresh OIDC
//! token but the auth middleware refuses requests until an admin flips the
//! status to `active`.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::StoreError;
use crate::traits::{UserApiKey, UserRow, UserStatus, UserStore};

fn map_sqlx(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StoreError::Constraint(db.to_string())
        }
        other => StoreError::Io(other.to_string()),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn row_to_user(row: &sqlx::sqlite::SqliteRow) -> Result<UserRow, StoreError> {
    let status_text: String = row.try_get("status").map_err(map_sqlx)?;
    let status = UserStatus::parse(&status_text)
        .ok_or_else(|| StoreError::Malformed(format!("status={status_text}")))?;
    Ok(UserRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        subject: row.try_get("subject").map_err(map_sqlx)?,
        email: row.try_get("email").map_err(map_sqlx)?,
        display_name: row.try_get("display_name").map_err(map_sqlx)?,
        status,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        activated_at: row.try_get("activated_at").map_err(map_sqlx)?,
        last_seen_at: row.try_get("last_seen_at").map_err(map_sqlx)?,
        openrouter_key_id: row.try_get("openrouter_key_id").map_err(map_sqlx)?,
        openrouter_key_limit_usd: row.try_get("openrouter_key_limit_usd").map_err(map_sqlx)?,
    })
}

#[derive(Debug, Clone)]
pub struct SqlxUserStore {
    pool: SqlitePool,
}

impl SqlxUserStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserStore for SqlxUserStore {
    async fn create(&self, row: UserRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO users \
             (id, subject, email, display_name, status, created_at, activated_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.subject)
        .bind(&row.email)
        .bind(&row.display_name)
        .bind(row.status.as_str())
        .bind(row.created_at)
        .bind(row.activated_at)
        .bind(row.last_seen_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<UserRow>, StoreError> {
        let r = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn get_by_subject(&self, subject: &str) -> Result<Option<UserRow>, StoreError> {
        let r = sqlx::query("SELECT * FROM users WHERE subject = ?")
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match r {
            Some(row) => Ok(Some(row_to_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<UserRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.iter().map(row_to_user).collect()
    }

    async fn set_status(&self, id: &str, status: UserStatus) -> Result<(), StoreError> {
        let now = now_secs();
        let activated_at: Option<i64> = if matches!(status, UserStatus::Active) {
            Some(now)
        } else {
            None
        };
        let r = sqlx::query(
            "UPDATE users SET status = ?1, \
                              activated_at = COALESCE(?2, activated_at) \
             WHERE id = ?3",
        )
        .bind(status.as_str())
        .bind(activated_at)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn touch_last_seen(&self, id: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET last_seen_at = ? WHERE id = ?")
            .bind(now_secs())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn mint_api_key(
        &self,
        user_id: &str,
        label: Option<&str>,
    ) -> Result<String, StoreError> {
        let token = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO user_api_keys (token, user_id, label, created_at, revoked_at) \
             VALUES (?, ?, ?, ?, NULL)",
        )
        .bind(&token)
        .bind(user_id)
        .bind(label)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(token)
    }

    async fn resolve_api_key(&self, token: &str) -> Result<Option<UserApiKey>, StoreError> {
        let row = sqlx::query(
            "SELECT token, user_id, label, created_at, revoked_at \
             FROM user_api_keys WHERE token = ? AND revoked_at IS NULL",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| UserApiKey {
            token: r.get("token"),
            user_id: r.get("user_id"),
            label: r.get("label"),
            created_at: r.get("created_at"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn revoke_api_key(&self, token: &str) -> Result<(), StoreError> {
        let r = sqlx::query(
            "UPDATE user_api_keys SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL",
        )
        .bind(now_secs())
        .bind(token)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_openrouter_key_id(
        &self,
        user_id: &str,
        key_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET openrouter_key_id = ? WHERE id = ?")
            .bind(key_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_openrouter_limit(
        &self,
        user_id: &str,
        limit_usd: f64,
    ) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE users SET openrouter_key_limit_usd = ? WHERE id = ?")
            .bind(limit_usd)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn sample(subject: &str) -> UserRow {
        UserRow {
            id: format!("u-{subject}"),
            subject: subject.into(),
            email: Some(format!("{subject}@example")),
            display_name: Some(subject.into()),
            status: UserStatus::Inactive,
            created_at: 100,
            activated_at: None,
            last_seen_at: None,
            openrouter_key_id: None,
            openrouter_key_limit_usd: 10.0,
        }
    }

    #[tokio::test]
    async fn openrouter_key_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxUserStore::new(pool);
        store.create(sample("alice")).await.unwrap();

        // Default limit is 10.0 from the migration default.
        let r0 = store.get("u-alice").await.unwrap().unwrap();
        assert!(r0.openrouter_key_id.is_none());
        assert!((r0.openrouter_key_limit_usd - 10.0).abs() < 1e-9);

        store
            .set_openrouter_key_id("u-alice", Some("or-key-abc"))
            .await
            .unwrap();
        store.set_openrouter_limit("u-alice", 25.0).await.unwrap();

        let r1 = store.get("u-alice").await.unwrap().unwrap();
        assert_eq!(r1.openrouter_key_id.as_deref(), Some("or-key-abc"));
        assert!((r1.openrouter_key_limit_usd - 25.0).abs() < 1e-9);

        // Clearing on suspend / delete.
        store.set_openrouter_key_id("u-alice", None).await.unwrap();
        let r2 = store.get("u-alice").await.unwrap().unwrap();
        assert!(r2.openrouter_key_id.is_none());
    }

    #[tokio::test]
    async fn create_get_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxUserStore::new(pool);
        store.create(sample("alice")).await.unwrap();
        let got = store.get_by_subject("alice").await.unwrap().unwrap();
        assert_eq!(got.id, "u-alice");
        assert_eq!(got.status, UserStatus::Inactive);
    }

    #[tokio::test]
    async fn activate_user_sets_activated_at() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxUserStore::new(pool);
        store.create(sample("alice")).await.unwrap();
        store
            .set_status("u-alice", UserStatus::Active)
            .await
            .unwrap();
        let got = store.get("u-alice").await.unwrap().unwrap();
        assert_eq!(got.status, UserStatus::Active);
        assert!(got.activated_at.is_some());
    }

    #[tokio::test]
    async fn api_key_mint_resolve_revoke() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxUserStore::new(pool);
        store.create(sample("alice")).await.unwrap();
        let tok = store.mint_api_key("u-alice", Some("ci")).await.unwrap();
        assert_eq!(tok.len(), 32);
        let resolved = store.resolve_api_key(&tok).await.unwrap().unwrap();
        assert_eq!(resolved.user_id, "u-alice");
        assert_eq!(resolved.label.as_deref(), Some("ci"));
        store.revoke_api_key(&tok).await.unwrap();
        assert!(store.resolve_api_key(&tok).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn legacy_user_seeded_by_migration() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxUserStore::new(pool);
        let legacy = store.get("legacy").await.unwrap().unwrap();
        assert_eq!(legacy.subject, "legacy");
        assert_eq!(legacy.status, UserStatus::Suspended);
    }
}
