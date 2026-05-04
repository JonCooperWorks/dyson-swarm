//! sqlx-backed [`UserSecretStore`] and [`SystemSecretStore`] impls.
//!
//! These are dumb wrappers over sqlite — they store and return whatever
//! `ciphertext` bytes the caller hands in.  Encryption / decryption is
//! the responsibility of the service layer above
//! (`UserSecretsService` / `SystemSecretsService`) which routes through
//! the relevant [`crate::envelope::EnvelopeCipher`].
//!
//! Both active tables use the `ciphertext TEXT` column shape from
//! migration `0005_envelope_secrets.sql`.  Age-armored ciphertext is
//! ASCII so TEXT (rather than BLOB) keeps schema and tooling simple.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::{SystemSecretStore, UserSecretStore};

#[derive(Debug, Clone)]
pub struct SqlxUserSecretStore {
    pool: SqlitePool,
}

impl SqlxUserSecretStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone)]
pub struct SqlxSystemSecretStore {
    pool: SqlitePool,
}

impl SqlxSystemSecretStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserSecretStore for SqlxUserSecretStore {
    async fn put(&self, user_id: &str, name: &str, ciphertext: &str) -> Result<(), StoreError> {
        let now = now_secs();
        sqlx::query(
            "INSERT INTO user_secrets (user_id, name, ciphertext, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(user_id, name) DO UPDATE SET \
                ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(name)
        .bind(ciphertext)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, user_id: &str, name: &str) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("SELECT ciphertext FROM user_secrets WHERE user_id = ? AND name = ?")
            .bind(user_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(
                r.try_get::<String, _>("ciphertext").map_err(map_sqlx)?,
            )),
            None => Ok(None),
        }
    }

    async fn delete(&self, user_id: &str, name: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM user_secrets WHERE user_id = ? AND name = ?")
            .bind(user_id)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list(&self, user_id: &str) -> Result<Vec<(String, String)>, StoreError> {
        let rows = sqlx::query(
            "SELECT name, ciphertext FROM user_secrets WHERE user_id = ? ORDER BY name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter()
            .map(|r| {
                let n: String = r.try_get("name").map_err(map_sqlx)?;
                let v: String = r.try_get("ciphertext").map_err(map_sqlx)?;
                Ok((n, v))
            })
            .collect()
    }
}

// ───────────────────────────────────────────────────────────────────
// system_secrets
// ───────────────────────────────────────────────────────────────────

#[async_trait]
impl SystemSecretStore for SqlxSystemSecretStore {
    async fn put(&self, name: &str, ciphertext: &str) -> Result<(), StoreError> {
        let now = now_secs();
        sqlx::query(
            "INSERT INTO system_secrets (name, ciphertext, created_at, updated_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(name) DO UPDATE SET \
                ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
        )
        .bind(name)
        .bind(ciphertext)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("SELECT ciphertext FROM system_secrets WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(
                r.try_get::<String, _>("ciphertext").map_err(map_sqlx)?,
            )),
            None => Ok(None),
        }
    }

    async fn delete(&self, name: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM system_secrets WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_names(&self) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query("SELECT name FROM system_secrets ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.iter()
            .map(|r| r.try_get::<String, _>("name").map_err(map_sqlx))
            .collect()
    }
}
