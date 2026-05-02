//! Versioned data migrations that need runtime secrets.
//!
//! SQLx migrations own schema. This module mirrors Dyson's in-process
//! migration chain for data rewrites that need application code or envelope
//! keys. Migrations are idempotent, versioned in sqlite, and run at startup
//! before stores that expect the current on-disk shape are constructed.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::envelope::EnvelopeCipher;
use crate::error::StoreError;
use crate::now_secs;

pub const CURRENT_VERSION: i64 = 1;

const MIGRATION_NAME: &str = "runtime_secret_sealing";
const AGE_ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied: bool,
    pub proxy_tokens_sealed: usize,
    pub instance_bearers_sealed: usize,
}

enum Step {
    SealRuntimeSecrets,
}

struct Migration {
    from_version: i64,
    description: &'static str,
    steps: &'static [Step],
}

const fn migrations() -> &'static [Migration] {
    &[Migration {
        from_version: 0,
        description: "Seal legacy proxy tokens and instance bearer tokens",
        steps: &[Step::SealRuntimeSecrets],
    }]
}

pub async fn migrate(
    pool: &SqlitePool,
    cipher: &dyn EnvelopeCipher,
) -> Result<MigrationReport, StoreError> {
    ensure_version_table(pool).await?;
    let version = read_version(pool).await?;
    if version > CURRENT_VERSION {
        return Err(StoreError::Malformed(format!(
            "runtime data migration version {version} is newer than this build (max {CURRENT_VERSION})"
        )));
    }
    if version == CURRENT_VERSION {
        return Ok(MigrationReport::default());
    }

    let mut current = version;
    let mut report = MigrationReport::default();
    for migration in migrations() {
        if migration.from_version < current {
            continue;
        }
        if migration.from_version != current {
            return Err(StoreError::Malformed(format!(
                "runtime data migration gap: database is at version {current}, next migration starts at {}",
                migration.from_version
            )));
        }

        tracing::info!(
            from = migration.from_version,
            to = migration.from_version + 1,
            description = migration.description,
            "applying runtime data migration"
        );

        for step in migration.steps {
            apply_step(pool, cipher, step, &mut report).await?;
        }
        current = migration.from_version + 1;
        write_version(pool, current).await?;
        report.applied = true;
    }

    Ok(report)
}

async fn ensure_version_table(pool: &SqlitePool) -> Result<(), StoreError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS swarm_data_migrations (
            name TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn read_version(pool: &SqlitePool) -> Result<i64, StoreError> {
    let row = sqlx::query("SELECT version FROM swarm_data_migrations WHERE name = ?")
        .bind(MIGRATION_NAME)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    Ok(row.map(|r| r.get("version")).unwrap_or(0))
}

async fn write_version(pool: &SqlitePool, version: i64) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO swarm_data_migrations (name, version, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
           version = excluded.version,
           updated_at = excluded.updated_at",
    )
    .bind(MIGRATION_NAME)
    .bind(version)
    .bind(now_secs())
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn apply_step(
    pool: &SqlitePool,
    cipher: &dyn EnvelopeCipher,
    step: &Step,
    report: &mut MigrationReport,
) -> Result<(), StoreError> {
    match step {
        Step::SealRuntimeSecrets => {
            report.proxy_tokens_sealed += seal_proxy_tokens(pool, cipher).await?;
            report.instance_bearers_sealed += seal_instance_bearers(pool, cipher).await?;
            Ok(())
        }
    }
}

async fn seal_proxy_tokens(
    pool: &SqlitePool,
    cipher: &dyn EnvelopeCipher,
) -> Result<usize, StoreError> {
    let rows = sqlx::query("SELECT token FROM proxy_tokens")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    let mut sealed = 0usize;
    for row in rows {
        let token: String = row.get("token");
        if is_current_ciphertext(cipher, "proxy token", &token)? {
            continue;
        }
        let sealed_token = seal_text(cipher, "proxy token", &token)?;
        sqlx::query("UPDATE proxy_tokens SET token = ? WHERE token = ?")
            .bind(sealed_token)
            .bind(token)
            .execute(pool)
            .await
            .map_err(map_sqlx)?;
        sealed += 1;
    }
    Ok(sealed)
}

async fn seal_instance_bearers(
    pool: &SqlitePool,
    cipher: &dyn EnvelopeCipher,
) -> Result<usize, StoreError> {
    let rows = sqlx::query("SELECT id, bearer_token FROM instances")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    let mut sealed = 0usize;
    for row in rows {
        let id: String = row.get("id");
        let bearer: String = row.get("bearer_token");
        if is_current_ciphertext(cipher, "instance bearer", &bearer)? {
            continue;
        }
        let sealed_bearer = seal_text(cipher, "instance bearer", &bearer)?;
        sqlx::query("UPDATE instances SET bearer_token = ? WHERE id = ?")
            .bind(sealed_bearer)
            .bind(id)
            .execute(pool)
            .await
            .map_err(map_sqlx)?;
        sealed += 1;
    }
    Ok(sealed)
}

fn is_current_ciphertext(
    cipher: &dyn EnvelopeCipher,
    label: &str,
    stored: &str,
) -> Result<bool, StoreError> {
    match cipher.open(stored.as_bytes()) {
        Ok(_) => Ok(true),
        Err(err) if stored.starts_with(AGE_ARMOR_HEADER) => Err(StoreError::Malformed(format!(
            "{label} is sealed but cannot be opened: {err}"
        ))),
        Err(_) => Ok(false),
    }
}

fn seal_text(
    cipher: &dyn EnvelopeCipher,
    label: &str,
    plaintext: &str,
) -> Result<String, StoreError> {
    let sealed = cipher
        .seal(plaintext.as_bytes())
        .map_err(|e| StoreError::Io(format!("seal {label}: {e}")))?;
    String::from_utf8(sealed).map_err(|_| StoreError::Malformed(format!("{label} was not utf-8")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::instances::SqlxInstanceStore;
    use crate::db::open_in_memory;
    use crate::db::tokens::SqlxTokenStore;
    use crate::envelope::{AgeCipherDirectory, CipherDirectory};
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore, TokenStore};
    use std::sync::Arc;

    fn system_cipher() -> Arc<dyn EnvelopeCipher> {
        let tmp = tempfile::tempdir().unwrap();
        let dir = AgeCipherDirectory::new(tmp.path()).unwrap();
        dir.system().unwrap()
    }

    fn row(id: &str, bearer: &str) -> InstanceRow {
        InstanceRow {
            id: id.into(),
            owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
            cube_sandbox_id: None,
            template_id: "tpl".into(),
            status: InstanceStatus::Live,
            bearer_token: bearer.into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::NoLocalNet,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn seals_legacy_runtime_secret_rows_and_marks_version() {
        let pool = open_in_memory().await.unwrap();
        let cipher = system_cipher();
        sqlx::query(
            "INSERT INTO instances
             (id, owner_id, name, task, cube_sandbox_id, template_id, status, bearer_token,
              pinned, expires_at, last_active_at, last_probe_at, last_probe_status,
              created_at, destroyed_at, rotated_to,
              network_policy_kind, network_policy_entries, network_policy_cidrs, models, tools)
             VALUES (?, ?, '', '', NULL, 'tpl', 'live', ?, 0, NULL, 0, NULL, NULL,
                     0, NULL, NULL, 'nolocalnet', '', '', '[]', '[]')",
        )
        .bind("i-legacy")
        .bind("legacy")
        .bind("0123456789abcdef0123456789abcdef")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_tokens (token, instance_id, provider, created_at, revoked_at)
             VALUES ('pt_legacy', 'i-legacy', 'openrouter', 0, NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let report = migrate(&pool, cipher.as_ref()).await.unwrap();
        assert_eq!(
            report,
            MigrationReport {
                applied: true,
                proxy_tokens_sealed: 1,
                instance_bearers_sealed: 1,
            }
        );

        let stored_bearer: String =
            sqlx::query_scalar("SELECT bearer_token FROM instances WHERE id = 'i-legacy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let stored_token: String =
            sqlx::query_scalar("SELECT token FROM proxy_tokens WHERE instance_id = 'i-legacy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(stored_bearer, "0123456789abcdef0123456789abcdef");
        assert_ne!(stored_token, "pt_legacy");

        let instances = SqlxInstanceStore::new(pool.clone(), cipher.clone());
        assert_eq!(
            instances
                .get("i-legacy")
                .await
                .unwrap()
                .unwrap()
                .bearer_token,
            "0123456789abcdef0123456789abcdef"
        );
        let tokens = SqlxTokenStore::new(pool.clone(), cipher.clone());
        assert!(tokens.resolve("pt_legacy").await.unwrap().is_some());

        let rerun = migrate(&pool, cipher.as_ref()).await.unwrap();
        assert_eq!(rerun, MigrationReport::default());
    }

    #[tokio::test]
    async fn already_sealed_rows_are_not_resealed() {
        let pool = open_in_memory().await.unwrap();
        let cipher = system_cipher();
        let instances = SqlxInstanceStore::new(pool.clone(), cipher.clone());
        instances.create(row("i-sealed", "bearer")).await.unwrap();
        let tokens = SqlxTokenStore::new(pool.clone(), cipher.clone());
        let token = tokens
            .mint("i-sealed", crate::instance::SHARED_PROVIDER)
            .await
            .unwrap();
        let before_bearer: String =
            sqlx::query_scalar("SELECT bearer_token FROM instances WHERE id = 'i-sealed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let before_token: String =
            sqlx::query_scalar("SELECT token FROM proxy_tokens WHERE instance_id = 'i-sealed'")
                .fetch_one(&pool)
                .await
                .unwrap();

        let report = migrate(&pool, cipher.as_ref()).await.unwrap();
        assert_eq!(
            report,
            MigrationReport {
                applied: true,
                proxy_tokens_sealed: 0,
                instance_bearers_sealed: 0,
            }
        );
        let after_bearer: String =
            sqlx::query_scalar("SELECT bearer_token FROM instances WHERE id = 'i-sealed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let after_token: String =
            sqlx::query_scalar("SELECT token FROM proxy_tokens WHERE instance_id = 'i-sealed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after_bearer, before_bearer);
        assert_eq!(after_token, before_token);
        assert!(tokens.resolve(&token).await.unwrap().is_some());
    }
}
