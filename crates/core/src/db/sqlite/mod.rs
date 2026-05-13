//! SQLite-backed implementations of the `*Store` traits.
//!
//! Queries are runtime-checked (`sqlx::query`/`query_as`) rather than
//! compile-time-checked (`sqlx::query!`). The macro form requires either
//! sqlx-cli to prepare an offline cache or a live `DATABASE_URL` at build
//! time. Every query is exercised by unit tests under the store modules, so
//! malformed SQL still fails fast.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::config::{Config, DatabaseBackend};
use crate::envelope::{CipherDirectory, EnvelopeCipher};
use crate::error::StoreError;
use crate::traits::{
    AdminAuditStore, ArtefactCacheStore, AuditStore, DeliveryStore, InstanceStore, McpAuditStore,
    McpDockerCatalogStore, PolicyStore, SessionStore, ShareStore, SkillMarketplaceSourceStore,
    SnapshotStore, StateFileStore, SystemSecretStore, TokenStore, UserSecretStore, UserStore,
    WebhookStore,
};

pub mod artefacts;
pub mod audit;
pub mod instances;
pub mod mcp_catalog;
pub mod policies;
mod runtime_migrations;
pub mod secrets;
pub mod sessions;
pub mod shares;
pub mod skill_marketplace;
pub mod snapshots;
pub mod state_files;
pub mod tokens;
pub mod users;
pub mod webhooks;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

/// Translate a [`sqlx::Error`] into the crate-level [`StoreError`] flavour
/// callers expect. Shared so every SQLite store can use the same mapping:
/// `RowNotFound` to `NotFound`, unique-violation to `Constraint`, and
/// everything else to `Io`.
pub(crate) fn map_sqlx(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StoreError::Constraint(db.to_string())
        }
        other => StoreError::Io(other.to_string()),
    }
}

pub async fn open(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
        }
    }
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    secure_db_perms(path)?;
    Ok(pool)
}

pub async fn open_configured_sqlite(cfg: &Config) -> Result<SqlitePool, StoreError> {
    match cfg.database_backend {
        DatabaseBackend::Sqlite => open(&cfg.db_path).await.map_err(map_sqlx),
        DatabaseBackend::Postgres => Err(StoreError::Io(
            "open_configured_sqlite cannot open database_backend=postgres".into(),
        )),
    }
}

pub fn runtime_migrator(pool: SqlitePool) -> Arc<dyn crate::db::RuntimeMigrator> {
    Arc::new(runtime_migrations::SqliteRuntimeMigrator::new(pool))
}

pub fn artefact_cache_store(pool: SqlitePool) -> Arc<dyn ArtefactCacheStore> {
    Arc::new(artefacts::SqlxArtefactStore::new(pool))
}

pub fn instance_store(pool: SqlitePool, cipher: Arc<dyn EnvelopeCipher>) -> Arc<dyn InstanceStore> {
    Arc::new(instances::SqlxInstanceStore::new(pool, cipher))
}

pub fn token_store(pool: SqlitePool, cipher: Arc<dyn EnvelopeCipher>) -> Arc<dyn TokenStore> {
    Arc::new(tokens::SqlxTokenStore::new(pool, cipher))
}

pub fn user_secret_store(pool: SqlitePool) -> Arc<dyn UserSecretStore> {
    Arc::new(secrets::SqlxUserSecretStore::new(pool))
}

pub fn system_secret_store(pool: SqlitePool) -> Arc<dyn SystemSecretStore> {
    Arc::new(secrets::SqlxSystemSecretStore::new(pool))
}

pub fn user_store(pool: SqlitePool, ciphers: Arc<dyn CipherDirectory>) -> Arc<dyn UserStore> {
    Arc::new(users::SqlxUserStore::new(pool, ciphers))
}

pub fn snapshot_store(pool: SqlitePool) -> Arc<dyn SnapshotStore> {
    Arc::new(snapshots::SqliteSnapshotStore::new(pool))
}

pub fn policy_store(pool: SqlitePool) -> Arc<dyn PolicyStore> {
    Arc::new(policies::SqlitePolicyStore::new(pool))
}

pub fn audit_store(pool: SqlitePool) -> Arc<dyn AuditStore> {
    Arc::new(audit::SqliteAuditStore::new(pool))
}

pub fn mcp_audit_store(pool: SqlitePool) -> Arc<dyn McpAuditStore> {
    Arc::new(audit::SqliteMcpAuditStore::new(pool))
}

pub fn admin_audit_store(pool: SqlitePool) -> Arc<dyn AdminAuditStore> {
    Arc::new(audit::SqliteAdminAuditStore::new(pool))
}

pub fn session_store(pool: SqlitePool) -> Arc<dyn SessionStore> {
    Arc::new(sessions::SqliteSessionStore::new(pool))
}

pub fn state_file_store(pool: SqlitePool) -> Arc<dyn StateFileStore> {
    Arc::new(state_files::SqlxStateFileStore::new(pool))
}

pub fn share_store(pool: SqlitePool) -> Arc<dyn ShareStore> {
    Arc::new(shares::SqlxShareStore::new(pool))
}

pub fn webhook_store(pool: SqlitePool) -> Arc<dyn WebhookStore> {
    Arc::new(webhooks::SqlxWebhookStore::new(pool))
}

pub fn delivery_store(pool: SqlitePool) -> Arc<dyn DeliveryStore> {
    Arc::new(webhooks::SqlxDeliveryStore::new(pool))
}

pub fn mcp_docker_catalog_store(pool: SqlitePool) -> Arc<dyn McpDockerCatalogStore> {
    Arc::new(mcp_catalog::SqlxMcpDockerCatalogStore::new(pool))
}

pub fn skill_marketplace_source_store(pool: SqlitePool) -> Arc<dyn SkillMarketplaceSourceStore> {
    Arc::new(skill_marketplace::SqlxSkillMarketplaceSourceStore::new(
        pool,
    ))
}

#[cfg(unix)]
fn secure_db_perms(path: &Path) -> Result<(), sqlx::Error> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(sqlx::Error::Io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_db_perms(_path: &Path) -> Result<(), sqlx::Error> {
    Ok(())
}

/// In-memory pool for tests. Single connection so the same database is
/// visible across calls.
pub async fn open_in_memory() -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect("sqlite::memory:")
        .await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    Ok(pool)
}

#[cfg(test)]
pub(crate) fn test_system_cipher() -> std::sync::Arc<dyn crate::envelope::EnvelopeCipher> {
    let tmp = tempfile::tempdir().expect("test keys tempdir");
    let dir = crate::envelope::AgeCipherDirectory::new(tmp.path()).expect("test cipher dir");
    crate::envelope::CipherDirectory::system(&dir).expect("test system cipher")
}
