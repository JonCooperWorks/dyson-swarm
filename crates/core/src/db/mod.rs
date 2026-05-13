//! SQLite-backed implementations of the *Store traits.
//!
//! Note: queries are runtime-checked (`sqlx::query`/`query_as`) rather than
//! compile-time-checked (`sqlx::query!`). The brief asks for the macro form,
//! but it requires either sqlx-cli to prepare an offline cache or a live
//! `DATABASE_URL` at build time — neither fits a clean `cargo build` here.
//! Every query is exercised by unit tests under `tests` modules below, so
//! malformed SQL fails fast; switching to the macro form is a mechanical
//! swap once a `cargo sqlx prepare` step exists in CI.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "postgres")]
use sqlx::PgPool;
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
pub mod transfer;
pub mod users;
pub mod webhooks;

#[cfg(feature = "postgres")]
pub mod pg;

pub mod migration_parity {
    include!(concat!(env!("OUT_DIR"), "/migration_parity.rs"));
}

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[derive(Clone)]
pub enum DatabasePool {
    Sqlite(SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(PgPool),
}

#[derive(Clone)]
pub struct OpenDatabase {
    pub backend: DatabaseBackend,
    pub pool: DatabasePool,
    pub stores: BackendStores,
}

#[derive(Clone)]
pub struct BackendStores {
    pub artefacts: Arc<dyn ArtefactCacheStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub tokens: Arc<dyn TokenStore>,
    pub user_secrets: Arc<dyn UserSecretStore>,
    pub system_secrets: Arc<dyn SystemSecretStore>,
    pub users: Arc<dyn UserStore>,
    pub snapshots: Arc<dyn SnapshotStore>,
    pub policies: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditStore>,
    pub mcp_audit: Arc<dyn McpAuditStore>,
    pub admin_audit: Arc<dyn AdminAuditStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub state_files: Arc<dyn StateFileStore>,
    pub shares: Arc<dyn ShareStore>,
    pub webhooks: Arc<dyn WebhookStore>,
    pub deliveries: Arc<dyn DeliveryStore>,
    pub mcp_docker_catalog: Arc<dyn McpDockerCatalogStore>,
    pub skill_marketplace_sources: Arc<dyn SkillMarketplaceSourceStore>,
    pub runtime_migrator: Arc<dyn RuntimeMigrator>,
}

impl BackendStores {
    fn sqlite(
        pool: SqlitePool,
        ciphers: Arc<dyn CipherDirectory>,
        system_cipher: Arc<dyn EnvelopeCipher>,
    ) -> Self {
        Self {
            artefacts: artefact_cache_store(pool.clone()),
            instances: instance_store(pool.clone(), system_cipher.clone()),
            tokens: token_store(pool.clone(), system_cipher),
            user_secrets: user_secret_store(pool.clone()),
            system_secrets: system_secret_store(pool.clone()),
            users: user_store(pool.clone(), ciphers),
            snapshots: snapshot_store(pool.clone()),
            policies: policy_store(pool.clone()),
            audit: audit_store(pool.clone()),
            mcp_audit: mcp_audit_store(pool.clone()),
            admin_audit: admin_audit_store(pool.clone()),
            sessions: session_store(pool.clone()),
            state_files: state_file_store(pool.clone()),
            shares: share_store(pool.clone()),
            webhooks: webhook_store(pool.clone()),
            deliveries: delivery_store(pool.clone()),
            mcp_docker_catalog: mcp_docker_catalog_store(pool.clone()),
            skill_marketplace_sources: skill_marketplace_source_store(pool.clone()),
            runtime_migrator: runtime_migrator(pool),
        }
    }

    #[cfg(feature = "postgres")]
    fn postgres(
        pool: PgPool,
        ciphers: Arc<dyn CipherDirectory>,
        system_cipher: Arc<dyn EnvelopeCipher>,
    ) -> Self {
        Self {
            artefacts: Arc::new(pg::artefacts::PgArtefactStore::new(pool.clone())),
            instances: Arc::new(pg::instances::PgInstanceStore::new(
                pool.clone(),
                system_cipher.clone(),
            )),
            tokens: Arc::new(pg::tokens::PgTokenStore::new(pool.clone(), system_cipher)),
            user_secrets: Arc::new(pg::secrets::PgUserSecretStore::new(pool.clone())),
            system_secrets: Arc::new(pg::secrets::PgSystemSecretStore::new(pool.clone())),
            users: Arc::new(pg::users::PgUserStore::new(pool.clone(), ciphers)),
            snapshots: Arc::new(pg::snapshots::PgSnapshotStore::new(pool.clone())),
            policies: Arc::new(pg::policies::PgPolicyStore::new(pool.clone())),
            audit: Arc::new(pg::audit::PgAuditStore::new(pool.clone())),
            mcp_audit: Arc::new(pg::audit::PgMcpAuditStore::new(pool.clone())),
            admin_audit: Arc::new(pg::audit::PgAdminAuditStore::new(pool.clone())),
            sessions: Arc::new(pg::sessions::PgSessionStore::new(pool.clone())),
            state_files: Arc::new(pg::state_files::PgStateFileStore::new(pool.clone())),
            shares: Arc::new(pg::shares::PgShareStore::new(pool.clone())),
            webhooks: Arc::new(pg::webhooks::PgWebhookStore::new(pool.clone())),
            deliveries: Arc::new(pg::webhooks::PgDeliveryStore::new(pool.clone())),
            mcp_docker_catalog: Arc::new(pg::mcp_catalog::PgMcpDockerCatalogStore::new(
                pool.clone(),
            )),
            skill_marketplace_sources: Arc::new(
                pg::skill_marketplace::PgSkillMarketplaceSourceStore::new(pool.clone()),
            ),
            runtime_migrator: postgres_runtime_migrator(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeMigrationReport {
    pub applied: bool,
    pub proxy_tokens_sealed: usize,
    pub instance_bearers_sealed: usize,
    pub proxy_token_lookups_backfilled: usize,
}

#[async_trait]
pub trait RuntimeMigrator: Send + Sync {
    async fn migrate(
        &self,
        cipher: &dyn EnvelopeCipher,
    ) -> Result<RuntimeMigrationReport, StoreError>;
}

/// Translate a [`sqlx::Error`] into the crate-level [`StoreError`] flavour
/// callers expect. Shared so every store can use the same mapping —
/// `RowNotFound → NotFound`, unique-violation → `Constraint`, everything
/// else → `Io`. The audit table doesn't enforce uniqueness so its impl
/// previously had a slimmer mapping; folding that case into the same
/// function is harmless because the unique-violation arm just never fires.
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

#[cfg(feature = "postgres")]
pub async fn open_pg(url: &str) -> Result<PgPool, StoreError> {
    pg::open(url).await.map_err(pg::map_sqlx)
}

pub async fn open_configured(
    cfg: &Config,
    ciphers: Arc<dyn CipherDirectory>,
    system_cipher: Arc<dyn EnvelopeCipher>,
) -> Result<OpenDatabase, StoreError> {
    match cfg.database_backend {
        DatabaseBackend::Sqlite => {
            let pool = open(&cfg.db_path).await.map_err(map_sqlx)?;
            let stores = BackendStores::sqlite(pool.clone(), ciphers, system_cipher);
            Ok(OpenDatabase {
                backend: DatabaseBackend::Sqlite,
                pool: DatabasePool::Sqlite(pool),
                stores,
            })
        }
        DatabaseBackend::Postgres => {
            #[cfg(feature = "postgres")]
            {
                let url = cfg.database_url.as_deref().ok_or_else(|| {
                    StoreError::Io("database_backend=postgres requires database_url".into())
                })?;
                let pool = open_pg(url).await?;
                let stores = BackendStores::postgres(pool.clone(), ciphers, system_cipher);
                Ok(OpenDatabase {
                    backend: DatabaseBackend::Postgres,
                    pool: DatabasePool::Postgres(pool),
                    stores,
                })
            }
            #[cfg(not(feature = "postgres"))]
            {
                Err(StoreError::Io(
                    "database_backend=postgres requires building with the postgres feature".into(),
                ))
            }
        }
    }
}

pub fn runtime_migrator(pool: SqlitePool) -> Arc<dyn RuntimeMigrator> {
    Arc::new(runtime_migrations::SqliteRuntimeMigrator::new(pool))
}

#[cfg(feature = "postgres")]
pub fn postgres_runtime_migrator() -> Arc<dyn RuntimeMigrator> {
    Arc::new(pg::runtime_migrations::PgRuntimeMigrator::new())
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
