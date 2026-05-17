//! Persistence backend wiring.

use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
#[cfg(feature = "postgres")]
use sqlx::PgPool;
use sqlx::SqlitePool;

use crate::config::{Config, DatabaseBackend};
use crate::envelope::{CipherDirectory, EnvelopeCipher};
use crate::error::StoreError;
use crate::traits::{
    AdminAuditStore, AgentSecretStore, AgentSkillPublicationStore, ArtefactCacheStore, AuditStore,
    DeliveryStore, InstanceChannelStore, InstanceStore, LlmToolCallStore, McpAuditStore,
    McpDockerCatalogStore, PolicyStore, SecretAccessAuditStore, SessionStore, ShareStore,
    SkillMarketplaceSourceStore, SnapshotStore, StateFileStore, SystemSecretStore, TokenStore,
    UserSecretStore, UserStore, WebhookStore,
};

#[cfg(feature = "postgres")]
pub mod pg;
pub mod sqlite;
pub mod transfer;

pub mod migration_parity {
    include!(concat!(env!("OUT_DIR"), "/migration_parity.rs"));
}

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
    pub channels: Arc<dyn InstanceChannelStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub tokens: Arc<dyn TokenStore>,
    pub user_secrets: Arc<dyn UserSecretStore>,
    pub agent_secrets: Arc<dyn AgentSecretStore>,
    pub system_secrets: Arc<dyn SystemSecretStore>,
    pub users: Arc<dyn UserStore>,
    pub snapshots: Arc<dyn SnapshotStore>,
    pub policies: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditStore>,
    pub mcp_audit: Arc<dyn McpAuditStore>,
    pub llm_tool_calls: Arc<dyn LlmToolCallStore>,
    pub admin_audit: Arc<dyn AdminAuditStore>,
    pub secret_access_audit: Arc<dyn SecretAccessAuditStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub state_files: Arc<dyn StateFileStore>,
    pub shares: Arc<dyn ShareStore>,
    pub webhooks: Arc<dyn WebhookStore>,
    pub deliveries: Arc<dyn DeliveryStore>,
    pub mcp_docker_catalog: Arc<dyn McpDockerCatalogStore>,
    pub skill_marketplace_sources: Arc<dyn SkillMarketplaceSourceStore>,
    pub agent_skill_publications: Arc<dyn AgentSkillPublicationStore>,
    pub runtime_migrator: Arc<dyn RuntimeMigrator>,
}

impl BackendStores {
    fn sqlite(
        pool: SqlitePool,
        ciphers: Arc<dyn CipherDirectory>,
        system_cipher: Arc<dyn EnvelopeCipher>,
    ) -> Self {
        Self {
            artefacts: sqlite::artefact_cache_store(pool.clone()),
            channels: sqlite::instance_channel_store(pool.clone()),
            instances: sqlite::instance_store(pool.clone(), system_cipher.clone(), ciphers.clone()),
            tokens: sqlite::token_store(pool.clone(), system_cipher, ciphers.clone()),
            user_secrets: sqlite::user_secret_store(pool.clone()),
            agent_secrets: sqlite::agent_secret_store(pool.clone()),
            system_secrets: sqlite::system_secret_store(pool.clone()),
            users: sqlite::user_store(pool.clone(), ciphers),
            snapshots: sqlite::snapshot_store(pool.clone()),
            policies: sqlite::policy_store(pool.clone()),
            audit: sqlite::audit_store(pool.clone()),
            mcp_audit: sqlite::mcp_audit_store(pool.clone()),
            llm_tool_calls: sqlite::llm_tool_call_store(pool.clone()),
            admin_audit: sqlite::admin_audit_store(pool.clone()),
            secret_access_audit: sqlite::secret_access_audit_store(pool.clone()),
            sessions: sqlite::session_store(pool.clone()),
            state_files: sqlite::state_file_store(pool.clone()),
            shares: sqlite::share_store(pool.clone()),
            webhooks: sqlite::webhook_store(pool.clone()),
            deliveries: sqlite::delivery_store(pool.clone()),
            mcp_docker_catalog: sqlite::mcp_docker_catalog_store(pool.clone()),
            skill_marketplace_sources: sqlite::skill_marketplace_source_store(pool.clone()),
            agent_skill_publications: sqlite::agent_skill_publication_store(pool.clone()),
            runtime_migrator: sqlite::runtime_migrator(pool),
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
            channels: Arc::new(pg::channels::PgInstanceChannelStore::new(pool.clone())),
            instances: Arc::new(pg::instances::PgInstanceStore::new_with_ciphers(
                pool.clone(),
                system_cipher.clone(),
                ciphers.clone(),
            )),
            tokens: Arc::new(pg::tokens::PgTokenStore::new_with_kms(
                pool.clone(),
                system_cipher,
                ciphers.clone(),
                Arc::new(pg::audit::PgSecretAccessAuditStore::new(pool.clone())),
            )),
            user_secrets: Arc::new(pg::secrets::PgUserSecretStore::new(pool.clone())),
            agent_secrets: Arc::new(pg::agent_secrets::PgAgentSecretStore::new(pool.clone())),
            system_secrets: Arc::new(pg::secrets::PgSystemSecretStore::new(pool.clone())),
            users: Arc::new(pg::users::PgUserStore::new(pool.clone(), ciphers)),
            snapshots: Arc::new(pg::snapshots::PgSnapshotStore::new(pool.clone())),
            policies: Arc::new(pg::policies::PgPolicyStore::new(pool.clone())),
            audit: Arc::new(pg::audit::PgAuditStore::new(pool.clone())),
            mcp_audit: Arc::new(pg::audit::PgMcpAuditStore::new(pool.clone())),
            llm_tool_calls: Arc::new(pg::audit::PgLlmToolCallStore::new(pool.clone())),
            admin_audit: Arc::new(pg::audit::PgAdminAuditStore::new(pool.clone())),
            secret_access_audit: Arc::new(pg::audit::PgSecretAccessAuditStore::new(pool.clone())),
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
            agent_skill_publications: Arc::new(
                pg::agent_skill_publications::PgAgentSkillPublicationStore::new(pool.clone()),
            ),
            runtime_migrator: postgres_runtime_migrator(),
        }
    }
}

pub(crate) fn token_lookup_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Provider string stamped on rows minted via `TokenStore::mint_ingest`.
/// The internal-ingest route filters resolved tokens by prefix (`it_`),
/// so the provider field is largely a documentation-and-grep handle for
/// operators inspecting the table directly.
pub const INGEST_PROVIDER: &str = "ingest";

/// Base provider namespace for state-sync tokens. Concrete tokens are
/// always scoped as `state_sync:<generation>` so only the current
/// sandbox generation can write durable swarm state.
pub const STATE_SYNC_PROVIDER: &str = "state_sync";

pub fn state_sync_provider(generation: &str) -> String {
    let generation = generation.trim();
    debug_assert!(!generation.is_empty(), "state generation is required");
    format!("{STATE_SYNC_PROVIDER}:{generation}")
}

pub fn state_sync_provider_matches(provider: &str, generation: &str) -> bool {
    let generation = generation.trim();
    if generation.is_empty() {
        return false;
    }
    provider == state_sync_provider(generation)
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

pub async fn open_configured_sqlite(cfg: &Config) -> Result<SqlitePool, StoreError> {
    sqlite::open_configured_sqlite(cfg).await
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
            let pool = sqlite::open(&cfg.db_path).await.map_err(sqlite::map_sqlx)?;
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

#[cfg(feature = "postgres")]
pub fn postgres_runtime_migrator() -> Arc<dyn RuntimeMigrator> {
    Arc::new(pg::runtime_migrations::PgRuntimeMigrator::new())
}
