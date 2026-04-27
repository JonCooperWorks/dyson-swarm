use std::collections::BTreeMap;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::ProviderConfig;
use crate::error::{BackupError, CubeError, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Live,
    Paused,
    Cold,
    Destroyed,
}

impl InstanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Paused => "paused",
            Self::Cold => "cold",
            Self::Destroyed => "destroyed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "live" => Some(Self::Live),
            "paused" => Some(Self::Paused),
            "cold" => Some(Self::Cold),
            "destroyed" => Some(Self::Destroyed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotKind {
    Auto,
    Manual,
    Backup,
}

impl SnapshotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Backup => "backup",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "manual" => Some(Self::Manual),
            "backup" => Some(Self::Backup),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ProbeResult {
    Healthy,
    Degraded { reason: String },
    Unreachable { reason: String },
}

#[derive(Debug, Clone)]
pub struct InstanceRow {
    pub id: String,
    pub cube_sandbox_id: Option<String>,
    pub template_id: String,
    pub status: InstanceStatus,
    pub bearer_token: String,
    pub pinned: bool,
    pub expires_at: Option<i64>,
    pub last_active_at: i64,
    pub last_probe_at: Option<i64>,
    pub last_probe_status: Option<ProbeResult>,
    pub created_at: i64,
    pub destroyed_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub id: String,
    pub source_instance_id: String,
    pub parent_snapshot_id: Option<String>,
    pub kind: SnapshotKind,
    pub path: String,
    pub host_ip: String,
    pub remote_uri: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CreateSandboxArgs {
    pub template_id: String,
    pub env: BTreeMap<String, String>,
    pub from_snapshot_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SandboxInfo {
    pub sandbox_id: String,
    pub host_ip: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub snapshot_id: String,
    pub path: String,
    pub host_ip: String,
}

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub token: String,
    pub instance_id: String,
    pub provider: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub status: Option<InstanceStatus>,
    /// Whether to include rows with `status = "destroyed"`. Default false.
    pub include_destroyed: bool,
}

#[async_trait]
pub trait CubeClient: Send + Sync {
    async fn create_sandbox(&self, args: CreateSandboxArgs) -> Result<SandboxInfo, CubeError>;
    async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), CubeError>;
    async fn snapshot_sandbox(
        &self,
        sandbox_id: &str,
        name: &str,
    ) -> Result<SnapshotInfo, CubeError>;
    async fn delete_snapshot(&self, snapshot_id: &str, host_ip: &str) -> Result<(), CubeError>;
}

#[async_trait]
pub trait InstanceStore: Send + Sync {
    async fn create(&self, row: InstanceRow) -> Result<(), StoreError>;
    async fn get(&self, id: &str) -> Result<Option<InstanceRow>, StoreError>;
    async fn list(&self, filter: ListFilter) -> Result<Vec<InstanceRow>, StoreError>;
    async fn update_status(&self, id: &str, status: InstanceStatus) -> Result<(), StoreError>;
    /// Set the Cube-side sandbox id once Cube has assigned one. Needed
    /// because the row must exist before `TokenStore::mint` (FK), but the
    /// sandbox id is only known after the Cube call returns.
    async fn set_cube_sandbox_id(&self, id: &str, sandbox_id: &str) -> Result<(), StoreError>;
    async fn touch(&self, id: &str) -> Result<(), StoreError>;
    async fn pin(&self, id: &str, pinned: bool, ttl: Option<i64>) -> Result<(), StoreError>;
    async fn record_probe(&self, id: &str, status: ProbeResult) -> Result<(), StoreError>;
    async fn expired(&self, now: i64) -> Result<Vec<InstanceRow>, StoreError>;
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put(&self, instance_id: &str, name: &str, value: &str) -> Result<(), StoreError>;
    async fn delete(&self, instance_id: &str, name: &str) -> Result<(), StoreError>;
    async fn list(&self, instance_id: &str) -> Result<Vec<(String, String)>, StoreError>;
}

#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn mint(&self, instance_id: &str, provider: &str) -> Result<String, StoreError>;
    async fn resolve(&self, token: &str) -> Result<Option<TokenRecord>, StoreError>;
    async fn revoke_for_instance(&self, instance_id: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait HealthProber: Send + Sync {
    async fn probe(&self, instance: &InstanceRow) -> ProbeResult;
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub instance_id: String,
    pub provider: String,
    pub model: Option<String>,
    pub prompt_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub status_code: i64,
    pub duration_ms: i64,
    pub occurred_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyRecord {
    pub allowed_providers: Vec<String>,
    pub allowed_models: Vec<String>,
    pub daily_token_budget: Option<u64>,
    pub monthly_usd_budget: Option<f64>,
    pub rps_limit: Option<u32>,
}

#[async_trait]
pub trait SnapshotStore: Send + Sync {
    async fn insert(&self, row: &SnapshotRow) -> Result<(), StoreError>;
    async fn get(&self, id: &str) -> Result<Option<SnapshotRow>, StoreError>;
    async fn list_for_instance(&self, instance_id: &str) -> Result<Vec<SnapshotRow>, StoreError>;
    async fn update_remote_uri(&self, id: &str, uri: &str) -> Result<(), StoreError>;
    async fn update_path(&self, id: &str, path: &str) -> Result<(), StoreError>;
    async fn mark_deleted(&self, id: &str, when: i64) -> Result<(), StoreError>;
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Look up a policy by *subject* — for the multi-tenant build this is a
    /// `user_id`. The pre-tenancy build keyed on `instance_id`; the trait
    /// stays opaque so phase 2 can swap the meaning without re-plumbing.
    async fn get(&self, subject: &str) -> Result<Option<PolicyRecord>, StoreError>;
    async fn put(&self, subject: &str, policy: &PolicyRecord) -> Result<(), StoreError>;
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn insert(&self, entry: &AuditEntry) -> Result<(), StoreError>;
    /// Sum prompt+output tokens for `subject` (instance_id today, owner_id
    /// after phase 6) over the past 24h.
    async fn daily_tokens(&self, subject: &str, now: i64) -> Result<u64, StoreError>;
}

#[async_trait]
pub trait BackupSink: Send + Sync {
    /// Tag a snapshot as backup-class and (for remote sinks) copy its bytes
    /// to durable storage. Returns the canonical URI of the stored blob,
    /// or `None` if the sink is local-only.
    async fn promote(&self, snapshot: &SnapshotRow) -> Result<Option<String>, BackupError>;
    /// Pull a previously-promoted backup back to a local path on the Cube
    /// host. Idempotent — if the bytes are already present at the row's
    /// `path`, returns immediately.
    async fn pull(&self, snapshot: &SnapshotRow) -> Result<PathBuf, BackupError>;
    async fn list(&self, instance_id: &str) -> Result<Vec<SnapshotRow>, BackupError>;
    async fn delete(&self, snapshot: &SnapshotRow) -> Result<(), BackupError>;
}

/// Per-provider quirk handling for the LLM proxy.
pub trait ProviderAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    /// Lifetime is tied to the borrowed `ProviderConfig` so impls can
    /// return `&config.upstream` directly.
    fn upstream_base_url<'a>(&self, config: &'a ProviderConfig) -> &'a str;
    fn rewrite_auth(
        &self,
        headers: &mut axum::http::HeaderMap,
        url: &mut axum::http::Uri,
        real_key: &str,
    );
}
