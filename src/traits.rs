use std::collections::BTreeMap;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::ProviderConfig;
use crate::error::{BackupError, CubeError, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// Auto-created from a fresh OIDC `sub` but not yet approved by an
    /// admin. The auth middleware returns 403 for inactive users.
    Inactive,
    /// Approved by an admin. Normal access.
    Active,
    /// Disabled by an admin. Same observable effect as Inactive but kept
    /// distinct so the UI can show "needs approval" vs "blocked".
    Suspended,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inactive" => Some(Self::Inactive),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub status: UserStatus,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    /// Stable OpenRouter Provisioning-API key id, or None before the
    /// first lazy mint.  Set when the proxy mints a key for this
    /// user; cleared when an admin suspends/deletes them and swarm
    /// revokes upstream.
    pub openrouter_key_id: Option<String>,
    /// USD spend cap on this user's OR key.  Default $10 (set by the
    /// migration); admin can raise per-tenant.  Mirrored upstream on
    /// every change so OR enforces it server-side.
    pub openrouter_key_limit_usd: f64,
}

#[derive(Debug, Clone)]
pub struct UserApiKey {
    pub token: String,
    pub user_id: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    /// Create a brand-new row. The caller is responsible for the id (uuid).
    async fn create(&self, row: UserRow) -> Result<(), StoreError>;
    async fn get(&self, id: &str) -> Result<Option<UserRow>, StoreError>;
    async fn get_by_subject(&self, subject: &str) -> Result<Option<UserRow>, StoreError>;
    async fn list(&self) -> Result<Vec<UserRow>, StoreError>;
    async fn set_status(&self, id: &str, status: UserStatus) -> Result<(), StoreError>;
    async fn touch_last_seen(&self, id: &str) -> Result<(), StoreError>;

    /// Persist (or clear) the OpenRouter Provisioning-API key id for
    /// `user_id`.  Called after a successful POST /keys mint, and
    /// again with `None` after an admin-triggered DELETE upstream.
    async fn set_openrouter_key_id(
        &self,
        user_id: &str,
        key_id: Option<&str>,
    ) -> Result<(), StoreError>;
    /// Update the per-user USD cap on the OR key.  The caller is
    /// responsible for mirroring the change upstream via the
    /// Provisioning API; this method only persists the local view.
    async fn set_openrouter_limit(
        &self,
        user_id: &str,
        limit_usd: f64,
    ) -> Result<(), StoreError>;

    /// Mint an opaque bearer for `user_id`. Used by CI/admin paths that
    /// can't do an OIDC flow.
    async fn mint_api_key(
        &self,
        user_id: &str,
        label: Option<&str>,
    ) -> Result<String, StoreError>;
    async fn resolve_api_key(&self, token: &str) -> Result<Option<UserApiKey>, StoreError>;
    async fn revoke_api_key(&self, token: &str) -> Result<(), StoreError>;
}

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
    pub owner_id: String,
    /// Human-readable label ("PR reviewer for foo/bar"). Optional —
    /// stored as empty string when unset. Surfaced as `SWARM_NAME` in
    /// the sandbox env at create/restore time.
    pub name: String,
    /// Free-text mission statement. Surfaced as `SWARM_TASK` in the
    /// sandbox env at create/restore time. Per the design: swarm
    /// seeds this on first boot; the agent (Dyson) owns identity from
    /// then on, so subsequent edits in swarm don't propagate to a
    /// running sandbox without an explicit re-onboard.
    pub task: String,
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
    /// Set by the binary-rotation sweep to pin a Live source row to
    /// the new instance that absorbed its workspace state.  Stamped
    /// after the snapshot+restore step succeeds, before the destroy
    /// step runs — so a crash between restore and destroy leaves a
    /// re-runnable hint: the next sweep sees the marker, skips the
    /// snapshot+restore (which already produced the successor), and
    /// retries just the destroy.  `None` for every row that has
    /// never been a rotation source.
    pub rotated_to: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub id: String,
    pub owner_id: String,
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
    /// Look up by id without an owner filter. Reserved for system-internal
    /// flows (TTL sweep, probe loop, proxy resolving an instance by its
    /// proxy_token) where the caller has already authorised the access.
    /// Tenant-facing routes use [`get_for_owner`].
    async fn get(&self, id: &str) -> Result<Option<InstanceRow>, StoreError>;
    /// Owner-scoped lookup: returns `Ok(None)` for rows not owned by
    /// `owner_id` even if the id matches some other tenant's row.
    async fn get_for_owner(
        &self,
        owner_id: &str,
        id: &str,
    ) -> Result<Option<InstanceRow>, StoreError>;
    /// Owner-scoped list. `owner_id == "*"` is god-mode (admin only).
    async fn list(
        &self,
        owner_id: &str,
        filter: ListFilter,
    ) -> Result<Vec<InstanceRow>, StoreError>;
    async fn update_status(&self, id: &str, status: InstanceStatus) -> Result<(), StoreError>;
    /// Set the Cube-side sandbox id once Cube has assigned one. Needed
    /// because the row must exist before `TokenStore::mint` (FK), but the
    /// sandbox id is only known after the Cube call returns.
    async fn set_cube_sandbox_id(&self, id: &str, sandbox_id: &str) -> Result<(), StoreError>;
    async fn touch(&self, id: &str) -> Result<(), StoreError>;
    /// Owner-scoped rename. `name` and `task` are both replaced; pass
    /// the existing values for fields that aren't changing. Returns
    /// `NotFound` if the row exists but belongs to someone else (no
    /// cross-tenant existence oracle).
    async fn update_identity(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
        task: &str,
    ) -> Result<(), StoreError>;
    async fn pin(&self, id: &str, pinned: bool, ttl: Option<i64>) -> Result<(), StoreError>;
    async fn record_probe(&self, id: &str, status: ProbeResult) -> Result<(), StoreError>;
    async fn expired(&self, now: i64) -> Result<Vec<InstanceRow>, StoreError>;
    /// Stamp the source row of a binary rotation with the id of the
    /// new instance that took over its workspace.  Called once per
    /// source after a successful snapshot+restore, before the destroy
    /// step.  Re-running with the same target is a no-op write.
    async fn set_rotated_to(&self, id: &str, target_id: &str) -> Result<(), StoreError>;
}

/// Per-instance secrets — opaque ciphertexts stored against an instance row.
///
/// All methods deal in **ciphertext**: the store is dumb sqlite; encryption
/// happens one layer up in `SecretsService`, which routes through the
/// instance owner's [`crate::envelope::EnvelopeCipher`].  The `&str` shape
/// is fine because age's armored output is ASCII, mapped to a TEXT column.
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put(
        &self,
        instance_id: &str,
        name: &str,
        ciphertext: &str,
    ) -> Result<(), StoreError>;
    async fn delete(&self, instance_id: &str, name: &str) -> Result<(), StoreError>;
    /// Returns `(name, ciphertext)` pairs ordered by name.  The service
    /// layer decrypts.
    async fn list(&self, instance_id: &str) -> Result<Vec<(String, String)>, StoreError>;
}

/// Per-user opaque ciphertexts.  Same dumb-store contract as
/// [`SecretStore`]; the service layer seals/opens with the user's
/// own [`crate::envelope::EnvelopeCipher`], so cross-user reads of
/// the raw column yield only undecryptable bytes.
#[async_trait]
pub trait UserSecretStore: Send + Sync {
    async fn put(
        &self,
        user_id: &str,
        name: &str,
        ciphertext: &str,
    ) -> Result<(), StoreError>;
    async fn get(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<Option<String>, StoreError>;
    async fn delete(&self, user_id: &str, name: &str) -> Result<(), StoreError>;
    /// Returns `(name, ciphertext)` pairs ordered by name.
    async fn list(&self, user_id: &str) -> Result<Vec<(String, String)>, StoreError>;
}

/// Global opaque ciphertexts (one row per `name`).  Used for provider
/// API keys, the OpenRouter provisioning key, and anything else not
/// owned by a real user.  Encrypted with the system-scope cipher
/// (see [`crate::envelope::SYSTEM_KEY_ID`]).
#[async_trait]
pub trait SystemSecretStore: Send + Sync {
    async fn put(&self, name: &str, ciphertext: &str) -> Result<(), StoreError>;
    async fn get(&self, name: &str) -> Result<Option<String>, StoreError>;
    async fn delete(&self, name: &str) -> Result<(), StoreError>;
    /// Returns names only (operators inspect via `swarm secret list system`).
    async fn list_names(&self) -> Result<Vec<String>, StoreError>;
}

#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn mint(&self, instance_id: &str, provider: &str) -> Result<String, StoreError>;
    async fn resolve(&self, token: &str) -> Result<Option<TokenRecord>, StoreError>;
    async fn revoke_for_instance(&self, instance_id: &str) -> Result<(), StoreError>;
    /// Reverse of `resolve`: given an instance id, return the active
    /// (non-revoked) proxy_token for that instance.  Used by the
    /// image-gen rewire sweep — it needs the same token already
    /// embedded in the instance's chat provider so the new image
    /// provider entry authenticates against swarm's `/llm` proxy.
    /// Returns `None` for instances created before Stage 8 (no
    /// proxy_token row exists) so callers can skip them quietly.
    async fn lookup_by_instance(&self, instance_id: &str)
        -> Result<Option<String>, StoreError>;
}

#[async_trait]
pub trait HealthProber: Send + Sync {
    async fn probe(&self, instance: &InstanceRow) -> ProbeResult;
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub owner_id: String,
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
