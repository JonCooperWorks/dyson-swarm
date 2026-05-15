use std::path::Path;
use std::str::FromStr;

#[cfg(feature = "postgres")]
use std::fmt::Write as _;

use sqlx::sqlite::{SqliteArguments, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

#[cfg(feature = "postgres")]
use sqlx::postgres::{PgArguments, PgPoolOptions};
#[cfg(feature = "postgres")]
use sqlx::{PgPool, Postgres};

use crate::config::DatabaseBackend;
use crate::db::sqlite::{MIGRATOR, map_sqlx};
use crate::error::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTableCount {
    pub table: &'static str,
    pub rows: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReport {
    pub counts: Vec<TransferTableCount>,
}

#[derive(Debug, Clone, Copy)]
enum ColumnKind {
    I64,
    F64,
    Text,
    Bytes,
}

#[derive(Debug, Clone, Copy)]
struct ColumnSpec {
    name: &'static str,
    kind: ColumnKind,
}

#[derive(Debug, Clone, Copy)]
struct TableSpec {
    name: &'static str,
    columns: &'static [ColumnSpec],
    order_by: &'static str,
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    serial_column: Option<&'static str>,
}

#[derive(Debug, Clone)]
enum Cell {
    Null,
    I64(i64),
    F64(f64),
    Text(String),
    Bytes(Vec<u8>),
}

const fn col(name: &'static str, kind: ColumnKind) -> ColumnSpec {
    ColumnSpec { name, kind }
}

const USERS: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("subject", ColumnKind::Text),
    col("email", ColumnKind::Text),
    col("display_name", ColumnKind::Text),
    col("status", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("activated_at", ColumnKind::I64),
    col("last_seen_at", ColumnKind::I64),
    col("openrouter_key_id", ColumnKind::Text),
    col("openrouter_key_limit_usd", ColumnKind::F64),
    col("email_ciphertext", ColumnKind::Text),
];

const USER_API_KEYS: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("user_id", ColumnKind::Text),
    col("prefix", ColumnKind::Text),
    col("ciphertext", ColumnKind::Text),
    col("label", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("revoked_at", ColumnKind::I64),
];

const INSTANCES: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("cube_sandbox_id", ColumnKind::Text),
    col("template_id", ColumnKind::Text),
    col("status", ColumnKind::Text),
    col("bearer_token", ColumnKind::Text),
    col("pinned", ColumnKind::I64),
    col("expires_at", ColumnKind::I64),
    col("last_active_at", ColumnKind::I64),
    col("last_probe_at", ColumnKind::I64),
    col("last_probe_status", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("destroyed_at", ColumnKind::I64),
    col("owner_id", ColumnKind::Text),
    col("name", ColumnKind::Text),
    col("task", ColumnKind::Text),
    col("rotated_to", ColumnKind::Text),
    col("network_policy_kind", ColumnKind::Text),
    col("network_policy_entries", ColumnKind::Text),
    col("network_policy_cidrs", ColumnKind::Text),
    col("models", ColumnKind::Text),
    col("tools", ColumnKind::Text),
    col("state_generation", ColumnKind::Text),
];

const USER_POLICIES: &[ColumnSpec] = &[
    col("user_id", ColumnKind::Text),
    col("allowed_providers", ColumnKind::Text),
    col("allowed_models", ColumnKind::Text),
    col("daily_token_budget", ColumnKind::I64),
    col("monthly_usd_budget", ColumnKind::F64),
    col("rps_limit", ColumnKind::I64),
];

const SYSTEM_SECRETS: &[ColumnSpec] = &[
    col("name", ColumnKind::Text),
    col("ciphertext", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
];

const USER_SECRETS: &[ColumnSpec] = &[
    col("user_id", ColumnKind::Text),
    col("name", ColumnKind::Text),
    col("ciphertext", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
];

const PROXY_TOKENS: &[ColumnSpec] = &[
    col("token", ColumnKind::Text),
    col("instance_id", ColumnKind::Text),
    col("provider", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("revoked_at", ColumnKind::I64),
    col("token_lookup", ColumnKind::Text),
    col("expected_src_ip", ColumnKind::Text),
];

const SNAPSHOTS: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("source_instance_id", ColumnKind::Text),
    col("parent_snapshot_id", ColumnKind::Text),
    col("kind", ColumnKind::Text),
    col("path", ColumnKind::Text),
    col("host_ip", ColumnKind::Text),
    col("remote_uri", ColumnKind::Text),
    col("size_bytes", ColumnKind::I64),
    col("created_at", ColumnKind::I64),
    col("deleted_at", ColumnKind::I64),
    col("owner_id", ColumnKind::Text),
    col("content_hash", ColumnKind::Text),
];

const LLM_AUDIT: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("instance_id", ColumnKind::Text),
    col("provider", ColumnKind::Text),
    col("model", ColumnKind::Text),
    col("prompt_tokens", ColumnKind::I64),
    col("output_tokens", ColumnKind::I64),
    col("status_code", ColumnKind::I64),
    col("duration_ms", ColumnKind::I64),
    col("occurred_at", ColumnKind::I64),
    col("owner_id", ColumnKind::Text),
    col("key_source", ColumnKind::Text),
    col("completed", ColumnKind::I64),
];

const ARTEFACT_CACHE: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("instance_id", ColumnKind::Text),
    col("owner_id", ColumnKind::Text),
    col("chat_id", ColumnKind::Text),
    col("artefact_id", ColumnKind::Text),
    col("kind", ColumnKind::Text),
    col("title", ColumnKind::Text),
    col("mime", ColumnKind::Text),
    col("bytes", ColumnKind::I64),
    col("metadata_json", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("cached_at", ColumnKind::I64),
    col("body_ciphertext", ColumnKind::Bytes),
];

const ARTEFACT_SHARES: &[ColumnSpec] = &[
    col("jti", ColumnKind::Text),
    col("instance_id", ColumnKind::Text),
    col("chat_id", ColumnKind::Text),
    col("artefact_id", ColumnKind::Text),
    col("created_by", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("expires_at", ColumnKind::I64),
    col("revoked_at", ColumnKind::I64),
    col("label", ColumnKind::Text),
];

const ARTEFACT_SHARE_ACCESSES: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("jti", ColumnKind::Text),
    col("accessed_at", ColumnKind::I64),
    col("remote_addr", ColumnKind::Text),
    col("user_agent", ColumnKind::Text),
    col("status", ColumnKind::I64),
];

const INSTANCE_WEBHOOKS: &[ColumnSpec] = &[
    col("instance_id", ColumnKind::Text),
    col("name", ColumnKind::Text),
    col("description", ColumnKind::Text),
    col("auth_scheme", ColumnKind::Text),
    col("secret_name", ColumnKind::Text),
    col("enabled", ColumnKind::I64),
    col("created_at", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
    col("signature_header", ColumnKind::Text),
    col("verifier_mode", ColumnKind::Text),
    col("signature_algo", ColumnKind::Text),
    col("signature_encoding", ColumnKind::Text),
    col("signature_prefix", ColumnKind::Text),
    col("signature_separator", ColumnKind::Text),
    col("signature_value_split", ColumnKind::Text),
    col("timestamp_header", ColumnKind::Text),
    col("timestamp_skew_secs", ColumnKind::I64),
    col("payload_template", ColumnKind::Text),
    col("idempotency_header", ColumnKind::Text),
    col("bearer_path_token", ColumnKind::Text),
];

const WEBHOOK_DELIVERIES: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("instance_id", ColumnKind::Text),
    col("webhook_name", ColumnKind::Text),
    col("fired_at", ColumnKind::I64),
    col("status_code", ColumnKind::I64),
    col("latency_ms", ColumnKind::I64),
    col("request_id", ColumnKind::Text),
    col("signature_ok", ColumnKind::I64),
    col("error", ColumnKind::Text),
    col("body", ColumnKind::Bytes),
    col("body_size", ColumnKind::I64),
    col("content_type", ColumnKind::Text),
    col("verify_error", ColumnKind::Text),
    col("request_headers", ColumnKind::Text),
    col("replayed_from_delivery_id", ColumnKind::Text),
    col("replayed_by_user_id", ColumnKind::Text),
];

const WEBHOOK_DELIVERIES_SEEN: &[ColumnSpec] = &[
    col("webhook_row_id", ColumnKind::Text),
    col("idempotency_key", ColumnKind::Text),
    col("first_seen_at", ColumnKind::I64),
];

const STATE_FILES: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("instance_id", ColumnKind::Text),
    col("owner_id", ColumnKind::Text),
    col("namespace", ColumnKind::Text),
    col("path", ColumnKind::Text),
    col("mime", ColumnKind::Text),
    col("bytes", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
    col("synced_at", ColumnKind::I64),
    col("deleted_at", ColumnKind::I64),
    col("body_ciphertext", ColumnKind::Bytes),
];

const MCP_DOCKER_CATALOG: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("label", ColumnKind::Text),
    col("description", ColumnKind::Text),
    col("template", ColumnKind::Text),
    col("placeholders_json", ColumnKind::Text),
    col("source", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
    col("deleted_at", ColumnKind::I64),
    col("status", ColumnKind::Text),
    col("requested_by_user_id", ColumnKind::Text),
];

const SKILL_MARKETPLACE_SOURCES: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("source_type", ColumnKind::Text),
    col("location", ColumnKind::Text),
    col("enabled", ColumnKind::I64),
    col("created_at", ColumnKind::I64),
    col("updated_at", ColumnKind::I64),
    col("deleted_at", ColumnKind::I64),
    col("last_fetch_at", ColumnKind::I64),
    col("last_success_at", ColumnKind::I64),
    col("last_error", ColumnKind::Text),
];

const AGENT_SKILL_PUBLICATIONS: &[ColumnSpec] = &[
    col("instance_id", ColumnKind::Text),
    col("owner_id", ColumnKind::Text),
    col("skill", ColumnKind::Text),
    col("published_by", ColumnKind::Text),
    col("published_at", ColumnKind::I64),
    col("revoked_at", ColumnKind::I64),
];

const MCP_AUDIT: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("owner_id", ColumnKind::Text),
    col("instance_id", ColumnKind::Text),
    col("server_name", ColumnKind::Text),
    col("tool", ColumnKind::Text),
    col("status", ColumnKind::I64),
    col("duration_ms", ColumnKind::I64),
    col("ts", ColumnKind::I64),
    col("completed", ColumnKind::I64),
];

const LLM_TOOL_CALL: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("llm_audit_id", ColumnKind::I64),
    col("owner_id", ColumnKind::Text),
    col("instance_id", ColumnKind::Text),
    col("tool_use_id", ColumnKind::Text),
    col("tool_name", ColumnKind::Text),
    col("mcp_server", ColumnKind::Text),
    col("input_sealed", ColumnKind::Bytes),
    col("result_sealed", ColumnKind::Bytes),
    col("is_error", ColumnKind::I64),
    col("called_at", ColumnKind::I64),
    col("resulted_at", ColumnKind::I64),
    col("mcp_audit_id", ColumnKind::I64),
];

const ADMIN_AUDIT: &[ColumnSpec] = &[
    col("id", ColumnKind::I64),
    col("actor_subject", ColumnKind::Text),
    col("action", ColumnKind::Text),
    col("target_user", ColumnKind::Text),
    col("params_hash", ColumnKind::Text),
    col("ts", ColumnKind::I64),
];

const SESSIONS: &[ColumnSpec] = &[
    col("id", ColumnKind::Text),
    col("user_id", ColumnKind::Text),
    col("created_at", ColumnKind::I64),
    col("last_seen_at", ColumnKind::I64),
    col("revoked_at", ColumnKind::I64),
];

const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "users",
        columns: USERS,
        order_by: "id",
        serial_column: None,
    },
    TableSpec {
        name: "user_api_keys",
        columns: USER_API_KEYS,
        order_by: "id",
        serial_column: None,
    },
    TableSpec {
        name: "instances",
        columns: INSTANCES,
        order_by: "created_at, id",
        serial_column: None,
    },
    TableSpec {
        name: "user_policies",
        columns: USER_POLICIES,
        order_by: "user_id",
        serial_column: None,
    },
    TableSpec {
        name: "system_secrets",
        columns: SYSTEM_SECRETS,
        order_by: "name",
        serial_column: None,
    },
    TableSpec {
        name: "user_secrets",
        columns: USER_SECRETS,
        order_by: "user_id, name",
        serial_column: None,
    },
    TableSpec {
        name: "proxy_tokens",
        columns: PROXY_TOKENS,
        order_by: "created_at, token",
        serial_column: None,
    },
    TableSpec {
        name: "snapshots",
        columns: SNAPSHOTS,
        order_by: "created_at, id",
        serial_column: None,
    },
    TableSpec {
        name: "llm_audit",
        columns: LLM_AUDIT,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "artefact_cache",
        columns: ARTEFACT_CACHE,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "artefact_shares",
        columns: ARTEFACT_SHARES,
        order_by: "created_at, jti",
        serial_column: None,
    },
    TableSpec {
        name: "artefact_share_accesses",
        columns: ARTEFACT_SHARE_ACCESSES,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "instance_webhooks",
        columns: INSTANCE_WEBHOOKS,
        order_by: "instance_id, name",
        serial_column: None,
    },
    TableSpec {
        name: "webhook_deliveries",
        columns: WEBHOOK_DELIVERIES,
        order_by: "fired_at, id",
        serial_column: None,
    },
    TableSpec {
        name: "webhook_deliveries_seen",
        columns: WEBHOOK_DELIVERIES_SEEN,
        order_by: "webhook_row_id, idempotency_key",
        serial_column: None,
    },
    TableSpec {
        name: "instance_state_files",
        columns: STATE_FILES,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "mcp_docker_catalog",
        columns: MCP_DOCKER_CATALOG,
        order_by: "id",
        serial_column: None,
    },
    TableSpec {
        name: "skill_marketplace_sources",
        columns: SKILL_MARKETPLACE_SOURCES,
        order_by: "id",
        serial_column: None,
    },
    TableSpec {
        name: "agent_skill_publications",
        columns: AGENT_SKILL_PUBLICATIONS,
        order_by: "instance_id, skill",
        serial_column: None,
    },
    TableSpec {
        name: "mcp_audit",
        columns: MCP_AUDIT,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "llm_tool_call",
        columns: LLM_TOOL_CALL,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "admin_audit",
        columns: ADMIN_AUDIT,
        order_by: "id",
        serial_column: Some("id"),
    },
    TableSpec {
        name: "sessions",
        columns: SESSIONS,
        order_by: "id",
        serial_column: None,
    },
];

pub async fn run(
    from: DatabaseBackend,
    to: DatabaseBackend,
    source_url: &str,
    target_url: &str,
) -> Result<TransferReport, StoreError> {
    match (from, to) {
        (DatabaseBackend::Sqlite, DatabaseBackend::Sqlite) => {
            let source = open_sqlite(source_url).await?;
            let target = open_sqlite(target_url).await?;
            transfer_sqlite_to_sqlite(&source, &target).await
        }
        #[cfg(feature = "postgres")]
        (DatabaseBackend::Sqlite, DatabaseBackend::Postgres) => {
            let source = open_sqlite(source_url).await?;
            let target = open_pg(target_url).await?;
            transfer_sqlite_to_pg(&source, &target).await
        }
        #[cfg(feature = "postgres")]
        (DatabaseBackend::Postgres, DatabaseBackend::Sqlite) => {
            let source = open_pg(source_url).await?;
            let target = open_sqlite(target_url).await?;
            transfer_pg_to_sqlite(&source, &target).await
        }
        #[cfg(feature = "postgres")]
        (DatabaseBackend::Postgres, DatabaseBackend::Postgres) => {
            let source = open_pg(source_url).await?;
            let target = open_pg(target_url).await?;
            transfer_pg_to_pg(&source, &target).await
        }
        #[cfg(not(feature = "postgres"))]
        (DatabaseBackend::Postgres, _) | (_, DatabaseBackend::Postgres) => Err(StoreError::Io(
            "Postgres transfer requires building with the postgres feature".into(),
        )),
    }
}

pub const fn table_names() -> &'static [&'static str] {
    const NAMES: &[&str] = &[
        "users",
        "user_api_keys",
        "instances",
        "user_policies",
        "system_secrets",
        "user_secrets",
        "proxy_tokens",
        "snapshots",
        "llm_audit",
        "artefact_cache",
        "artefact_shares",
        "artefact_share_accesses",
        "instance_webhooks",
        "webhook_deliveries",
        "webhook_deliveries_seen",
        "instance_state_files",
        "mcp_docker_catalog",
        "skill_marketplace_sources",
        "agent_skill_publications",
        "mcp_audit",
        "llm_tool_call",
        "admin_audit",
        "sessions",
    ];
    NAMES
}

async fn open_sqlite(url: &str) -> Result<SqlitePool, StoreError> {
    let url = if url.starts_with("sqlite:") {
        url.to_owned()
    } else {
        let path = Path::new(url);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        format!("sqlite://{url}")
    };
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(map_sqlx)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .map_err(map_sqlx)?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(pool)
}

#[cfg(feature = "postgres")]
async fn open_pg(url: &str) -> Result<PgPool, StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await
        .map_err(crate::db::pg::map_sqlx)?;
    crate::db::pg::MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(pool)
}

async fn transfer_sqlite_to_sqlite(
    source: &SqlitePool,
    target: &SqlitePool,
) -> Result<TransferReport, StoreError> {
    cleanup_sqlite_seed(target).await?;
    ensure_sqlite_empty(target).await?;
    let mut tx = target.begin().await.map_err(map_sqlx)?;
    let mut counts = Vec::new();
    for table in TABLES {
        let rows = read_sqlite_table(source, table).await?;
        for row in &rows {
            insert_sqlite_row(&mut tx, table, row).await?;
        }
        counts.push(TransferTableCount {
            table: table.name,
            rows: i64::try_from(rows.len()).unwrap_or(i64::MAX),
        });
    }
    tx.commit().await.map_err(map_sqlx)?;
    verify_sqlite_counts(target, &counts).await?;
    Ok(TransferReport { counts })
}

#[cfg(feature = "postgres")]
async fn transfer_sqlite_to_pg(
    source: &SqlitePool,
    target: &PgPool,
) -> Result<TransferReport, StoreError> {
    cleanup_pg_seed(target).await?;
    ensure_pg_empty(target).await?;
    let mut tx = target.begin().await.map_err(crate::db::pg::map_sqlx)?;
    let mut counts = Vec::new();
    for table in TABLES {
        let rows = read_sqlite_table(source, table).await?;
        for row in &rows {
            insert_pg_row(&mut tx, table, row).await?;
        }
        reset_pg_sequence(&mut tx, table).await?;
        counts.push(TransferTableCount {
            table: table.name,
            rows: i64::try_from(rows.len()).unwrap_or(i64::MAX),
        });
    }
    tx.commit().await.map_err(crate::db::pg::map_sqlx)?;
    verify_pg_counts(target, &counts).await?;
    Ok(TransferReport { counts })
}

#[cfg(feature = "postgres")]
async fn transfer_pg_to_sqlite(
    source: &PgPool,
    target: &SqlitePool,
) -> Result<TransferReport, StoreError> {
    cleanup_sqlite_seed(target).await?;
    ensure_sqlite_empty(target).await?;
    let mut tx = target.begin().await.map_err(map_sqlx)?;
    let mut counts = Vec::new();
    for table in TABLES {
        let rows = read_pg_table(source, table).await?;
        for row in &rows {
            insert_sqlite_row(&mut tx, table, row).await?;
        }
        counts.push(TransferTableCount {
            table: table.name,
            rows: i64::try_from(rows.len()).unwrap_or(i64::MAX),
        });
    }
    tx.commit().await.map_err(map_sqlx)?;
    verify_sqlite_counts(target, &counts).await?;
    Ok(TransferReport { counts })
}

#[cfg(feature = "postgres")]
async fn transfer_pg_to_pg(source: &PgPool, target: &PgPool) -> Result<TransferReport, StoreError> {
    cleanup_pg_seed(target).await?;
    ensure_pg_empty(target).await?;
    let mut tx = target.begin().await.map_err(crate::db::pg::map_sqlx)?;
    let mut counts = Vec::new();
    for table in TABLES {
        let rows = read_pg_table(source, table).await?;
        for row in &rows {
            insert_pg_row(&mut tx, table, row).await?;
        }
        reset_pg_sequence(&mut tx, table).await?;
        counts.push(TransferTableCount {
            table: table.name,
            rows: i64::try_from(rows.len()).unwrap_or(i64::MAX),
        });
    }
    tx.commit().await.map_err(crate::db::pg::map_sqlx)?;
    verify_pg_counts(target, &counts).await?;
    Ok(TransferReport { counts })
}

async fn cleanup_sqlite_seed(pool: &SqlitePool) -> Result<(), StoreError> {
    sqlx::query(
        "DELETE FROM users \
         WHERE id = 'legacy' AND subject = 'legacy' \
           AND NOT EXISTS (SELECT 1 FROM instances WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM snapshots WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_api_keys WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_policies WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_secrets WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM llm_audit WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM mcp_audit WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM sessions WHERE user_id = 'legacy')",
    )
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn cleanup_pg_seed(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::query(
        "DELETE FROM users \
         WHERE id = 'legacy' AND subject = 'legacy' \
           AND NOT EXISTS (SELECT 1 FROM instances WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM snapshots WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_api_keys WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_policies WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM user_secrets WHERE user_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM llm_audit WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM mcp_audit WHERE owner_id = 'legacy') \
           AND NOT EXISTS (SELECT 1 FROM sessions WHERE user_id = 'legacy')",
    )
    .execute(pool)
    .await
    .map_err(crate::db::pg::map_sqlx)?;
    Ok(())
}

async fn ensure_sqlite_empty(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut populated = Vec::new();
    for table in TABLES {
        let count = sqlite_count(pool, table.name).await?;
        if count != 0 {
            populated.push(format!("{}={count}", table.name));
        }
    }
    if populated.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Constraint(format!(
            "target not empty: tables [{}]",
            populated.join(", ")
        )))
    }
}

#[cfg(feature = "postgres")]
async fn ensure_pg_empty(pool: &PgPool) -> Result<(), StoreError> {
    let mut populated = Vec::new();
    for table in TABLES {
        let count = pg_count(pool, table.name).await?;
        if count != 0 {
            populated.push(format!("{}={count}", table.name));
        }
    }
    if populated.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Constraint(format!(
            "target not empty: tables [{}]",
            populated.join(", ")
        )))
    }
}

async fn verify_sqlite_counts(
    pool: &SqlitePool,
    expected: &[TransferTableCount],
) -> Result<(), StoreError> {
    let mut mismatches = Vec::new();
    for item in expected {
        let got = sqlite_count(pool, item.table).await?;
        if got != item.rows {
            mismatches.push(format!("{} source={} target={got}", item.table, item.rows));
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Constraint(format!(
            "transfer count mismatch: {}",
            mismatches.join(", ")
        )))
    }
}

#[cfg(feature = "postgres")]
async fn verify_pg_counts(
    pool: &PgPool,
    expected: &[TransferTableCount],
) -> Result<(), StoreError> {
    let mut mismatches = Vec::new();
    for item in expected {
        let got = pg_count(pool, item.table).await?;
        if got != item.rows {
            mismatches.push(format!("{} source={} target={got}", item.table, item.rows));
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Constraint(format!(
            "transfer count mismatch: {}",
            mismatches.join(", ")
        )))
    }
}

async fn sqlite_count(pool: &SqlitePool, table: &str) -> Result<i64, StoreError> {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let row = sqlx::query(&sql).fetch_one(pool).await.map_err(map_sqlx)?;
    row.try_get("n").map_err(map_sqlx)
}

#[cfg(feature = "postgres")]
async fn pg_count(pool: &PgPool, table: &str) -> Result<i64, StoreError> {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let row = sqlx::query(&sql)
        .fetch_one(pool)
        .await
        .map_err(crate::db::pg::map_sqlx)?;
    row.try_get("n").map_err(crate::db::pg::map_sqlx)
}

async fn read_sqlite_table(
    pool: &SqlitePool,
    table: &TableSpec,
) -> Result<Vec<Vec<Cell>>, StoreError> {
    let sql = select_sql(table);
    let rows = sqlx::query(&sql).fetch_all(pool).await.map_err(map_sqlx)?;
    rows.into_iter()
        .map(|row| {
            table
                .columns
                .iter()
                .map(|column| sqlite_cell(&row, column))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

#[cfg(feature = "postgres")]
async fn read_pg_table(pool: &PgPool, table: &TableSpec) -> Result<Vec<Vec<Cell>>, StoreError> {
    let sql = select_sql(table);
    let rows = sqlx::query(&sql)
        .fetch_all(pool)
        .await
        .map_err(crate::db::pg::map_sqlx)?;
    rows.into_iter()
        .map(|row| {
            table
                .columns
                .iter()
                .map(|column| pg_cell(&row, column))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

fn select_sql(table: &TableSpec) -> String {
    let cols = table
        .columns
        .iter()
        .map(|c| c.name)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT {cols} FROM {} ORDER BY {}",
        table.name, table.order_by
    )
}

fn sqlite_cell(row: &sqlx::sqlite::SqliteRow, column: &ColumnSpec) -> Result<Cell, StoreError> {
    match column.kind {
        ColumnKind::I64 => row
            .try_get::<Option<i64>, _>(column.name)
            .map(|v| v.map(Cell::I64).unwrap_or(Cell::Null))
            .map_err(map_sqlx),
        ColumnKind::F64 => row
            .try_get::<Option<f64>, _>(column.name)
            .map(|v| v.map(Cell::F64).unwrap_or(Cell::Null))
            .map_err(map_sqlx),
        ColumnKind::Text => row
            .try_get::<Option<String>, _>(column.name)
            .map(|v| v.map(Cell::Text).unwrap_or(Cell::Null))
            .map_err(map_sqlx),
        ColumnKind::Bytes => row
            .try_get::<Option<Vec<u8>>, _>(column.name)
            .map(|v| v.map(Cell::Bytes).unwrap_or(Cell::Null))
            .map_err(map_sqlx),
    }
}

#[cfg(feature = "postgres")]
fn pg_cell(row: &sqlx::postgres::PgRow, column: &ColumnSpec) -> Result<Cell, StoreError> {
    match column.kind {
        ColumnKind::I64 => row
            .try_get::<Option<i64>, _>(column.name)
            .map(|v| v.map(Cell::I64).unwrap_or(Cell::Null))
            .map_err(crate::db::pg::map_sqlx),
        ColumnKind::F64 => row
            .try_get::<Option<f64>, _>(column.name)
            .map(|v| v.map(Cell::F64).unwrap_or(Cell::Null))
            .map_err(crate::db::pg::map_sqlx),
        ColumnKind::Text => row
            .try_get::<Option<String>, _>(column.name)
            .map(|v| v.map(Cell::Text).unwrap_or(Cell::Null))
            .map_err(crate::db::pg::map_sqlx),
        ColumnKind::Bytes => row
            .try_get::<Option<Vec<u8>>, _>(column.name)
            .map(|v| v.map(Cell::Bytes).unwrap_or(Cell::Null))
            .map_err(crate::db::pg::map_sqlx),
    }
}

async fn insert_sqlite_row(
    tx: &mut Transaction<'_, Sqlite>,
    table: &TableSpec,
    cells: &[Cell],
) -> Result<(), StoreError> {
    let sql = insert_sqlite_sql(table);
    let mut query = sqlx::query_with(&sql, SqliteArguments::default());
    for (column, cell) in table.columns.iter().zip(cells) {
        query = bind_sqlite(query, column.kind, cell);
    }
    query.execute(&mut **tx).await.map_err(map_sqlx)?;
    Ok(())
}

fn insert_sqlite_sql(table: &TableSpec) -> String {
    let cols = table
        .columns
        .iter()
        .map(|c| c.name)
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (0..table.columns.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO {} ({cols}) VALUES ({placeholders})",
        table.name
    )
}

fn bind_sqlite<'q>(
    mut query: sqlx::query::Query<'q, Sqlite, SqliteArguments<'q>>,
    kind: ColumnKind,
    cell: &Cell,
) -> sqlx::query::Query<'q, Sqlite, SqliteArguments<'q>> {
    match (kind, cell) {
        (ColumnKind::I64, Cell::Null) => query = query.bind(Option::<i64>::None),
        (ColumnKind::I64, Cell::I64(v)) => query = query.bind(*v),
        (ColumnKind::F64, Cell::Null) => query = query.bind(Option::<f64>::None),
        (ColumnKind::F64, Cell::F64(v)) => query = query.bind(*v),
        (ColumnKind::Text, Cell::Null) => query = query.bind(Option::<String>::None),
        (ColumnKind::Text, Cell::Text(v)) => query = query.bind(v.clone()),
        (ColumnKind::Bytes, Cell::Null) => query = query.bind(Option::<Vec<u8>>::None),
        (ColumnKind::Bytes, Cell::Bytes(v)) => query = query.bind(v.clone()),
        (_, other) => panic!("transfer cell type mismatch for sqlite bind: {other:?}"),
    }
    query
}

#[cfg(feature = "postgres")]
async fn insert_pg_row(
    tx: &mut Transaction<'_, Postgres>,
    table: &TableSpec,
    cells: &[Cell],
) -> Result<(), StoreError> {
    let sql = insert_pg_sql(table);
    let mut query = sqlx::query_with(&sql, PgArguments::default());
    for (column, cell) in table.columns.iter().zip(cells) {
        query = bind_pg(query, column.kind, cell);
    }
    query
        .execute(&mut **tx)
        .await
        .map_err(crate::db::pg::map_sqlx)?;
    Ok(())
}

#[cfg(feature = "postgres")]
fn insert_pg_sql(table: &TableSpec) -> String {
    let cols = table
        .columns
        .iter()
        .map(|c| c.name)
        .collect::<Vec<_>>()
        .join(", ");
    let mut placeholders = String::new();
    for idx in 1..=table.columns.len() {
        if idx > 1 {
            placeholders.push_str(", ");
        }
        let _ = write!(placeholders, "${idx}");
    }
    format!(
        "INSERT INTO {} ({cols}) VALUES ({placeholders})",
        table.name
    )
}

#[cfg(feature = "postgres")]
fn bind_pg<'q>(
    mut query: sqlx::query::Query<'q, Postgres, PgArguments>,
    kind: ColumnKind,
    cell: &Cell,
) -> sqlx::query::Query<'q, Postgres, PgArguments> {
    match (kind, cell) {
        (ColumnKind::I64, Cell::Null) => query = query.bind(Option::<i64>::None),
        (ColumnKind::I64, Cell::I64(v)) => query = query.bind(*v),
        (ColumnKind::F64, Cell::Null) => query = query.bind(Option::<f64>::None),
        (ColumnKind::F64, Cell::F64(v)) => query = query.bind(*v),
        (ColumnKind::Text, Cell::Null) => query = query.bind(Option::<String>::None),
        (ColumnKind::Text, Cell::Text(v)) => query = query.bind(v.clone()),
        (ColumnKind::Bytes, Cell::Null) => query = query.bind(Option::<Vec<u8>>::None),
        (ColumnKind::Bytes, Cell::Bytes(v)) => query = query.bind(v.clone()),
        (_, other) => panic!("transfer cell type mismatch for pg bind: {other:?}"),
    }
    query
}

#[cfg(feature = "postgres")]
async fn reset_pg_sequence(
    tx: &mut Transaction<'_, Postgres>,
    table: &TableSpec,
) -> Result<(), StoreError> {
    let Some(column) = table.serial_column else {
        return Ok(());
    };
    let sql = format!(
        "SELECT setval(pg_get_serial_sequence('{}', '{}'), COALESCE((SELECT MAX({}) FROM {}), 0) + 1, false)",
        table.name, column, column, table.name
    );
    sqlx::query(&sql)
        .execute(&mut **tx)
        .await
        .map_err(crate::db::pg::map_sqlx)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_representative_fixture(pool: &SqlitePool) {
        sqlx::query(
            "INSERT INTO users \
             (id, subject, email, display_name, status, created_at, activated_at, last_seen_at, openrouter_key_id, openrouter_key_limit_usd, email_ciphertext) \
             VALUES ('u1', 'sub-1', 'u1@example.test', 'User One', 'active', 100, 101, 102, 'or-key', 12.5, 'cipher-email')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO instances \
             (id, cube_sandbox_id, template_id, status, bearer_token, pinned, expires_at, last_active_at, last_probe_at, last_probe_status, created_at, destroyed_at, owner_id, name, task, rotated_to, network_policy_kind, network_policy_entries, network_policy_cidrs, models, tools, state_generation) \
             VALUES ('i1', 'cube-1', 'tpl-1', 'live', 'bearer-sealed', 1, NULL, 200, 201, NULL, 199, NULL, 'u1', 'agent', 'task', NULL, 'open', '', '', '[\"openai/gpt-test\"]', '[\"shell\"]', 'gen-1')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_api_keys (id, user_id, prefix, ciphertext, label, created_at, revoked_at) \
             VALUES ('api-key-1', 'u1', 'deadbeef', 'cipher-api-key', 'ci', 210, NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_policies (user_id, allowed_providers, allowed_models, daily_token_budget, monthly_usd_budget, rps_limit) \
             VALUES ('u1', 'openrouter', 'model-a,model-b', 1000, 42.0, 5)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO system_secrets (name, ciphertext, created_at, updated_at) \
             VALUES ('system.secret', 'cipher-system', 220, 221)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_secrets (user_id, name, ciphertext, created_at, updated_at) \
             VALUES ('u1', 'user.secret', 'cipher-user', 230, 231)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_tokens (token, instance_id, provider, created_at, revoked_at, token_lookup, expected_src_ip) \
             VALUES ('proxy-token', 'i1', 'openrouter', 240, NULL, 'lookup', '10.0.0.2')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO snapshots \
             (id, source_instance_id, parent_snapshot_id, kind, path, host_ip, remote_uri, size_bytes, created_at, deleted_at, owner_id, content_hash) \
             VALUES ('s1', 'i1', NULL, 'manual', '/tmp/snap.tar', '127.0.0.1', 's3://bucket/s1', 1234, 250, NULL, 'u1', 'hash')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO llm_audit \
             (id, instance_id, provider, model, prompt_tokens, output_tokens, status_code, duration_ms, occurred_at, owner_id, key_source, completed) \
             VALUES (7, 'i1', 'openrouter', 'model-a', 11, 12, 200, 99, 260, 'u1', 'user', 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artefact_cache \
             (id, instance_id, owner_id, chat_id, artefact_id, kind, title, mime, bytes, metadata_json, created_at, cached_at, body_ciphertext) \
             VALUES (8, 'i1', 'u1', 'chat-1', 'art-1', 'text', 'Artefact', 'text/plain', 4, '{\"k\":\"v\"}', 270, 271, x'01020304')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artefact_shares \
             (jti, instance_id, chat_id, artefact_id, created_by, created_at, expires_at, revoked_at, label) \
             VALUES ('share-1', 'i1', 'chat-1', 'art-1', 'u1', 280, 380, NULL, 'share label')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artefact_share_accesses \
             (id, jti, accessed_at, remote_addr, user_agent, status) \
             VALUES (9, 'share-1', 281, '127.0.0.1', 'test-agent', 200)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO instance_webhooks \
             (instance_id, name, description, auth_scheme, secret_name, enabled, created_at, updated_at, signature_header, \
              verifier_mode, signature_algo, signature_encoding, signature_prefix, signature_separator, signature_value_split, \
              timestamp_header, timestamp_skew_secs, payload_template, idempotency_header, bearer_path_token) \
             VALUES ('i1', 'hook', 'desc', 'hmac-sha256', 'user.secret', 1, 290, 291, 'X-Signature', \
              'hmac_v2', 'sha256', 'hex', 'sha256=', NULL, '=', NULL, 300, '{{body}}', 'x-delivery-id', NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO webhook_deliveries \
             (id, instance_id, webhook_name, fired_at, status_code, latency_ms, request_id, signature_ok, error, body, body_size, content_type, \
              verify_error, request_headers, replayed_from_delivery_id, replayed_by_user_id) \
             VALUES ('delivery-1', 'i1', 'hook', 292, 202, 12, 'req-1', 1, NULL, x'0506', 2, 'application/json', \
              NULL, '{\"x-test\":\"1\"}', NULL, NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO webhook_deliveries_seen \
             (webhook_row_id, idempotency_key, first_seen_at) \
             VALUES ('i1/hook', 'req-1', 292)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO instance_state_files \
             (id, instance_id, owner_id, namespace, path, mime, bytes, updated_at, synced_at, deleted_at, body_ciphertext) \
             VALUES (10, 'i1', 'u1', 'workspace', '/file.txt', 'text/plain', 5, 300, 301, NULL, x'0708')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mcp_docker_catalog \
             (id, label, description, template, placeholders_json, source, created_at, updated_at, deleted_at, status, requested_by_user_id) \
             VALUES ('mcp-1', 'MCP', 'desc', '{\"command\":\"run\"}', '[]', 'admin', 310, 311, NULL, 'active', NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO skill_marketplace_sources \
             (id, source_type, location, enabled, created_at, updated_at, deleted_at, last_fetch_at, last_success_at, last_error) \
             VALUES ('skills-1', 'inline', '{\"skills\":[]}', 1, 320, 321, NULL, 322, 323, NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_skill_publications \
             (instance_id, owner_id, skill, published_by, published_at, revoked_at) \
             VALUES ('i1', 'u1', 'debug-logs', 'u1', 324, NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mcp_audit \
             (id, owner_id, instance_id, server_name, tool, status, duration_ms, ts, completed) \
             VALUES (11, 'u1', 'i1', 'mcp-1', 'tool', 200, 14, 330, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO llm_tool_call \
             (id, llm_audit_id, owner_id, instance_id, tool_use_id, tool_name, mcp_server, input_sealed, result_sealed, is_error, called_at, resulted_at, mcp_audit_id) \
             VALUES (13, 7, 'u1', 'i1', 'tool-use-1', 'mcp__mcp-1__tool', 'mcp-1', x'0A0B', x'0C0D', 0, 331, 332, 11)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO admin_audit \
             (id, actor_subject, action, target_user, params_hash, ts) \
             VALUES (14, 'admin', 'activate', 'u1', 'hash', 340)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sessions (id, user_id, created_at, last_seen_at, revoked_at) \
             VALUES ('sess-1', 'u1', 350, 351, NULL)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn sqlite_fixture(path: &Path) -> SqlitePool {
        let pool = open_sqlite(path.to_str().unwrap()).await.unwrap();
        seed_representative_fixture(&pool).await;
        pool.close().await;
        open_sqlite(path.to_str().unwrap()).await.unwrap()
    }

    async fn assert_sqlite_counts(path: &Path, expected: &[TransferTableCount]) {
        let pool = open_sqlite(path.to_str().unwrap()).await.unwrap();
        verify_sqlite_counts(&pool, expected).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_transfer_refuses_without_empty_target() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.db");
        let target = tmp.path().join("target.db");
        let source_pool = sqlite_fixture(&source).await;
        source_pool.close().await;
        let target_pool = open_sqlite(target.to_str().unwrap()).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at, openrouter_key_limit_usd) \
             VALUES ('target-user', 'target-subject', 'active', 1, 10.0)",
        )
        .execute(&target_pool)
        .await
        .unwrap();
        target_pool.close().await;

        let err = run(
            DatabaseBackend::Sqlite,
            DatabaseBackend::Sqlite,
            source.to_str().unwrap(),
            target.to_str().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("target not empty: tables [users=1]"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn sqlite_transfer_copies_representative_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.db");
        let target = tmp.path().join("target.db");
        let source_pool = sqlite_fixture(&source).await;
        source_pool.close().await;

        let report = run(
            DatabaseBackend::Sqlite,
            DatabaseBackend::Sqlite,
            source.to_str().unwrap(),
            target.to_str().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(report.counts.len(), TABLES.len());
        assert_eq!(
            report
                .counts
                .iter()
                .find(|item| item.table == "users")
                .unwrap()
                .rows,
            2
        );
        assert_sqlite_counts(&target, &report.counts).await;
    }

    #[cfg(feature = "postgres")]
    fn with_schema_option(base: &str, schema: &str) -> String {
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}options=-c%20search_path%3D{schema}")
    }

    #[cfg(feature = "postgres")]
    async fn create_pg_schema() -> Option<(PgPool, String, String)> {
        let url = match std::env::var("PG_TEST_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => return None,
        };
        let schema = format!("dyson_transfer_{}", uuid::Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let quoted = format!("\"{schema}\"");
        sqlx::query(&format!("CREATE SCHEMA {quoted}"))
            .execute(&admin)
            .await
            .unwrap();
        let schema_url = with_schema_option(&url, &schema);
        Some((admin, schema, schema_url))
    }

    #[cfg(feature = "postgres")]
    async fn drop_pg_schema(admin: &PgPool, schema: &str) {
        let quoted = format!("\"{schema}\"");
        sqlx::query(&format!("DROP SCHEMA IF EXISTS {quoted} CASCADE"))
            .execute(admin)
            .await
            .unwrap();
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn sqlite_postgres_roundtrip_copies_representative_fixture_when_configured() {
        let Some((admin, schema, pg_url)) = create_pg_schema().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source.db");
        let roundtrip = tmp.path().join("roundtrip.db");
        let source_pool = sqlite_fixture(&source).await;
        source_pool.close().await;

        let to_pg = run(
            DatabaseBackend::Sqlite,
            DatabaseBackend::Postgres,
            source.to_str().unwrap(),
            &pg_url,
        )
        .await
        .unwrap();
        verify_pg_counts(&open_pg(&pg_url).await.unwrap(), &to_pg.counts)
            .await
            .unwrap();

        let back = run(
            DatabaseBackend::Postgres,
            DatabaseBackend::Sqlite,
            &pg_url,
            roundtrip.to_str().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(to_pg.counts, back.counts);
        assert_sqlite_counts(&roundtrip, &back.counts).await;

        drop_pg_schema(&admin, &schema).await;
    }
}
