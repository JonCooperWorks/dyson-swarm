//! Operator maintenance for the local age KMS v2 envelope.

use std::collections::BTreeMap;
use std::path::Path;

use sqlx::{Row, SqlitePool};

use crate::db::sqlite::map_sqlx;
use crate::envelope::{
    CipherDirectory, KmsContext, KmsEnvelope, KmsScope, SecretAccessOperation, SecretAccessReason,
    SecretAccessResult, is_v2_envelope, open_context, rewrap_context,
};
use crate::error::StoreError;
use crate::now_secs;
use crate::secrets::system_secret_context;

const AGE_ARMOR_PREFIX: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmsTableCounts {
    pub table: String,
    pub scope: String,
    pub scanned: usize,
    pub already_v2: usize,
    pub legacy: usize,
    pub migrated: usize,
    pub skipped_empty: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmsMigrationReport {
    pub dry_run: bool,
    pub counts: Vec<KmsTableCounts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsDoctorCheck {
    pub name: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KmsDoctorReport {
    pub checks: Vec<KmsDoctorCheck>,
    pub scan: KmsMigrationReport,
}

impl KmsDoctorReport {
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }
}

#[derive(Default)]
struct Counts {
    scanned: usize,
    already_v2: usize,
    legacy: usize,
    migrated: usize,
    skipped_empty: usize,
}

#[derive(Default)]
struct CountsByScope(BTreeMap<(String, String), Counts>);

impl CountsByScope {
    fn bump(&mut self, table: &str, scope: KmsScope, f: impl FnOnce(&mut Counts)) {
        let counts = self
            .0
            .entry((table.to_owned(), scope.as_str().to_owned()))
            .or_default();
        f(counts);
    }

    fn finish(self) -> Vec<KmsTableCounts> {
        self.0
            .into_iter()
            .map(|((table, scope), counts)| KmsTableCounts {
                table,
                scope,
                scanned: counts.scanned,
                already_v2: counts.already_v2,
                legacy: counts.legacy,
                migrated: counts.migrated,
                skipped_empty: counts.skipped_empty,
            })
            .collect()
    }
}

struct ValueMigration {
    new_value: Option<Vec<u8>>,
    already_v2: bool,
    legacy: bool,
    needs_rewrap: bool,
    key_id: String,
    key_version: u32,
}

fn migrate_value(
    ciphers: &dyn CipherDirectory,
    context: &KmsContext,
    stored: &[u8],
    dry_run: bool,
    allow_plaintext_legacy: bool,
) -> Result<ValueMigration, StoreError> {
    if stored.is_empty() {
        return Ok(ValueMigration {
            new_value: None,
            already_v2: false,
            legacy: false,
            needs_rewrap: false,
            key_id: String::new(),
            key_version: 0,
        });
    }
    let opened = match open_context(ciphers, context, stored, SecretAccessReason::Migration) {
        Ok(opened) => opened,
        Err(_err)
            if allow_plaintext_legacy
                && !is_v2_envelope(stored)
                && !stored.starts_with(AGE_ARMOR_PREFIX) =>
        {
            crate::envelope::OpenEnvelopeResult {
                plaintext: stored.to_vec(),
                key_id: "legacy/plaintext".to_owned(),
                key_version: 0,
                legacy: true,
                needs_rewrap: true,
            }
        }
        Err(err) => {
            return Err(StoreError::Malformed(format!(
                "KMS open failed for scope {} name {:?}: {err}",
                context.scope, context.name
            )));
        }
    };
    let already_v2 = !opened.needs_rewrap && !opened.legacy;
    let new_value = if opened.needs_rewrap && !dry_run {
        Some(
            rewrap_context(
                ciphers,
                context,
                &opened.plaintext,
                SecretAccessReason::Migration,
            )
            .map_err(|e| StoreError::Io(format!("KMS rewrap failed: {e}")))?,
        )
    } else {
        None
    };
    Ok(ValueMigration {
        new_value,
        already_v2,
        legacy: opened.legacy,
        needs_rewrap: opened.needs_rewrap,
        key_id: opened.key_id,
        key_version: opened.key_version,
    })
}

async fn audit_event(
    pool: &SqlitePool,
    context: &KmsContext,
    operation: SecretAccessOperation,
    result: SecretAccessResult,
    key_id: Option<&str>,
    key_version: Option<u32>,
    error: Option<&str>,
) -> Result<(), StoreError> {
    let (error_class, error_message) = error
        .map(|msg| (Some("kms".to_owned()), Some(redact_error(msg))))
        .unwrap_or((None, None));
    sqlx::query(
        "INSERT INTO secret_access_audit \
         (timestamp, actor_kind, actor_id, reason, operation, scope, owner_id, instance_id, secret_name, \
          key_id, key_version, result, error_class, error_message) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now_secs())
    .bind("operator_cli")
    .bind(Option::<String>::None)
    .bind(SecretAccessReason::Migration.as_str())
    .bind(operation.as_str())
    .bind(context.scope.as_str())
    .bind(&context.owner_id)
    .bind(&context.instance_id)
    .bind(&context.name)
    .bind(key_id)
    .bind(key_version.map(i64::from))
    .bind(result.as_str())
    .bind(error_class)
    .bind(error_message)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

fn redact_error(message: &str) -> String {
    message.chars().take(240).collect()
}

fn text(bytes: Vec<u8>) -> Result<String, StoreError> {
    String::from_utf8(bytes).map_err(|_| StoreError::Malformed("KMS envelope was not utf-8".into()))
}

pub async fn migrate_sqlite(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
) -> Result<KmsMigrationReport, StoreError> {
    let mut counts = CountsByScope::default();
    migrate_system_secrets(pool, ciphers, dry_run, &mut counts).await?;
    migrate_user_secrets(pool, ciphers, dry_run, &mut counts).await?;
    migrate_user_api_keys(pool, ciphers, dry_run, &mut counts).await?;
    migrate_user_emails(pool, ciphers, dry_run, &mut counts).await?;
    migrate_instances(pool, ciphers, dry_run, &mut counts).await?;
    migrate_proxy_tokens(pool, ciphers, dry_run, &mut counts).await?;
    migrate_state_files(pool, ciphers, dry_run, &mut counts).await?;
    migrate_artefacts(pool, ciphers, dry_run, &mut counts).await?;
    migrate_webhook_deliveries(pool, ciphers, dry_run, &mut counts).await?;
    migrate_llm_tool_calls(pool, ciphers, dry_run, &mut counts).await?;
    Ok(KmsMigrationReport {
        dry_run,
        counts: counts.finish(),
    })
}

async fn migrate_system_secrets(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT name, ciphertext FROM system_secrets")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let name: String = row.get("name");
        let ciphertext: String = row.get("ciphertext");
        let context = system_secret_context(&name);
        let result = migrate_value(ciphers, &context, ciphertext.as_bytes(), dry_run, false)?;
        record_counts(counts, "system_secrets", &context, &result);
        if let Some(new_value) = result.new_value {
            let new_value = text(new_value)?;
            sqlx::query("UPDATE system_secrets SET ciphertext = ?, updated_at = ? WHERE name = ?")
                .bind(new_value)
                .bind(now_secs())
                .bind(&name)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_user_secrets(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT user_id, name, ciphertext FROM user_secrets")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let user_id: String = row.get("user_id");
        let name: String = row.get("name");
        let ciphertext: String = row.get("ciphertext");
        let context = KmsContext::user_secret(user_id.clone(), name.clone());
        let result = migrate_value(ciphers, &context, ciphertext.as_bytes(), dry_run, false)?;
        record_counts(counts, "user_secrets", &context, &result);
        if let Some(new_value) = result.new_value {
            let new_value = text(new_value)?;
            sqlx::query(
                "UPDATE user_secrets SET ciphertext = ?, updated_at = ? \
                 WHERE user_id = ? AND name = ?",
            )
            .bind(new_value)
            .bind(now_secs())
            .bind(&user_id)
            .bind(&name)
            .execute(pool)
            .await
            .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_user_api_keys(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT id, user_id, ciphertext FROM user_api_keys")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let id: String = row.get("id");
        let user_id: String = row.get("user_id");
        let ciphertext: String = row.get("ciphertext");
        let context = KmsContext::user_scoped(
            KmsScope::UserApiKey,
            user_id.clone(),
            None,
            Some(id.clone()),
        );
        let result = migrate_value(ciphers, &context, ciphertext.as_bytes(), dry_run, false)?;
        record_counts(counts, "user_api_keys", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE user_api_keys SET ciphertext = ? WHERE id = ?")
                .bind(text(new_value)?)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_user_emails(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT id, email_ciphertext FROM users WHERE email_ciphertext IS NOT NULL AND email_ciphertext != ''")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let id: String = row.get("id");
        let ciphertext: String = row.get("email_ciphertext");
        let context = KmsContext::user_scoped(
            KmsScope::UserProfile,
            id.clone(),
            None,
            Some("email".to_owned()),
        );
        let result = migrate_value(ciphers, &context, ciphertext.as_bytes(), dry_run, false)?;
        record_counts(counts, "users.email_ciphertext", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE users SET email_ciphertext = ? WHERE id = ?")
                .bind(text(new_value)?)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_instances(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT id, owner_id, bearer_token FROM instances")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let id: String = row.get("id");
        let owner_id: String = row.get("owner_id");
        let bearer: String = row.get("bearer_token");
        let context = KmsContext {
            scope: KmsScope::RuntimeToken,
            owner_id: Some(owner_id),
            instance_id: Some(id.clone()),
            name: Some("instance_bearer".to_owned()),
        };
        let result = migrate_value(ciphers, &context, bearer.as_bytes(), dry_run, false)?;
        record_counts(counts, "instances.bearer_token", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE instances SET bearer_token = ? WHERE id = ?")
                .bind(text(new_value)?)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_proxy_tokens(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT token, instance_id, provider FROM proxy_tokens")
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
    for row in rows {
        let token: String = row.get("token");
        let instance_id: String = row.get("instance_id");
        let provider: String = row.get("provider");
        let context = KmsContext {
            scope: KmsScope::RuntimeToken,
            owner_id: None,
            instance_id: Some(instance_id),
            name: Some(format!("proxy_token:{provider}")),
        };
        let result = migrate_value(ciphers, &context, token.as_bytes(), dry_run, false)?;
        record_counts(counts, "proxy_tokens.token", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE proxy_tokens SET token = ? WHERE token = ?")
                .bind(text(new_value)?)
                .bind(&token)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_state_files(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, namespace, path, body_ciphertext \
         FROM instance_state_files WHERE body_ciphertext IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    for row in rows {
        let id: i64 = row.get("id");
        let instance_id: String = row.get("instance_id");
        let owner_id: String = row.get("owner_id");
        let namespace: String = row.get("namespace");
        let path: String = row.get("path");
        let body: Vec<u8> = row.get("body_ciphertext");
        let context = KmsContext::user_scoped(
            KmsScope::StateFile,
            owner_id,
            Some(instance_id),
            Some(format!("{namespace}:{path}")),
        );
        if body.is_empty() {
            counts.bump("instance_state_files.body_ciphertext", context.scope, |c| {
                c.scanned += 1;
                c.skipped_empty += 1;
            });
            continue;
        }
        let result = migrate_value(ciphers, &context, &body, dry_run, false)?;
        record_counts(
            counts,
            "instance_state_files.body_ciphertext",
            &context,
            &result,
        );
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE instance_state_files SET body_ciphertext = ? WHERE id = ?")
                .bind(new_value)
                .bind(id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_artefacts(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, body_ciphertext \
         FROM artefact_cache WHERE body_ciphertext IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    for row in rows {
        let id: i64 = row.get("id");
        let instance_id: String = row.get("instance_id");
        let owner_id: String = row.get("owner_id");
        let chat_id: String = row.get("chat_id");
        let artefact_id: String = row.get("artefact_id");
        let body: Vec<u8> = row.get("body_ciphertext");
        let context = KmsContext::user_scoped(
            KmsScope::Artefact,
            owner_id,
            Some(instance_id),
            Some(format!("{chat_id}:{artefact_id}")),
        );
        if body.is_empty() {
            counts.bump("artefact_cache.body_ciphertext", context.scope, |c| {
                c.scanned += 1;
                c.skipped_empty += 1;
            });
            continue;
        }
        let result = migrate_value(ciphers, &context, &body, dry_run, false)?;
        record_counts(counts, "artefact_cache.body_ciphertext", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE artefact_cache SET body_ciphertext = ? WHERE id = ?")
                .bind(new_value)
                .bind(id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_webhook_deliveries(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT d.id, d.instance_id, i.owner_id, d.webhook_name, d.body \
         FROM webhook_deliveries d \
         JOIN instances i ON i.id = d.instance_id \
         WHERE d.body IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    for row in rows {
        let id: String = row.get("id");
        let instance_id: String = row.get("instance_id");
        let owner_id: String = row.get("owner_id");
        let webhook_name: String = row.get("webhook_name");
        let body: Vec<u8> = row.get("body");
        let context = KmsContext::user_scoped(
            KmsScope::WebhookDelivery,
            owner_id,
            Some(instance_id),
            Some(webhook_name),
        );
        if body.is_empty() {
            counts.bump("webhook_deliveries.body", context.scope, |c| {
                c.scanned += 1;
                c.skipped_empty += 1;
            });
            continue;
        }
        let result = migrate_value(ciphers, &context, &body, dry_run, true)?;
        record_counts(counts, "webhook_deliveries.body", &context, &result);
        if let Some(new_value) = result.new_value {
            sqlx::query("UPDATE webhook_deliveries SET body = ? WHERE id = ?")
                .bind(new_value)
                .bind(&id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
            audit_event(
                pool,
                &context,
                SecretAccessOperation::Rewrap,
                SecretAccessResult::Success,
                Some(&result.key_id),
                Some(result.key_version),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn migrate_llm_tool_calls(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    dry_run: bool,
    counts: &mut CountsByScope,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT id, owner_id, instance_id, tool_use_id, input_sealed, result_sealed \
         FROM llm_tool_call \
         WHERE input_sealed IS NOT NULL OR result_sealed IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    for row in rows {
        let id: i64 = row.get("id");
        let owner_id: String = row.get("owner_id");
        let instance_id: String = row.get("instance_id");
        let tool_use_id: String = row.get("tool_use_id");
        let input: Option<Vec<u8>> = row.get("input_sealed");
        let result: Option<Vec<u8>> = row.get("result_sealed");
        if let Some(input) = input {
            let context = KmsContext::user_scoped(
                KmsScope::LlmToolCall,
                owner_id.clone(),
                Some(instance_id.clone()),
                Some(format!("input:{tool_use_id}")),
            );
            let migration = migrate_value(ciphers, &context, &input, dry_run, false)?;
            record_counts(counts, "llm_tool_call.input_sealed", &context, &migration);
            if let Some(new_value) = migration.new_value {
                sqlx::query("UPDATE llm_tool_call SET input_sealed = ? WHERE id = ?")
                    .bind(new_value)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(map_sqlx)?;
                audit_event(
                    pool,
                    &context,
                    SecretAccessOperation::Rewrap,
                    SecretAccessResult::Success,
                    Some(&migration.key_id),
                    Some(migration.key_version),
                    None,
                )
                .await?;
            }
        }
        if let Some(result) = result {
            let context = KmsContext::user_scoped(
                KmsScope::LlmToolCall,
                owner_id.clone(),
                Some(instance_id.clone()),
                Some(format!("result:{tool_use_id}")),
            );
            let migration = migrate_value(ciphers, &context, &result, dry_run, false)?;
            record_counts(counts, "llm_tool_call.result_sealed", &context, &migration);
            if let Some(new_value) = migration.new_value {
                sqlx::query("UPDATE llm_tool_call SET result_sealed = ? WHERE id = ?")
                    .bind(new_value)
                    .bind(id)
                    .execute(pool)
                    .await
                    .map_err(map_sqlx)?;
                audit_event(
                    pool,
                    &context,
                    SecretAccessOperation::Rewrap,
                    SecretAccessResult::Success,
                    Some(&migration.key_id),
                    Some(migration.key_version),
                    None,
                )
                .await?;
            }
        }
    }
    Ok(())
}

fn record_counts(
    counts: &mut CountsByScope,
    table: &str,
    context: &KmsContext,
    result: &ValueMigration,
) {
    counts.bump(table, context.scope, |c| {
        c.scanned += 1;
        if result.already_v2 {
            c.already_v2 += 1;
        }
        if result.legacy {
            c.legacy += 1;
        }
        if result.needs_rewrap {
            c.migrated += 1;
        }
    });
}

pub async fn doctor_sqlite(
    pool: &SqlitePool,
    ciphers: &dyn CipherDirectory,
    keys_dir: &Path,
) -> KmsDoctorReport {
    let mut checks = Vec::new();
    checks.push(check_keys_dir(keys_dir));
    checks.push(check_audit_table(pool).await);
    checks.extend(check_v2_key_files(pool, keys_dir).await);
    let scan = match migrate_sqlite(pool, ciphers, true).await {
        Ok(report) => {
            let legacy: usize = report.counts.iter().map(|c| c.legacy).sum();
            checks.push(KmsDoctorCheck {
                name: "decryptability_scan".to_owned(),
                ok: true,
                message: format!("scan completed; {legacy} legacy row(s) would be rewrapped"),
            });
            report
        }
        Err(err) => {
            checks.push(KmsDoctorCheck {
                name: "decryptability_scan".to_owned(),
                ok: false,
                message: err.to_string(),
            });
            KmsMigrationReport {
                dry_run: true,
                counts: Vec::new(),
            }
        }
    };
    KmsDoctorReport { checks, scan }
}

fn check_keys_dir(keys_dir: &Path) -> KmsDoctorCheck {
    let mut ok = keys_dir.is_dir();
    let mut message = if ok {
        "present".to_owned()
    } else {
        "missing".to_owned()
    };
    #[cfg(unix)]
    if ok {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(keys_dir) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                ok = mode.trailing_zeros() >= 6;
                message = format!("mode {mode:03o}");
            }
            Err(err) => {
                ok = false;
                message = err.to_string();
            }
        }
    }
    KmsDoctorCheck {
        name: "keys_dir".to_owned(),
        ok,
        message,
    }
}

async fn check_audit_table(pool: &SqlitePool) -> KmsDoctorCheck {
    let exists = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'secret_access_audit'",
    )
    .fetch_optional(pool)
    .await;
    match exists {
        Ok(Some(_)) => KmsDoctorCheck {
            name: "audit_table".to_owned(),
            ok: true,
            message: "present".to_owned(),
        },
        Ok(None) => KmsDoctorCheck {
            name: "audit_table".to_owned(),
            ok: false,
            message: "missing".to_owned(),
        },
        Err(err) => KmsDoctorCheck {
            name: "audit_table".to_owned(),
            ok: false,
            message: err.to_string(),
        },
    }
}

async fn check_v2_key_files(pool: &SqlitePool, keys_dir: &Path) -> Vec<KmsDoctorCheck> {
    let mut checks = Vec::new();
    for (label, values) in collect_v2_values(pool).await {
        match values {
            Ok(values) => {
                for value in values {
                    if let Ok(env) = serde_json::from_slice::<KmsEnvelope>(&value)
                        && env.version == 2
                    {
                        let path = keys_dir
                            .join(&env.key_id)
                            .join(format!("v{}.age", env.key_version));
                        if !path.is_file() {
                            checks.push(KmsDoctorCheck {
                                name: format!("missing_key:{label}"),
                                ok: false,
                                message: format!("{} v{} missing", env.key_id, env.key_version),
                            });
                        }
                    }
                }
            }
            Err(err) => checks.push(KmsDoctorCheck {
                name: format!("scan_v2:{label}"),
                ok: false,
                message: err.to_string(),
            }),
        }
    }
    if checks.is_empty() {
        checks.push(KmsDoctorCheck {
            name: "referenced_key_versions".to_owned(),
            ok: true,
            message: "all referenced v2 key files found".to_owned(),
        });
    }
    checks
}

async fn collect_v2_values(
    pool: &SqlitePool,
) -> Vec<(&'static str, Result<Vec<Vec<u8>>, StoreError>)> {
    let mut out = Vec::new();
    out.push((
        "system_secrets",
        collect_text(pool, "SELECT ciphertext FROM system_secrets").await,
    ));
    out.push((
        "user_secrets",
        collect_text(pool, "SELECT ciphertext FROM user_secrets").await,
    ));
    out.push((
        "user_api_keys",
        collect_text(pool, "SELECT ciphertext FROM user_api_keys").await,
    ));
    out.push((
        "users.email_ciphertext",
        collect_text(
            pool,
            "SELECT email_ciphertext AS ciphertext FROM users WHERE email_ciphertext IS NOT NULL",
        )
        .await,
    ));
    out.push((
        "proxy_tokens",
        collect_text(pool, "SELECT token AS ciphertext FROM proxy_tokens").await,
    ));
    out.push((
        "instances",
        collect_text(pool, "SELECT bearer_token AS ciphertext FROM instances").await,
    ));
    out.push((
        "state_files",
        collect_blob(
            pool,
            "SELECT body_ciphertext AS ciphertext FROM instance_state_files WHERE body_ciphertext IS NOT NULL",
        )
        .await,
    ));
    out.push((
        "artefacts",
        collect_blob(
            pool,
            "SELECT body_ciphertext AS ciphertext FROM artefact_cache WHERE body_ciphertext IS NOT NULL",
        )
        .await,
    ));
    out.push((
        "webhook_deliveries",
        collect_blob(
            pool,
            "SELECT body AS ciphertext FROM webhook_deliveries WHERE body IS NOT NULL",
        )
        .await,
    ));
    out.push((
        "llm_tool_call.input_sealed",
        collect_blob(
            pool,
            "SELECT input_sealed AS ciphertext FROM llm_tool_call WHERE input_sealed IS NOT NULL",
        )
        .await,
    ));
    out.push((
        "llm_tool_call.result_sealed",
        collect_blob(
            pool,
            "SELECT result_sealed AS ciphertext FROM llm_tool_call WHERE result_sealed IS NOT NULL",
        )
        .await,
    ));
    out
}

async fn collect_text(pool: &SqlitePool, sql: &str) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows = sqlx::query(sql).fetch_all(pool).await.map_err(map_sqlx)?;
    rows.into_iter()
        .map(|row| {
            let value: String = row.try_get("ciphertext").map_err(map_sqlx)?;
            Ok(value.into_bytes())
        })
        .collect()
}

async fn collect_blob(pool: &SqlitePool, sql: &str) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows = sqlx::query(sql).fetch_all(pool).await.map_err(map_sqlx)?;
    rows.into_iter()
        .map(|row| row.try_get("ciphertext").map_err(map_sqlx))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite::open_in_memory;
    use crate::envelope::{AgeCipherDirectory, CipherDirectory};
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};
    use std::sync::Arc;

    fn user_id(seed: u8) -> String {
        format!("{:032x}", u128::from(seed) | (u128::from(seed) << 64))
    }

    #[tokio::test]
    async fn migrate_sqlite_rewraps_legacy_rows_and_is_idempotent() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn CipherDirectory> = Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let user = user_id(0x61);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&user)
        .bind("kms-test")
        .bind(now_secs())
        .execute(&pool)
        .await
        .unwrap();

        let legacy_user = dir
            .for_user(&user)
            .unwrap()
            .seal(b"user-plaintext")
            .unwrap();
        let legacy_system = dir.system().unwrap().seal(b"system-plaintext").unwrap();
        sqlx::query(
            "INSERT INTO user_secrets (user_id, name, ciphertext, created_at, updated_at) \
             VALUES (?, 'mcp.inst.github', ?, 1, 1)",
        )
        .bind(&user)
        .bind(std::str::from_utf8(&legacy_user).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO system_secrets (name, ciphertext, created_at, updated_at) \
             VALUES ('provider.openai.api_key', ?, 1, 1)",
        )
        .bind(std::str::from_utf8(&legacy_system).unwrap())
        .execute(&pool)
        .await
        .unwrap();

        let dry = migrate_sqlite(&pool, dir.as_ref(), true).await.unwrap();
        assert_eq!(dry.counts.iter().map(|c| c.migrated).sum::<usize>(), 2);

        let report = migrate_sqlite(&pool, dir.as_ref(), false).await.unwrap();
        assert_eq!(report.counts.iter().map(|c| c.migrated).sum::<usize>(), 2);
        let stored_user: String = sqlx::query_scalar("SELECT ciphertext FROM user_secrets")
            .fetch_one(&pool)
            .await
            .unwrap();
        let stored_system: String = sqlx::query_scalar("SELECT ciphertext FROM system_secrets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::envelope::is_v2_envelope(stored_user.as_bytes()));
        assert!(crate::envelope::is_v2_envelope(stored_system.as_bytes()));
        let user_env: KmsEnvelope = serde_json::from_str(&stored_user).unwrap();
        let system_env: KmsEnvelope = serde_json::from_str(&stored_system).unwrap();
        assert!(user_env.rewrapped_at.is_some());
        assert!(system_env.rewrapped_at.is_some());
        assert!(!stored_user.contains("user-plaintext"));
        assert!(!stored_system.contains("system-plaintext"));

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secret_access_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audit_count, 2);
        let leaked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secret_access_audit \
             WHERE COALESCE(error_message, '') LIKE '%plaintext%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(leaked, 0);

        let rerun = migrate_sqlite(&pool, dir.as_ref(), false).await.unwrap();
        assert_eq!(rerun.counts.iter().map(|c| c.migrated).sum::<usize>(), 0);
    }

    #[tokio::test]
    async fn migrate_llm_tool_call_writes_audit_rows() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn CipherDirectory> = Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let user = user_id(0x63);
        let instance_id = "inst-llm";
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&user)
        .bind("kms-llm-test")
        .bind(now_secs())
        .execute(&pool)
        .await
        .unwrap();
        crate::db::sqlite::instances::SqlxInstanceStore::new_with_ciphers(
            pool.clone(),
            dir.system().unwrap(),
            dir.clone(),
        )
        .create(InstanceRow {
            id: instance_id.into(),
            owner_id: user.clone(),
            name: "llm".into(),
            task: String::new(),
            cube_sandbox_id: None,
            state_generation: String::new(),
            template_id: "t".into(),
            status: InstanceStatus::Live,
            bearer_token: "bearer".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: now_secs(),
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        })
        .await
        .unwrap();
        let legacy_input = dir.for_user(&user).unwrap().seal(br#"{"x":1}"#).unwrap();
        let legacy_result = dir
            .for_user(&user)
            .unwrap()
            .seal(br#"{"ok":true}"#)
            .unwrap();
        sqlx::query(
            "INSERT INTO llm_tool_call \
             (owner_id, instance_id, tool_use_id, tool_name, input_sealed, result_sealed, is_error, called_at, resulted_at) \
             VALUES (?, ?, 'use-1', 'bash', ?, ?, 0, 1, 2)",
        )
        .bind(&user)
        .bind(instance_id)
        .bind(legacy_input)
        .bind(legacy_result)
        .execute(&pool)
        .await
        .unwrap();

        let report = migrate_sqlite(&pool, dir.as_ref(), false).await.unwrap();
        assert_eq!(
            report
                .counts
                .iter()
                .filter(|c| c.table.starts_with("llm_tool_call."))
                .map(|c| c.migrated)
                .sum::<usize>(),
            2
        );
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secret_access_audit \
             WHERE scope = 'llm_tool_call' AND operation = 'rewrap' AND result = 'success'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 2);
    }

    #[tokio::test]
    async fn doctor_reports_missing_referenced_key_file() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn CipherDirectory> = Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let user = user_id(0x62);
        sqlx::query(
            "INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)",
        )
        .bind(&user)
        .bind("kms-doctor-test")
        .bind(now_secs())
        .execute(&pool)
        .await
        .unwrap();

        let context = KmsContext::user_secret(user.clone(), "mcp.inst.github");
        let sealed = crate::envelope::seal_context(
            dir.as_ref(),
            &context,
            b"doctor-secret",
            SecretAccessReason::Test,
        )
        .unwrap();
        sqlx::query(
            "INSERT INTO user_secrets (user_id, name, ciphertext, created_at, updated_at) \
             VALUES (?, 'mcp.inst.github', ?, 1, 1)",
        )
        .bind(&user)
        .bind(std::str::from_utf8(&sealed).unwrap())
        .execute(&pool)
        .await
        .unwrap();

        std::fs::remove_file(
            tmp.path()
                .join("users")
                .join(&user)
                .join("mcp")
                .join("v1.age"),
        )
        .unwrap();
        let report = doctor_sqlite(&pool, dir.as_ref(), tmp.path()).await;
        assert!(report.checks.iter().any(|check| {
            !check.ok
                && check.name == "missing_key:user_secrets"
                && check
                    .message
                    .contains(&format!("users/{user}/mcp v1 missing"))
        }));
    }
}
