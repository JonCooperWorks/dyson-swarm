use async_trait::async_trait;
use sqlx::{Executor, PgPool, Postgres, Row};
use std::sync::Arc;

use crate::db::pg::map_sqlx;
use crate::envelope::EnvelopeCipher;
use crate::error::StoreError;
use crate::network_policy::NetworkPolicy;
use crate::now_secs;
use crate::traits::{InstanceRow, InstanceStatus, InstanceStore, ListFilter, ProbeResult};

/// Decode the three on-disk policy columns into the in-memory
/// `NetworkPolicy` enum + the resolved CIDR vec.  Forward-compat:
/// unknown kinds (a future migration adds a new profile) collapse to
/// `Open` so old swarm binaries don't crash on rows newer binaries
/// wrote.
fn decode_policy(kind: &str, entries_csv: &str, cidrs_csv: &str) -> (NetworkPolicy, Vec<String>) {
    let entries: Vec<String> = csv_to_vec(entries_csv);
    let cidrs: Vec<String> = csv_to_vec(cidrs_csv);
    // Unknown kinds collapse to `NoLocalNet` (the safer default) so
    // an old swarm binary doesn't open up local-network egress on rows
    // a newer binary wrote with an unknown profile.  `"nolocalnet"`
    // intentionally falls through the wildcard for the same reason.
    let policy = match kind {
        "airgap" => NetworkPolicy::Airgap,
        "allowlist" => NetworkPolicy::Allowlist { entries },
        "denylist" => NetworkPolicy::Denylist { entries },
        "open" => NetworkPolicy::Open,
        _ => NetworkPolicy::NoLocalNet,
    };
    (policy, cidrs)
}

fn csv_to_vec(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

fn vec_to_csv(v: &[String]) -> String {
    v.join(",")
}

#[derive(Debug, Clone)]
pub struct PgInstanceStore {
    pool: PgPool,
    cipher: Arc<dyn EnvelopeCipher>,
}

impl PgInstanceStore {
    pub fn new(pool: PgPool, cipher: Arc<dyn EnvelopeCipher>) -> Self {
        Self { pool, cipher }
    }
}

fn seal_bearer(cipher: &dyn EnvelopeCipher, bearer: &str) -> Result<String, StoreError> {
    let sealed = cipher
        .seal(bearer.as_bytes())
        .map_err(|e| StoreError::Io(format!("seal instance bearer: {e}")))?;
    String::from_utf8(sealed)
        .map_err(|_| StoreError::Malformed("sealed instance bearer was not utf-8".into()))
}

fn open_bearer(cipher: &dyn EnvelopeCipher, stored: &str) -> Result<String, StoreError> {
    let plain = cipher
        .open(stored.as_bytes())
        .map_err(|e| StoreError::Malformed(format!("open instance bearer: {e}")))?;
    String::from_utf8(plain)
        .map_err(|_| StoreError::Malformed("instance bearer plaintext was not utf-8".into()))
}

fn row_to_instance(
    row: &sqlx::postgres::PgRow,
    cipher: &dyn EnvelopeCipher,
) -> Result<InstanceRow, StoreError> {
    let status_text: String = row.try_get("status").map_err(map_sqlx)?;
    let status = InstanceStatus::parse(&status_text)
        .ok_or_else(|| StoreError::Malformed(format!("status={status_text}")))?;
    let pinned_int: i64 = row.try_get("pinned").map_err(map_sqlx)?;
    let probe_text: Option<String> = row.try_get("last_probe_status").map_err(map_sqlx)?;
    let last_probe_status = match probe_text {
        Some(t) => Some(
            serde_json::from_str::<ProbeResult>(&t)
                .map_err(|e| StoreError::Malformed(format!("last_probe_status: {e}")))?,
        ),
        None => None,
    };
    let kind: String = row.try_get("network_policy_kind").map_err(map_sqlx)?;
    let entries_csv: String = row.try_get("network_policy_entries").map_err(map_sqlx)?;
    let cidrs_csv: String = row.try_get("network_policy_cidrs").map_err(map_sqlx)?;
    let (network_policy, network_policy_cidrs) = decode_policy(&kind, &entries_csv, &cidrs_csv);
    let models_json: String = row.try_get("models").map_err(map_sqlx)?;
    let models: Vec<String> = serde_json::from_str(&models_json)
        .map_err(|e| StoreError::Malformed(format!("models: {e}")))?;
    let tools_json: String = row.try_get("tools").map_err(map_sqlx)?;
    let tools: Vec<String> = serde_json::from_str(&tools_json)
        .map_err(|e| StoreError::Malformed(format!("tools: {e}")))?;
    Ok(InstanceRow {
        id: row.try_get("id").map_err(map_sqlx)?,
        owner_id: row.try_get("owner_id").map_err(map_sqlx)?,
        name: row.try_get("name").map_err(map_sqlx)?,
        task: row.try_get("task").map_err(map_sqlx)?,
        cube_sandbox_id: row.try_get("cube_sandbox_id").map_err(map_sqlx)?,
        state_generation: row.try_get("state_generation").map_err(map_sqlx)?,
        template_id: row.try_get("template_id").map_err(map_sqlx)?,
        status,
        bearer_token: open_bearer(
            cipher,
            &row.try_get::<String, _>("bearer_token").map_err(map_sqlx)?,
        )?,
        pinned: pinned_int != 0,
        expires_at: row.try_get("expires_at").map_err(map_sqlx)?,
        last_active_at: row.try_get("last_active_at").map_err(map_sqlx)?,
        last_probe_at: row.try_get("last_probe_at").map_err(map_sqlx)?,
        last_probe_status,
        created_at: row.try_get("created_at").map_err(map_sqlx)?,
        destroyed_at: row.try_get("destroyed_at").map_err(map_sqlx)?,
        rotated_to: row.try_get("rotated_to").map_err(map_sqlx)?,
        network_policy,
        network_policy_cidrs,
        models,
        tools,
    })
}

struct EncodedInstanceInsert {
    probe_json: Option<String>,
    kind: String,
    entries_csv: String,
    cidrs_csv: String,
    models_json: String,
    tools_json: String,
    bearer_token: String,
}

fn encode_instance_insert(
    row: &InstanceRow,
    cipher: &dyn EnvelopeCipher,
) -> Result<EncodedInstanceInsert, StoreError> {
    let probe_json = match &row.last_probe_status {
        Some(p) => Some(serde_json::to_string(p).map_err(|e| StoreError::Io(e.to_string()))?),
        None => None,
    };
    let models_json = serde_json::to_string(&row.models)
        .map_err(|e| StoreError::Io(format!("models encode: {e}")))?;
    let tools_json = serde_json::to_string(&row.tools)
        .map_err(|e| StoreError::Io(format!("tools encode: {e}")))?;
    Ok(EncodedInstanceInsert {
        probe_json,
        kind: row.network_policy.kind_str().to_owned(),
        entries_csv: vec_to_csv(row.network_policy.entries()),
        cidrs_csv: vec_to_csv(&row.network_policy_cidrs),
        models_json,
        tools_json,
        bearer_token: seal_bearer(cipher, &row.bearer_token)?,
    })
}

async fn insert_instance_row<'e, E>(
    executor: E,
    row: &InstanceRow,
    encoded: &EncodedInstanceInsert,
) -> Result<(), StoreError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO instances \
         (id, owner_id, name, task, cube_sandbox_id, state_generation, template_id, status, bearer_token, \
          pinned, expires_at, last_active_at, last_probe_at, last_probe_status, \
          created_at, destroyed_at, rotated_to, \
          network_policy_kind, network_policy_entries, network_policy_cidrs, models, tools) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)",
    )
    .bind(&row.id)
    .bind(&row.owner_id)
    .bind(&row.name)
    .bind(&row.task)
    .bind(&row.cube_sandbox_id)
    .bind(&row.state_generation)
    .bind(&row.template_id)
    .bind(row.status.as_str())
    .bind(&encoded.bearer_token)
    .bind(row.pinned as i64)
    .bind(row.expires_at)
    .bind(row.last_active_at)
    .bind(row.last_probe_at)
    .bind(&encoded.probe_json)
    .bind(row.created_at)
    .bind(row.destroyed_at)
    .bind(&row.rotated_to)
    .bind(&encoded.kind)
    .bind(&encoded.entries_csv)
    .bind(&encoded.cidrs_csv)
    .bind(&encoded.models_json)
    .bind(&encoded.tools_json)
    .execute(executor)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait]
impl InstanceStore for PgInstanceStore {
    async fn create(&self, row: InstanceRow) -> Result<(), StoreError> {
        let encoded = encode_instance_insert(&row, self.cipher.as_ref())?;
        insert_instance_row(&self.pool, &row, &encoded).await?;
        Ok(())
    }

    async fn create_with_owner_limit(
        &self,
        row: InstanceRow,
        limit: u64,
    ) -> Result<bool, StoreError> {
        let encoded = encode_instance_insert(&row, self.cipher.as_ref())?;
        let mut conn = self.pool.acquire().await.map_err(map_sqlx)?;
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .map_err(map_sqlx)?;
        let count_row = match sqlx::query(
            "SELECT COUNT(*) AS n FROM instances WHERE owner_id = $1 AND status != 'destroyed'",
        )
        .bind(&row.owner_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sqlx)
        {
            Ok(row) => row,
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(err);
            }
        };
        let count: i64 = match count_row.try_get("n").map_err(map_sqlx) {
            Ok(count) => count,
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(err);
            }
        };
        if u64::try_from(count.max(0)).unwrap_or(0) >= limit {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(false);
        }
        if let Err(err) = insert_instance_row(&mut *conn, &row, &encoded).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(err);
        }
        sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map_err(map_sqlx)?;
        Ok(true)
    }

    async fn get(&self, id: &str) -> Result<Option<InstanceRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM instances WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_instance(&r, self.cipher.as_ref())?)),
            None => Ok(None),
        }
    }

    async fn get_for_owner(
        &self,
        owner_id: &str,
        id: &str,
    ) -> Result<Option<InstanceRow>, StoreError> {
        // owner_id == "*" is the system-internal bypass used by TTL sweep
        // and the proxy. User-facing routes never pass it.
        let row =
            sqlx::query("SELECT * FROM instances WHERE id = $1 AND ($2 = '*' OR owner_id = $2)")
                .bind(id)
                .bind(owner_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_instance(&r, self.cipher.as_ref())?)),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        owner_id: &str,
        filter: ListFilter,
    ) -> Result<Vec<InstanceRow>, StoreError> {
        let status_filter: Option<String> = filter.status.map(|s| s.as_str().to_owned());
        let all_owners = i64::from(owner_id == "*");
        let rows = sqlx::query(
            "SELECT * FROM instances \
             WHERE ($1 = 1 OR owner_id = $2) \
               AND ($3 IS NULL OR status = $3) \
               AND ($4 = 1 OR status != 'destroyed') \
             ORDER BY created_at DESC",
        )
        .bind(all_owners)
        .bind(owner_id)
        .bind(status_filter)
        .bind(filter.include_destroyed as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter()
            .map(|row| row_to_instance(row, self.cipher.as_ref()))
            .collect()
    }

    async fn set_cube_sandbox_id(&self, id: &str, sandbox_id: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE instances SET cube_sandbox_id = $1 WHERE id = $2")
            .bind(sandbox_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if r.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update_status(&self, id: &str, status: InstanceStatus) -> Result<(), StoreError> {
        let now = now_secs();
        let mut conn = self.pool.acquire().await.map_err(map_sqlx)?;
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .map_err(map_sqlx)?;
        let result = match sqlx::query(
            "UPDATE instances SET status = $1, \
                                  destroyed_at = CASE WHEN $1 = 'destroyed' THEN $2 ELSE destroyed_at END \
             WHERE id = $3",
        )
        .bind(status.as_str())
        .bind(now)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx)
        {
            Ok(result) => result,
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(err);
            }
        };
        if result.rows_affected() == 0 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(StoreError::NotFound);
        }
        sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn touch(&self, id: &str) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE instances SET last_active_at = $1 WHERE id = $2")
            .bind(now_secs())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update_identity(
        &self,
        owner_id: &str,
        id: &str,
        name: &str,
        task: &str,
    ) -> Result<(), StoreError> {
        // Owner-scoped: a 0-row update for an id that exists but isn't
        // ours surfaces as NotFound, matching the get_for_owner contract.
        // owner_id == "*" is the system bypass (TTL sweep, etc.) and is
        // not intended for tenant-facing flows but kept consistent with
        // the rest of the store.
        let result = sqlx::query(
            "UPDATE instances SET name = $1, task = $2 \
             WHERE id = $3 AND ($4 = '*' OR owner_id = $4)",
        )
        .bind(name)
        .bind(task)
        .bind(id)
        .bind(owner_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn pin(&self, id: &str, pinned: bool, ttl: Option<i64>) -> Result<(), StoreError> {
        let expires_at = if pinned {
            None
        } else {
            ttl.map(|t| now_secs() + t)
        };
        let result = sqlx::query("UPDATE instances SET pinned = $1, expires_at = $2 WHERE id = $3")
            .bind(pinned as i64)
            .bind(expires_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn record_probe(&self, id: &str, status: ProbeResult) -> Result<(), StoreError> {
        let json = serde_json::to_string(&status).map_err(|e| StoreError::Io(e.to_string()))?;
        let result = sqlx::query(
            "UPDATE instances SET last_probe_at = $1, last_probe_status = $2 \
             WHERE id = $3 AND status != 'destroyed'",
        )
        .bind(now_secs())
        .bind(json)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_rotated_to(&self, id: &str, target_id: &str) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE instances SET rotated_to = $1 \
             WHERE id = $2 AND status != 'destroyed'",
        )
        .bind(target_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_models(&self, id: &str, models: &[String]) -> Result<(), StoreError> {
        let json = serde_json::to_string(models)
            .map_err(|e| StoreError::Io(format!("models encode: {e}")))?;
        let result = sqlx::query(
            "UPDATE instances SET models = $1 \
             WHERE id = $2 AND status != 'destroyed'",
        )
        .bind(json)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_tools(&self, id: &str, tools: &[String]) -> Result<(), StoreError> {
        let json = serde_json::to_string(tools)
            .map_err(|e| StoreError::Io(format!("tools encode: {e}")))?;
        let result = sqlx::query(
            "UPDATE instances SET tools = $1 \
             WHERE id = $2 AND status != 'destroyed'",
        )
        .bind(json)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn replace_cube_sandbox(
        &self,
        id: &str,
        new_cube_sandbox_id: &str,
        new_state_generation: &str,
        new_template_id: &str,
        new_network_policy: &crate::network_policy::NetworkPolicy,
        new_network_policy_cidrs: &[String],
        now: i64,
    ) -> Result<(), StoreError> {
        let kind = new_network_policy.kind_str().to_owned();
        let entries_csv = vec_to_csv(new_network_policy.entries());
        let cidrs_csv = vec_to_csv(new_network_policy_cidrs);
        let result = sqlx::query(
            "UPDATE instances SET \
                cube_sandbox_id = $1, \
                state_generation = $2, \
                template_id = $3, \
                network_policy_kind = $4, \
                network_policy_entries = $5, \
                network_policy_cidrs = $6, \
                last_probe_at = NULL, \
                last_probe_status = NULL, \
                last_active_at = $7, \
                rotated_to = NULL, \
                status = 'configuring' \
             WHERE id = $8",
        )
        .bind(new_cube_sandbox_id)
        .bind(new_state_generation)
        .bind(new_template_id)
        .bind(kind)
        .bind(entries_csv)
        .bind(cidrs_csv)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn expired(&self, now: i64) -> Result<Vec<InstanceRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM instances \
             WHERE pinned = 0 \
               AND expires_at IS NOT NULL \
               AND expires_at < $1 \
               AND status != 'destroyed'",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter()
            .map(|row| row_to_instance(row, self.cipher.as_ref()))
            .collect()
    }
}
