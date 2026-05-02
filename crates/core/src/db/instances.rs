use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;

use crate::db::map_sqlx;
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
pub struct SqlxInstanceStore {
    pool: SqlitePool,
    cipher: Option<Arc<dyn EnvelopeCipher>>,
}

impl SqlxInstanceStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool, cipher: None }
    }

    pub fn sealed(pool: SqlitePool, cipher: Arc<dyn EnvelopeCipher>) -> Self {
        Self {
            pool,
            cipher: Some(cipher),
        }
    }
}

fn is_legacy_bearer(stored: &str) -> bool {
    stored.len() == 32 && stored.bytes().all(|b| b.is_ascii_hexdigit())
}

fn seal_bearer(cipher: Option<&dyn EnvelopeCipher>, bearer: &str) -> Result<String, StoreError> {
    let Some(cipher) = cipher else {
        return Ok(bearer.to_owned());
    };
    let sealed = cipher
        .seal(bearer.as_bytes())
        .map_err(|e| StoreError::Io(format!("seal instance bearer: {e}")))?;
    String::from_utf8(sealed)
        .map_err(|_| StoreError::Malformed("sealed instance bearer was not utf-8".into()))
}

fn open_bearer(cipher: Option<&dyn EnvelopeCipher>, stored: &str) -> Result<String, StoreError> {
    if is_legacy_bearer(stored) {
        return Ok(stored.to_owned());
    }
    let Some(cipher) = cipher else {
        return Ok(stored.to_owned());
    };
    let plain = cipher
        .open(stored.as_bytes())
        .map_err(|e| StoreError::Malformed(format!("open instance bearer: {e}")))?;
    String::from_utf8(plain)
        .map_err(|_| StoreError::Malformed("instance bearer plaintext was not utf-8".into()))
}

fn row_to_instance(
    row: &sqlx::sqlite::SqliteRow,
    cipher: Option<&dyn EnvelopeCipher>,
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

#[async_trait]
impl InstanceStore for SqlxInstanceStore {
    async fn create(&self, row: InstanceRow) -> Result<(), StoreError> {
        let probe_json = match &row.last_probe_status {
            Some(p) => Some(serde_json::to_string(p).map_err(|e| StoreError::Io(e.to_string()))?),
            None => None,
        };
        let kind = row.network_policy.kind_str().to_owned();
        let entries_csv = vec_to_csv(row.network_policy.entries());
        let cidrs_csv = vec_to_csv(&row.network_policy_cidrs);
        let models_json = serde_json::to_string(&row.models)
            .map_err(|e| StoreError::Io(format!("models encode: {e}")))?;
        let tools_json = serde_json::to_string(&row.tools)
            .map_err(|e| StoreError::Io(format!("tools encode: {e}")))?;
        let bearer_token = seal_bearer(self.cipher.as_deref(), &row.bearer_token)?;
        sqlx::query(
            "INSERT INTO instances \
             (id, owner_id, name, task, cube_sandbox_id, template_id, status, bearer_token, \
              pinned, expires_at, last_active_at, last_probe_at, last_probe_status, \
              created_at, destroyed_at, rotated_to, \
              network_policy_kind, network_policy_entries, network_policy_cidrs, models, tools) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.owner_id)
        .bind(&row.name)
        .bind(&row.task)
        .bind(&row.cube_sandbox_id)
        .bind(&row.template_id)
        .bind(row.status.as_str())
        .bind(&bearer_token)
        .bind(row.pinned as i64)
        .bind(row.expires_at)
        .bind(row.last_active_at)
        .bind(row.last_probe_at)
        .bind(probe_json)
        .bind(row.created_at)
        .bind(row.destroyed_at)
        .bind(&row.rotated_to)
        .bind(kind)
        .bind(entries_csv)
        .bind(cidrs_csv)
        .bind(models_json)
        .bind(tools_json)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<InstanceRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM instances WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_instance(&r, self.cipher.as_deref())?)),
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
            sqlx::query("SELECT * FROM instances WHERE id = ?1 AND (?2 = '*' OR owner_id = ?2)")
                .bind(id)
                .bind(owner_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_instance(&r, self.cipher.as_deref())?)),
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
             WHERE (?1 = 1 OR owner_id = ?2) \
               AND (?3 IS NULL OR status = ?3) \
               AND (?4 = 1 OR status != 'destroyed') \
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
            .map(|row| row_to_instance(row, self.cipher.as_deref()))
            .collect()
    }

    async fn set_cube_sandbox_id(&self, id: &str, sandbox_id: &str) -> Result<(), StoreError> {
        let r = sqlx::query("UPDATE instances SET cube_sandbox_id = ? WHERE id = ?")
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
        let result = sqlx::query(
            "UPDATE instances SET status = ?1, \
                                  destroyed_at = CASE WHEN ?1 = 'destroyed' THEN ?2 ELSE destroyed_at END \
             WHERE id = ?3",
        )
        .bind(status.as_str())
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

    async fn touch(&self, id: &str) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE instances SET last_active_at = ? WHERE id = ?")
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
            "UPDATE instances SET name = ?1, task = ?2 \
             WHERE id = ?3 AND (?4 = '*' OR owner_id = ?4)",
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
        let result = sqlx::query("UPDATE instances SET pinned = ?1, expires_at = ?2 WHERE id = ?3")
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
            "UPDATE instances SET last_probe_at = ?, last_probe_status = ? WHERE id = ?",
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
        let result = sqlx::query("UPDATE instances SET rotated_to = ? WHERE id = ?")
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
        let result = sqlx::query("UPDATE instances SET models = ? WHERE id = ?")
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
        let result = sqlx::query("UPDATE instances SET tools = ? WHERE id = ?")
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
                cube_sandbox_id = ?1, \
                template_id = ?2, \
                network_policy_kind = ?3, \
                network_policy_entries = ?4, \
                network_policy_cidrs = ?5, \
                last_probe_at = NULL, \
                last_probe_status = NULL, \
                last_active_at = ?6, \
                rotated_to = NULL, \
                status = 'live' \
             WHERE id = ?7",
        )
        .bind(new_cube_sandbox_id)
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
               AND expires_at < ? \
               AND status != 'destroyed'",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.iter()
            .map(|row| row_to_instance(row, self.cipher.as_deref()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::envelope::EnvelopeError;

    #[derive(Debug)]
    struct TestCipher;

    impl EnvelopeCipher for TestCipher {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let mut out = b"sealed:".to_vec();
            out.extend_from_slice(plaintext);
            Ok(out)
        }

        fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            ciphertext
                .strip_prefix(b"sealed:")
                .map(|s| s.to_vec())
                .ok_or(EnvelopeError::Corrupt)
        }
    }

    fn sample(id: &str) -> InstanceRow {
        InstanceRow {
            id: id.to_owned(),
            owner_id: "legacy".into(),
            name: String::new(),
            task: String::new(),
            cube_sandbox_id: Some(format!("sb-{id}")),
            template_id: "tpl-1".into(),
            status: InstanceStatus::Live,
            bearer_token: format!("tok-{id}"),
            pinned: false,
            expires_at: Some(1000),
            last_active_at: 100,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 50,
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn create_get_round_trip() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        let got = store.get("a").await.unwrap().expect("present");
        assert_eq!(got.id, "a");
        assert_eq!(got.status, InstanceStatus::Live);
        assert_eq!(got.cube_sandbox_id.as_deref(), Some("sb-a"));
        assert!(!got.pinned);
        assert!(store.get("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sealed_store_does_not_persist_plaintext_bearer() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::sealed(pool.clone(), Arc::new(TestCipher));
        let row = sample("a");
        let bearer = row.bearer_token.clone();
        store.create(row).await.unwrap();

        let raw = sqlx::query("SELECT bearer_token FROM instances WHERE id = 'a'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let stored: String = raw.get("bearer_token");
        assert_ne!(stored, bearer);
        assert_eq!(stored, format!("sealed:{bearer}"));

        let got = store.get("a").await.unwrap().expect("present");
        assert_eq!(got.bearer_token, bearer);
    }

    #[tokio::test]
    async fn sealed_store_still_reads_legacy_plaintext_bearer() {
        let pool = open_in_memory().await.unwrap();
        let legacy = SqlxInstanceStore::new(pool.clone());
        let mut row = sample("a");
        row.bearer_token = "0123456789abcdef0123456789abcdef".to_string();
        legacy.create(row).await.unwrap();

        let sealed = SqlxInstanceStore::sealed(pool, Arc::new(TestCipher));
        let got = sealed.get("a").await.unwrap().expect("present");
        assert_eq!(got.bearer_token, "0123456789abcdef0123456789abcdef");
    }

    #[tokio::test]
    async fn update_status_destroys() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        store
            .update_status("a", InstanceStatus::Destroyed)
            .await
            .unwrap();
        let got = store.get("a").await.unwrap().unwrap();
        assert_eq!(got.status, InstanceStatus::Destroyed);
        assert!(got.destroyed_at.is_some());
    }

    #[tokio::test]
    async fn pin_clears_expiry_unpin_sets_it() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        store.pin("a", true, None).await.unwrap();
        let pinned = store.get("a").await.unwrap().unwrap();
        assert!(pinned.pinned);
        assert!(pinned.expires_at.is_none());

        store.pin("a", false, Some(60)).await.unwrap();
        let unpinned = store.get("a").await.unwrap().unwrap();
        assert!(!unpinned.pinned);
        assert!(unpinned.expires_at.is_some());
    }

    #[tokio::test]
    async fn record_probe_round_trips_through_json() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        store
            .record_probe(
                "a",
                ProbeResult::Degraded {
                    reason: "slow".into(),
                },
            )
            .await
            .unwrap();
        let got = store.get("a").await.unwrap().unwrap();
        match got.last_probe_status {
            Some(ProbeResult::Degraded { reason }) => assert_eq!(reason, "slow"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(got.last_probe_at.is_some());
    }

    #[tokio::test]
    async fn expired_excludes_pinned_and_destroyed() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        let mut a = sample("a");
        a.expires_at = Some(50);
        store.create(a).await.unwrap();

        let mut b = sample("b");
        b.expires_at = Some(50);
        b.pinned = true;
        store.create(b).await.unwrap();

        let mut c = sample("c");
        c.expires_at = Some(50);
        c.status = InstanceStatus::Destroyed;
        store.create(c).await.unwrap();

        let mut d = sample("d");
        d.expires_at = Some(2000);
        store.create(d).await.unwrap();

        let exp = store.expired(100).await.unwrap();
        let ids: Vec<_> = exp.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[tokio::test]
    async fn list_filters_destroyed_by_default() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        let mut b = sample("b");
        b.status = InstanceStatus::Destroyed;
        store.create(b).await.unwrap();

        let live_only = store.list("*", ListFilter::default()).await.unwrap();
        assert_eq!(live_only.len(), 1);
        assert_eq!(live_only[0].id, "a");

        let all = store
            .list(
                "*",
                ListFilter {
                    status: None,
                    include_destroyed: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn update_identity_round_trips_and_is_owner_scoped() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();

        store
            .update_identity("legacy", "a", "PR reviewer", "Watch for PRs")
            .await
            .unwrap();
        let row = store.get("a").await.unwrap().unwrap();
        assert_eq!(row.name, "PR reviewer");
        assert_eq!(row.task, "Watch for PRs");

        // Wrong owner → NotFound (no oracle).
        let err = store
            .update_identity("someone-else", "a", "x", "y")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound));

        // Unchanged from the failed update.
        let row = store.get("a").await.unwrap().unwrap();
        assert_eq!(row.name, "PR reviewer");
    }

    #[tokio::test]
    async fn touch_updates_last_active() {
        let pool = open_in_memory().await.unwrap();
        let store = SqlxInstanceStore::new(pool);
        store.create(sample("a")).await.unwrap();
        let before = store.get("a").await.unwrap().unwrap().last_active_at;
        // touch sets to now, which is far larger than 100
        store.touch("a").await.unwrap();
        let after = store.get("a").await.unwrap().unwrap().last_active_at;
        assert!(after > before);
    }
}
