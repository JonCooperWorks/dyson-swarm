//! Sqlite-backed store for `artefact_shares` + `artefact_share_accesses`.
//!
//! The capability lives in the URL itself (HMAC-signed payload).  This
//! table is the index/audit/revocation oracle: rows here let the SPA
//! list a user's live shares and let the verifier reject revoked
//! tokens.  Bytes are never stored; the artefact body comes from the
//! per-instance dyson agent on demand.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;

#[derive(Debug, Clone)]
pub struct ShareRow {
    pub jti: String,
    pub instance_id: String,
    pub chat_id: String,
    pub artefact_id: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShareSpec<'a> {
    pub jti: &'a str,
    pub instance_id: &'a str,
    pub chat_id: &'a str,
    pub artefact_id: &'a str,
    pub created_by: &'a str,
    pub expires_at: i64,
    pub label: Option<&'a str>,
}

/// Insert a freshly-minted share row.
///
/// Caller has already (a) generated the random `jti`, (b) signed the
/// payload with the user's signing key, and (c) verified the artefact
/// exists in dyson.  This function is a thin wrapper around the
/// INSERT — no validation of `expires_at` ordering is done here so
/// tests can mint deliberately-expired rows when exercising the
/// expiry branch of the verifier.
pub async fn mint(pool: &SqlitePool, spec: ShareSpec<'_>) -> Result<ShareRow, StoreError> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO artefact_shares \
            (jti, instance_id, chat_id, artefact_id, created_by, \
             created_at, expires_at, revoked_at, label) \
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
    )
    .bind(spec.jti)
    .bind(spec.instance_id)
    .bind(spec.chat_id)
    .bind(spec.artefact_id)
    .bind(spec.created_by)
    .bind(now)
    .bind(spec.expires_at)
    .bind(spec.label)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(ShareRow {
        jti: spec.jti.to_owned(),
        instance_id: spec.instance_id.to_owned(),
        chat_id: spec.chat_id.to_owned(),
        artefact_id: spec.artefact_id.to_owned(),
        created_by: spec.created_by.to_owned(),
        created_at: now,
        expires_at: spec.expires_at,
        revoked_at: None,
        label: spec.label.map(str::to_owned),
    })
}

/// Hot-path lookup for the public read route.  Returns `Some` only if
/// the row exists; the caller is responsible for checking
/// `revoked_at`.  Expiry is *not* checked here — the verifier
/// already rejected expired payloads in pure-CPU steps before any DB
/// I/O, and we don't want to duplicate that gate at a different layer
/// where its meaning would diverge.
pub async fn find_by_jti(pool: &SqlitePool, jti: &str) -> Result<Option<ShareRow>, StoreError> {
    let row = sqlx::query(
        "SELECT jti, instance_id, chat_id, artefact_id, created_by, \
                created_at, expires_at, revoked_at, label \
         FROM artefact_shares WHERE jti = ?",
    )
    .bind(jti)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx)?;
    row.map(row_to_share).transpose()
}

/// All shares minted by `user_id` for `instance_id`, newest first.
/// Owner-scoping happens at the HTTP layer (the caller has already
/// checked `instances.owner_id == user_id` via `instances::get`); this
/// function trusts the caller and runs a straight SELECT.
pub async fn list_for_instance(
    pool: &SqlitePool,
    user_id: &str,
    instance_id: &str,
) -> Result<Vec<ShareRow>, StoreError> {
    let rows = sqlx::query(
        "SELECT jti, instance_id, chat_id, artefact_id, created_by, \
                created_at, expires_at, revoked_at, label \
         FROM artefact_shares \
         WHERE instance_id = ? AND created_by = ? \
         ORDER BY created_at DESC",
    )
    .bind(instance_id)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    rows.into_iter().map(row_to_share).collect()
}

/// Idempotent revoke.  Marks `revoked_at` on a row owned by `user_id`.
/// Returns `Ok(true)` if a row was modified, `Ok(false)` if the row
/// didn't exist or was already revoked or wasn't theirs.  No oracle —
/// callers map both false outcomes to 204.
pub async fn revoke(pool: &SqlitePool, jti: &str, user_id: &str) -> Result<bool, StoreError> {
    let now = now_secs();
    let r = sqlx::query(
        "UPDATE artefact_shares SET revoked_at = ? \
         WHERE jti = ? AND created_by = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(jti)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(r.rows_affected() > 0)
}

/// Append an audit row.  Called only after the verifier has accepted
/// the request all the way through to a real instance lookup — bad-sig
/// and expired hits never reach here, by design (write-amplification DoS).
pub async fn record_access(
    pool: &SqlitePool,
    jti: &str,
    remote_addr: Option<&str>,
    user_agent: Option<&str>,
    status: i32,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO artefact_share_accesses \
            (jti, accessed_at, remote_addr, user_agent, status) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(jti)
    .bind(now_secs())
    .bind(remote_addr)
    .bind(user_agent)
    .bind(status)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

/// Recent accesses for one share.  Powers the "delivery log"-style
/// detail view in the SPA's Shares panel.  `limit` is bounded by the
/// caller; we don't enforce a max here so test code can request more.
pub async fn list_accesses(
    pool: &SqlitePool,
    jti: &str,
    limit: u32,
) -> Result<Vec<ShareAccessRow>, StoreError> {
    // accessed_at is a unix-second column — two appends in the same
    // second tie on time; the tiebreak on `id DESC` keeps "newest
    // first" stable.  The id is autoincrement so its order matches
    // insert order.
    let rows = sqlx::query(
        "SELECT id, jti, accessed_at, remote_addr, user_agent, status \
         FROM artefact_share_accesses \
         WHERE jti = ? \
         ORDER BY accessed_at DESC, id DESC \
         LIMIT ?",
    )
    .bind(jti)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    rows.iter()
        .map(|r| {
            Ok(ShareAccessRow {
                id: r.try_get("id").map_err(map_sqlx)?,
                jti: r.try_get("jti").map_err(map_sqlx)?,
                accessed_at: r.try_get("accessed_at").map_err(map_sqlx)?,
                remote_addr: r.try_get("remote_addr").map_err(map_sqlx)?,
                user_agent: r.try_get("user_agent").map_err(map_sqlx)?,
                status: r.try_get("status").map_err(map_sqlx)?,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ShareAccessRow {
    pub id: i64,
    pub jti: String,
    pub accessed_at: i64,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub status: i32,
}

fn row_to_share(r: sqlx::sqlite::SqliteRow) -> Result<ShareRow, StoreError> {
    Ok(ShareRow {
        jti: r.try_get("jti").map_err(map_sqlx)?,
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        chat_id: r.try_get("chat_id").map_err(map_sqlx)?,
        artefact_id: r.try_get("artefact_id").map_err(map_sqlx)?,
        created_by: r.try_get("created_by").map_err(map_sqlx)?,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        expires_at: r.try_get("expires_at").map_err(map_sqlx)?,
        revoked_at: r.try_get("revoked_at").map_err(map_sqlx)?,
        label: r.try_get("label").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    /// Seed both a `users` row and the dependent `instances` row.
    /// FK constraints are enforced (open_in_memory turns the pragma
    /// on), so the parent rows have to exist before `mint` can write
    /// an `artefact_shares` row.
    async fn seed_instance(pool: &SqlitePool, id: &str, owner_id: &str) {
        sqlx::query(
            "INSERT OR IGNORE INTO users \
                (id, subject, email, display_name, status, created_at, \
                 activated_at, last_seen_at, openrouter_key_id, openrouter_key_limit_usd) \
             VALUES (?, ?, NULL, NULL, 'active', 0, NULL, NULL, NULL, 10.0)",
        )
        .bind(owner_id)
        .bind(owner_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO instances \
                (id, owner_id, name, task, cube_sandbox_id, template_id, status, bearer_token, \
                 pinned, expires_at, last_active_at, last_probe_at, last_probe_status, \
                 created_at, destroyed_at, rotated_to, \
                 network_policy_kind, network_policy_entries, network_policy_cidrs, models, tools) \
             VALUES (?, ?, '', '', 'sb', 'tpl', 'live', 'tok', 0, NULL, 0, NULL, NULL, \
                     0, NULL, NULL, 'open', '', '', '[]', '[]')",
        )
        .bind(id)
        .bind(owner_id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn mint_then_find_round_trips() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-a", "alice").await;
        let row = mint(
            &pool,
            ShareSpec {
                jti: "00112233445566778899aabbccddeeff",
                instance_id: "inst-a",
                chat_id: "c1",
                artefact_id: "a1",
                created_by: "alice",
                expires_at: now_secs() + 3600,
                label: Some("smoke"),
            },
        )
        .await
        .unwrap();
        assert_eq!(row.created_by, "alice");
        let got = find_by_jti(&pool, "00112233445566778899aabbccddeeff")
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.instance_id, "inst-a");
        assert_eq!(got.chat_id, "c1");
        assert!(got.revoked_at.is_none());
    }

    #[tokio::test]
    async fn revoke_marks_revoked_at_and_is_idempotent() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-a", "alice").await;
        mint(
            &pool,
            ShareSpec {
                jti: "ff",
                instance_id: "inst-a",
                chat_id: "c",
                artefact_id: "a",
                created_by: "alice",
                expires_at: now_secs() + 60,
                label: None,
            },
        )
        .await
        .unwrap();
        assert!(revoke(&pool, "ff", "alice").await.unwrap());
        let got = find_by_jti(&pool, "ff").await.unwrap().unwrap();
        assert!(got.revoked_at.is_some());
        // Second revoke is a no-op (already revoked).
        assert!(!revoke(&pool, "ff", "alice").await.unwrap());
    }

    #[tokio::test]
    async fn revoke_only_succeeds_for_owner() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-a", "alice").await;
        mint(
            &pool,
            ShareSpec {
                jti: "f1",
                instance_id: "inst-a",
                chat_id: "c",
                artefact_id: "a",
                created_by: "alice",
                expires_at: now_secs() + 60,
                label: None,
            },
        )
        .await
        .unwrap();
        // Bob can't revoke alice's share — no row matches the
        // (jti, created_by) pair so 0 rows are affected.
        assert!(!revoke(&pool, "f1", "bob").await.unwrap());
        let got = find_by_jti(&pool, "f1").await.unwrap().unwrap();
        assert!(got.revoked_at.is_none());
    }

    #[tokio::test]
    async fn instance_delete_cascades_share_rows() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-z", "alice").await;
        mint(
            &pool,
            ShareSpec {
                jti: "abcd",
                instance_id: "inst-z",
                chat_id: "c",
                artefact_id: "a",
                created_by: "alice",
                expires_at: now_secs() + 60,
                label: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("DELETE FROM instances WHERE id = ?")
            .bind("inst-z")
            .execute(&pool)
            .await
            .unwrap();
        assert!(find_by_jti(&pool, "abcd").await.unwrap().is_none());
    }

    async fn mk(pool: &SqlitePool, jti: &str, instance: &str, user: &str) {
        mint(
            pool,
            ShareSpec {
                jti,
                instance_id: instance,
                chat_id: "c",
                artefact_id: "a",
                created_by: user,
                expires_at: now_secs() + 60,
                label: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn list_for_instance_excludes_other_instances_and_users() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-a", "alice").await;
        seed_instance(&pool, "inst-b", "alice").await;
        seed_instance(&pool, "inst-c", "bob").await;
        mk(&pool, "aa", "inst-a", "alice").await;
        mk(&pool, "bb", "inst-b", "alice").await;
        mk(&pool, "cc", "inst-c", "bob").await;
        let got = list_for_instance(&pool, "alice", "inst-a").await.unwrap();
        let ids: Vec<_> = got.iter().map(|r| r.jti.as_str()).collect();
        assert_eq!(ids, vec!["aa"]);
    }

    #[tokio::test]
    async fn record_access_appends_and_lists_newest_first() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(&pool, "inst-a", "alice").await;
        mint(
            &pool,
            ShareSpec {
                jti: "j",
                instance_id: "inst-a",
                chat_id: "c",
                artefact_id: "a",
                created_by: "alice",
                expires_at: now_secs() + 60,
                label: None,
            },
        )
        .await
        .unwrap();
        record_access(&pool, "j", Some("1.2.3.4"), Some("curl"), 200)
            .await
            .unwrap();
        record_access(&pool, "j", Some("1.2.3.5"), Some("curl"), 404)
            .await
            .unwrap();
        let logs = list_accesses(&pool, "j", 10).await.unwrap();
        assert_eq!(logs.len(), 2);
        // Newest first: status 404 was inserted second.
        assert_eq!(logs[0].status, 404);
        assert_eq!(logs[1].status, 200);
    }
}
