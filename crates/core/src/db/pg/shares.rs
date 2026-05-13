//! Pg-backed store for `artefact_shares` + `artefact_share_accesses`.
//!
//! The capability lives in the URL itself (HMAC-signed payload).  This
//! table is the index/audit/revocation oracle: rows here let the SPA
//! list a user's live shares and let the verifier reject revoked
//! tokens.  Bytes are never stored; the artefact body comes from the
//! per-instance dyson agent on demand.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::ShareStore;

pub use crate::traits::{ShareAccessRow, ShareRow, ShareSpec};

#[derive(Clone)]
pub struct PgShareStore {
    pool: PgPool,
}

impl PgShareStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ShareStore for PgShareStore {
    async fn mint(&self, spec: ShareSpec<'_>) -> Result<ShareRow, StoreError> {
        mint(&self.pool, spec).await
    }

    async fn find_by_jti(&self, jti: &str) -> Result<Option<ShareRow>, StoreError> {
        find_by_jti(&self.pool, jti).await
    }

    async fn list_for_instance(
        &self,
        user_id: &str,
        instance_id: &str,
    ) -> Result<Vec<ShareRow>, StoreError> {
        list_for_instance(&self.pool, user_id, instance_id).await
    }

    async fn revoke(&self, jti: &str, user_id: &str) -> Result<bool, StoreError> {
        revoke(&self.pool, jti, user_id).await
    }

    async fn record_access(
        &self,
        jti: &str,
        remote_addr: Option<&str>,
        user_agent: Option<&str>,
        status: i32,
    ) -> Result<(), StoreError> {
        record_access(&self.pool, jti, remote_addr, user_agent, status).await
    }

    async fn list_accesses(
        &self,
        jti: &str,
        limit: u32,
    ) -> Result<Vec<ShareAccessRow>, StoreError> {
        list_accesses(&self.pool, jti, limit).await
    }
}

/// Insert a freshly-minted share row.
///
/// Caller has already (a) generated the random `jti`, (b) signed the
/// payload with the user's signing key, and (c) verified the artefact
/// exists in dyson.  This function is a thin wrapper around the
/// INSERT — no validation of `expires_at` ordering is done here so
/// tests can mint deliberately-expired rows when exercising the
/// expiry branch of the verifier.
pub async fn mint(pool: &PgPool, spec: ShareSpec<'_>) -> Result<ShareRow, StoreError> {
    let now = now_secs();
    sqlx::query(
        "INSERT INTO artefact_shares \
            (jti, instance_id, chat_id, artefact_id, created_by, \
             created_at, expires_at, revoked_at, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)",
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
        artefact_title: None,
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
pub async fn find_by_jti(pool: &PgPool, jti: &str) -> Result<Option<ShareRow>, StoreError> {
    let row = sqlx::query(
        "SELECT jti, instance_id, chat_id, artefact_id, created_by, \
                created_at, expires_at, revoked_at, label, \
                NULL AS artefact_title \
         FROM artefact_shares WHERE jti = $1",
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
    pool: &PgPool,
    user_id: &str,
    instance_id: &str,
) -> Result<Vec<ShareRow>, StoreError> {
    let rows = sqlx::query(
        "SELECT s.jti, s.instance_id, s.chat_id, s.artefact_id, s.created_by, \
                s.created_at, s.expires_at, s.revoked_at, s.label, \
                ac.title AS artefact_title \
         FROM artefact_shares s \
         LEFT JOIN artefact_cache ac \
           ON ac.owner_id = s.created_by \
          AND ac.instance_id = s.instance_id \
          AND ac.chat_id = s.chat_id \
          AND ac.artefact_id = s.artefact_id \
         WHERE s.instance_id = $1 AND s.created_by = $2 \
         ORDER BY s.created_at DESC",
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
pub async fn revoke(pool: &PgPool, jti: &str, user_id: &str) -> Result<bool, StoreError> {
    let now = now_secs();
    let r = sqlx::query(
        "UPDATE artefact_shares SET revoked_at = $1 \
         WHERE jti = $2 AND created_by = $3 AND revoked_at IS NULL",
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
    pool: &PgPool,
    jti: &str,
    remote_addr: Option<&str>,
    user_agent: Option<&str>,
    status: i32,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO artefact_share_accesses \
            (jti, accessed_at, remote_addr, user_agent, status) \
         VALUES ($1, $2, $3, $4, $5)",
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
    pool: &PgPool,
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
         WHERE jti = $1 \
         ORDER BY accessed_at DESC, id DESC \
         LIMIT $2",
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

fn row_to_share(r: sqlx::postgres::PgRow) -> Result<ShareRow, StoreError> {
    Ok(ShareRow {
        jti: r.try_get("jti").map_err(map_sqlx)?,
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        chat_id: r.try_get("chat_id").map_err(map_sqlx)?,
        artefact_id: r.try_get("artefact_id").map_err(map_sqlx)?,
        artefact_title: r.try_get("artefact_title").map_err(map_sqlx)?,
        created_by: r.try_get("created_by").map_err(map_sqlx)?,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        expires_at: r.try_get("expires_at").map_err(map_sqlx)?,
        revoked_at: r.try_get("revoked_at").map_err(map_sqlx)?,
        label: r.try_get("label").map_err(map_sqlx)?,
    })
}
