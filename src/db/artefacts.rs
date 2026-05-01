//! SQLite-backed store for the `artefact_cache` table — swarm's copy
//! of dyson-emitted artefact metadata.  Bytes live on disk under the
//! `body_path`; this layer only handles the row.
//!
//! Identity is `(instance_id, chat_id, artefact_id)`.  `upsert_meta`
//! is the ingest hot path — called every time the share read path or
//! the swarm-side artefact list endpoint pulls fresh bytes from a
//! cube.  `update_body` writes the on-disk path + size + mime once
//! the body has actually been written; the two are split so a partial
//! failure between metadata-write and body-write doesn't leave a row
//! pointing at nothing (we update the path *after* the body lands).

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;

/// One cached artefact row.  `body_path` is relative to the operator's
/// `[backup].local_cache_dir`; the service layer joins it with the
/// configured root before opening the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedArtefact {
    pub id: i64,
    pub instance_id: String,
    pub owner_id: String,
    pub chat_id: String,
    pub artefact_id: String,
    pub kind: String,
    pub title: String,
    pub mime: Option<String>,
    pub bytes: i64,
    pub body_path: String,
    pub metadata_json: Option<String>,
    pub created_at: i64,
    pub cached_at: i64,
}

/// Insert (or refresh metadata of) a cached artefact row.  No body
/// bytes are written here — the caller follows up with `update_body`
/// once the bytes are committed to disk.  Returns the row id either
/// way; the row's `body_path` is set on insert and *not* clobbered on
/// upsert (preserves an already-warm cache when only metadata
/// refreshes).
pub struct UpsertSpec<'a> {
    pub instance_id: &'a str,
    pub owner_id: &'a str,
    pub chat_id: &'a str,
    pub artefact_id: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub created_at: i64,
    /// Initial body_path used only when the row doesn't already exist.
    /// Subsequent upserts leave the existing path alone — `update_body`
    /// is the explicit path-rewrite call.
    pub body_path_seed: &'a str,
    pub metadata_json: Option<&'a str>,
}

/// UPSERT the metadata.  Returns `(row_id, body_path)` so the caller
/// has the path to write bytes to even on the "row already existed"
/// branch.  We never overwrite `body_path` here so a successful body
/// write from a prior call survives a subsequent metadata-only refresh.
pub async fn upsert_meta(
    pool: &SqlitePool,
    spec: UpsertSpec<'_>,
) -> Result<(i64, String), StoreError> {
    let now = now_secs();
    // Use ON CONFLICT to keep the existing body_path, bytes, mime when the
    // tuple is already cached — a metadata refresh shouldn't blow away
    // a known-good body.  cached_at IS bumped so the GC sees the row as
    // recently-touched.
    sqlx::query(
        "INSERT INTO artefact_cache \
            (instance_id, owner_id, chat_id, artefact_id, kind, title, \
             mime, bytes, body_path, metadata_json, created_at, cached_at) \
         VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?) \
         ON CONFLICT(instance_id, chat_id, artefact_id) DO UPDATE SET \
            kind = excluded.kind, \
            title = excluded.title, \
            metadata_json = excluded.metadata_json, \
            cached_at = excluded.cached_at",
    )
    .bind(spec.instance_id)
    .bind(spec.owner_id)
    .bind(spec.chat_id)
    .bind(spec.artefact_id)
    .bind(spec.kind)
    .bind(spec.title)
    .bind(spec.body_path_seed)
    .bind(spec.metadata_json)
    .bind(spec.created_at)
    .bind(now)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;

    let row = sqlx::query(
        "SELECT id, body_path FROM artefact_cache \
         WHERE instance_id = ? AND chat_id = ? AND artefact_id = ?",
    )
    .bind(spec.instance_id)
    .bind(spec.chat_id)
    .bind(spec.artefact_id)
    .fetch_one(pool)
    .await
    .map_err(map_sqlx)?;
    let id: i64 = row.try_get("id").map_err(map_sqlx)?;
    let body_path: String = row.try_get("body_path").map_err(map_sqlx)?;
    Ok((id, body_path))
}

/// Promote a row's `body_path` + size + mime once the body has been
/// committed to disk.  Idempotent — a second call with the same path
/// is fine.
pub async fn update_body(
    pool: &SqlitePool,
    id: i64,
    body_path: &str,
    bytes: i64,
    mime: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE artefact_cache \
         SET body_path = ?, bytes = ?, mime = ?, cached_at = ? \
         WHERE id = ?",
    )
    .bind(body_path)
    .bind(bytes)
    .bind(mime)
    .bind(now_secs())
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

/// Fetch a single cached artefact by identity tuple.
pub async fn find(
    pool: &SqlitePool,
    instance_id: &str,
    chat_id: &str,
    artefact_id: &str,
) -> Result<Option<CachedArtefact>, StoreError> {
    let row = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_path, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE instance_id = ? AND chat_id = ? AND artefact_id = ?",
    )
    .bind(instance_id)
    .bind(chat_id)
    .bind(artefact_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx)?;
    row.map(row_to_cached).transpose()
}

/// Owner-scoped: every cached artefact for one instance, newest-first.
pub async fn list_for_instance(
    pool: &SqlitePool,
    owner_id: &str,
    instance_id: &str,
) -> Result<Vec<CachedArtefact>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_path, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE owner_id = ? AND instance_id = ? \
         ORDER BY cached_at DESC",
    )
    .bind(owner_id)
    .bind(instance_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    rows.into_iter().map(row_to_cached).collect()
}

/// Owner-scoped: every cached artefact for an owner, across instances,
/// newest-first.  Powers the swarm UI's "all my artefacts" panel.
pub async fn list_for_owner(
    pool: &SqlitePool,
    owner_id: &str,
    limit: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_path, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE owner_id = ? \
         ORDER BY cached_at DESC \
         LIMIT ?",
    )
    .bind(owner_id)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    rows.into_iter().map(row_to_cached).collect()
}

/// Delete one cached row.  Returns `true` if a row was removed.  The
/// caller is responsible for unlinking the on-disk body — this layer
/// doesn't know the absolute path, only the relative `body_path`.
pub async fn delete(
    pool: &SqlitePool,
    owner_id: &str,
    instance_id: &str,
    chat_id: &str,
    artefact_id: &str,
) -> Result<bool, StoreError> {
    let r = sqlx::query(
        "DELETE FROM artefact_cache \
         WHERE owner_id = ? AND instance_id = ? AND chat_id = ? AND artefact_id = ?",
    )
    .bind(owner_id)
    .bind(instance_id)
    .bind(chat_id)
    .bind(artefact_id)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;
    Ok(r.rows_affected() > 0)
}

fn row_to_cached(r: sqlx::sqlite::SqliteRow) -> Result<CachedArtefact, StoreError> {
    Ok(CachedArtefact {
        id: r.try_get("id").map_err(map_sqlx)?,
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        owner_id: r.try_get("owner_id").map_err(map_sqlx)?,
        chat_id: r.try_get("chat_id").map_err(map_sqlx)?,
        artefact_id: r.try_get("artefact_id").map_err(map_sqlx)?,
        kind: r.try_get("kind").map_err(map_sqlx)?,
        title: r.try_get("title").map_err(map_sqlx)?,
        mime: r.try_get("mime").map_err(map_sqlx)?,
        bytes: r.try_get("bytes").map_err(map_sqlx)?,
        body_path: r.try_get("body_path").map_err(map_sqlx)?,
        metadata_json: r.try_get("metadata_json").map_err(map_sqlx)?,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        cached_at: r.try_get("cached_at").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn spec<'a>(
        instance: &'a str,
        owner: &'a str,
        chat: &'a str,
        art: &'a str,
        body_path: &'a str,
    ) -> UpsertSpec<'a> {
        UpsertSpec {
            instance_id: instance,
            owner_id: owner,
            chat_id: chat,
            artefact_id: art,
            kind: "security_review",
            title: "Test artefact",
            created_at: 1_700_000_000,
            body_path_seed: body_path,
            metadata_json: None,
        }
    }

    #[tokio::test]
    async fn upsert_then_find_round_trips() {
        let pool = open_in_memory().await.unwrap();
        let (id, body_path) = upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1", "p/1"))
            .await
            .unwrap();
        assert!(id > 0);
        assert_eq!(body_path, "p/1");
        let got = find(&pool, "inst-a", "c1", "a1").await.unwrap().unwrap();
        assert_eq!(got.title, "Test artefact");
        assert_eq!(got.owner_id, "alice");
        assert_eq!(got.body_path, "p/1");
        assert_eq!(got.bytes, 0); // body not written yet
    }

    #[tokio::test]
    async fn upsert_does_not_clobber_existing_body_path() {
        // Critical invariant: a metadata refresh must not destroy a
        // warm cache.  `body_path_seed` is only used on first insert;
        // subsequent upserts keep the old path.
        let pool = open_in_memory().await.unwrap();
        let (_, p1) = upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1", "p/first"))
            .await
            .unwrap();
        // Pretend body landed.
        update_body(&pool, 1, "p/first", 1234, Some("text/markdown"))
            .await
            .unwrap();
        // Re-upsert with a different seed — body_path must NOT change.
        let (_, p2) = upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1", "p/second"))
            .await
            .unwrap();
        assert_eq!(p1, "p/first");
        assert_eq!(p2, "p/first", "second upsert clobbered body_path");
        let got = find(&pool, "inst-a", "c1", "a1").await.unwrap().unwrap();
        assert_eq!(got.bytes, 1234);
        assert_eq!(got.mime.as_deref(), Some("text/markdown"));
    }

    #[tokio::test]
    async fn list_for_instance_owner_scopes() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1", "p/1"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-a", "bob", "c2", "a2", "p/2"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-b", "alice", "c3", "a3", "p/3"))
            .await
            .unwrap();
        let list = list_for_instance(&pool, "alice", "inst-a").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].artefact_id, "a1");
    }

    #[tokio::test]
    async fn list_for_owner_includes_all_instances() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c", "a1", "p/1"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-b", "alice", "c", "a2", "p/2"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-x", "bob", "c", "ax", "p/x"))
            .await
            .unwrap();
        let list = list_for_owner(&pool, "alice", 100).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn delete_is_owner_scoped() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1", "p/1"))
            .await
            .unwrap();
        // Bob can't delete alice's row.
        let removed = delete(&pool, "bob", "inst-a", "c1", "a1").await.unwrap();
        assert!(!removed);
        assert!(find(&pool, "inst-a", "c1", "a1").await.unwrap().is_some());
        // Alice can.
        let removed = delete(&pool, "alice", "inst-a", "c1", "a1").await.unwrap();
        assert!(removed);
        assert!(find(&pool, "inst-a", "c1", "a1").await.unwrap().is_none());
    }
}
