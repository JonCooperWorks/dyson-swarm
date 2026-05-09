//! SQLite-backed store for the `artefact_cache` table — swarm's copy
//! of dyson-emitted artefact metadata and sealed body bytes.
//!
//! Identity is `(instance_id, chat_id, artefact_id)`.  `upsert_meta`
//! is the ingest hot path — called every time the share read path or
//! the swarm-side artefact list endpoint pulls fresh bytes from a
//! cube.  `update_body` stores the sealed body + size + mime once
//! the body has been sealed.

use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;

/// One cached artefact row. `body_ciphertext` is sealed under the
/// row owner before it enters the store. `None` means metadata-only:
/// the artefact is known, but swarm does not yet have durable bytes.
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
    pub body_ciphertext: Option<Vec<u8>>,
    pub metadata_json: Option<String>,
    pub created_at: i64,
    pub cached_at: i64,
}

/// Insert (or refresh metadata of) a cached artefact row.  No body
/// bytes are written here — the caller follows up with `update_body`.
/// Existing body bytes are not clobbered by metadata-only refreshes.
pub struct UpsertSpec<'a> {
    pub instance_id: &'a str,
    pub owner_id: &'a str,
    pub chat_id: &'a str,
    pub artefact_id: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub created_at: i64,
    pub metadata_json: Option<&'a str>,
}

/// UPSERT the metadata. Returns the row id. We never overwrite
/// `body_ciphertext` here so a successful body write from a prior call
/// survives a subsequent metadata-only refresh.
pub async fn upsert_meta(pool: &SqlitePool, spec: UpsertSpec<'_>) -> Result<i64, StoreError> {
    let now = now_secs();
    // Use ON CONFLICT to keep the existing body bytes, bytes, mime when the
    // tuple is already cached — a metadata refresh shouldn't blow away
    // a known-good body.  cached_at IS bumped so the GC sees the row as
    // recently-touched.
    sqlx::query(
        "INSERT INTO artefact_cache \
            (instance_id, owner_id, chat_id, artefact_id, kind, title, \
             mime, bytes, body_ciphertext, metadata_json, created_at, cached_at) \
         VALUES (?, ?, ?, ?, ?, ?, NULL, 0, NULL, ?, ?, ?) \
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
    .bind(spec.metadata_json)
    .bind(spec.created_at)
    .bind(now)
    .execute(pool)
    .await
    .map_err(map_sqlx)?;

    let row = sqlx::query(
        "SELECT id FROM artefact_cache \
         WHERE instance_id = ? AND chat_id = ? AND artefact_id = ?",
    )
    .bind(spec.instance_id)
    .bind(spec.chat_id)
    .bind(spec.artefact_id)
    .fetch_one(pool)
    .await
    .map_err(map_sqlx)?;
    let id: i64 = row.try_get("id").map_err(map_sqlx)?;
    Ok(id)
}

/// Promote a row's sealed body + size + mime. Idempotent — a second
/// call with the same bytes is fine.
pub async fn update_body(
    pool: &SqlitePool,
    id: i64,
    bytes: i64,
    mime: Option<&str>,
    body_ciphertext: &[u8],
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE artefact_cache \
         SET bytes = ?, mime = ?, body_ciphertext = ?, cached_at = ? \
         WHERE id = ?",
    )
    .bind(bytes)
    .bind(mime)
    .bind(body_ciphertext)
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
                kind, title, mime, bytes, body_ciphertext, metadata_json, \
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
    list_for_instance_page(pool, owner_id, instance_id, None, u32::MAX, 0).await
}

/// Owner-scoped: one page of cached artefacts for an instance.
/// Optional `chat_id` narrows to a single dyson conversation.
pub async fn list_for_instance_page(
    pool: &SqlitePool,
    owner_id: &str,
    instance_id: &str,
    chat_id: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    let mut sql = String::from(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_ciphertext, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE owner_id = ? AND instance_id = ?",
    );
    if chat_id.is_some() {
        sql.push_str(" AND chat_id = ?");
    }
    sql.push_str(" ORDER BY cached_at DESC, id DESC LIMIT ? OFFSET ?");

    let mut query = sqlx::query(&sql).bind(owner_id).bind(instance_id);
    if let Some(chat_id) = chat_id {
        query = query.bind(chat_id);
    }
    query = query.bind(i64::from(limit)).bind(i64::from(offset));

    let rows = query.fetch_all(pool).await.map_err(map_sqlx)?;
    rows.into_iter().map(row_to_cached).collect()
}

/// Owner-scoped: every cached artefact for an owner, across instances,
/// newest-first.  Powers the swarm UI's "all my artefacts" panel.
pub async fn list_for_owner(
    pool: &SqlitePool,
    owner_id: &str,
    limit: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    list_for_owner_page(pool, owner_id, limit, 0).await
}

/// Owner-scoped: one page across every instance.
pub async fn list_for_owner_page(
    pool: &SqlitePool,
    owner_id: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_ciphertext, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE owner_id = ? \
         ORDER BY cached_at DESC, id DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(owner_id)
    .bind(i64::from(limit))
    .bind(i64::from(offset))
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    rows.into_iter().map(row_to_cached).collect()
}

/// Delete one cached row.  Returns `true` if a row was removed.
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
        body_ciphertext: r.try_get("body_ciphertext").map_err(map_sqlx)?,
        metadata_json: r.try_get("metadata_json").map_err(map_sqlx)?,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        cached_at: r.try_get("cached_at").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn spec<'a>(instance: &'a str, owner: &'a str, chat: &'a str, art: &'a str) -> UpsertSpec<'a> {
        UpsertSpec {
            instance_id: instance,
            owner_id: owner,
            chat_id: chat,
            artefact_id: art,
            kind: "security_review",
            title: "Test artefact",
            created_at: 1_700_000_000,
            metadata_json: None,
        }
    }

    #[tokio::test]
    async fn upsert_then_find_round_trips() {
        let pool = open_in_memory().await.unwrap();
        let id = upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1"))
            .await
            .unwrap();
        assert!(id > 0);
        let got = find(&pool, "inst-a", "c1", "a1").await.unwrap().unwrap();
        assert_eq!(got.title, "Test artefact");
        assert_eq!(got.owner_id, "alice");
        assert_eq!(got.body_ciphertext, None);
        assert_eq!(got.bytes, 0); // body not written yet
    }

    #[tokio::test]
    async fn upsert_does_not_clobber_existing_body() {
        // Critical invariant: a metadata refresh must not destroy a
        // warm cached body.
        let pool = open_in_memory().await.unwrap();
        let id = upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1"))
            .await
            .unwrap();
        update_body(&pool, id, 1234, Some("text/markdown"), b"sealed")
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1"))
            .await
            .unwrap();
        let got = find(&pool, "inst-a", "c1", "a1").await.unwrap().unwrap();
        assert_eq!(got.bytes, 1234);
        assert_eq!(got.mime.as_deref(), Some("text/markdown"));
        assert_eq!(got.body_ciphertext.as_deref(), Some(b"sealed".as_slice()));
    }

    #[tokio::test]
    async fn list_for_instance_owner_scopes() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-a", "bob", "c2", "a2"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-b", "alice", "c3", "a3"))
            .await
            .unwrap();
        let list = list_for_instance(&pool, "alice", "inst-a").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].artefact_id, "a1");
    }

    #[tokio::test]
    async fn list_for_owner_includes_all_instances() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c", "a1"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-b", "alice", "c", "a2"))
            .await
            .unwrap();
        upsert_meta(&pool, spec("inst-x", "bob", "c", "ax"))
            .await
            .unwrap();
        let list = list_for_owner(&pool, "alice", 100).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn paginated_lists_apply_offset_and_chat_filter() {
        let pool = open_in_memory().await.unwrap();
        for (idx, (chat, art)) in [("c1", "a1"), ("c2", "a2"), ("c1", "a3"), ("c2", "a4")]
            .into_iter()
            .enumerate()
        {
            upsert_meta(&pool, spec("inst-a", "alice", chat, art))
                .await
                .unwrap();
            sqlx::query(
                "UPDATE artefact_cache SET cached_at = ? \
                 WHERE instance_id = 'inst-a' AND artefact_id = ?",
            )
            .bind(100 + idx as i64)
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        }

        let page = list_for_instance_page(&pool, "alice", "inst-a", None, 2, 1)
            .await
            .unwrap();
        assert_eq!(
            page.iter()
                .map(|r| r.artefact_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a3", "a2"],
        );

        let chat_page = list_for_instance_page(&pool, "alice", "inst-a", Some("c1"), 10, 0)
            .await
            .unwrap();
        assert_eq!(
            chat_page
                .iter()
                .map(|r| r.artefact_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a3", "a1"],
        );

        let owner_page = list_for_owner_page(&pool, "alice", 2, 2).await.unwrap();
        assert_eq!(
            owner_page
                .iter()
                .map(|r| r.artefact_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a2", "a1"],
        );
    }

    #[tokio::test]
    async fn delete_is_owner_scoped() {
        let pool = open_in_memory().await.unwrap();
        upsert_meta(&pool, spec("inst-a", "alice", "c1", "a1"))
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
