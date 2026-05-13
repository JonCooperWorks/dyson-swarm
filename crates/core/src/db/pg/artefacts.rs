//! SQLite-backed store for the `artefact_cache` table — swarm's copy
//! of dyson-emitted artefact metadata and sealed body bytes.
//!
//! Identity is `(instance_id, chat_id, artefact_id)`.  `upsert_meta`
//! is the ingest hot path — called every time the share read path or
//! the swarm-side artefact list endpoint pulls fresh bytes from a
//! cube.  `update_body` stores the sealed body + size + mime once
//! the body has been sealed.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::now_secs;
use crate::traits::ArtefactCacheStore;

pub use crate::traits::{ArtefactUpsertSpec as UpsertSpec, CachedArtefact};

#[derive(Clone)]
pub struct PgArtefactStore {
    pool: PgPool,
}

impl PgArtefactStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ArtefactCacheStore for PgArtefactStore {
    async fn upsert_meta(&self, spec: UpsertSpec<'_>) -> Result<i64, StoreError> {
        upsert_meta(&self.pool, spec).await
    }

    async fn update_body(
        &self,
        id: i64,
        bytes: i64,
        mime: Option<&str>,
        body_ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        update_body(&self.pool, id, bytes, mime, body_ciphertext).await
    }

    async fn find(
        &self,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<Option<CachedArtefact>, StoreError> {
        find(&self.pool, instance_id, chat_id, artefact_id).await
    }

    async fn list_for_instance(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<Vec<CachedArtefact>, StoreError> {
        list_for_instance(&self.pool, owner_id, instance_id).await
    }

    async fn list_for_instance_page(
        &self,
        owner_id: &str,
        instance_id: &str,
        chat_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<CachedArtefact>, StoreError> {
        list_for_instance_page(&self.pool, owner_id, instance_id, chat_id, limit, offset).await
    }

    async fn list_for_owner(
        &self,
        owner_id: &str,
        limit: u32,
    ) -> Result<Vec<CachedArtefact>, StoreError> {
        list_for_owner(&self.pool, owner_id, limit).await
    }

    async fn list_for_owner_page(
        &self,
        owner_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<CachedArtefact>, StoreError> {
        list_for_owner_page(&self.pool, owner_id, limit, offset).await
    }

    async fn delete(
        &self,
        owner_id: &str,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
    ) -> Result<bool, StoreError> {
        delete(&self.pool, owner_id, instance_id, chat_id, artefact_id).await
    }
}

/// UPSERT the metadata. Returns the row id. We never overwrite
/// `body_ciphertext` here so a successful body write from a prior call
/// survives a subsequent metadata-only refresh.
pub async fn upsert_meta(pool: &PgPool, spec: UpsertSpec<'_>) -> Result<i64, StoreError> {
    let now = now_secs();
    // Use ON CONFLICT to keep the existing body bytes, bytes, mime when the
    // tuple is already cached — a metadata refresh shouldn't blow away
    // a known-good body.  cached_at IS bumped so the GC sees the row as
    // recently-touched.
    sqlx::query(
        "INSERT INTO artefact_cache \
            (instance_id, owner_id, chat_id, artefact_id, kind, title, \
             mime, bytes, body_ciphertext, metadata_json, created_at, cached_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NULL, 0, NULL, $7, $8, $9) \
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
         WHERE instance_id = $1 AND chat_id = $2 AND artefact_id = $3",
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
    pool: &PgPool,
    id: i64,
    bytes: i64,
    mime: Option<&str>,
    body_ciphertext: &[u8],
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE artefact_cache \
         SET bytes = $1, mime = $2, body_ciphertext = $3, cached_at = $4 \
         WHERE id = $5",
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
    pool: &PgPool,
    instance_id: &str,
    chat_id: &str,
    artefact_id: &str,
) -> Result<Option<CachedArtefact>, StoreError> {
    let row = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_ciphertext, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE instance_id = $1 AND chat_id = $2 AND artefact_id = $3",
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
    pool: &PgPool,
    owner_id: &str,
    instance_id: &str,
) -> Result<Vec<CachedArtefact>, StoreError> {
    list_for_instance_page(pool, owner_id, instance_id, None, u32::MAX, 0).await
}

/// Owner-scoped: one page of cached artefacts for an instance.
/// Optional `chat_id` narrows to a single dyson conversation.
pub async fn list_for_instance_page(
    pool: &PgPool,
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
         WHERE owner_id = $1 AND instance_id = $2",
    );
    if chat_id.is_some() {
        sql.push_str(" AND chat_id = $3");
    }
    let limit_slot = if chat_id.is_some() { 4 } else { 3 };
    let offset_slot = limit_slot + 1;
    sql.push_str(&format!(
        " ORDER BY cached_at DESC, id DESC LIMIT ${limit_slot} OFFSET ${offset_slot}"
    ));

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
    pool: &PgPool,
    owner_id: &str,
    limit: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    list_for_owner_page(pool, owner_id, limit, 0).await
}

/// Owner-scoped: one page across every instance.
pub async fn list_for_owner_page(
    pool: &PgPool,
    owner_id: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<CachedArtefact>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, owner_id, chat_id, artefact_id, \
                kind, title, mime, bytes, body_ciphertext, metadata_json, \
                created_at, cached_at \
         FROM artefact_cache \
         WHERE owner_id = $1 \
         ORDER BY cached_at DESC, id DESC \
         LIMIT $2 OFFSET $3",
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
    pool: &PgPool,
    owner_id: &str,
    instance_id: &str,
    chat_id: &str,
    artefact_id: &str,
) -> Result<bool, StoreError> {
    let r = sqlx::query(
        "DELETE FROM artefact_cache \
         WHERE owner_id = $1 AND instance_id = $2 AND chat_id = $3 AND artefact_id = $4",
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

fn row_to_cached(r: sqlx::postgres::PgRow) -> Result<CachedArtefact, StoreError> {
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
