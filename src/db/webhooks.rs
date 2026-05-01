//! sqlx-backed `WebhookStore` and `DeliveryStore` impls.
//!
//! Webhook signing keys live in `instance_secrets` (sealed under the
//! owner's age cipher) and are referenced by `secret_name`.  Delivery
//! rows persist metadata for every fire plus the request body sealed
//! under the same owner cipher (the store sees opaque ciphertext; the
//! service layer in `crate::webhooks` does the seal/open).

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::db::map_sqlx;
use crate::error::StoreError;
use crate::traits::{DeliveryRow, DeliveryStore, WebhookAuthScheme, WebhookRow, WebhookStore};

#[derive(Debug, Clone)]
pub struct SqlxWebhookStore {
    pool: SqlitePool,
}

impl SqlxWebhookStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone)]
pub struct SqlxDeliveryStore {
    pool: SqlitePool,
}

impl SqlxDeliveryStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn row_to_webhook(r: sqlx::sqlite::SqliteRow) -> Result<WebhookRow, StoreError> {
    let scheme: String = r.try_get("auth_scheme").map_err(map_sqlx)?;
    let auth_scheme = WebhookAuthScheme::parse(&scheme)
        .ok_or_else(|| StoreError::Malformed(format!("unknown auth_scheme {scheme:?}")))?;
    Ok(WebhookRow {
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        name: r.try_get("name").map_err(map_sqlx)?,
        description: r.try_get("description").map_err(map_sqlx)?,
        auth_scheme,
        secret_name: r.try_get("secret_name").map_err(map_sqlx)?,
        enabled: r.try_get::<i64, _>("enabled").map_err(map_sqlx)? != 0,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        updated_at: r.try_get("updated_at").map_err(map_sqlx)?,
    })
}

#[async_trait]
impl WebhookStore for SqlxWebhookStore {
    async fn put(&self, row: &WebhookRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO instance_webhooks \
                (instance_id, name, description, auth_scheme, secret_name, \
                 enabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(instance_id, name) DO UPDATE SET \
                description = excluded.description, \
                auth_scheme = excluded.auth_scheme, \
                secret_name = excluded.secret_name, \
                enabled     = excluded.enabled, \
                updated_at  = excluded.updated_at",
        )
        .bind(&row.instance_id)
        .bind(&row.name)
        .bind(&row.description)
        .bind(row.auth_scheme.as_str())
        .bind(&row.secret_name)
        .bind(i64::from(row.enabled))
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, instance_id: &str, name: &str) -> Result<Option<WebhookRow>, StoreError> {
        let row = sqlx::query(
            "SELECT instance_id, name, description, auth_scheme, secret_name, \
                    enabled, created_at, updated_at \
             FROM instance_webhooks \
             WHERE instance_id = ? AND name = ?",
        )
        .bind(instance_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match row {
            Some(r) => Ok(Some(row_to_webhook(r)?)),
            None => Ok(None),
        }
    }

    async fn list_for_instance(&self, instance_id: &str) -> Result<Vec<WebhookRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT instance_id, name, description, auth_scheme, secret_name, \
                    enabled, created_at, updated_at \
             FROM instance_webhooks \
             WHERE instance_id = ? \
             ORDER BY name",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_webhook).collect()
    }

    async fn delete(&self, instance_id: &str, name: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM instance_webhooks WHERE instance_id = ? AND name = ?")
            .bind(instance_id)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_enabled(
        &self,
        instance_id: &str,
        name: &str,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let now = crate::now_secs();
        let res = sqlx::query(
            "UPDATE instance_webhooks SET enabled = ?, updated_at = ? \
             WHERE instance_id = ? AND name = ?",
        )
        .bind(i64::from(enabled))
        .bind(now)
        .bind(instance_id)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update_fields(
        &self,
        instance_id: &str,
        name: &str,
        description: Option<&str>,
        auth_scheme: Option<WebhookAuthScheme>,
        secret_name: Option<Option<&str>>,
        enabled: Option<bool>,
    ) -> Result<(), StoreError> {
        // Read-modify-write so a partial PATCH doesn't have to compose
        // the variadic SQL.  The webhooks table is small and PATCH
        // calls are rare; correctness > a single-shot UPDATE.
        let Some(existing) = self.get(instance_id, name).await? else {
            return Err(StoreError::NotFound);
        };
        let next = WebhookRow {
            description: description
                .map(str::to_owned)
                .unwrap_or(existing.description),
            auth_scheme: auth_scheme.unwrap_or(existing.auth_scheme),
            secret_name: match secret_name {
                Some(v) => v.map(str::to_owned),
                None => existing.secret_name,
            },
            enabled: enabled.unwrap_or(existing.enabled),
            updated_at: crate::now_secs(),
            ..existing
        };
        self.put(&next).await
    }
}

#[async_trait]
impl DeliveryStore for SqlxDeliveryStore {
    async fn insert(&self, row: &DeliveryRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO webhook_deliveries \
                (id, instance_id, webhook_name, fired_at, status_code, \
                 latency_ms, request_id, signature_ok, error, \
                 body, body_size, content_type) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.instance_id)
        .bind(&row.webhook_name)
        .bind(row.fired_at)
        .bind(i64::from(row.status_code))
        .bind(row.latency_ms)
        .bind(&row.request_id)
        .bind(i64::from(row.signature_ok))
        .bind(&row.error)
        .bind(row.body.as_deref())
        .bind(row.body_size)
        .bind(&row.content_type)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_for_webhook(
        &self,
        instance_id: &str,
        webhook_name: &str,
        limit: u32,
    ) -> Result<Vec<DeliveryRow>, StoreError> {
        // Deliberately omit `body` from the projection — the SPA's
        // recent-deliveries panel is the only consumer and the body
        // is operator-only audit material.  `body_size` and
        // `content_type` go on the wire so the panel can show
        // "<n> bytes / <ctype>" without exposing the payload.
        let rows = sqlx::query(
            "SELECT id, instance_id, webhook_name, fired_at, status_code, \
                    latency_ms, request_id, signature_ok, error, \
                    body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = ? AND webhook_name = ? \
             ORDER BY fired_at DESC \
             LIMIT ?",
        )
        .bind(instance_id)
        .bind(webhook_name)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter().map(metadata_row).collect()
    }

    async fn list_for_instance(
        &self,
        instance_id: &str,
        webhook_name: Option<&str>,
        q: Option<&str>,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<DeliveryRow>, StoreError> {
        // Same projection rule as `list_for_webhook` — body bytes only
        // come down the wire on the detail page.  We compose the
        // optional filters with positional placeholders rather than
        // string-concat'ing the values: SQLite treats bound parameters
        // as data, never as SQL.
        //
        // For `q`: matches against the recorded error string only.
        // Bodies are sealed under the owner's age cipher (the service
        // layer in `crate::webhooks` does the seal), so a SQL-side
        // substring search would only ever hit ciphertext bytes, which
        // is useless.  Operators searching payload contents need to
        // scan with the cipher loaded — out of scope for the store.
        let mut sql = String::from(
            "SELECT id, instance_id, webhook_name, fired_at, status_code, \
                    latency_ms, request_id, signature_ok, error, \
                    body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = ?",
        );
        if webhook_name.is_some() {
            sql.push_str(" AND webhook_name = ?");
        }
        if before.is_some() {
            sql.push_str(" AND fired_at < ?");
        }
        if q.is_some() {
            sql.push_str(" AND LOWER(COALESCE(error, '')) LIKE ?");
        }
        sql.push_str(" ORDER BY fired_at DESC LIMIT ?");

        let mut query = sqlx::query(&sql).bind(instance_id);
        if let Some(name) = webhook_name {
            query = query.bind(name.to_string());
        }
        if let Some(before) = before {
            query = query.bind(before);
        }
        if let Some(needle) = q {
            let like = format!("%{}%", needle.to_lowercase());
            query = query.bind(like);
        }
        query = query.bind(i64::from(limit));

        let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter().map(metadata_row).collect()
    }

    async fn get_by_id(
        &self,
        instance_id: &str,
        delivery_id: &str,
    ) -> Result<Option<DeliveryRow>, StoreError> {
        // Detail-page projection: includes `body` so an operator can
        // see exactly what the agent received.  Owner scoping happens
        // at the service layer; the `instance_id` predicate is the
        // last line of defence in case a caller routes around it.
        let row = sqlx::query(
            "SELECT id, instance_id, webhook_name, fired_at, status_code, \
                    latency_ms, request_id, signature_ok, error, \
                    body, body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = ? AND id = ?",
        )
        .bind(instance_id)
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(DeliveryRow {
                id: r.try_get("id").map_err(map_sqlx)?,
                instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
                webhook_name: r.try_get("webhook_name").map_err(map_sqlx)?,
                fired_at: r.try_get("fired_at").map_err(map_sqlx)?,
                status_code: r.try_get::<i64, _>("status_code").map_err(map_sqlx)? as i32,
                latency_ms: r.try_get("latency_ms").map_err(map_sqlx)?,
                request_id: r.try_get("request_id").map_err(map_sqlx)?,
                signature_ok: r.try_get::<i64, _>("signature_ok").map_err(map_sqlx)? != 0,
                error: r.try_get("error").map_err(map_sqlx)?,
                body: r.try_get::<Option<Vec<u8>>, _>("body").map_err(map_sqlx)?,
                body_size: r.try_get("body_size").map_err(map_sqlx)?,
                content_type: r.try_get("content_type").map_err(map_sqlx)?,
            })),
        }
    }
}

fn metadata_row(r: sqlx::sqlite::SqliteRow) -> Result<DeliveryRow, StoreError> {
    Ok(DeliveryRow {
        id: r.try_get("id").map_err(map_sqlx)?,
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        webhook_name: r.try_get("webhook_name").map_err(map_sqlx)?,
        fired_at: r.try_get("fired_at").map_err(map_sqlx)?,
        status_code: r.try_get::<i64, _>("status_code").map_err(map_sqlx)? as i32,
        latency_ms: r.try_get("latency_ms").map_err(map_sqlx)?,
        request_id: r.try_get("request_id").map_err(map_sqlx)?,
        signature_ok: r.try_get::<i64, _>("signature_ok").map_err(map_sqlx)? != 0,
        error: r.try_get("error").map_err(map_sqlx)?,
        body: None,
        body_size: r.try_get("body_size").map_err(map_sqlx)?,
        content_type: r.try_get("content_type").map_err(map_sqlx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::traits::{InstanceRow, InstanceStatus, InstanceStore};

    async fn seed_instance(pool: sqlx::SqlitePool, id: &str) {
        crate::db::instances::SqlxInstanceStore::new(pool)
            .create(InstanceRow {
                id: id.into(),
                owner_id: "legacy".into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: None,
                template_id: "t".into(),
                status: InstanceStatus::Live,
                bearer_token: "b".into(),
                pinned: false,
                expires_at: None,
                last_active_at: 0,
                last_probe_at: None,
                last_probe_status: None,
                created_at: 0,
                destroyed_at: None,
                rotated_to: None,
                network_policy: crate::network_policy::NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
    }

    fn row(instance: &str, name: &str) -> WebhookRow {
        WebhookRow {
            instance_id: instance.into(),
            name: name.into(),
            description: "do the thing".into(),
            auth_scheme: WebhookAuthScheme::HmacSha256,
            secret_name: Some(format!("_webhook_{name}")),
            enabled: true,
            created_at: 100,
            updated_at: 100,
        }
    }

    #[tokio::test]
    async fn put_get_list_roundtrip() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool);

        store.put(&row("i1", "ping")).await.unwrap();
        store.put(&row("i1", "deploy")).await.unwrap();

        let got = store.get("i1", "ping").await.unwrap().unwrap();
        assert_eq!(got.name, "ping");
        assert!(got.enabled);
        assert_eq!(got.auth_scheme, WebhookAuthScheme::HmacSha256);

        let listed = store.list_for_instance("i1").await.unwrap();
        assert_eq!(
            listed.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["deploy", "ping"]
        );
    }

    #[tokio::test]
    async fn put_is_idempotent_upsert() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool);

        let mut r = row("i1", "ping");
        store.put(&r).await.unwrap();
        r.description = "new desc".into();
        r.updated_at = 200;
        store.put(&r).await.unwrap();

        let got = store.get("i1", "ping").await.unwrap().unwrap();
        assert_eq!(got.description, "new desc");
        assert_eq!(got.updated_at, 200);
    }

    #[tokio::test]
    async fn set_enabled_flips_bit() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool);
        store.put(&row("i1", "ping")).await.unwrap();

        store.set_enabled("i1", "ping", false).await.unwrap();
        let got = store.get("i1", "ping").await.unwrap().unwrap();
        assert!(!got.enabled);

        store.set_enabled("i1", "ping", true).await.unwrap();
        let got = store.get("i1", "ping").await.unwrap().unwrap();
        assert!(got.enabled);
    }

    #[tokio::test]
    async fn set_enabled_unknown_is_not_found() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool);
        let err = store.set_enabled("i1", "missing", false).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[tokio::test]
    async fn delete_cascades_with_instance() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool.clone());
        store.put(&row("i1", "ping")).await.unwrap();

        // Destroy the instance row — FK cascade should remove the webhook.
        sqlx::query("DELETE FROM instances WHERE id = ?")
            .bind("i1")
            .execute(&pool)
            .await
            .unwrap();
        assert!(store.list_for_instance("i1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delivery_log_orders_newest_first() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let webhooks = SqlxWebhookStore::new(pool.clone());
        webhooks.put(&row("i1", "ping")).await.unwrap();
        let deliveries = SqlxDeliveryStore::new(pool);

        for (i, ts) in [100i64, 200, 150].into_iter().enumerate() {
            deliveries
                .insert(&DeliveryRow {
                    id: format!("d-{i}"),
                    instance_id: "i1".into(),
                    webhook_name: "ping".into(),
                    fired_at: ts,
                    status_code: 204,
                    latency_ms: 10,
                    request_id: None,
                    signature_ok: true,
                    error: None,
                    body: None,
                    body_size: None,
                    content_type: None,
                })
                .await
                .unwrap();
        }

        let listed = deliveries.list_for_webhook("i1", "ping", 10).await.unwrap();
        let timestamps: Vec<_> = listed.iter().map(|r| r.fired_at).collect();
        assert_eq!(timestamps, vec![200, 150, 100]);
    }

    #[tokio::test]
    async fn instance_audit_list_paginates_and_searches() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        seed_instance(pool.clone(), "i2").await;
        let webhooks = SqlxWebhookStore::new(pool.clone());
        webhooks.put(&row("i1", "ping")).await.unwrap();
        webhooks.put(&row("i1", "deploy")).await.unwrap();
        webhooks.put(&row("i2", "ping")).await.unwrap();
        let deliveries = SqlxDeliveryStore::new(pool);

        let mk = |id: &str,
                  instance: &str,
                  name: &str,
                  ts: i64,
                  body: &[u8],
                  error: Option<&str>|
         -> DeliveryRow {
            DeliveryRow {
                id: id.into(),
                instance_id: instance.into(),
                webhook_name: name.into(),
                fired_at: ts,
                status_code: 204,
                latency_ms: 10,
                request_id: None,
                signature_ok: true,
                error: error.map(str::to_owned),
                body: Some(body.to_vec()),
                body_size: Some(body.len() as i64),
                content_type: Some("application/json".into()),
            }
        };
        deliveries
            .insert(&mk(
                "a",
                "i1",
                "ping",
                100,
                b"{\"action\":\"opened\"}",
                Some("upstream timeout"),
            ))
            .await
            .unwrap();
        deliveries
            .insert(&mk("b", "i1", "deploy", 200, b"{\"ref\":\"main\"}", None))
            .await
            .unwrap();
        deliveries
            .insert(&mk(
                "c",
                "i1",
                "ping",
                300,
                b"{\"action\":\"closed\"}",
                None,
            ))
            .await
            .unwrap();
        deliveries
            .insert(&mk("d", "i2", "ping", 400, b"other tenant", None))
            .await
            .unwrap();

        let listed = deliveries
            .list_for_instance("i1", None, None, None, 10)
            .await
            .unwrap();
        assert_eq!(
            listed.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["c", "b", "a"],
        );
        assert!(listed.iter().all(|r| r.body.is_none()));

        let page1 = deliveries
            .list_for_instance("i1", None, None, None, 2)
            .await
            .unwrap();
        assert_eq!(
            page1.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["c", "b"]
        );
        let cursor = page1.last().unwrap().fired_at;
        let page2 = deliveries
            .list_for_instance("i1", None, None, Some(cursor), 2)
            .await
            .unwrap();
        assert_eq!(
            page2.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );

        let pings = deliveries
            .list_for_instance("i1", Some("ping"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(
            pings.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["c", "a"]
        );

        // `q` is now an error-text substring search.  Bodies are
        // sealed at the service layer so the store can't grep them.
        let timeouts = deliveries
            .list_for_instance("i1", None, Some("TIMEOUT"), None, 10)
            .await
            .unwrap();
        assert_eq!(
            timeouts.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
    }

    #[tokio::test]
    async fn get_by_id_includes_body_and_scopes_to_instance() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        seed_instance(pool.clone(), "i2").await;
        let webhooks = SqlxWebhookStore::new(pool.clone());
        webhooks.put(&row("i1", "ping")).await.unwrap();
        let deliveries = SqlxDeliveryStore::new(pool);

        deliveries
            .insert(&DeliveryRow {
                id: "d1".into(),
                instance_id: "i1".into(),
                webhook_name: "ping".into(),
                fired_at: 100,
                status_code: 204,
                latency_ms: 5,
                request_id: Some("req-1".into()),
                signature_ok: true,
                error: None,
                body: Some(b"{\"hello\":\"world\"}".to_vec()),
                body_size: Some(17),
                content_type: Some("application/json".into()),
            })
            .await
            .unwrap();

        let got = deliveries.get_by_id("i1", "d1").await.unwrap().unwrap();
        assert_eq!(
            got.body.as_deref(),
            Some(b"{\"hello\":\"world\"}".as_slice())
        );
        assert_eq!(got.content_type.as_deref(), Some("application/json"));

        assert!(deliveries.get_by_id("i2", "d1").await.unwrap().is_none());
        assert!(
            deliveries
                .get_by_id("i1", "missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn update_fields_partial_patch() {
        let pool = open_in_memory().await.unwrap();
        seed_instance(pool.clone(), "i1").await;
        let store = SqlxWebhookStore::new(pool);
        store.put(&row("i1", "ping")).await.unwrap();

        store
            .update_fields(
                "i1",
                "ping",
                Some("updated description"),
                Some(WebhookAuthScheme::Bearer),
                None,
                None,
            )
            .await
            .unwrap();

        let got = store.get("i1", "ping").await.unwrap().unwrap();
        assert_eq!(got.description, "updated description");
        assert_eq!(got.auth_scheme, WebhookAuthScheme::Bearer);
        assert!(got.enabled);
        assert_eq!(got.secret_name.as_deref(), Some("_webhook_ping"));
    }
}
