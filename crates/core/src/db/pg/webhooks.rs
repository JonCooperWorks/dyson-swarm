//! sqlx-backed `WebhookStore` and `DeliveryStore` impls.
//!
//! Webhook signing keys live in `user_secrets` (sealed under the
//! owner's age cipher) and are referenced by `secret_name`.  Delivery
//! rows persist metadata for every fire plus the request body sealed
//! under the same owner cipher (the store sees opaque ciphertext; the
//! service layer in `crate::webhooks` does the seal/open).

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::db::pg::map_sqlx;
use crate::error::StoreError;
use crate::traits::{DeliveryRow, DeliveryStore, WebhookAuthScheme, WebhookRow, WebhookStore};

#[derive(Debug, Clone)]
pub struct PgWebhookStore {
    pool: PgPool,
}

impl PgWebhookStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone)]
pub struct PgDeliveryStore {
    pool: PgPool,
}

impl PgDeliveryStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn row_to_webhook(r: sqlx::postgres::PgRow) -> Result<WebhookRow, StoreError> {
    let scheme: String = r.try_get("auth_scheme").map_err(map_sqlx)?;
    let auth_scheme = WebhookAuthScheme::parse(&scheme)
        .ok_or_else(|| StoreError::Malformed(format!("unknown auth_scheme {scheme:?}")))?;
    Ok(WebhookRow {
        instance_id: r.try_get("instance_id").map_err(map_sqlx)?,
        name: r.try_get("name").map_err(map_sqlx)?,
        description: r.try_get("description").map_err(map_sqlx)?,
        auth_scheme,
        signature_header: r.try_get("signature_header").map_err(map_sqlx)?,
        verifier_mode: r.try_get("verifier_mode").map_err(map_sqlx)?,
        signature_algo: r.try_get("signature_algo").map_err(map_sqlx)?,
        signature_encoding: r.try_get("signature_encoding").map_err(map_sqlx)?,
        signature_prefix: r.try_get("signature_prefix").map_err(map_sqlx)?,
        signature_separator: r.try_get("signature_separator").map_err(map_sqlx)?,
        signature_value_split: r.try_get("signature_value_split").map_err(map_sqlx)?,
        timestamp_header: r.try_get("timestamp_header").map_err(map_sqlx)?,
        timestamp_skew_secs: r.try_get("timestamp_skew_secs").map_err(map_sqlx)?,
        payload_template: r.try_get("payload_template").map_err(map_sqlx)?,
        idempotency_header: r.try_get("idempotency_header").map_err(map_sqlx)?,
        bearer_path_token: r.try_get("bearer_path_token").map_err(map_sqlx)?,
        preset_id: r.try_get("preset_id").map_err(map_sqlx)?,
        secret_name: r.try_get("secret_name").map_err(map_sqlx)?,
        enabled: r.try_get::<i64, _>("enabled").map_err(map_sqlx)? != 0,
        created_at: r.try_get("created_at").map_err(map_sqlx)?,
        updated_at: r.try_get("updated_at").map_err(map_sqlx)?,
    })
}

#[async_trait]
impl WebhookStore for PgWebhookStore {
    async fn put(&self, row: &WebhookRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO instance_webhooks \
                (instance_id, name, description, auth_scheme, signature_header, secret_name, \
                 enabled, created_at, updated_at, verifier_mode, signature_algo, signature_encoding, \
                 signature_prefix, signature_separator, signature_value_split, timestamp_header, \
                 timestamp_skew_secs, payload_template, idempotency_header, bearer_path_token, preset_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) \
             ON CONFLICT(instance_id, name) DO UPDATE SET \
                description = excluded.description, \
                auth_scheme = excluded.auth_scheme, \
                signature_header = excluded.signature_header, \
                secret_name = excluded.secret_name, \
                enabled     = excluded.enabled, \
                updated_at  = excluded.updated_at, \
                verifier_mode = excluded.verifier_mode, \
                signature_algo = excluded.signature_algo, \
                signature_encoding = excluded.signature_encoding, \
                signature_prefix = excluded.signature_prefix, \
                signature_separator = excluded.signature_separator, \
                signature_value_split = excluded.signature_value_split, \
                timestamp_header = excluded.timestamp_header, \
                timestamp_skew_secs = excluded.timestamp_skew_secs, \
                payload_template = excluded.payload_template, \
                idempotency_header = excluded.idempotency_header, \
                bearer_path_token = excluded.bearer_path_token, \
                preset_id = excluded.preset_id",
        )
        .bind(&row.instance_id)
        .bind(&row.name)
        .bind(&row.description)
        .bind(row.auth_scheme.as_str())
        .bind(&row.signature_header)
        .bind(&row.secret_name)
        .bind(i64::from(row.enabled))
        .bind(row.created_at)
        .bind(row.updated_at)
        .bind(&row.verifier_mode)
        .bind(&row.signature_algo)
        .bind(&row.signature_encoding)
        .bind(&row.signature_prefix)
        .bind(&row.signature_separator)
        .bind(&row.signature_value_split)
        .bind(&row.timestamp_header)
        .bind(row.timestamp_skew_secs)
        .bind(&row.payload_template)
        .bind(&row.idempotency_header)
        .bind(&row.bearer_path_token)
        .bind(&row.preset_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, instance_id: &str, name: &str) -> Result<Option<WebhookRow>, StoreError> {
        let row = sqlx::query(
            "SELECT instance_id, name, description, auth_scheme, signature_header, secret_name, \
                    enabled, created_at, updated_at, verifier_mode, signature_algo, signature_encoding, \
                    signature_prefix, signature_separator, signature_value_split, timestamp_header, \
                    timestamp_skew_secs, payload_template, idempotency_header, bearer_path_token, preset_id \
             FROM instance_webhooks \
             WHERE instance_id = $1 AND name = $2",
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
            "SELECT instance_id, name, description, auth_scheme, signature_header, secret_name, \
                    enabled, created_at, updated_at, verifier_mode, signature_algo, signature_encoding, \
                    signature_prefix, signature_separator, signature_value_split, timestamp_header, \
                    timestamp_skew_secs, payload_template, idempotency_header, bearer_path_token, preset_id \
             FROM instance_webhooks \
             WHERE instance_id = $1 \
             ORDER BY name",
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_webhook).collect()
    }

    async fn delete(&self, instance_id: &str, name: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM instance_webhooks WHERE instance_id = $1 AND name = $2")
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
            "UPDATE instance_webhooks SET enabled = $1, updated_at = $2 \
             WHERE instance_id = $3 AND name = $4",
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
            signature_header: existing.signature_header,
            verifier_mode: existing.verifier_mode,
            signature_algo: existing.signature_algo,
            signature_encoding: existing.signature_encoding,
            signature_prefix: existing.signature_prefix,
            signature_separator: existing.signature_separator,
            signature_value_split: existing.signature_value_split,
            timestamp_header: existing.timestamp_header,
            timestamp_skew_secs: existing.timestamp_skew_secs,
            payload_template: existing.payload_template,
            idempotency_header: existing.idempotency_header,
            bearer_path_token: existing.bearer_path_token,
            preset_id: existing.preset_id,
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
impl DeliveryStore for PgDeliveryStore {
    async fn insert(&self, row: &DeliveryRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO webhook_deliveries \
                (id, instance_id, webhook_name, fired_at, status_code, \
                 latency_ms, request_id, signature_ok, error, \
                 body, body_size, content_type, verify_error, request_headers, \
                 replayed_from_delivery_id, replayed_by_user_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
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
        .bind(&row.verify_error)
        .bind(&row.request_headers)
        .bind(&row.replayed_from_delivery_id)
        .bind(&row.replayed_by_user_id)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn try_mark_delivery_seen(
        &self,
        webhook_row_id: &str,
        idempotency_key: &str,
        first_seen_at: i64,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "INSERT INTO webhook_deliveries_seen \
                (webhook_row_id, idempotency_key, first_seen_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT(webhook_row_id, idempotency_key) DO NOTHING",
        )
        .bind(webhook_row_id)
        .bind(idempotency_key)
        .bind(first_seen_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(res.rows_affected() == 1)
    }

    async fn sweep_seen_deliveries_before(&self, cutoff: i64) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM webhook_deliveries_seen WHERE first_seen_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(res.rows_affected())
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
                    verify_error, request_headers, replayed_from_delivery_id, \
                    replayed_by_user_id, body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = $1 AND webhook_name = $2 \
             ORDER BY fired_at DESC \
             LIMIT $3",
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
                    verify_error, request_headers, replayed_from_delivery_id, \
                    replayed_by_user_id, body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = $1",
        );
        let mut slot = 2;
        if webhook_name.is_some() {
            sql.push_str(&format!(" AND webhook_name = ${slot}"));
            slot += 1;
        }
        if before.is_some() {
            sql.push_str(&format!(" AND fired_at < ${slot}"));
            slot += 1;
        }
        if q.is_some() {
            sql.push_str(&format!(" AND LOWER(COALESCE(error, '')) LIKE ${slot}"));
            slot += 1;
        }
        sql.push_str(&format!(" ORDER BY fired_at DESC LIMIT ${slot}"));

        let mut query = sqlx::query(&sql).bind(instance_id);
        if let Some(name) = webhook_name {
            query = query.bind(name.to_owned());
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
                    verify_error, request_headers, replayed_from_delivery_id, \
                    replayed_by_user_id, body, body_size, content_type \
             FROM webhook_deliveries \
             WHERE instance_id = $1 AND id = $2",
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
                verify_error: r.try_get("verify_error").map_err(map_sqlx)?,
                request_headers: r.try_get("request_headers").map_err(map_sqlx)?,
                replayed_from_delivery_id: r
                    .try_get("replayed_from_delivery_id")
                    .map_err(map_sqlx)?,
                replayed_by_user_id: r.try_get("replayed_by_user_id").map_err(map_sqlx)?,
                body: r.try_get::<Option<Vec<u8>>, _>("body").map_err(map_sqlx)?,
                body_size: r.try_get("body_size").map_err(map_sqlx)?,
                content_type: r.try_get("content_type").map_err(map_sqlx)?,
            })),
        }
    }
}

fn metadata_row(r: sqlx::postgres::PgRow) -> Result<DeliveryRow, StoreError> {
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
        verify_error: r.try_get("verify_error").map_err(map_sqlx)?,
        request_headers: r.try_get("request_headers").map_err(map_sqlx)?,
        replayed_from_delivery_id: r.try_get("replayed_from_delivery_id").map_err(map_sqlx)?,
        replayed_by_user_id: r.try_get("replayed_by_user_id").map_err(map_sqlx)?,
        body: None,
        body_size: r.try_get("body_size").map_err(map_sqlx)?,
        content_type: r.try_get("content_type").map_err(map_sqlx)?,
    })
}
