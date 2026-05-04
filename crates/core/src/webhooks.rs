//! Per-instance webhooks ("tasks" in the SPA copy).
//!
//! - `WebhookService` glues:
//!     1. `WebhookStore`         — metadata (name, description, scheme, enabled)
//!     2. `UserSecretsService`   — signing keys (sealed under owner's age cipher)
//!     3. `DeliveryStore`        — audit log (metadata + sealed body)
//!     4. `WebhookDispatcher`    — posts into the agent's webhook chat
//!     5. `CipherDirectory`      — owner-keyed age ciphers; used to seal
//!                                 audit bodies at write time and open
//!                                 them on the detail-page read.
//!
//! Verification timing-attack defenses: HMAC compares use `subtle`'s
//! constant-time `ConstantTimeEq`; bearer compares use the same.
//!
//! Request bodies are kept for audit but sealed under the instance
//! owner's age cipher before insert, so a stolen SQLite file alone
//! does not expose historical webhook payloads — an attacker would
//! also need the owner's age key (kept outside the DB).  Body-text
//! search across rows is not available at the store layer for the
//! same reason: the bytes on disk are ciphertext.  `body_size` and
//! `error` remain plaintext for "what happened" queries.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use http::header::HeaderName;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::envelope::CipherDirectory;
use crate::error::StoreError;
use crate::instance::InstanceService;
use crate::secrets::{SecretsError, UserSecretsService};
use crate::traits::{
    DeliveryRow, DeliveryStore, InstanceRow, WebhookAuthScheme, WebhookRow, WebhookStore,
};

/// Sentinel that armored age ciphertext starts with.  We use this on
/// the read side to tell sealed bodies (current writes) apart from
/// legacy plaintext bodies that pre-date encryption — those open as-is
/// rather than going through the cipher.
///
/// `pub(crate)` so the artefact cache can use the same sentinel for
/// its on-disk legacy-fallback detection — the two stores share the
/// same age envelope shape and the same legacy-row posture.
pub(crate) const AGE_ARMOR_PREFIX: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// Maximum body size accepted at `/webhooks/<id>/<name>`.  Mirrors
/// dyson's `MAX_TURN_BODY` so we never accept a payload the agent
/// would refuse downstream.
pub const MAX_WEBHOOK_BODY: usize = 4 * 1024 * 1024;

/// Stable HTTP chat id prefix used by swarm webhook delivery inside
/// each dyson sandbox.  The webhook name is already slug-validated
/// (`[a-z0-9_-]`, max 64), so prefix + name is safe as a Dyson chat id
/// and stays within Dyson's requested-id limit of 80 chars.
pub const WEBHOOK_CHAT_ID_PREFIX: &str = "c-swarm-webhook-";
pub const WEBHOOK_CHAT_TITLE_PREFIX: &str = "Webhook: ";

/// Default page size for "recent deliveries" panel.  Caps higher to
/// keep the SPA's payload bounded; operators with shell access can
/// query the table directly.
pub const DEFAULT_DELIVERY_LIMIT: u32 = 50;
pub const MAX_DELIVERY_LIMIT: u32 = 200;
pub const DEFAULT_SIGNATURE_HEADER: &str = "x-swarm-signature";

/// Legacy convention for webhook signing keys when they lived in
/// `instance_secrets`.  Anything with this prefix is managed
/// infrastructure state and must never be exposed to an agent runtime.
pub const LEGACY_WEBHOOK_SECRET_PREFIX: &str = "_webhook_";

/// Convention for the `secret_name` column: signing keys are stored in
/// `user_secrets` under a per-instance, per-webhook key.  They verify
/// inbound webhooks only; they are not agent-readable runtime secrets.
pub const WEBHOOK_SECRET_PREFIX: &str = "webhook:";

pub fn webhook_secret_name(instance_id: &str, webhook_name: &str) -> String {
    format!("{WEBHOOK_SECRET_PREFIX}{instance_id}:{webhook_name}")
}

pub fn webhook_chat_id(webhook_name: &str) -> String {
    format!("{WEBHOOK_CHAT_ID_PREFIX}{webhook_name}")
}

pub fn webhook_chat_title(webhook_name: &str) -> String {
    format!("{WEBHOOK_CHAT_TITLE_PREFIX}{webhook_name}")
}

/// Lower-cased name accepted for the URL path.  Slug-ish: ascii
/// alnum, hyphen, underscore, 1..64.
pub fn validate_webhook_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("webhook name must not be empty");
    }
    if name.len() > 64 {
        return Err("webhook name too long (max 64 chars)");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("webhook name must be lowercase ascii alphanumerics, hyphens or underscores");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secrets(#[from] SecretsError),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("instance not yet ready (warming up)")]
    NotReady,
    #[error("dispatch failed: {0}")]
    Dispatch(String),
}

/// One ready-to-write spec.  `secret` is plaintext on the way in; the
/// service seals it via `UserSecretsService` and stores the resulting
/// `secret_name` pointer on the row.  `secret = None` is only valid for
/// `auth_scheme = None`; the service enforces this at PUT time.
#[derive(Debug, Clone)]
pub struct WebhookSpec {
    pub instance_id: String,
    pub name: String,
    pub description: String,
    pub auth_scheme: WebhookAuthScheme,
    /// Header to read for HMAC signatures. `None` keeps the existing
    /// value on update, or defaults to `x-swarm-signature` on create.
    pub signature_header: Option<String>,
    /// `Some(plaintext)` to (re)set the signing key, `None` to leave
    /// the existing secret in place (only meaningful on update).
    pub secret_plaintext: Option<String>,
    pub enabled: bool,
}

/// Anything that can deliver a verified webhook payload to a running
/// dyson sandbox.  Trait so tests can swap in a recorder without
/// standing up an agent HTTP server.
#[async_trait]
pub trait WebhookDispatcher: Send + Sync {
    /// Find or create the agent's stable webhook conversation and
    /// post the payload as the next turn.  `description` is the
    /// operator-authored task
    /// brief; `headers` is the safe-allowlisted header subset to
    /// forward; `body` is the raw inbound body bytes.
    ///
    /// Returns the agent's HTTP status on the *turn* call (the most
    /// meaningful one to surface in the delivery row).
    async fn dispatch(
        &self,
        instance: &InstanceRow,
        webhook_name: &str,
        description: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<u16, String>;
}

/// No-op dispatcher used in tests and any deployment that wants to
/// disable webhook delivery without removing the routes.  Always
/// returns 204 — but the caller's verify-and-log path is still
/// exercised, so signatures, audit rows, and rate limits all behave.
pub struct NullWebhookDispatcher;

#[async_trait]
impl WebhookDispatcher for NullWebhookDispatcher {
    async fn dispatch(
        &self,
        _: &InstanceRow,
        _: &str,
        _: &str,
        _: &[(String, String)],
        _: &[u8],
    ) -> Result<u16, String> {
        Ok(204)
    }
}

/// Default dispatcher: hits the cubeproxy hostname with the instance
/// bearer.  Mirrors how `dyson_proxy::forward` reaches the agent.
pub struct HttpWebhookDispatcher {
    http: reqwest::Client,
    sandbox_domain: String,
}

impl HttpWebhookDispatcher {
    pub fn new(http: reqwest::Client, sandbox_domain: impl Into<String>) -> Self {
        Self {
            http,
            sandbox_domain: sandbox_domain.into(),
        }
    }

    fn cube_port() -> u16 {
        std::env::var("SWARM_CUBE_INTERNAL_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(80)
    }

    fn cube_base_url(sandbox_domain: &str, port: u16, sandbox_id: &str) -> String {
        format!(
            "https://{port}-{sandbox_id}.{}",
            sandbox_domain.trim_end_matches('/')
        )
    }

    async fn ensure_webhook_chat_id(
        &self,
        base: &str,
        bearer: &str,
        webhook_name: &str,
    ) -> Result<String, String> {
        let target_id = webhook_chat_id(webhook_name);
        let target_title = webhook_chat_title(webhook_name);
        let list_resp = self
            .http
            .get(format!("{base}/api/conversations"))
            .header("Authorization", bearer)
            .send()
            .await
            .map_err(|e| format!("list-conversations send: {e}"))?;
        let list_status = list_resp.status();
        if !list_status.is_success() {
            let body = list_resp.text().await.unwrap_or_default();
            return Err(format!("list-conversations {list_status}: {body}"));
        }
        let conversations: Vec<ConversationSummary> = list_resp
            .json()
            .await
            .map_err(|e| format!("list-conversations parse: {e}"))?;
        if let Some(existing) = find_webhook_chat(&conversations, &target_id, &target_title) {
            return Ok(existing.to_string());
        }

        let create_resp = self
            .http
            .post(format!("{base}/api/conversations"))
            .header("Authorization", bearer)
            .header("X-Dyson-CSRF", "swarm-webhook")
            .json(&serde_json::json!({
                "id": target_id,
                "title": target_title,
            }))
            .send()
            .await
            .map_err(|e| format!("create-conversation send: {e}"))?;
        let create_status = create_resp.status();
        if !create_status.is_success() {
            let body = create_resp.text().await.unwrap_or_default();
            return Err(format!("create-conversation {create_status}: {body}"));
        }
        let created: CreateConversationResponse = create_resp
            .json()
            .await
            .map_err(|e| format!("create-conversation parse: {e}"))?;
        if created.id != webhook_chat_id(webhook_name) {
            tracing::debug!(
                requested = %webhook_chat_id(webhook_name),
                returned = %created.id,
                "dyson ignored requested webhook chat id; using returned compatibility chat"
            );
        }
        Ok(created.id)
    }
}

#[async_trait]
impl WebhookDispatcher for HttpWebhookDispatcher {
    async fn dispatch(
        &self,
        instance: &InstanceRow,
        webhook_name: &str,
        description: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<u16, String> {
        let Some(sandbox_id) = instance
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            return Err("instance has no cube sandbox id".into());
        };
        let port = Self::cube_port();
        let base = Self::cube_base_url(&self.sandbox_domain, port, sandbox_id);
        let bearer = format!("Bearer {}", instance.bearer_token);

        // 1. Find or create this webhook URL's stable conversation.
        let chat_id = self
            .ensure_webhook_chat_id(&base, &bearer, webhook_name)
            .await?;

        // 2. Compose the prompt and POST a turn.
        let prompt = render_prompt(description, headers, body);
        let turn_resp = self
            .http
            .post(format!(
                "{base}/api/conversations/{}/turn",
                urlencode(&chat_id)
            ))
            .header("Authorization", &bearer)
            .header("X-Dyson-CSRF", "swarm-webhook")
            .json(&serde_json::json!({ "prompt": prompt, "attachments": [] }))
            .send()
            .await
            .map_err(|e| format!("turn send: {e}"))?;
        let turn_status = turn_resp.status();
        if !turn_status.is_success() {
            let body = turn_resp.text().await.unwrap_or_default();
            return Err(format!("turn {turn_status}: {body}"));
        }
        Ok(turn_status.as_u16())
    }
}

#[derive(Debug, serde::Deserialize)]
struct ConversationSummary {
    id: String,
    title: String,
}

#[derive(Debug, serde::Deserialize)]
struct CreateConversationResponse {
    id: String,
}

fn find_webhook_chat<'a>(
    conversations: &'a [ConversationSummary],
    target_id: &str,
    target_title: &str,
) -> Option<&'a str> {
    conversations
        .iter()
        .find(|c| c.id == target_id || c.title == target_title)
        .map(|c| c.id.as_str())
}

/// Build the prompt shipped to the agent.  Bodies are best-effort
/// utf8-decoded and truncated; non-utf8 payloads land as a hex
/// hexdump-of-first-bytes rather than getting silently dropped.
fn render_prompt(description: &str, headers: &[(String, String)], body: &[u8]) -> String {
    let mut s = String::with_capacity(description.len() + body.len() + 256);
    if !description.trim().is_empty() {
        s.push_str(description.trim());
        s.push_str("\n\n");
    }
    s.push_str("---\nWebhook payload");
    if !headers.is_empty() {
        s.push_str(" (headers: ");
        for (i, (k, v)) in headers.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        s.push(')');
    }
    s.push_str(":\n");
    if let Ok(text) = std::str::from_utf8(body) {
        s.push_str(text);
    } else {
        // Cap binary payloads at 1KiB hex preview — nothing useful
        // beyond that fits in a turn prompt.
        let preview_len = body.len().min(1024);
        s.push_str("(non-utf8, hex preview): ");
        s.push_str(&hex::encode(&body[..preview_len]));
        if body.len() > preview_len {
            s.push_str("...");
        }
    }
    s
}

fn urlencode(s: &str) -> String {
    // Conservative: encode anything that isn't unreserved.  Used only
    // for `chat_id` (uuid) and webhook names (already validated to
    // ascii-alnum + - + _).
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved =
            b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~';
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Clone)]
pub struct WebhookService {
    webhooks: Arc<dyn WebhookStore>,
    deliveries: Arc<dyn DeliveryStore>,
    user_secrets: Arc<UserSecretsService>,
    instances: Arc<InstanceService>,
    dispatcher: Arc<dyn WebhookDispatcher>,
    /// Per-user age ciphers — used to seal audit bodies so the SQLite
    /// file can't be read offline to recover historical webhook
    /// payloads.  Same directory used by the secret services so we
    /// don't bring a second key namespace into the picture.
    ciphers: Arc<dyn CipherDirectory>,
}

impl WebhookService {
    pub fn new(
        webhooks: Arc<dyn WebhookStore>,
        deliveries: Arc<dyn DeliveryStore>,
        user_secrets: Arc<UserSecretsService>,
        instances: Arc<InstanceService>,
        dispatcher: Arc<dyn WebhookDispatcher>,
        ciphers: Arc<dyn CipherDirectory>,
    ) -> Self {
        Self {
            webhooks,
            deliveries,
            user_secrets,
            instances,
            dispatcher,
            ciphers,
        }
    }

    pub async fn list(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<Vec<WebhookRow>, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        Ok(self.webhooks.list_for_instance(instance_id).await?)
    }

    pub async fn get(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<WebhookRow, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        self.webhooks
            .get(instance_id, name)
            .await?
            .ok_or(WebhookError::NotFound)
    }

    /// Create OR update — idempotent.  When `auth_scheme` requires a
    /// secret, `spec.secret_plaintext` must be `Some(...)` on create
    /// or whenever the scheme is being switched.  On update with the
    /// same scheme, `None` leaves the existing secret in place.
    pub async fn put(&self, owner_id: &str, spec: WebhookSpec) -> Result<WebhookRow, WebhookError> {
        validate_webhook_name(&spec.name).map_err(|m| WebhookError::BadRequest(m.to_string()))?;
        self.ensure_owner(owner_id, &spec.instance_id).await?;

        let now = crate::now_secs();
        let existing = self.webhooks.get(&spec.instance_id, &spec.name).await?;
        let signature_header = match spec.signature_header.as_deref() {
            Some(raw) => validate_signature_header(raw)
                .map_err(|m| WebhookError::BadRequest(m.to_string()))?,
            None => existing
                .as_ref()
                .map(|r| r.signature_header.clone())
                .unwrap_or_else(|| DEFAULT_SIGNATURE_HEADER.to_string()),
        };

        // Resolve the secret pointer.  When the scheme needs a key,
        // we either (a) reuse the existing secret_name when no new
        // plaintext is provided AND the row already had one, or
        // (b) seal the new plaintext under the convention name.
        let secret_name = if spec.auth_scheme.needs_secret() {
            match (
                &spec.secret_plaintext,
                existing.as_ref().and_then(|r| r.secret_name.as_ref()),
            ) {
                (Some(plain), _) => {
                    let target = webhook_secret_name(&spec.instance_id, &spec.name);
                    self.user_secrets
                        .put(owner_id, &target, plain.as_bytes())
                        .await?;
                    Some(target)
                }
                (None, Some(prev)) => Some(prev.clone()),
                (None, None) => {
                    return Err(WebhookError::BadRequest(
                        "auth scheme requires a signing secret on first save".into(),
                    ));
                }
            }
        } else {
            // Auth = none — no secret needed.  If the row had one,
            // we leave the orphaned ciphertext in place rather than
            // deleting it; flipping back to a signed scheme will
            // overwrite the same name anyway, and removing it would
            // require an audit hop we don't need.
            None
        };

        let row = WebhookRow {
            instance_id: spec.instance_id,
            name: spec.name,
            description: spec.description,
            auth_scheme: spec.auth_scheme,
            signature_header,
            secret_name,
            enabled: spec.enabled,
            created_at: existing.as_ref().map(|r| r.created_at).unwrap_or(now),
            updated_at: now,
        };
        self.webhooks.put(&row).await?;
        Ok(row)
    }

    pub async fn delete(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<(), WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        // Cascade the linked signing key, best-effort.  A failed
        // secret delete is logged but doesn't block the row delete.
        if let Ok(Some(row)) = self.webhooks.get(instance_id, name).await
            && let Some(secret_name) = row.secret_name.as_deref()
            && let Err(e) = self.user_secrets.delete(owner_id, secret_name).await
        {
            tracing::warn!(
                instance = %instance_id, webhook = %name, error = %e,
                "webhook delete: linked secret cleanup failed"
            );
        }
        self.webhooks.delete(instance_id, name).await?;
        Ok(())
    }

    pub async fn set_enabled(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
        enabled: bool,
    ) -> Result<WebhookRow, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        self.webhooks
            .set_enabled(instance_id, name, enabled)
            .await?;
        self.webhooks
            .get(instance_id, name)
            .await?
            .ok_or(WebhookError::NotFound)
    }

    pub async fn list_deliveries(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
        limit: u32,
    ) -> Result<Vec<DeliveryRow>, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        let limit = limit.min(MAX_DELIVERY_LIMIT).max(1);
        Ok(self
            .deliveries
            .list_for_webhook(instance_id, name, limit)
            .await?)
    }

    /// Cross-task audit listing.  Owner-scoped at the entry point, then
    /// passes through to the store.  `webhook_name` narrows to a single
    /// task when the operator is filtering by name in the SPA; `q` is
    /// a substring match on the recorded error text (bodies are sealed
    /// at rest, so the store can't grep them); `before` is the cursor
    /// (the previous page's oldest `fired_at` value).
    pub async fn list_instance_deliveries(
        &self,
        owner_id: &str,
        instance_id: &str,
        webhook_name: Option<&str>,
        q: Option<&str>,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<DeliveryRow>, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        let limit = limit.min(MAX_DELIVERY_LIMIT).max(1);
        Ok(self
            .deliveries
            .list_for_instance(instance_id, webhook_name, q, before, limit)
            .await?)
    }

    /// Single delivery row including the request body — for the audit
    /// detail page.  Owner-scoped at the entry; the store also bounds
    /// the query by `instance_id` so a guessed delivery id can't reach
    /// into another tenant.
    ///
    /// Bodies are sealed under the owner's age cipher at write time.
    /// We open them here so callers see plaintext and don't have to
    /// know about the at-rest format.  Rows persisted before encryption
    /// shipped (legacy plaintext, no age armor header) pass through
    /// unchanged so the audit history stays readable.  A row whose
    /// ciphertext fails to open with the owner's current key (e.g.
    /// the key was rotated and the row is now orphaned) returns with
    /// `body = None`; a warning is logged so operators can see that
    /// some history is unrecoverable rather than silently empty.
    pub async fn get_delivery(
        &self,
        owner_id: &str,
        instance_id: &str,
        delivery_id: &str,
    ) -> Result<DeliveryRow, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        let mut row = self
            .deliveries
            .get_by_id(instance_id, delivery_id)
            .await?
            .ok_or(WebhookError::NotFound)?;
        if let Some(stored) = row.body.take() {
            row.body = self.open_audit_body(owner_id, &row.id, stored);
        }
        Ok(row)
    }

    fn open_audit_body(
        &self,
        owner_id: &str,
        delivery_id: &str,
        stored: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if !stored.starts_with(AGE_ARMOR_PREFIX) {
            // Legacy row written before bodies were sealed — surface
            // as-is so historical audits remain readable.
            return Some(stored);
        }
        match self.ciphers.for_user(owner_id) {
            Ok(cipher) => match cipher.open(&stored) {
                Ok(plain) => Some(plain),
                Err(e) => {
                    tracing::warn!(
                        delivery = %delivery_id, error = %e,
                        "webhook delivery: body decrypt failed (key rotated?) — surfacing as empty"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    delivery = %delivery_id, error = %e,
                    "webhook delivery: owner cipher unavailable — body suppressed"
                );
                None
            }
        }
    }

    /// Public-facing entrypoint.  Owner-LESS — verification replaces
    /// user auth.  Returns 4xx-shaped errors as `Err(...)` so the HTTP
    /// layer can map them; on success returns the agent's status code
    /// (typically 202 from the agent's own `POST /turn`).
    ///
    /// Always writes a `webhook_deliveries` row in the terminal arm so
    /// failed signatures show up alongside successes.
    pub async fn verify_and_dispatch(
        &self,
        instance_id: &str,
        name: &str,
        signature_headers: &[(String, String)],
        bearer_header: Option<&str>,
        request_id: Option<&str>,
        forward_headers: Vec<(String, String)>,
        content_type: Option<String>,
        body: &[u8],
    ) -> Result<u16, WebhookError> {
        let started = Instant::now();
        let res = self
            .verify_and_dispatch_inner(
                instance_id,
                name,
                signature_headers,
                bearer_header,
                &forward_headers,
                body,
            )
            .await;
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let (status_code, signature_ok, error_text) = match &res {
            Ok(s) => (i32::from(*s), true, None),
            Err(WebhookError::SignatureMismatch) => (401, false, Some("signature mismatch".into())),
            Err(WebhookError::NotFound) => (404, false, Some("not found".into())),
            Err(WebhookError::NotReady) => (503, true, Some("instance warming up".into())),
            Err(WebhookError::Dispatch(e)) => (502, true, Some(e.clone())),
            Err(WebhookError::BadRequest(m)) => (400, false, Some(m.clone())),
            Err(WebhookError::Store(e)) => (500, false, Some(e.to_string())),
            Err(WebhookError::Secrets(e)) => (500, false, Some(e.to_string())),
        };

        // Don't write a delivery row when the webhook itself was 404 —
        // the FK would fail (no such (instance_id, webhook_name) pair)
        // and a "delivery for a webhook that doesn't exist" row is
        // useless to operators anyway.
        if !matches!(res, Err(WebhookError::NotFound)) {
            // Seal the body under the instance owner's age cipher
            // before storing.  We need the owner_id, which the inner
            // call already resolved — re-resolve it here cheaply
            // rather than threading it back out (this path runs at
            // webhook-fire frequency, not per-request).  If the
            // owner can't be resolved (instance vanished mid-flight)
            // OR the seal fails, we drop the body and keep just the
            // metadata row so the audit trail still lands.
            let sealed_body = match self.seal_body_for_audit(instance_id, body).await {
                Ok(b) => b,
                Err(reason) => {
                    tracing::warn!(
                        instance = %instance_id, webhook = %name, %reason,
                        "webhook delivery: body seal failed; storing without body"
                    );
                    None
                }
            };
            let row = DeliveryRow {
                id: Uuid::new_v4().simple().to_string(),
                instance_id: instance_id.to_string(),
                webhook_name: name.to_string(),
                fired_at: crate::now_secs(),
                status_code,
                latency_ms: elapsed_ms,
                request_id: request_id.map(str::to_owned),
                signature_ok,
                error: error_text,
                // Audit storage: keep the body for every delivery we
                // accepted into the pipeline, sealed under the owner's
                // age cipher.  An attacker with read access to the
                // SQLite file alone can't recover historical webhook
                // payloads — they need the owner's age key too, which
                // lives outside the DB.  body_size always reflects the
                // *plaintext* length so audits can tell "no body" from
                // "body present" without decrypting.
                body: sealed_body,
                body_size: Some(i64::try_from(body.len()).unwrap_or(i64::MAX)),
                content_type,
            };
            if let Err(e) = self.deliveries.insert(&row).await {
                tracing::warn!(
                    instance = %instance_id, webhook = %name, error = %e,
                    "webhook delivery: log insert failed"
                );
            }
        }
        res
    }

    /// Resolve the instance owner and seal `body` under their age
    /// cipher.  Returns `Ok(None)` for empty bodies (nothing to seal).
    /// Returns `Err(reason)` on any failure so the caller can log and
    /// fall back to a body-less audit row.
    async fn seal_body_for_audit(
        &self,
        instance_id: &str,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        if body.is_empty() {
            return Ok(None);
        }
        let owner_id = self
            .instances
            .get_unscoped(instance_id)
            .await
            .map(|r| r.owner_id)
            .map_err(|e| format!("owner lookup: {e}"))?;
        let cipher = self
            .ciphers
            .for_user(&owner_id)
            .map_err(|e| format!("cipher: {e}"))?;
        let ct = cipher.seal(body).map_err(|e| format!("seal: {e}"))?;
        Ok(Some(ct))
    }

    async fn verify_and_dispatch_inner(
        &self,
        instance_id: &str,
        name: &str,
        signature_headers: &[(String, String)],
        bearer_header: Option<&str>,
        forward_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<u16, WebhookError> {
        let row = self
            .webhooks
            .get(instance_id, name)
            .await?
            .filter(|r| r.enabled)
            .ok_or(WebhookError::NotFound)?;

        // Fetch the instance row unscoped — owner check doesn't apply
        // here, the caller is anonymous and we've already proved
        // possession via signature (or no-auth was explicitly chosen).
        let instance = self
            .instances
            .get_unscoped(instance_id)
            .await
            .map_err(|_| WebhookError::NotFound)?;
        if instance.cube_sandbox_id.as_deref().unwrap_or("").is_empty() {
            return Err(WebhookError::NotReady);
        }
        let owner_id = instance.owner_id.clone();

        // Verify before fetching the secret for `none` (cheap path
        // first) so we avoid the round-trip when auth is disabled.
        match row.auth_scheme {
            WebhookAuthScheme::None => {}
            WebhookAuthScheme::Bearer => {
                let provided = bearer_header
                    .and_then(strip_bearer)
                    .ok_or(WebhookError::SignatureMismatch)?;
                let expected = self.load_secret(&owner_id, &row).await?;
                if !ct_eq(expected.as_bytes(), provided.as_bytes()) {
                    return Err(WebhookError::SignatureMismatch);
                }
            }
            WebhookAuthScheme::HmacSha256 => {
                let header = signature_header_value(signature_headers, &row.signature_header)
                    .ok_or(WebhookError::SignatureMismatch)?;
                let provided_hex = header.strip_prefix("sha256=").unwrap_or(header).trim();
                let provided =
                    hex::decode(provided_hex).map_err(|_| WebhookError::SignatureMismatch)?;
                let key = self.load_secret(&owner_id, &row).await?;
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| WebhookError::SignatureMismatch)?;
                mac.update(body);
                if mac.verify_slice(&provided).is_err() {
                    return Err(WebhookError::SignatureMismatch);
                }
            }
        }

        let status = self
            .dispatcher
            .dispatch(
                &instance,
                &row.name,
                &row.description,
                forward_headers,
                body,
            )
            .await
            .map_err(WebhookError::Dispatch)?;
        Ok(status)
    }

    async fn load_secret(&self, owner_id: &str, row: &WebhookRow) -> Result<String, WebhookError> {
        let secret_name = row
            .secret_name
            .as_deref()
            .ok_or(WebhookError::SignatureMismatch)?;
        let bytes = self
            .user_secrets
            .get(owner_id, secret_name)
            .await?
            .ok_or(WebhookError::SignatureMismatch)?;
        String::from_utf8(bytes).map_err(|_| WebhookError::SignatureMismatch)
    }

    async fn ensure_owner(&self, owner_id: &str, instance_id: &str) -> Result<(), WebhookError> {
        match self.instances.get(owner_id, instance_id).await {
            Ok(_) => Ok(()),
            Err(crate::error::SwarmError::NotFound) => Err(WebhookError::NotFound),
            Err(e) => Err(WebhookError::Dispatch(e.to_string())),
        }
    }
}

fn strip_bearer(h: &str) -> Option<&str> {
    let trimmed = h.trim();
    trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .map(str::trim)
}

fn validate_signature_header(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("signature header is required");
    }
    let name = HeaderName::from_bytes(trimmed.as_bytes())
        .map_err(|_| "signature header is not a valid HTTP header name")?;
    Ok(name.as_str().to_ascii_lowercase())
}

fn signature_header_value<'a>(headers: &'a [(String, String)], wanted: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_policy::NetworkPolicy;
    use crate::traits::{
        CreateSandboxArgs, CubeClient, InstanceRow, InstanceStatus, InstanceStore, SandboxInfo,
        SecretStore, SnapshotInfo, TokenStore, WebhookAuthScheme,
    };

    struct StubCube;

    #[async_trait::async_trait]
    impl CubeClient for StubCube {
        async fn create_sandbox(
            &self,
            _: CreateSandboxArgs,
        ) -> Result<SandboxInfo, crate::error::CubeError> {
            unreachable!()
        }

        async fn destroy_sandbox(&self, _: &str) -> Result<(), crate::error::CubeError> {
            unreachable!()
        }

        async fn snapshot_sandbox(
            &self,
            _: &str,
            _: &str,
        ) -> Result<SnapshotInfo, crate::error::CubeError> {
            unreachable!()
        }

        async fn delete_snapshot(&self, _: &str, _: &str) -> Result<(), crate::error::CubeError> {
            unreachable!()
        }
    }

    #[test]
    fn validate_name_accepts_slug() {
        assert!(validate_webhook_name("ping").is_ok());
        assert!(validate_webhook_name("github-deploy").is_ok());
        assert!(validate_webhook_name("with_underscore").is_ok());
        assert!(validate_webhook_name("a1b2c3").is_ok());
    }

    #[test]
    fn validate_name_rejects_uppercase() {
        assert!(validate_webhook_name("PING").is_err());
        assert!(validate_webhook_name("Ping").is_err());
    }

    #[test]
    fn validate_name_rejects_empty_or_too_long() {
        assert!(validate_webhook_name("").is_err());
        assert!(validate_webhook_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn validate_name_rejects_whitespace_or_special() {
        assert!(validate_webhook_name("hello world").is_err());
        assert!(validate_webhook_name("with/slash").is_err());
        assert!(validate_webhook_name("with.dot").is_err());
    }

    #[test]
    fn webhook_secret_name_scopes_to_instance() {
        assert_eq!(webhook_secret_name("i1", "ping"), "webhook:i1:ping");
    }

    #[tokio::test]
    async fn put_stores_verifier_key_outside_instance_secrets() {
        let pool = crate::db::open_in_memory().await.unwrap();
        let owner = "00000000000000a100000000000000a1";
        sqlx::query(
            "INSERT INTO users (id, subject, email, display_name, status, created_at, activated_at) \
             VALUES (?, ?, NULL, 'Webhook Owner', 'active', 0, 0)",
        )
        .bind(owner)
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> = Arc::new(
            crate::db::instances::SqlxInstanceStore::new(pool.clone(), system_cipher.clone()),
        );
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(crate::db::secrets::SqlxSecretStore::new(pool.clone()));
        let token_store: Arc<dyn TokenStore> = Arc::new(crate::db::tokens::SqlxTokenStore::new(
            pool.clone(),
            system_cipher,
        ));
        instances_store
            .create(InstanceRow {
                id: "i1".into(),
                owner_id: owner.into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: None,
                template_id: "tpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "bt".into(),
                pinned: false,
                expires_at: None,
                last_active_at: crate::now_secs(),
                last_probe_at: None,
                last_probe_status: None,
                created_at: crate::now_secs(),
                destroyed_at: None,
                rotated_to: None,
                network_policy: NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
        let instance_svc = Arc::new(InstanceService::new(
            Arc::new(StubCube),
            instances_store,
            secret_store.clone(),
            token_store,
            "http://swarm.test/llm",
        ));
        let user_secrets = Arc::new(UserSecretsService::new(
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone())),
            cipher_dir.clone(),
        ));
        let svc = WebhookService::new(
            Arc::new(crate::db::webhooks::SqlxWebhookStore::new(pool.clone())),
            Arc::new(crate::db::webhooks::SqlxDeliveryStore::new(pool.clone())),
            user_secrets.clone(),
            instance_svc,
            Arc::new(NullWebhookDispatcher),
            cipher_dir,
        );

        let row = svc
            .put(
                owner,
                WebhookSpec {
                    instance_id: "i1".into(),
                    name: "ping".into(),
                    description: "verify me".into(),
                    auth_scheme: WebhookAuthScheme::HmacSha256,
                    signature_header: None,
                    secret_plaintext: Some("super-secret".into()),
                    enabled: true,
                },
            )
            .await
            .unwrap();

        assert_eq!(row.secret_name.as_deref(), Some("webhook:i1:ping"));
        assert!(
            secret_store.list("i1").await.unwrap().is_empty(),
            "webhook verifier keys must not be stored in agent runtime secrets"
        );
        let stored = user_secrets
            .get(owner, "webhook:i1:ping")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8(stored).unwrap(), "super-secret");
    }

    #[tokio::test]
    async fn hmac_verify_uses_configured_signature_header() {
        let pool = crate::db::open_in_memory().await.unwrap();
        let owner = "00000000000000a100000000000000a1";
        sqlx::query(
            "INSERT INTO users (id, subject, email, display_name, status, created_at, activated_at) \
             VALUES (?, ?, NULL, 'Webhook Owner', 'active', 0, 0)",
        )
        .bind(owner)
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
        let keys_tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(crate::envelope::AgeCipherDirectory::new(keys_tmp.path()).unwrap());
        let system_cipher = cipher_dir.system().unwrap();
        let instances_store: Arc<dyn InstanceStore> = Arc::new(
            crate::db::instances::SqlxInstanceStore::new(pool.clone(), system_cipher.clone()),
        );
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(crate::db::secrets::SqlxSecretStore::new(pool.clone()));
        let token_store: Arc<dyn TokenStore> = Arc::new(crate::db::tokens::SqlxTokenStore::new(
            pool.clone(),
            system_cipher,
        ));
        instances_store
            .create(InstanceRow {
                id: "i1".into(),
                owner_id: owner.into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: Some("sb1".into()),
                template_id: "tpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "bt".into(),
                pinned: false,
                expires_at: None,
                last_active_at: crate::now_secs(),
                last_probe_at: None,
                last_probe_status: None,
                created_at: crate::now_secs(),
                destroyed_at: None,
                rotated_to: None,
                network_policy: NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
        let instance_svc = Arc::new(InstanceService::new(
            Arc::new(StubCube),
            instances_store,
            secret_store,
            token_store,
            "http://swarm.test/llm",
        ));
        let user_secrets = Arc::new(UserSecretsService::new(
            Arc::new(crate::db::secrets::SqlxUserSecretStore::new(pool.clone())),
            cipher_dir.clone(),
        ));
        let svc = WebhookService::new(
            Arc::new(crate::db::webhooks::SqlxWebhookStore::new(pool.clone())),
            Arc::new(crate::db::webhooks::SqlxDeliveryStore::new(pool.clone())),
            user_secrets,
            instance_svc,
            Arc::new(NullWebhookDispatcher),
            cipher_dir,
        );

        let row = svc
            .put(
                owner,
                WebhookSpec {
                    instance_id: "i1".into(),
                    name: "github".into(),
                    description: "handle github".into(),
                    auth_scheme: WebhookAuthScheme::HmacSha256,
                    signature_header: Some("X-Hub-Signature-256".into()),
                    secret_plaintext: Some("super-secret".into()),
                    enabled: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(row.signature_header, "x-hub-signature-256");

        let body = br#"{"zen":"keep it logically awesome"}"#;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"super-secret").unwrap();
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        let wrong_header = svc
            .verify_and_dispatch(
                "i1",
                "github",
                &[(DEFAULT_SIGNATURE_HEADER.into(), signature.clone())],
                None,
                None,
                Vec::new(),
                Some("application/json".into()),
                body,
            )
            .await
            .unwrap_err();
        assert!(matches!(wrong_header, WebhookError::SignatureMismatch));

        let status = svc
            .verify_and_dispatch(
                "i1",
                "github",
                &[("X-Hub-Signature-256".into(), signature)],
                None,
                Some("req-1"),
                Vec::new(),
                Some("application/json".into()),
                body,
            )
            .await
            .unwrap();
        assert_eq!(status, 204);
    }

    #[test]
    fn auth_scheme_roundtrip() {
        for s in [
            WebhookAuthScheme::HmacSha256,
            WebhookAuthScheme::Bearer,
            WebhookAuthScheme::None,
        ] {
            assert_eq!(WebhookAuthScheme::parse(s.as_str()), Some(s));
        }
        assert!(WebhookAuthScheme::parse("nonsense").is_none());
    }

    #[test]
    fn auth_scheme_needs_secret_only_when_authed() {
        assert!(WebhookAuthScheme::HmacSha256.needs_secret());
        assert!(WebhookAuthScheme::Bearer.needs_secret());
        assert!(!WebhookAuthScheme::None.needs_secret());
    }

    #[test]
    fn ct_eq_matches_eq_for_same_length() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
    }

    #[test]
    fn ct_eq_short_circuits_on_length() {
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn strip_bearer_handles_both_cases() {
        assert_eq!(strip_bearer("Bearer abc"), Some("abc"));
        assert_eq!(strip_bearer("bearer abc"), Some("abc"));
        assert_eq!(strip_bearer("abc"), None);
    }

    #[test]
    fn render_prompt_truncates_and_labels() {
        let s = render_prompt(
            "do thing",
            &[("X-Type".into(), "json".into())],
            b"{\"a\":1}",
        );
        assert!(s.contains("do thing"));
        assert!(s.contains("X-Type=json"));
        assert!(s.contains("{\"a\":1}"));
    }

    #[test]
    fn render_prompt_handles_non_utf8() {
        let s = render_prompt("brief", &[], &[0xff, 0xfe]);
        assert!(s.contains("non-utf8"));
        assert!(s.contains("fffe"));
    }

    #[test]
    fn webhook_chat_id_is_safe_and_distinct_per_webhook_name() {
        let mail = webhook_chat_id("mail");
        let github = webhook_chat_id("github");
        assert_eq!(mail, "c-swarm-webhook-mail");
        assert_eq!(github, "c-swarm-webhook-github");
        assert_ne!(mail, github);
        assert!(mail.starts_with("c-"));
        assert!(
            mail.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "webhook chat id must be safe as a dyson chat-history directory"
        );

        let max_name = "a".repeat(64);
        let max_id = webhook_chat_id(&max_name);
        assert_eq!(max_id.len(), 80, "must fit dyson's requested-id limit");
        assert!(
            max_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "webhook chat id must be safe as a dyson chat-history directory"
        );
    }

    #[test]
    fn find_webhook_chat_prefers_stable_id_or_compat_title() {
        let target_id = webhook_chat_id("mail");
        let target_title = webhook_chat_title("mail");
        let by_id = vec![
            ConversationSummary {
                id: "c-0001".into(),
                title: "other".into(),
            },
            ConversationSummary {
                id: target_id.clone(),
                title: "after restart".into(),
            },
        ];
        assert_eq!(
            find_webhook_chat(&by_id, &target_id, &target_title),
            Some(target_id.as_str())
        );

        let by_title = vec![ConversationSummary {
            id: "c-0002".into(),
            title: target_title.clone(),
        }];
        assert_eq!(
            find_webhook_chat(&by_title, &target_id, &target_title),
            Some("c-0002")
        );

        let github_id = webhook_chat_id("github");
        let github_title = webhook_chat_title("github");
        assert_eq!(
            find_webhook_chat(&by_title, &github_id, &github_title),
            None,
            "mail's compatibility title must not catch github deliveries"
        );
    }

    #[test]
    fn http_dispatcher_targets_cubeproxy_authority() {
        let base = HttpWebhookDispatcher::cube_base_url("cube.test/", 80, "sb-abc");
        assert_eq!(base, "https://80-sb-abc.cube.test");
    }
}
