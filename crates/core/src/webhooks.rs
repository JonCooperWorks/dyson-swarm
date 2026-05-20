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
//! owner's age cipher before insert, so a stolen store file alone
//! does not expose historical webhook payloads — an attacker would
//! also need the owner's age key (kept outside the DB).  Body-text
//! search across rows is not available at the store layer for the
//! same reason: the bytes on disk are ciphertext.  `body_size` and
//! `error` remain plaintext for "what happened" queries.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use http::header::HeaderName;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::envelope::{
    CipherDirectory, KmsContext, KmsScope, SecretAccessReason, is_v2_envelope, open_context,
    seal_context,
};
use crate::error::StoreError;
use crate::http::InternalHttpClient;
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

pub struct DispatchCtx<'a> {
    pub instance_id: &'a str,
    pub name: &'a str,
    pub signature_headers: &'a [(String, String)],
    pub bearer_header: Option<&'a str>,
    pub bearer_path_token: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub forward_headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: &'a [u8],
}

/// Convention for the `secret_name` column: signing keys are stored in
/// `user_secrets` under a per-instance, per-webhook key.  They verify
/// inbound webhooks only; they are not agent-readable runtime secrets.
pub const WEBHOOK_SECRET_PREFIX: &str = "webhook:";

pub fn webhook_secret_name(instance_id: &str, webhook_name: &str) -> String {
    format!("{WEBHOOK_SECRET_PREFIX}{instance_id}:{webhook_name}")
}

pub fn webhook_row_key(instance_id: &str, webhook_name: &str) -> String {
    format!("{instance_id}:{webhook_name}")
}

pub fn webhook_chat_id(webhook_name: &str) -> String {
    format!("{WEBHOOK_CHAT_ID_PREFIX}{webhook_name}")
}

pub fn webhook_chat_title(webhook_name: &str) -> String {
    format!("{WEBHOOK_CHAT_TITLE_PREFIX}{webhook_name}")
}

fn webhook_delivery_context(owner_id: &str, instance_id: &str, webhook_name: &str) -> KmsContext {
    KmsContext::user_scoped(
        KmsScope::WebhookDelivery,
        owner_id.to_owned(),
        Some(instance_id.to_owned()),
        Some(webhook_name.to_owned()),
    )
}

pub fn clamp_delivery_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_DELIVERY_LIMIT)
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
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("replay deduped: {0}")]
    ReplayDeduped(String),
    #[error("instance not yet ready (warming up)")]
    NotReady,
    #[error("dispatch failed: {0}")]
    Dispatch(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookVerifierMode {
    None,
    HmacV2,
    BearerV2,
}

impl WebhookVerifierMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HmacV2 => "hmac_v2",
            Self::BearerV2 => "bearer_v2",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "none" => Some(Self::None),
            "hmac_v2" => Some(Self::HmacV2),
            "bearer_v2" => Some(Self::BearerV2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Sha256,
    Sha1,
    Sha512,
}

impl SignatureAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Sha512 => "sha512",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "sha256" => Some(Self::Sha256),
            "sha1" => Some(Self::Sha1),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEncoding {
    Hex,
    Base64,
}

impl SignatureEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base64 => "base64",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "hex" => Some(Self::Hex),
            "base64" => Some(Self::Base64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebhookVerifierConfig {
    pub mode: WebhookVerifierMode,
    pub signature_header: String,
    pub signature_algo: Option<SignatureAlgorithm>,
    pub signature_encoding: Option<SignatureEncoding>,
    pub signature_prefix: Option<String>,
    pub signature_separator: Option<String>,
    pub signature_value_split: Option<String>,
    pub timestamp_header: Option<String>,
    pub timestamp_skew_secs: Option<u64>,
    pub payload_template: Option<String>,
    pub idempotency_header: Option<String>,
    pub bearer_path_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyOutcome {
    pub rendered_payload: Option<Vec<u8>>,
    pub matched_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifyError {
    #[error("missing header {name}")]
    MissingHeader { name: String },
    #[error("missing timestamp")]
    MissingTimestamp,
    #[error("timestamp outside skew: now={now} ts={ts} skew_secs={skew_secs}")]
    TimestampOutOfSkew { now: i64, ts: i64, skew_secs: u64 },
    #[error("missing signature")]
    MissingSignature,
    #[error("malformed signature: {reason}")]
    MalformedSignature { reason: String },
    #[error("unknown signature version {version}")]
    UnknownVersion { version: String, known: Vec<String> },
    #[error("all signatures mismatched")]
    AllSignaturesMismatched,
    #[error("unknown template placeholder {name}")]
    UnknownPlaceholder { name: String },
    #[error("replay deduped: {key}")]
    ReplayDeduped { key: String },
}

impl VerifyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingHeader { .. } => "MissingHeader",
            Self::MissingTimestamp => "MissingTimestamp",
            Self::TimestampOutOfSkew { .. } => "TimestampOutOfSkew",
            Self::MissingSignature => "MissingSignature",
            Self::MalformedSignature { .. } => "MalformedSignature",
            Self::UnknownVersion { .. } => "UnknownVersion",
            Self::AllSignaturesMismatched => "AllSignaturesMismatched",
            Self::UnknownPlaceholder { .. } => "UnknownPlaceholder",
            Self::ReplayDeduped { .. } => "ReplayDeduped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebhookVerifierPreset {
    pub id: String,
    pub label: String,
    pub docs_url: String,
    pub verifier: WebhookVerifierConfig,
}

fn hmac_preset(
    id: &str,
    label: &str,
    docs_url: &str,
    signature_header: &str,
    encoding: SignatureEncoding,
    signature_prefix: Option<&str>,
    signature_separator: Option<&str>,
    signature_value_split: Option<&str>,
    timestamp_header: Option<&str>,
    payload_template: &str,
    idempotency_header: Option<&str>,
) -> WebhookVerifierPreset {
    WebhookVerifierPreset {
        id: id.to_owned(),
        label: label.to_owned(),
        docs_url: docs_url.to_owned(),
        verifier: WebhookVerifierConfig {
            mode: WebhookVerifierMode::HmacV2,
            signature_header: signature_header.to_owned(),
            signature_algo: Some(SignatureAlgorithm::Sha256),
            signature_encoding: Some(encoding),
            signature_prefix: signature_prefix.map(str::to_owned),
            signature_separator: signature_separator.map(str::to_owned),
            signature_value_split: signature_value_split.map(str::to_owned),
            timestamp_header: timestamp_header.map(str::to_owned),
            timestamp_skew_secs: Some(300),
            payload_template: Some(payload_template.to_owned()),
            idempotency_header: idempotency_header.map(str::to_owned),
            bearer_path_token: None,
        },
    }
}

pub fn webhook_presets() -> Vec<WebhookVerifierPreset> {
    vec![
        hmac_preset(
            "standard-webhooks",
            "Standard Webhooks",
            "https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md",
            "webhook-signature",
            SignatureEncoding::Base64,
            Some("v1,"),
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        ),
        hmac_preset(
            "github",
            "GitHub",
            "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
            "x-hub-signature-256",
            SignatureEncoding::Hex,
            Some("sha256="),
            None,
            Some("="),
            None,
            "{{body}}",
            Some("x-github-delivery"),
        ),
        hmac_preset(
            "stripe",
            "Stripe",
            "https://docs.stripe.com/webhooks/signature",
            "stripe-signature",
            SignatureEncoding::Hex,
            Some("v1="),
            Some(","),
            Some("="),
            Some("stripe-signature"),
            "{{timestamp}}.{{body}}",
            None,
        ),
        hmac_preset(
            "slack",
            "Slack",
            "https://api.slack.com/authentication/verifying-requests-from-slack",
            "x-slack-signature",
            SignatureEncoding::Hex,
            Some("v0="),
            None,
            Some("="),
            Some("x-slack-request-timestamp"),
            "v0:{{timestamp}}:{{body}}",
            None,
        ),
        hmac_preset(
            "shopify",
            "Shopify",
            "https://shopify.dev/docs/apps/build/webhooks/subscribe/https#step-2-validate-the-origin-of-your-webhook-to-ensure-its-coming-from-shopify",
            "x-shopify-hmac-sha256",
            SignatureEncoding::Base64,
            None,
            None,
            None,
            None,
            "{{body}}",
            Some("x-shopify-webhook-id"),
        ),
        svix_preset(),
    ]
}

pub fn webhook_preset(id: &str) -> Option<WebhookVerifierPreset> {
    webhook_presets().into_iter().find(|p| p.id == id)
}

pub fn svix_preset() -> WebhookVerifierPreset {
    // Svix documents the signed content as "<id>.<timestamp>.<raw body>"
    // and the space-delimited "v1,<base64>" signature format at
    // https://docs.svix.com/receiving/verifying-payloads/how-manual.
    hmac_preset(
        "svix",
        "Svix",
        "https://docs.svix.com/receiving/verifying-payloads/how-manual",
        "svix-signature",
        SignatureEncoding::Base64,
        Some("v1,"),
        Some(" "),
        Some(","),
        Some("svix-timestamp"),
        "{{id}}.{{timestamp}}.{{body}}",
        Some("svix-id"),
    )
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
    pub preset_id: Option<String>,
    pub verifier: Option<WebhookVerifierConfig>,
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
    http: InternalHttpClient,
    sandbox_domain: String,
}

impl HttpWebhookDispatcher {
    pub fn new(http: InternalHttpClient, sandbox_domain: impl Into<String>) -> Self {
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
            return Ok(existing.to_owned());
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
    /// Per-user age ciphers — used to seal audit bodies so the store
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
        validate_webhook_name(&spec.name).map_err(|m| WebhookError::BadRequest(m.to_owned()))?;
        self.ensure_owner(owner_id, &spec.instance_id).await?;

        let now = crate::now_secs();
        let existing = self.webhooks.get(&spec.instance_id, &spec.name).await?;
        let signature_header = match spec.signature_header.as_deref() {
            Some(raw) => validate_signature_header(raw)
                .map_err(|m| WebhookError::BadRequest(m.to_owned()))?,
            None => existing
                .as_ref()
                .map(|r| r.signature_header.clone())
                .unwrap_or_else(|| DEFAULT_SIGNATURE_HEADER.to_owned()),
        };
        let verifier = match spec.verifier.clone() {
            Some(verifier) => verifier,
            None => existing
                .as_ref()
                .map(row_verifier_config)
                .transpose()?
                .unwrap_or_else(|| default_verifier_config(spec.auth_scheme, signature_header)),
        };
        validate_verifier_config(&verifier).map_err(|e| WebhookError::BadRequest(e.to_string()))?;
        if let Some(preset_id) = spec.preset_id.as_deref() {
            let preset = webhook_preset(preset_id).ok_or_else(|| {
                WebhookError::BadRequest(format!("unknown preset_id {preset_id}"))
            })?;
            if verifier != preset.verifier {
                return Err(WebhookError::BadRequest(format!(
                    "preset_id {preset_id} verifier config does not match the {label} preset",
                    label = preset.label
                )));
            }
        }

        // Resolve the secret pointer.  When the scheme needs a key,
        // we either (a) reuse the existing secret_name when no new
        // plaintext is provided AND the row already had one, or
        // (b) seal the new plaintext under the convention name.
        let secret_name = if verifier_needs_user_secret(&verifier) {
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
            signature_header: verifier.signature_header.clone(),
            verifier_mode: verifier.mode.as_str().to_owned(),
            signature_algo: verifier.signature_algo.map(|v| v.as_str().to_owned()),
            signature_encoding: verifier.signature_encoding.map(|v| v.as_str().to_owned()),
            signature_prefix: verifier.signature_prefix.clone(),
            signature_separator: verifier.signature_separator.clone(),
            signature_value_split: verifier.signature_value_split.clone(),
            timestamp_header: verifier.timestamp_header.clone(),
            timestamp_skew_secs: verifier.timestamp_skew_secs.map(|v| v as i64),
            payload_template: verifier.payload_template.clone(),
            idempotency_header: verifier.idempotency_header.clone(),
            bearer_path_token: verifier.bearer_path_token.clone().or_else(|| {
                (verifier.mode == WebhookVerifierMode::BearerV2).then(random_path_token)
            }),
            preset_id: spec.preset_id,
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
        let limit = clamp_delivery_limit(limit);
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
        let limit = clamp_delivery_limit(limit);
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
            row.body =
                self.open_audit_body(owner_id, instance_id, &row.webhook_name, &row.id, stored);
        }
        Ok(row)
    }

    pub async fn verify_only(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
        headers: &[(String, String)],
        bearer_header: Option<&str>,
        bearer_path_token: Option<&str>,
        body: &[u8],
    ) -> Result<VerifyOutcome, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        let row = self
            .webhooks
            .get(instance_id, name)
            .await?
            .ok_or(WebhookError::NotFound)?;
        let verifier = row_verifier_config(&row)?;
        let secret = if verifier_needs_user_secret(&verifier) {
            Some(self.load_secret(owner_id, &row).await?)
        } else {
            None
        };
        verify_inbound_request(
            &verifier,
            secret.as_deref(),
            headers,
            bearer_header,
            bearer_path_token,
            body,
            crate::now_secs(),
        )
        .map_err(WebhookError::Verify)
    }

    pub async fn verify_only_last_failed(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<VerifyOutcome, WebhookError> {
        self.ensure_owner(owner_id, instance_id).await?;
        let failed = self
            .deliveries
            .list_for_webhook(instance_id, name, DEFAULT_DELIVERY_LIMIT)
            .await?
            .into_iter()
            .find(|row| !row.signature_ok || row.status_code >= 400 || row.verify_error.is_some())
            .ok_or(WebhookError::NotFound)?;
        let detail = self.get_delivery(owner_id, instance_id, &failed.id).await?;
        let headers = delivery_request_headers(detail.request_headers.as_deref());
        let body = detail.body.unwrap_or_default();
        self.verify_only(
            owner_id,
            instance_id,
            name,
            &headers,
            header_value_from_pairs(&headers, "authorization"),
            None,
            &body,
        )
        .await
    }

    pub async fn replay_delivery(
        &self,
        owner_id: &str,
        instance_id: &str,
        delivery_id: &str,
        replayed_by_user_id: &str,
    ) -> Result<u16, WebhookError> {
        let row = self
            .get_delivery(owner_id, instance_id, delivery_id)
            .await?;
        let body = row.body.unwrap_or_default();
        let instance = self
            .instances
            .get(owner_id, instance_id)
            .await
            .map_err(|_| WebhookError::NotFound)?;
        if instance.cube_sandbox_id.as_deref().unwrap_or("").is_empty() {
            return Err(WebhookError::NotReady);
        }
        let webhook = self
            .webhooks
            .get(instance_id, &row.webhook_name)
            .await?
            .ok_or(WebhookError::NotFound)?;
        let started = Instant::now();
        let status = self
            .dispatcher
            .dispatch(&instance, &webhook.name, &webhook.description, &[], &body)
            .await
            .map_err(WebhookError::Dispatch)?;
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let sealed_body = self
            .seal_body_for_audit(instance_id, &row.webhook_name, &body)
            .await
            .unwrap_or(None);
        let replay_row = DeliveryRow {
            id: Uuid::new_v4().simple().to_string(),
            instance_id: instance_id.to_owned(),
            webhook_name: row.webhook_name,
            fired_at: crate::now_secs(),
            status_code: i32::from(status),
            latency_ms: elapsed_ms,
            request_id: Some(format!("replay:{delivery_id}:{replayed_by_user_id}")),
            signature_ok: true,
            error: None,
            verify_error: None,
            request_headers: row.request_headers,
            replayed_from_delivery_id: Some(delivery_id.to_owned()),
            replayed_by_user_id: Some(replayed_by_user_id.to_owned()),
            body: sealed_body,
            body_size: Some(i64::try_from(body.len()).unwrap_or(i64::MAX)),
            content_type: row.content_type,
        };
        self.deliveries.insert(&replay_row).await?;
        Ok(status)
    }

    fn open_audit_body(
        &self,
        owner_id: &str,
        instance_id: &str,
        webhook_name: &str,
        delivery_id: &str,
        stored: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if !stored.starts_with(AGE_ARMOR_PREFIX) && !is_v2_envelope(&stored) {
            // Legacy row written before bodies were sealed — surface
            // as-is so historical audits remain readable.
            return Some(stored);
        }
        let context = webhook_delivery_context(owner_id, instance_id, webhook_name);
        match open_context(
            self.ciphers.as_ref(),
            &context,
            &stored,
            SecretAccessReason::ArtefactRead,
        ) {
            Ok(opened) => Some(opened.plaintext),
            Err(e) => {
                tracing::warn!(
                    delivery = %delivery_id, error = %e,
                    "webhook delivery: body decrypt failed (key rotated?) — surfacing as empty"
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
    pub async fn verify_and_dispatch(&self, ctx: DispatchCtx<'_>) -> Result<u16, WebhookError> {
        let DispatchCtx {
            instance_id,
            name,
            signature_headers,
            bearer_header,
            bearer_path_token,
            request_id,
            forward_headers,
            content_type,
            body,
        } = ctx;
        let started = Instant::now();
        let res = self
            .verify_and_dispatch_inner(
                instance_id,
                name,
                signature_headers,
                bearer_header,
                bearer_path_token,
                &forward_headers,
                body,
            )
            .await;
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let (status_code, signature_ok, error_text) = match &res {
            Ok(s) => (i32::from(*s), true, None),
            Err(WebhookError::SignatureMismatch) => (401, false, Some("signature mismatch".into())),
            Err(WebhookError::Verify(e)) => (401, false, Some(e.to_string())),
            Err(WebhookError::ReplayDeduped(key)) => {
                (200, true, Some(format!("replay deduped: {key}")))
            }
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
            let sealed_body = match self.seal_body_for_audit(instance_id, name, body).await {
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
                instance_id: instance_id.to_owned(),
                webhook_name: name.to_owned(),
                fired_at: crate::now_secs(),
                status_code,
                latency_ms: elapsed_ms,
                request_id: request_id.map(str::to_owned),
                signature_ok,
                error: error_text,
                verify_error: match &res {
                    Err(WebhookError::Verify(e)) => Some(e.code().to_owned()),
                    _ => None,
                },
                request_headers: serde_json::to_string(&signature_headers).ok(),
                replayed_from_delivery_id: None,
                replayed_by_user_id: None,
                // Audit storage: keep the body for every delivery we
                // accepted into the pipeline, sealed under the owner's
                // age cipher.  An attacker with read access to the
                // store file alone can't recover historical webhook
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
        webhook_name: &str,
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
        let context = webhook_delivery_context(&owner_id, instance_id, webhook_name);
        let ct = seal_context(
            self.ciphers.as_ref(),
            &context,
            body,
            SecretAccessReason::ArtefactRead,
        )
        .map_err(|e| format!("seal: {e}"))?;
        Ok(Some(ct))
    }

    async fn verify_and_dispatch_inner(
        &self,
        instance_id: &str,
        name: &str,
        signature_headers: &[(String, String)],
        bearer_header: Option<&str>,
        bearer_path_token: Option<&str>,
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

        let verifier = row_verifier_config(&row)?;
        let secret = if verifier_needs_user_secret(&verifier) {
            Some(self.load_secret(&owner_id, &row).await?)
        } else {
            None
        };
        let verified = verify_inbound_request(
            &verifier,
            secret.as_deref(),
            signature_headers,
            bearer_header,
            bearer_path_token,
            body,
            crate::now_secs(),
        )
        .map_err(WebhookError::Verify)?;
        if let Some(header_name) = verifier.idempotency_header.as_deref() {
            let key = signature_header_value(signature_headers, header_name).ok_or_else(|| {
                WebhookError::Verify(VerifyError::MissingHeader {
                    name: header_name.to_owned(),
                })
            })?;
            let row_key = webhook_row_key(&row.instance_id, &row.name);
            let first = self
                .deliveries
                .try_mark_delivery_seen(&row_key, key, crate::now_secs())
                .await?;
            if !first {
                return Err(WebhookError::ReplayDeduped(key.to_owned()));
            }
        }
        let _ = verified;

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

fn header_value_from_pairs<'a>(headers: &'a [(String, String)], wanted: &str) -> Option<&'a str> {
    signature_header_value(headers, wanted)
}

fn delivery_request_headers(raw: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Array(rows) => rows
            .into_iter()
            .filter_map(|row| {
                let pair = row.as_array()?;
                let name = pair.first()?.as_str()?.to_owned();
                let value = pair.get(1)?.as_str()?.to_owned();
                Some((name, value))
            })
            .collect(),
        serde_json::Value::Object(map) => map
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_owned())))
            .collect(),
        _ => Vec::new(),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn constant_time_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    ct_eq(a, b)
}

pub fn validate_payload_template(template: &str) -> Result<(), VerifyError> {
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            return Err(VerifyError::UnknownPlaceholder {
                name: after_start.to_owned(),
            });
        };
        let name = &after_start[..end];
        match name {
            "body" | "timestamp" | "id" | "version" => {}
            other => {
                return Err(VerifyError::UnknownPlaceholder {
                    name: other.to_owned(),
                });
            }
        }
        rest = &after_start[end + 2..];
    }
    Ok(())
}

pub fn verify_inbound_request(
    config: &WebhookVerifierConfig,
    secret: Option<&str>,
    headers: &[(String, String)],
    _bearer_header: Option<&str>,
    bearer_path_token: Option<&str>,
    body: &[u8],
    now_secs: i64,
) -> Result<VerifyOutcome, VerifyError> {
    match config.mode {
        WebhookVerifierMode::None => Ok(VerifyOutcome {
            rendered_payload: None,
            matched_version: None,
        }),
        WebhookVerifierMode::BearerV2 => {
            let expected = config
                .bearer_path_token
                .as_deref()
                .ok_or(VerifyError::AllSignaturesMismatched)?;
            let provided = bearer_path_token.ok_or(VerifyError::AllSignaturesMismatched)?;
            if ct_eq(expected.as_bytes(), provided.as_bytes()) {
                Ok(VerifyOutcome {
                    rendered_payload: None,
                    matched_version: None,
                })
            } else {
                Err(VerifyError::AllSignaturesMismatched)
            }
        }
        WebhookVerifierMode::HmacV2 => verify_hmac_v2(config, secret, headers, body, now_secs),
    }
}

fn default_verifier_config(
    auth_scheme: WebhookAuthScheme,
    signature_header: String,
) -> WebhookVerifierConfig {
    match auth_scheme {
        WebhookAuthScheme::HmacSha256 => WebhookVerifierConfig {
            mode: WebhookVerifierMode::HmacV2,
            signature_header,
            signature_algo: Some(SignatureAlgorithm::Sha256),
            signature_encoding: Some(SignatureEncoding::Hex),
            signature_prefix: None,
            signature_separator: None,
            signature_value_split: Some("=".to_owned()),
            timestamp_header: None,
            timestamp_skew_secs: None,
            payload_template: Some("{{body}}".to_owned()),
            idempotency_header: None,
            bearer_path_token: None,
        },
        WebhookAuthScheme::Bearer => WebhookVerifierConfig {
            mode: WebhookVerifierMode::BearerV2,
            signature_header: String::new(),
            signature_algo: None,
            signature_encoding: None,
            signature_prefix: None,
            signature_separator: None,
            signature_value_split: None,
            timestamp_header: None,
            timestamp_skew_secs: None,
            payload_template: None,
            idempotency_header: None,
            bearer_path_token: Some(random_path_token()),
        },
        WebhookAuthScheme::None => WebhookVerifierConfig {
            mode: WebhookVerifierMode::None,
            signature_header: String::new(),
            signature_algo: None,
            signature_encoding: None,
            signature_prefix: None,
            signature_separator: None,
            signature_value_split: None,
            timestamp_header: None,
            timestamp_skew_secs: None,
            payload_template: None,
            idempotency_header: None,
            bearer_path_token: None,
        },
    }
}

pub fn row_verifier_config(row: &WebhookRow) -> Result<WebhookVerifierConfig, WebhookError> {
    let mode = WebhookVerifierMode::parse(&row.verifier_mode).ok_or_else(|| {
        WebhookError::BadRequest(format!(
            "unsupported webhook verifier mode {}; re-save this webhook using hmac_v2 or bearer_v2",
            row.verifier_mode
        ))
    })?;
    let signature_algo =
        match row.signature_algo.as_deref() {
            Some(raw) => Some(SignatureAlgorithm::parse(raw).ok_or_else(|| {
                WebhookError::BadRequest("unknown signature algorithm".to_owned())
            })?),
            None => None,
        };
    let signature_encoding = match row.signature_encoding.as_deref() {
        Some(raw) => Some(
            SignatureEncoding::parse(raw)
                .ok_or_else(|| WebhookError::BadRequest("unknown signature encoding".to_owned()))?,
        ),
        None => None,
    };
    Ok(WebhookVerifierConfig {
        mode,
        signature_header: row.signature_header.clone(),
        signature_algo,
        signature_encoding,
        signature_prefix: row.signature_prefix.clone(),
        signature_separator: row.signature_separator.clone(),
        signature_value_split: row.signature_value_split.clone(),
        timestamp_header: row.timestamp_header.clone(),
        timestamp_skew_secs: row.timestamp_skew_secs.map(|v| v as u64),
        payload_template: row.payload_template.clone(),
        idempotency_header: row.idempotency_header.clone(),
        bearer_path_token: row.bearer_path_token.clone(),
    })
}

fn validate_verifier_config(config: &WebhookVerifierConfig) -> Result<(), VerifyError> {
    if let Some(template) = config.payload_template.as_deref() {
        validate_payload_template(template)?;
    }
    Ok(())
}

fn verifier_needs_user_secret(config: &WebhookVerifierConfig) -> bool {
    matches!(config.mode, WebhookVerifierMode::HmacV2)
}

fn random_path_token() -> String {
    format!("whp_{}", Uuid::new_v4().simple())
}

fn verify_hmac_v2(
    config: &WebhookVerifierConfig,
    secret: Option<&str>,
    headers: &[(String, String)],
    body: &[u8],
    now_secs: i64,
) -> Result<VerifyOutcome, VerifyError> {
    validate_payload_template(config.payload_template.as_deref().unwrap_or("{{body}}"))?;
    let secret = secret.ok_or(VerifyError::AllSignaturesMismatched)?;
    let key = verifier_secret_key(secret)?;
    let signature_header = signature_header_value(headers, &config.signature_header)
        .ok_or(VerifyError::MissingSignature)?;
    let timestamp = match config.timestamp_header.as_deref() {
        None => None,
        Some(header_name) => {
            let raw = signature_header_value(headers, header_name)
                .ok_or(VerifyError::MissingTimestamp)?;
            Some(extract_timestamp(raw, config)?)
        }
    };
    if let Some(ts_raw) = timestamp.as_deref() {
        let ts = ts_raw
            .parse::<i64>()
            .map_err(|_| VerifyError::MissingTimestamp)?;
        let skew = config.timestamp_skew_secs.unwrap_or(300);
        if now_secs.abs_diff(ts) > skew {
            return Err(VerifyError::TimestampOutOfSkew {
                now: now_secs,
                ts,
                skew_secs: skew,
            });
        }
    }
    let id = match config.idempotency_header.as_deref() {
        None => None,
        Some(header_name) => Some(
            signature_header_value(headers, header_name)
                .ok_or_else(|| VerifyError::MissingHeader {
                    name: header_name.to_owned(),
                })?
                .to_owned(),
        ),
    };

    let algo = config.signature_algo.unwrap_or(SignatureAlgorithm::Sha256);
    let encoding = config.signature_encoding.unwrap_or(SignatureEncoding::Hex);
    let candidates = split_signature_candidates(signature_header, config);
    if candidates.is_empty() {
        return Err(VerifyError::MissingSignature);
    }
    let known_version = version_from_prefix(config.signature_prefix.as_deref().unwrap_or(""));
    let mut saw_known = false;
    let mut unknown_versions = Vec::new();
    let mut first_malformed = None;
    for candidate in candidates {
        let parsed = match parse_signature_candidate(&candidate, config) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => {
                if let Some(version) = candidate_version(&candidate, config) {
                    unknown_versions.push(version);
                }
                continue;
            }
            Err(e) => {
                first_malformed.get_or_insert(e);
                continue;
            }
        };
        saw_known = true;
        let rendered = render_payload_template(
            config.payload_template.as_deref().unwrap_or("{{body}}"),
            body,
            timestamp.as_deref(),
            id.as_deref(),
            parsed.version.as_deref(),
        )?;
        let expected = hmac_digest(algo, &key, &rendered);
        let provided = match decode_signature(parsed.encoded.trim(), encoding) {
            Ok(sig) => sig,
            Err(e) => {
                first_malformed.get_or_insert(e);
                continue;
            }
        };
        if ct_eq(&expected, &provided) {
            return Ok(VerifyOutcome {
                rendered_payload: Some(rendered),
                matched_version: parsed.version,
            });
        }
    }
    if !saw_known && !unknown_versions.is_empty() {
        let version = unknown_versions.remove(0);
        return Err(VerifyError::UnknownVersion {
            version,
            known: known_version.into_iter().collect(),
        });
    }
    if !saw_known && let Some(e) = first_malformed {
        return Err(e);
    }
    Err(VerifyError::AllSignaturesMismatched)
}

#[derive(Debug)]
struct ParsedSignature {
    version: Option<String>,
    encoded: String,
}

fn split_signature_candidates(header: &str, config: &WebhookVerifierConfig) -> Vec<String> {
    match config
        .signature_separator
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(sep) => header
            .split(sep)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        None => {
            let trimmed = header.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed.to_owned()]
            }
        }
    }
}

fn parse_signature_candidate(
    candidate: &str,
    config: &WebhookVerifierConfig,
) -> Result<Option<ParsedSignature>, VerifyError> {
    let prefix = config.signature_prefix.as_deref().unwrap_or("");
    if !prefix.is_empty() && !candidate.starts_with(prefix) {
        return Ok(None);
    }
    let version = candidate_version(candidate, config);
    let encoded = if let Some(split) = config
        .signature_value_split
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        match candidate.split_once(split) {
            Some((_, encoded)) => encoded.to_owned(),
            None if prefix.is_empty() => candidate.to_owned(),
            None => {
                return Err(VerifyError::MalformedSignature {
                    reason: format!("signature missing value split {split:?}"),
                });
            }
        }
    } else if prefix.is_empty() {
        candidate.to_owned()
    } else {
        candidate[prefix.len()..].to_owned()
    };
    Ok(Some(ParsedSignature { version, encoded }))
}

fn candidate_version(candidate: &str, config: &WebhookVerifierConfig) -> Option<String> {
    let split = config.signature_value_split.as_deref()?;
    if split.is_empty() {
        return None;
    }
    candidate
        .split_once(split)
        .map(|(version, _)| version.trim().to_owned())
        .filter(|version| !version.is_empty())
}

fn version_from_prefix(prefix: &str) -> Option<String> {
    let idx = prefix.find([',', '='])?;
    let version = prefix[..idx].trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_owned())
    }
}

fn decode_signature(raw: &str, encoding: SignatureEncoding) -> Result<Vec<u8>, VerifyError> {
    match encoding {
        SignatureEncoding::Hex => hex::decode(raw).map_err(|e| VerifyError::MalformedSignature {
            reason: e.to_string(),
        }),
        SignatureEncoding::Base64 => B64
            .decode(raw)
            .map_err(|e| VerifyError::MalformedSignature {
                reason: e.to_string(),
            }),
    }
}

fn verifier_secret_key(secret: &str) -> Result<Vec<u8>, VerifyError> {
    if let Some(rest) = secret.strip_prefix("whsec_") {
        return B64
            .decode(rest)
            .map_err(|e| VerifyError::MalformedSignature {
                reason: format!("invalid whsec secret: {e}"),
            });
    }
    Ok(secret.as_bytes().to_vec())
}

fn hmac_digest(algo: SignatureAlgorithm, key: &[u8], payload: &[u8]) -> Vec<u8> {
    match algo {
        SignatureAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
            mac.update(payload);
            mac.finalize().into_bytes().to_vec()
        }
        SignatureAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
            mac.update(payload);
            mac.finalize().into_bytes().to_vec()
        }
        SignatureAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
            mac.update(payload);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn extract_timestamp(raw: &str, config: &WebhookVerifierConfig) -> Result<String, VerifyError> {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(trimmed.to_owned());
    }
    let separator = config
        .signature_separator
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(",");
    for part in trimmed.split(separator).map(str::trim) {
        if let Some(ts) = part.strip_prefix("t=")
            && !ts.is_empty()
        {
            return Ok(ts.to_owned());
        }
    }
    Err(VerifyError::MissingTimestamp)
}

fn render_payload_template(
    template: &str,
    body: &[u8],
    timestamp: Option<&str>,
    id: Option<&str>,
    version: Option<&str>,
) -> Result<Vec<u8>, VerifyError> {
    validate_payload_template(template)?;
    let mut out = Vec::with_capacity(template.len() + body.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.extend_from_slice(rest[..start].as_bytes());
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            return Err(VerifyError::UnknownPlaceholder {
                name: after_start.to_owned(),
            });
        };
        let name = &after_start[..end];
        match name {
            "body" => out.extend_from_slice(body),
            "timestamp" => {
                let value = timestamp.ok_or(VerifyError::MissingTimestamp)?;
                out.extend_from_slice(value.as_bytes());
            }
            "id" => {
                let value = id.ok_or_else(|| VerifyError::MissingHeader {
                    name: "idempotency header".to_owned(),
                })?;
                out.extend_from_slice(value.as_bytes());
            }
            "version" => {
                let value = version.ok_or_else(|| VerifyError::MalformedSignature {
                    reason: "signature version required by payload template".to_owned(),
                })?;
                out.extend_from_slice(value.as_bytes());
            }
            other => {
                return Err(VerifyError::UnknownPlaceholder {
                    name: other.to_owned(),
                });
            }
        }
        rest = &after_start[end + 2..];
    }
    out.extend_from_slice(rest.as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_policy::NetworkPolicy;
    use crate::traits::{
        CreateSandboxArgs, CubeClient, InstanceRow, InstanceStatus, InstanceStore, SandboxInfo,
        SnapshotInfo, TokenStore, WebhookAuthScheme,
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

    fn fixture(vendor: &str, file: &str) -> &'static [u8] {
        match (vendor, file) {
            ("github", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/github/request.txt")
            }
            ("github", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/github/secret.txt")
            }
            ("standard", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/standard/request.txt")
            }
            ("standard", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/standard/secret.txt")
            }
            ("stripe", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/stripe/request.txt")
            }
            ("stripe", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/stripe/secret.txt")
            }
            ("slack", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/slack/request.txt")
            }
            ("slack", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/slack/secret.txt")
            }
            ("shopify", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/shopify/request.txt")
            }
            ("shopify", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/shopify/secret.txt")
            }
            ("svix", "request.txt") => {
                include_bytes!("../tests/fixtures/webhooks/svix/request.txt")
            }
            ("svix", "secret.txt") => {
                include_bytes!("../tests/fixtures/webhooks/svix/secret.txt")
            }
            _ => panic!("unknown webhook fixture {vendor}/{file}"),
        }
    }

    fn fixture_text(vendor: &str, file: &str) -> String {
        std::str::from_utf8(fixture(vendor, file))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn hmac_v2_config(
        signature_header: &str,
        signature_encoding: SignatureEncoding,
        signature_prefix: &str,
        signature_separator: Option<&str>,
        signature_value_split: Option<&str>,
        timestamp_header: Option<&str>,
        payload_template: &str,
        idempotency_header: Option<&str>,
    ) -> WebhookVerifierConfig {
        WebhookVerifierConfig {
            mode: WebhookVerifierMode::HmacV2,
            signature_header: signature_header.to_owned(),
            signature_algo: Some(SignatureAlgorithm::Sha256),
            signature_encoding: Some(signature_encoding),
            signature_prefix: Some(signature_prefix.to_owned()),
            signature_separator: signature_separator.map(str::to_owned),
            signature_value_split: signature_value_split.map(str::to_owned),
            timestamp_header: timestamp_header.map(str::to_owned),
            timestamp_skew_secs: Some(300),
            payload_template: Some(payload_template.to_owned()),
            idempotency_header: idempotency_header.map(str::to_owned),
            bearer_path_token: None,
        }
    }

    fn verify_fixture(
        cfg: &WebhookVerifierConfig,
        vendor: &str,
        headers: Vec<(&str, &str)>,
        now: i64,
    ) -> Result<VerifyOutcome, VerifyError> {
        let headers = headers
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect::<Vec<_>>();
        verify_inbound_request(
            cfg,
            Some(fixture_text(vendor, "secret.txt").as_str()),
            &headers,
            None,
            None,
            fixture(vendor, "request.txt"),
            now,
        )
    }

    #[test]
    fn hmac_v2_default_split_accepts_github_prefixed_signature() {
        let cfg = hmac_v2_config(
            "x-hub-signature-256",
            SignatureEncoding::Hex,
            "",
            None,
            Some("="),
            None,
            "{{body}}",
            None,
        );
        let out = verify_fixture(
            &cfg,
            "github",
            vec![(
                "X-Hub-Signature-256",
                "sha256=1ae84c7f758faa88395f24d75a762947277389c2071f1c3c478492f6a2112d0d",
            )],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(
            out.rendered_payload.as_deref(),
            Some(fixture("github", "request.txt"))
        );
        assert_eq!(out.matched_version.as_deref(), Some("sha256"));
    }

    #[test]
    fn hmac_v2_sha256_hex_no_prefix_verifies_github_fixture() {
        let cfg = hmac_v2_config(
            "x-hub-signature-256",
            SignatureEncoding::Hex,
            "",
            None,
            None,
            None,
            "{{body}}",
            None,
        );
        verify_fixture(
            &cfg,
            "github",
            vec![(
                "X-Hub-Signature-256",
                "1ae84c7f758faa88395f24d75a762947277389c2071f1c3c478492f6a2112d0d",
            )],
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn hmac_v2_sha256_base64_with_v1_prefix_verifies_standard_webhooks_fixture() {
        let cfg = hmac_v2_config(
            "webhook-signature",
            SignatureEncoding::Base64,
            "v1,",
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        );
        let out = verify_fixture(
            &cfg,
            "standard",
            vec![
                ("webhook-id", "msg_123"),
                ("webhook-timestamp", "1700000000"),
                (
                    "webhook-signature",
                    "v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=",
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(out.matched_version.as_deref(), Some("v1"));
        assert_eq!(
            out.rendered_payload.as_deref(),
            Some(b"msg_123.1700000000.{\"event\":\"ping\",\"ok\":true}\n".as_slice())
        );
    }

    #[test]
    fn hmac_v2_sha256_hex_with_timestamp_payload_verifies_stripe_fixture() {
        let cfg = hmac_v2_config(
            "stripe-signature",
            SignatureEncoding::Hex,
            "v1=",
            Some(","),
            Some("="),
            Some("stripe-signature"),
            "{{timestamp}}.{{body}}",
            None,
        );
        verify_fixture(
            &cfg,
            "stripe",
            vec![(
                "Stripe-Signature",
                "t=1700000000,v1=2101deb845397d1a40375dcb3dbfe33a57291ed706133814e22a52b09e6300c9",
            )],
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn hmac_v2_sha256_hex_with_v0_version_payload_verifies_slack_fixture() {
        let cfg = hmac_v2_config(
            "x-slack-signature",
            SignatureEncoding::Hex,
            "v0=",
            None,
            Some("="),
            Some("x-slack-request-timestamp"),
            "v0:{{timestamp}}:{{body}}",
            None,
        );
        let out = verify_fixture(
            &cfg,
            "slack",
            vec![
                ("X-Slack-Request-Timestamp", "1700000000"),
                (
                    "X-Slack-Signature",
                    "v0=2fe4647cd9c1970d385177f613fee537c122efa6a48011ed5270b7e5a1b8f1c0",
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(out.matched_version.as_deref(), Some("v0"));
    }

    #[test]
    fn hmac_v2_sha256_base64_verifies_shopify_fixture() {
        let cfg = hmac_v2_config(
            "x-shopify-hmac-sha256",
            SignatureEncoding::Base64,
            "",
            None,
            None,
            None,
            "{{body}}",
            None,
        );
        verify_fixture(
            &cfg,
            "shopify",
            vec![(
                "X-Shopify-Hmac-Sha256",
                "GuhMf3WPqog5XyTXWnYpRydzicIHHxw8R4SS9qIRLQ0=",
            )],
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn hmac_v2_replay_outside_skew_rejected_with_timestamp_out_of_skew() {
        let cfg = hmac_v2_config(
            "webhook-signature",
            SignatureEncoding::Base64,
            "v1,",
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        );
        let err = verify_fixture(
            &cfg,
            "standard",
            vec![
                ("webhook-id", "msg_123"),
                ("webhook-timestamp", "1700000000"),
                (
                    "webhook-signature",
                    "v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=",
                ),
            ],
            1_700_003_601,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::TimestampOutOfSkew { .. }));
    }

    #[test]
    fn hmac_v2_missing_timestamp_header_returns_missing_timestamp() {
        let cfg = hmac_v2_config(
            "webhook-signature",
            SignatureEncoding::Base64,
            "v1,",
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        );
        let err = verify_fixture(
            &cfg,
            "standard",
            vec![
                ("webhook-id", "msg_123"),
                (
                    "webhook-signature",
                    "v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=",
                ),
            ],
            1_700_000_000,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::MissingTimestamp);
    }

    #[test]
    fn hmac_v2_multi_sig_header_accepts_when_any_one_matches() {
        let cfg = hmac_v2_config(
            "webhook-signature",
            SignatureEncoding::Base64,
            "v1,",
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        );
        verify_fixture(
            &cfg,
            "standard",
            vec![
                ("webhook-id", "msg_123"),
                ("webhook-timestamp", "1700000000"),
                (
                    "webhook-signature",
                    "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=",
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn hmac_v2_multi_sig_header_skips_unknown_versions() {
        let cfg = hmac_v2_config(
            "webhook-signature",
            SignatureEncoding::Base64,
            "v1,",
            Some(" "),
            Some(","),
            Some("webhook-timestamp"),
            "{{id}}.{{timestamp}}.{{body}}",
            Some("webhook-id"),
        );
        let out = verify_fixture(
            &cfg,
            "standard",
            vec![
                ("webhook-id", "msg_123"),
                ("webhook-timestamp", "1700000000"),
                (
                    "webhook-signature",
                    "v9,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=",
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(out.matched_version.as_deref(), Some("v1"));
    }

    #[test]
    fn hmac_v2_wrong_secret_returns_all_signatures_mismatched() {
        let cfg = hmac_v2_config(
            "x-shopify-hmac-sha256",
            SignatureEncoding::Base64,
            "",
            None,
            None,
            None,
            "{{body}}",
            None,
        );
        let headers = vec![(
            "X-Shopify-Hmac-Sha256".to_owned(),
            "GuhMf3WPqog5XyTXWnYpRydzicIHHxw8R4SS9qIRLQ0=".to_owned(),
        )];
        let err = verify_inbound_request(
            &cfg,
            Some("wrong-secret"),
            &headers,
            None,
            None,
            fixture("shopify", "request.txt"),
            1_700_000_000,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::AllSignaturesMismatched);
    }

    #[test]
    fn hmac_v2_constant_time_compare_does_not_short_circuit_on_byte_match() {
        let expected = [0xabu8; 32];
        for i in 0..1000 {
            let mut candidate = expected;
            candidate[i % candidate.len()] ^= 0x01;
            assert!(!constant_time_bytes_eq(&expected, &candidate));
        }
        assert!(constant_time_bytes_eq(&expected, &expected));
    }

    #[test]
    fn bearer_v2_correct_token_accepted() {
        let cfg = WebhookVerifierConfig {
            mode: WebhookVerifierMode::BearerV2,
            signature_header: String::new(),
            signature_algo: None,
            signature_encoding: None,
            signature_prefix: None,
            signature_separator: None,
            signature_value_split: None,
            timestamp_header: None,
            timestamp_skew_secs: None,
            payload_template: None,
            idempotency_header: None,
            bearer_path_token: Some("tok_live_123".to_owned()),
        };
        verify_inbound_request(&cfg, None, &[], None, Some("tok_live_123"), b"{}", 0).unwrap();
    }

    #[test]
    fn bearer_v2_wrong_token_constant_time_rejected() {
        let cfg = WebhookVerifierConfig {
            mode: WebhookVerifierMode::BearerV2,
            signature_header: String::new(),
            signature_algo: None,
            signature_encoding: None,
            signature_prefix: None,
            signature_separator: None,
            signature_value_split: None,
            timestamp_header: None,
            timestamp_skew_secs: None,
            payload_template: None,
            idempotency_header: None,
            bearer_path_token: Some("tok_live_123".to_owned()),
        };
        let err = verify_inbound_request(&cfg, None, &[], None, Some("tok_live_456"), b"{}", 0)
            .unwrap_err();
        assert_eq!(err, VerifyError::AllSignaturesMismatched);
    }

    #[test]
    fn unknown_placeholder_rejected_at_save_time() {
        let err = validate_payload_template("{{id}}.{{missing}}.{{body}}").unwrap_err();
        assert_eq!(
            err,
            VerifyError::UnknownPlaceholder {
                name: "missing".to_owned()
            }
        );
    }

    #[test]
    fn svix_preset_verifies_recorded_fixture() {
        let cfg = svix_preset().verifier;
        let out = verify_fixture(
            &cfg,
            "svix",
            vec![
                ("svix-id", "msg_svix_1"),
                ("svix-timestamp", "1700000000"),
                (
                    "svix-signature",
                    "v1,rIQVOgymL66XhZlMhPJ2Ib+z0VNjxIz05sLiJMjKXhU=",
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(out.matched_version.as_deref(), Some("v1"));
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

    #[test]
    fn regression_delivery_limit_zero_clamps_to_one() {
        assert_eq!(clamp_delivery_limit(0), 1);
    }

    #[test]
    fn delivery_limit_clamps_at_configured_bounds() {
        assert_eq!(clamp_delivery_limit(1), 1);
        assert_eq!(clamp_delivery_limit(MAX_DELIVERY_LIMIT), MAX_DELIVERY_LIMIT);
        assert_eq!(
            clamp_delivery_limit(MAX_DELIVERY_LIMIT + 1),
            MAX_DELIVERY_LIMIT
        );
    }

    #[test]
    fn dispatch_ctx_carries_audit_metadata() {
        let headers = vec![("x-test".to_owned(), "ok".to_owned())];
        let ctx = DispatchCtx {
            instance_id: "i1",
            name: "github",
            signature_headers: &headers,
            bearer_header: Some("Bearer tok"),
            bearer_path_token: None,
            request_id: Some("req-1"),
            forward_headers: headers.clone(),
            content_type: Some("application/json".to_owned()),
            body: b"{}",
        };
        assert_eq!(ctx.instance_id, "i1");
        assert_eq!(ctx.name, "github");
        assert_eq!(ctx.signature_headers, headers.as_slice());
        assert_eq!(ctx.bearer_header, Some("Bearer tok"));
        assert_eq!(ctx.request_id, Some("req-1"));
        assert_eq!(ctx.forward_headers, headers);
        assert_eq!(ctx.content_type.as_deref(), Some("application/json"));
        assert_eq!(ctx.body, b"{}");
    }

    #[tokio::test]
    async fn put_stores_verifier_key_in_user_secrets() {
        let pool = crate::db::sqlite::open_in_memory().await.unwrap();
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
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(crate::db::sqlite::instances::SqlxInstanceStore::new(
                pool.clone(),
                system_cipher.clone(),
            ));
        let token_store: Arc<dyn TokenStore> = Arc::new(
            crate::db::sqlite::tokens::SqlxTokenStore::new(pool.clone(), system_cipher),
        );
        instances_store
            .create(InstanceRow {
                id: "i1".into(),
                owner_id: owner.into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: None,
                state_generation: String::new(),
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
            token_store,
            "http://swarm.test/llm",
        ));
        let user_secrets = Arc::new(UserSecretsService::new(
            Arc::new(crate::db::sqlite::secrets::SqlxUserSecretStore::new(
                pool.clone(),
            )),
            cipher_dir.clone(),
        ));
        let svc = WebhookService::new(
            Arc::new(crate::db::sqlite::webhooks::SqlxWebhookStore::new(
                pool.clone(),
            )),
            Arc::new(crate::db::sqlite::webhooks::SqlxDeliveryStore::new(
                pool.clone(),
            )),
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
                    preset_id: None,
                    verifier: None,
                    signature_header: None,
                    secret_plaintext: Some("super-secret".into()),
                    enabled: true,
                },
            )
            .await
            .unwrap();

        assert_eq!(row.secret_name.as_deref(), Some("webhook:i1:ping"));
        let stored = user_secrets
            .get(owner, "webhook:i1:ping")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8(stored).unwrap(), "super-secret");
    }

    #[tokio::test]
    async fn hmac_verify_uses_configured_signature_header() {
        let pool = crate::db::sqlite::open_in_memory().await.unwrap();
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
        let instances_store: Arc<dyn InstanceStore> =
            Arc::new(crate::db::sqlite::instances::SqlxInstanceStore::new(
                pool.clone(),
                system_cipher.clone(),
            ));
        let token_store: Arc<dyn TokenStore> = Arc::new(
            crate::db::sqlite::tokens::SqlxTokenStore::new(pool.clone(), system_cipher),
        );
        instances_store
            .create(InstanceRow {
                id: "i1".into(),
                owner_id: owner.into(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: Some("sb1".into()),
                state_generation: String::new(),
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
            token_store,
            "http://swarm.test/llm",
        ));
        let user_secrets = Arc::new(UserSecretsService::new(
            Arc::new(crate::db::sqlite::secrets::SqlxUserSecretStore::new(
                pool.clone(),
            )),
            cipher_dir.clone(),
        ));
        let svc = WebhookService::new(
            Arc::new(crate::db::sqlite::webhooks::SqlxWebhookStore::new(
                pool.clone(),
            )),
            Arc::new(crate::db::sqlite::webhooks::SqlxDeliveryStore::new(
                pool.clone(),
            )),
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
                    preset_id: None,
                    verifier: None,
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

        let wrong_headers = vec![(DEFAULT_SIGNATURE_HEADER.into(), signature.clone())];
        let wrong_header = svc
            .verify_and_dispatch(DispatchCtx {
                instance_id: "i1",
                name: "github",
                signature_headers: &wrong_headers,
                bearer_header: None,
                bearer_path_token: None,
                request_id: None,
                forward_headers: Vec::new(),
                content_type: Some("application/json".into()),
                body,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            wrong_header,
            WebhookError::Verify(VerifyError::MissingSignature)
        ));

        let right_headers = vec![("X-Hub-Signature-256".into(), signature)];
        let status = svc
            .verify_and_dispatch(DispatchCtx {
                instance_id: "i1",
                name: "github",
                signature_headers: &right_headers,
                bearer_header: None,
                bearer_path_token: None,
                request_id: Some("req-1"),
                forward_headers: Vec::new(),
                content_type: Some("application/json".into()),
                body,
            })
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
