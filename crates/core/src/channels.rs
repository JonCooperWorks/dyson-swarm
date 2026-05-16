//! Instance channels.  V1 is deliberately Telegram-shaped: one bot
//! per instance, token stored only in swarm's per-user secret store,
//! and dyson receives only proxy URLs plus an existing per-instance
//! bearer.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{StoreError, SwarmError};
use crate::now_secs;
use crate::secrets::UserSecretsService;
use crate::traits::{ChannelDeliveryRow, InstanceChannelRow, InstanceChannelStore, InstanceStore};

pub const TELEGRAM_KIND: &str = "telegram";

pub fn telegram_bot_token_secret_name(instance_id: &str) -> String {
    format!("channel:telegram:{instance_id}:bot-token")
}

pub fn telegram_webhook_secret_name(instance_id: &str) -> String {
    format!("channel:telegram:{instance_id}:webhook-secret")
}

pub fn telegram_token_shape_valid(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else {
        return false;
    };
    !id.is_empty()
        && id.chars().all(|c| c.is_ascii_digit())
        && secret.len() == 35
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

pub fn normalize_telegram_allowed_senders(entries: Vec<String>) -> ChannelsResult<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries {
        let Some(normalized) = normalize_telegram_allowed_sender(&entry)? else {
            continue;
        };
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    Ok(out)
}

fn normalize_telegram_allowed_sender(raw: &str) -> ChannelsResult<Option<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(Some(trimmed.to_owned()));
    }
    let username = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if (5..=32).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Ok(Some(username.to_ascii_lowercase()));
    }
    Err(ChannelsError::BadRequest(
        "Allowed Telegram users must be numeric user IDs or usernames".into(),
    ))
}

fn new_webhook_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectedTelegram {
    pub handle: String,
    pub connected_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramMe {
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramWebhookInfo {
    #[serde(default)]
    pub last_error_date: Option<i64>,
    #[serde(default)]
    pub last_error_message: Option<String>,
}

#[async_trait]
pub trait TelegramApi: Send + Sync {
    async fn get_me(&self, token: &str) -> Result<TelegramMe, String>;
    async fn set_webhook(
        &self,
        token: &str,
        url: &str,
        secret_token: &str,
        allowed_updates: &[&str],
    ) -> Result<(), String>;
    async fn delete_webhook(&self, token: &str) -> Result<(), String>;
    async fn get_webhook_info(&self, token: &str) -> Result<TelegramWebhookInfo, String>;
}

#[derive(Clone, Default)]
pub struct NoopTelegramApi;

#[async_trait]
impl TelegramApi for NoopTelegramApi {
    async fn get_me(&self, _token: &str) -> Result<TelegramMe, String> {
        Err("telegram api is not configured".into())
    }

    async fn set_webhook(
        &self,
        _token: &str,
        _url: &str,
        _secret_token: &str,
        _allowed_updates: &[&str],
    ) -> Result<(), String> {
        Err("telegram api is not configured".into())
    }

    async fn delete_webhook(&self, _token: &str) -> Result<(), String> {
        Err("telegram api is not configured".into())
    }

    async fn get_webhook_info(&self, _token: &str) -> Result<TelegramWebhookInfo, String> {
        Err("telegram api is not configured".into())
    }
}

#[derive(Clone)]
pub struct ReqwestTelegramApi {
    base_url: String,
    client: crate::http::InternalHttpClient,
}

impl ReqwestTelegramApi {
    pub fn new(base_url: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client: crate::http::InternalHttpClient::new()?,
        })
    }

    fn bot_url(&self, token: &str, method: &str) -> String {
        format!("{}/bot{token}/{method}", self.base_url)
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        method: &str,
        body: serde_json::Value,
    ) -> Result<T, String> {
        let resp = self
            .client
            .post(self.bot_url(token, method))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        decode_telegram_response(resp).await
    }
}

#[derive(Deserialize)]
struct TelegramEnvelope<T> {
    #[serde(default)]
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

async fn decode_telegram_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
) -> Result<T, String> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    match serde_json::from_str::<TelegramEnvelope<T>>(&text) {
        Ok(env) if status.is_success() && env.ok => env
            .result
            .ok_or_else(|| "Telegram response missing result".to_owned()),
        Ok(env) => Err(env.description.unwrap_or(text)),
        Err(_) => Err(text),
    }
}

#[async_trait]
impl TelegramApi for ReqwestTelegramApi {
    async fn get_me(&self, token: &str) -> Result<TelegramMe, String> {
        self.post_json(token, "getMe", serde_json::json!({})).await
    }

    async fn set_webhook(
        &self,
        token: &str,
        url: &str,
        secret_token: &str,
        allowed_updates: &[&str],
    ) -> Result<(), String> {
        let _: bool = self
            .post_json(
                token,
                "setWebhook",
                serde_json::json!({
                    "url": url,
                    "secret_token": secret_token,
                    "allowed_updates": allowed_updates,
                }),
            )
            .await?;
        Ok(())
    }

    async fn delete_webhook(&self, token: &str) -> Result<(), String> {
        let _: bool = self
            .post_json(token, "deleteWebhook", serde_json::json!({}))
            .await?;
        Ok(())
    }

    async fn get_webhook_info(&self, token: &str) -> Result<TelegramWebhookInfo, String> {
        self.post_json(token, "getWebhookInfo", serde_json::json!({}))
            .await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelsError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("channel already exists")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("instance not ready")]
    InstanceNotReady,
    #[error("telegram: {0}")]
    Telegram(String),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("secrets: {0}")]
    Secrets(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<crate::secrets::SecretsError> for ChannelsError {
    fn from(value: crate::secrets::SecretsError) -> Self {
        Self::Secrets(value.to_string())
    }
}

pub type ChannelsResult<T> = Result<T, ChannelsError>;

#[derive(Clone)]
pub struct ChannelsService {
    pub channels: Arc<dyn InstanceChannelStore>,
    pub instances: Arc<dyn InstanceStore>,
    pub user_secrets: Arc<UserSecretsService>,
    pub telegram: Arc<dyn TelegramApi>,
    pub public_origin: Option<String>,
}

impl ChannelsService {
    pub fn new(
        channels: Arc<dyn InstanceChannelStore>,
        instances: Arc<dyn InstanceStore>,
        user_secrets: Arc<UserSecretsService>,
        telegram: Arc<dyn TelegramApi>,
        public_origin: Option<String>,
    ) -> Self {
        Self {
            channels,
            instances,
            user_secrets,
            telegram,
            public_origin,
        }
    }

    pub async fn list(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> ChannelsResult<Vec<InstanceChannelRow>> {
        self.ensure_owner(owner_id, instance_id).await?;
        Ok(self.channels.list_for_instance(instance_id).await?)
    }

    pub async fn recent_telegram(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> ChannelsResult<Vec<ChannelDeliveryRow>> {
        self.ensure_owner(owner_id, instance_id).await?;
        Ok(self
            .channels
            .recent_deliveries(instance_id, TELEGRAM_KIND, 20)
            .await?)
    }

    pub async fn connect_telegram(
        &self,
        owner_id: &str,
        instance_id: &str,
        raw_token: &str,
        allowed_senders: Vec<String>,
    ) -> ChannelsResult<ConnectedTelegram> {
        self.ensure_owner(owner_id, instance_id).await?;
        let token = raw_token.trim();
        if !telegram_token_shape_valid(token) {
            return Err(ChannelsError::BadRequest(
                "Telegram token must match 123456:35-character-secret".into(),
            ));
        }
        let allowed_senders = normalize_telegram_allowed_senders(allowed_senders)?;
        if self
            .channels
            .get(instance_id, TELEGRAM_KIND)
            .await?
            .is_some()
        {
            return Err(ChannelsError::Conflict);
        }
        let origin = self
            .public_origin
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                ChannelsError::BadRequest("swarm public hostname is not configured".into())
            })?;

        let me = self
            .telegram
            .get_me(token)
            .await
            .map_err(ChannelsError::Telegram)?;
        let username = me
            .username
            .map(|s| s.trim_start_matches('@').to_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ChannelsError::BadRequest("Telegram getMe returned no username".into())
            })?;
        let handle = format!("@{username}");

        let webhook_secret = new_webhook_secret();
        let webhook_url = format!(
            "{}/v1/channels/telegram/{instance_id}/webhook",
            origin.trim_end_matches('/')
        );
        self.telegram
            .set_webhook(
                token,
                &webhook_url,
                &webhook_secret,
                &[
                    "message",
                    "edited_message",
                    "callback_query",
                    "channel_post",
                ],
            )
            .await
            .map_err(ChannelsError::Telegram)?;

        let token_secret_name = telegram_bot_token_secret_name(instance_id);
        let webhook_secret_name = telegram_webhook_secret_name(instance_id);
        let now = now_secs();

        self.user_secrets
            .put(owner_id, &token_secret_name, token.as_bytes())
            .await?;
        self.user_secrets
            .put(owner_id, &webhook_secret_name, webhook_secret.as_bytes())
            .await?;

        match self
            .channels
            .insert(InstanceChannelRow {
                id: 0,
                instance_id: instance_id.to_owned(),
                kind: TELEGRAM_KIND.to_owned(),
                handle: handle.clone(),
                secret_name: token_secret_name,
                webhook_secret_name,
                enabled: true,
                allowed_senders,
                last_inbound_at: None,
                created_at: now,
            })
            .await
        {
            Ok(_) => Ok(ConnectedTelegram {
                handle,
                connected_at: now,
            }),
            Err(StoreError::Constraint(_)) => Err(ChannelsError::Conflict),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn disconnect_telegram(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> ChannelsResult<()> {
        self.ensure_owner(owner_id, instance_id).await?;
        let row = self
            .channels
            .get(instance_id, TELEGRAM_KIND)
            .await?
            .ok_or(ChannelsError::NotFound)?;
        if let Some(token) = self.token_for(owner_id, &row).await? {
            if let Err(err) = self.telegram.delete_webhook(&token).await {
                tracing::warn!(instance = %instance_id, error = %err, "telegram deleteWebhook failed; continuing disconnect");
            }
        }
        self.user_secrets.delete(owner_id, &row.secret_name).await?;
        self.user_secrets
            .delete(owner_id, &row.webhook_secret_name)
            .await?;
        self.channels.delete(instance_id, TELEGRAM_KIND).await?;
        Ok(())
    }

    pub async fn set_telegram_enabled(
        &self,
        owner_id: &str,
        instance_id: &str,
        enabled: bool,
    ) -> ChannelsResult<InstanceChannelRow> {
        self.ensure_owner(owner_id, instance_id).await?;
        self.channels
            .set_enabled(instance_id, TELEGRAM_KIND, enabled)
            .await?
            .ok_or(ChannelsError::NotFound)
    }

    pub async fn set_telegram_settings(
        &self,
        owner_id: &str,
        instance_id: &str,
        enabled: Option<bool>,
        allowed_senders: Option<Vec<String>>,
    ) -> ChannelsResult<InstanceChannelRow> {
        self.ensure_owner(owner_id, instance_id).await?;
        if enabled.is_none() && allowed_senders.is_none() {
            return Err(ChannelsError::BadRequest(
                "nothing to update for Telegram channel".into(),
            ));
        }
        let normalized = allowed_senders
            .map(normalize_telegram_allowed_senders)
            .transpose()?;
        self.channels
            .set_settings(instance_id, TELEGRAM_KIND, enabled, normalized.as_deref())
            .await?
            .ok_or(ChannelsError::NotFound)
    }

    pub async fn telegram_webhook_secret(
        &self,
        owner_id: &str,
        row: &InstanceChannelRow,
    ) -> ChannelsResult<Option<String>> {
        let Some(bytes) = self
            .user_secrets
            .get(owner_id, &row.webhook_secret_name)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    pub async fn token_for(
        &self,
        owner_id: &str,
        row: &InstanceChannelRow,
    ) -> ChannelsResult<Option<String>> {
        let Some(bytes) = self.user_secrets.get(owner_id, &row.secret_name).await? else {
            return Ok(None);
        };
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    async fn ensure_owner(&self, owner_id: &str, instance_id: &str) -> ChannelsResult<()> {
        self.instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(ChannelsError::NotFound)?;
        Ok(())
    }
}

pub fn delivery_preview(body: &[u8]) -> String {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    let text = json
        .get("message")
        .or_else(|| json.get("edited_message"))
        .or_else(|| json.get("channel_post"))
        .and_then(|m| m.get("text").or_else(|| m.get("caption")))
        .and_then(|v| v.as_str())
        .or_else(|| {
            json.get("callback_query")
                .and_then(|c| c.get("data"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("");
    let mut out = text.chars().take(200).collect::<String>();
    if text.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

pub fn telegram_update_allowed_by_sender(allowed_senders: &[String], body: &[u8]) -> bool {
    if allowed_senders.is_empty() {
        return true;
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let allowed = allowed_senders
        .iter()
        .filter_map(|entry| normalize_telegram_allowed_sender(entry).ok().flatten())
        .collect::<HashSet<_>>();
    telegram_sender_candidates(&json)
        .into_iter()
        .any(|candidate| allowed.contains(&candidate))
}

fn telegram_sender_candidates(json: &serde_json::Value) -> Vec<String> {
    let from = json
        .get("message")
        .or_else(|| json.get("edited_message"))
        .or_else(|| json.get("channel_post"))
        .and_then(|m| m.get("from"))
        .or_else(|| json.get("callback_query").and_then(|c| c.get("from")));
    let Some(from) = from else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(id) = from.get("id").and_then(|v| v.as_i64()) {
        out.push(id.to_string());
    }
    if let Some(username) = from.get("username").and_then(|v| v.as_str()) {
        if let Ok(Some(normalized)) = normalize_telegram_allowed_sender(username) {
            out.push(normalized);
        }
    }
    out
}

impl From<ChannelsError> for SwarmError {
    fn from(value: ChannelsError) -> Self {
        match value {
            ChannelsError::BadRequest(msg) => SwarmError::BadRequest(msg),
            ChannelsError::Conflict => SwarmError::BadRequest("channel already exists".into()),
            ChannelsError::NotFound => SwarmError::NotFound,
            ChannelsError::Store(e) => SwarmError::Store(e),
            ChannelsError::Telegram(e) | ChannelsError::Secrets(e) | ChannelsError::Internal(e) => {
                SwarmError::Internal(e)
            }
            ChannelsError::InstanceNotReady => SwarmError::Internal("instance not ready".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_allowed_sender_entries_normalize_and_dedupe() {
        let entries = normalize_telegram_allowed_senders(vec![
            " 123456 ".into(),
            "@TopMan".into(),
            "topman".into(),
            "".into(),
        ])
        .unwrap();
        assert_eq!(entries, vec!["123456", "topman"]);
    }

    #[test]
    fn telegram_sender_allowlist_matches_id_or_username() {
        let body = br#"{
            "update_id": 1,
            "message": {
                "from": { "id": 42, "username": "TopMan" },
                "chat": { "id": 99, "type": "private" },
                "text": "hello"
            }
        }"#;
        assert!(telegram_update_allowed_by_sender(&["42".into()], body));
        assert!(telegram_update_allowed_by_sender(&["topman".into()], body));
        assert!(telegram_update_allowed_by_sender(&["@topman".into()], body));
        assert!(!telegram_update_allowed_by_sender(
            &["someoneelse".into()],
            body
        ));
    }
}
