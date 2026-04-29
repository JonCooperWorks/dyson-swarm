//! MCP server configurations, persistence, and OAuth state.
//!
//! Per-instance MCP server records live in [`crate::secrets::UserSecretsService`]
//! under `mcp.<instance_id>.<server_name>`.  The blob carries the upstream
//! URL, the auth shape, and (for OAuth) the persisted tokens.
//!
//! Why user_secrets and not a new table:
//!   The encryption shape we want is exactly what UserSecretsService gives —
//!   sealed with the *user's* age cipher so a stolen sqlite row leaks
//!   nothing without the owner's key file.  Stuffing the JSON blob there
//!   keyed by instance keeps us out of the migration business.
//!
//! The agent never sees the upstream URL or auth credentials.  It points
//! its `McpTransportConfig::Http` at `https://<swarm>/mcp/<instance>/<name>`
//! with the per-instance proxy_token; [`crate::proxy::mcp`] handles the
//! handshake, refresh, and forward.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::secrets::{SecretsError, UserSecretsService};

/// On-the-wire shape the SPA submits when hiring a Dyson with MCP
/// servers.  Mirrors the JSON the React form builds.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerSpec {
    /// Logical name (becomes the key under `mcp_servers` in dyson.json).
    pub name: String,
    /// Upstream MCP endpoint URL.
    pub url: String,
    pub auth: McpAuthSpec,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpAuthSpec {
    None,
    /// Static bearer token added on every forwarded request.
    Bearer { token: String },
    /// OAuth 2.1 Authorization Code + PKCE.  All discovery fields
    /// optional — leave empty to use `.well-known/oauth-authorization-server`
    /// against the server URL's origin and Dynamic Client Registration.
    Oauth {
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        authorization_url: Option<String>,
        #[serde(default)]
        token_url: Option<String>,
        #[serde(default)]
        registration_url: Option<String>,
    },
}

/// Persistent record stored in `user_secrets`.  Wraps the user-supplied
/// spec plus any swarm-managed OAuth state (tokens after a successful
/// flow, refreshed transparently on the proxy path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub url: String,
    pub auth: McpAuthSpec,
    /// Populated by the OAuth callback; refreshed on demand by the
    /// proxy when an access token is near or past its expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_tokens: Option<McpOAuthTokens>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthTokens {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds at which `access_token` becomes invalid.  None ⇒
    /// the server didn't return `expires_in` (rare; treat as long-lived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Resolved token endpoint — recorded so the proxy refresh path
    /// doesn't have to redo discovery on every refresh.
    pub token_url: String,
    /// Resolved client_id — same reason as `token_url`.
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl McpOAuthTokens {
    /// True when the access token has 60s or less of validity left.
    /// The 60s skew matches what dyson uses (auth/oauth.rs).
    pub fn needs_refresh(&self, now_secs: i64) -> bool {
        match self.expires_at {
            Some(exp) => exp - 60 <= now_secs,
            None => false,
        }
    }
}

impl McpServerEntry {
    pub fn from_spec(spec: McpServerSpec) -> (String, Self) {
        let McpServerSpec { name, url, auth } = spec;
        (
            name,
            Self {
                url,
                auth,
                oauth_tokens: None,
            },
        )
    }
}

/// Build the `user_secrets` row name for one server.
pub fn entry_key(instance_id: &str, server_name: &str) -> String {
    format!("mcp.{instance_id}.{server_name}")
}

/// Build the `user_secrets` row name for the index of server names
/// attached to an instance.  Stored as a JSON `["name1", "name2", ...]`
/// blob so the proxy can list/destroy without DB-level enumeration.
pub fn index_key(instance_id: &str) -> String {
    format!("mcp.{instance_id}._index")
}

/// Persist a list of MCP server specs for an instance.  Each spec is
/// sealed under the instance owner's cipher and an index row is
/// rewritten with the server names so subsequent enumeration is cheap.
///
/// Replaces any previous configuration for the instance — callers who
/// want incremental updates should read first, modify, write.
pub async fn put_all(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    specs: Vec<McpServerSpec>,
) -> Result<(), SecretsError> {
    let mut names: Vec<String> = Vec::with_capacity(specs.len());
    for spec in specs {
        let (name, entry) = McpServerEntry::from_spec(spec);
        let blob = serde_json::to_vec(&entry).map_err(|e| {
            SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
                "serialise mcp entry: {e}"
            )))
        })?;
        secrets.put(owner_id, &entry_key(instance_id, &name), &blob).await?;
        names.push(name);
    }
    let idx = serde_json::to_vec(&names).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "serialise mcp index: {e}"
        )))
    })?;
    secrets.put(owner_id, &index_key(instance_id), &idx).await?;
    Ok(())
}

/// Read a single server entry.  None = no row.
pub async fn get(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
) -> Result<Option<McpServerEntry>, SecretsError> {
    let Some(bytes) = secrets.get(owner_id, &entry_key(instance_id, server_name)).await? else {
        return Ok(None);
    };
    let entry: McpServerEntry = serde_json::from_slice(&bytes).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "parse mcp entry: {e}"
        )))
    })?;
    Ok(Some(entry))
}

/// Overwrite a single entry — used by the OAuth callback to stamp
/// freshly-minted tokens, and by the proxy refresh path.
pub async fn put(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
) -> Result<(), SecretsError> {
    let blob = serde_json::to_vec(entry).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "serialise mcp entry: {e}"
        )))
    })?;
    secrets.put(owner_id, &entry_key(instance_id, server_name), &blob).await?;
    Ok(())
}

/// List names attached to an instance.  Cheap — reads only the index row.
pub async fn list_names(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
) -> Result<Vec<String>, SecretsError> {
    let Some(bytes) = secrets.get(owner_id, &index_key(instance_id)).await? else {
        return Ok(Vec::new());
    };
    let names: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "parse mcp index: {e}"
        )))
    })?;
    Ok(names)
}

/// Delete every MCP server record for an instance.  Best-effort —
/// individual row failures are logged but don't fail the whole call.
/// Called from the instance destroy path so plaintext doesn't linger.
pub async fn forget_all(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
) -> Result<(), SecretsError> {
    let names = list_names(secrets, owner_id, instance_id).await?;
    for name in names {
        if let Err(err) = secrets.delete(owner_id, &entry_key(instance_id, &name)).await {
            tracing::warn!(
                error = %err,
                instance = %instance_id,
                server = %name,
                "mcp forget: row delete failed"
            );
        }
    }
    if let Err(err) = secrets.delete(owner_id, &index_key(instance_id)).await {
        tracing::warn!(
            error = %err,
            instance = %instance_id,
            "mcp forget: index delete failed"
        );
    }
    Ok(())
}

/// Render the per-server stanza the dyson loader expects under
/// `mcp_servers.<name>` in dyson.json.  The agent only ever sees the
/// swarm-internal proxy URL + bearer header — never the user's real
/// upstream URL or credentials.
///
/// `proxy_base` is the swarm's external `https://<host>` (the same
/// origin that fronts `/llm`).  `proxy_token` is the per-instance
/// bearer the agent already uses for `/llm`.
pub fn dyson_json_block(
    instance_id: &str,
    name: &str,
    proxy_base: &str,
    proxy_token: &str,
) -> serde_json::Value {
    let url = format!(
        "{}/mcp/{}/{}",
        proxy_base.trim_end_matches('/'),
        instance_id,
        name,
    );
    serde_json::json!({
        "url": url,
        "headers": {
            "Authorization": format!("Bearer {proxy_token}"),
        },
    })
}

// ───────────────────────────────────────────────────────────────────
// OAuth primitives — discovery, PKCE, token exchange/refresh.
// Ported from dyson/auth/oauth.rs so the swarm-side proxy can run
// the flow without depending on the agent crate.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuthMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DcrRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DcrResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
}

pub fn generate_pkce() -> PkceChallenge {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkceChallenge { verifier, challenge }
}

pub fn generate_state() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().r#gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn discover_metadata(
    server_url: &str,
    client: &reqwest::Client,
) -> Result<AuthMetadata, String> {
    // Discovery is performed against the URL's origin, not the full
    // path: a server at https://example.com/mcp publishes its metadata
    // under https://example.com/.well-known/oauth-authorization-server.
    let origin = origin_of(server_url)?;
    let url = format!("{origin}/.well-known/oauth-authorization-server");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("discovery {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("discovery {url}: HTTP {}", resp.status()));
    }
    resp.json::<AuthMetadata>()
        .await
        .map_err(|e| format!("parse metadata: {e}"))
}

fn origin_of(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("parse {url}: {e}"))?;
    let host = parsed.host_str().ok_or_else(|| format!("no host in {url}"))?;
    let scheme = parsed.scheme();
    Ok(match parsed.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

pub async fn register_client(
    url: &str,
    req: &DcrRequest,
    client: &reqwest::Client,
) -> Result<DcrResponse, String> {
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .map_err(|e| format!("DCR send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("DCR returned HTTP {}", resp.status()));
    }
    resp.json::<DcrResponse>()
        .await
        .map_err(|e| format!("DCR parse: {e}"))
}

pub fn build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    scopes: &[String],
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(authorization_endpoint)
        .map_err(|e| format!("parse auth endpoint: {e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state);
    Ok(url.to_string())
}

pub async fn exchange_code(
    token_url: &str,
    code: &str,
    verifier: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    if let Some(s) = client_secret {
        params.push(("client_secret", s));
    }
    post_token(token_url, &params, client).await
}

pub async fn refresh_token(
    token_url: &str,
    refresh: &str,
    client_id: &str,
    client_secret: Option<&str>,
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ];
    if let Some(s) = client_secret {
        params.push(("client_secret", s));
    }
    post_token(token_url, &params, client).await
}

async fn post_token(
    token_url: &str,
    params: &[(&str, &str)],
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    let resp = client
        .post(token_url)
        .form(params)
        .send()
        .await
        .map_err(|e| format!("token request: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token endpoint HTTP {status}: {body}"));
    }
    resp.json::<TokenResponse>()
        .await
        .map_err(|e| format!("parse token response: {e}"))
}

/// In-process cache of in-flight OAuth flows.  Holds the PKCE verifier
/// and the user/instance/server it was started for so the callback can
/// match the inbound `state` param.  Five-minute TTL — same as dyson's
/// own callback server.
#[derive(Clone, Default)]
pub struct OAuthFlowCache {
    inner: Arc<parking_lot::Mutex<std::collections::HashMap<String, PendingFlow>>>,
}

#[derive(Clone)]
pub struct PendingFlow {
    pub owner_id: String,
    pub instance_id: String,
    pub server_name: String,
    pub pkce_verifier: String,
    pub redirect_uri: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Unix seconds when this entry expires.
    pub expires_at: i64,
    /// Where to send the user's browser after the callback finishes.
    /// Defaults to the instance detail page; the SPA can override.
    pub return_to: Option<String>,
}

impl OAuthFlowCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, state: String, flow: PendingFlow) {
        // Opportunistic GC: every insert prunes expired entries.  At
        // typical load (a handful of in-flight flows per swarm) this is
        // a few-line scan; cheaper than a background sweeper task.
        let now = crate::now_secs();
        let mut g = self.inner.lock();
        g.retain(|_, v| v.expires_at > now);
        g.insert(state, flow);
    }

    pub fn take(&self, state: &str) -> Option<PendingFlow> {
        let now = crate::now_secs();
        let mut g = self.inner.lock();
        g.retain(|_, v| v.expires_at > now);
        g.remove(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::AgeCipherDirectory;
    use crate::traits::UserSecretStore;
    use std::sync::Mutex;

    struct MemUserSecretStore(Mutex<Vec<(String, String, String)>>);

    #[async_trait::async_trait]
    impl UserSecretStore for MemUserSecretStore {
        async fn put(
            &self,
            user_id: &str,
            name: &str,
            ct: &str,
        ) -> Result<(), crate::error::StoreError> {
            let mut v = self.0.lock().unwrap();
            v.retain(|(u, n, _)| !(u == user_id && n == name));
            v.push((user_id.to_owned(), name.to_owned(), ct.to_owned()));
            Ok(())
        }
        async fn get(
            &self,
            user_id: &str,
            name: &str,
        ) -> Result<Option<String>, crate::error::StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|(u, n, _)| u == user_id && n == name)
                .map(|(_, _, c)| c.clone()))
        }
        async fn delete(
            &self,
            user_id: &str,
            name: &str,
        ) -> Result<(), crate::error::StoreError> {
            self.0.lock().unwrap().retain(|(u, n, _)| !(u == user_id && n == name));
            Ok(())
        }
        async fn list(
            &self,
            user_id: &str,
        ) -> Result<Vec<(String, String)>, crate::error::StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, _, _)| u == user_id)
                .map(|(_, n, c)| (n.clone(), c.clone()))
                .collect())
        }
    }

    fn make_svc() -> (tempfile::TempDir, Arc<UserSecretsService>) {
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store: Arc<dyn UserSecretStore> = Arc::new(MemUserSecretStore(Mutex::new(Vec::new())));
        (tmp, Arc::new(UserSecretsService::new(store, dir)))
    }

    #[tokio::test]
    async fn round_trip_bearer_server() {
        let (_tmp, svc) = make_svc();
        let owner = "deadbeef".repeat(4);
        let instance = "i-abc";
        put_all(
            &svc,
            &owner,
            instance,
            vec![McpServerSpec {
                name: "linear".into(),
                url: "https://api.linear.app/mcp".into(),
                auth: McpAuthSpec::Bearer { token: "lin_xxx".into() },
            }],
        )
        .await
        .unwrap();

        let names = list_names(&svc, &owner, instance).await.unwrap();
        assert_eq!(names, vec!["linear"]);

        let entry = get(&svc, &owner, instance, "linear").await.unwrap().unwrap();
        assert_eq!(entry.url, "https://api.linear.app/mcp");
        match entry.auth {
            McpAuthSpec::Bearer { token } => assert_eq!(token, "lin_xxx"),
            _ => panic!("expected bearer auth"),
        }
    }

    #[tokio::test]
    async fn forget_all_clears_index_and_rows() {
        let (_tmp, svc) = make_svc();
        let owner = "cafef00d".repeat(4);
        let instance = "i-zzz";
        put_all(
            &svc,
            &owner,
            instance,
            vec![
                McpServerSpec {
                    name: "a".into(),
                    url: "https://a/mcp".into(),
                    auth: McpAuthSpec::None,
                },
                McpServerSpec {
                    name: "b".into(),
                    url: "https://b/mcp".into(),
                    auth: McpAuthSpec::Bearer { token: "t".into() },
                },
            ],
        )
        .await
        .unwrap();
        forget_all(&svc, &owner, instance).await.unwrap();
        assert!(get(&svc, &owner, instance, "a").await.unwrap().is_none());
        assert!(get(&svc, &owner, instance, "b").await.unwrap().is_none());
        assert!(list_names(&svc, &owner, instance).await.unwrap().is_empty());
    }

    #[test]
    fn dyson_json_block_uses_proxy_url() {
        let block = dyson_json_block("i-abc", "linear", "https://swarm.example/", "tok-1");
        assert_eq!(block["url"], "https://swarm.example/mcp/i-abc/linear");
        assert_eq!(block["headers"]["Authorization"], "Bearer tok-1");
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let p = generate_pkce();
        let want = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, want);
    }

    #[test]
    fn oauth_cache_take_removes_entry() {
        let cache = OAuthFlowCache::new();
        cache.insert(
            "state-1".into(),
            PendingFlow {
                owner_id: "u".into(),
                instance_id: "i".into(),
                server_name: "s".into(),
                pkce_verifier: "v".into(),
                redirect_uri: "https://swarm/mcp/oauth/callback".into(),
                token_url: "https://up/token".into(),
                client_id: "c".into(),
                client_secret: None,
                expires_at: i64::MAX,
                return_to: None,
            },
        );
        assert!(cache.take("state-1").is_some());
        assert!(cache.take("state-1").is_none(), "take must be one-shot");
    }

    #[test]
    fn needs_refresh_respects_60s_skew() {
        let now = 1_000_000_i64;
        let near = McpOAuthTokens {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: Some(now + 30),
            token_url: "u".into(),
            client_id: "c".into(),
            client_secret: None,
        };
        assert!(near.needs_refresh(now), "30s left should refresh");
        let far = McpOAuthTokens { expires_at: Some(now + 600), ..near.clone() };
        assert!(!far.needs_refresh(now));
    }

    #[test]
    fn auth_spec_serialisation_is_tagged() {
        let s = McpAuthSpec::Bearer { token: "t".into() };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["kind"], "bearer");
        assert_eq!(v["token"], "t");
    }
}
