//! OIDC `Authenticator`.
//!
//! Validates an inbound `Authorization: Bearer <jwt>` against the IdP's
//! JWKS. Checks: signature, `iss`, `aud`, `exp` (jsonwebtoken does this last
//! one for us). The `kid` from the JWT header picks the verifying key out
//! of the cached JWKS; an unknown `kid` triggers a JWKS refetch (the IdP
//! has rotated keys) and a single retry.
//!
//! The JWKS URL is discovered from `<issuer>/.well-known/openid-configuration`
//! on first use and cached. Failures to fetch the discovery doc surface as
//! `AuthError::Backend` so the operator notices.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;

use crate::auth::{
    AuthError, AuthSource, Authenticator, UserIdentity, extract_bearer, looks_like_jwt,
};

#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// The IdP's `iss` claim — must match exactly. e.g.
    /// `https://accounts.google.com`.
    pub issuer: String,
    /// The expected `aud` claim. Usually the swarm's client_id at the IdP.
    pub audience: String,
    /// Optional override for the JWKS URL. If `None` we discover it from
    /// `<issuer>/.well-known/openid-configuration`.
    pub jwks_url: Option<String>,
    /// How long to cache the JWKS before re-fetching even without a kid
    /// miss.  Default 10m — keeps revoked / rotated keys from being
    /// honoured for long after an IdP silently drops them from the JWKS
    /// (some IdPs don't bump `kid` for in-place rotations).  Operators
    /// can dial this up via `oidc.jwks_ttl_seconds` if their IdP is
    /// well-behaved and they want fewer JWKS round-trips.
    pub jwks_ttl: Duration,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Clone)]
pub struct OidcAuthenticator {
    cfg: OidcConfig,
    http: Client,
    cache: Arc<Mutex<JwksCache>>,
}

#[derive(Default)]
struct JwksCache {
    /// `kid` → `DecodingKey`. Reset on every fetch.
    keys: HashMap<String, DecodingKey>,
    /// Discovered JWKS URL. Lazily populated.
    jwks_url: Option<String>,
    fetched_at: Option<Instant>,
}

impl OidcAuthenticator {
    pub fn new(cfg: OidcConfig) -> Result<Self, reqwest::Error> {
        let http = Client::builder().timeout(Duration::from_secs(5)).build()?;
        Ok(Self {
            cfg,
            http,
            cache: Arc::new(Mutex::new(JwksCache::default())),
        })
    }

    /// Test/builder seam: inject a pre-built reqwest client (e.g. one
    /// pointing at a mock IdP).
    pub fn with_http(mut self, http: Client) -> Self {
        self.http = http;
        self
    }

    async fn ensure_jwks_url(&self) -> Result<String, AuthError> {
        if let Some(url) = &self.cfg.jwks_url {
            return Ok(url.clone());
        }
        let mut cache = self.cache.lock().await;
        if let Some(url) = &cache.jwks_url {
            return Ok(url.clone());
        }
        let disco_url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        let disco: DiscoveryDoc = self
            .http
            .get(&disco_url)
            .send()
            .await
            .map_err(|e| AuthError::Backend(format!("oidc discovery: {e}")))?
            .error_for_status()
            .map_err(|e| AuthError::Backend(format!("oidc discovery status: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Backend(format!("oidc discovery decode: {e}")))?;
        cache.jwks_url = Some(disco.jwks_uri.clone());
        Ok(disco.jwks_uri)
    }

    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        let url = self.ensure_jwks_url().await?;
        let jwks: Jwks = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::Backend(format!("jwks fetch: {e}")))?
            .error_for_status()
            .map_err(|e| AuthError::Backend(format!("jwks status: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Backend(format!("jwks decode: {e}")))?;
        let mut cache = self.cache.lock().await;
        cache.keys.clear();
        for k in jwks.keys {
            // Only RSA keys for now — the OIDC spec requires RS256 support;
            // ES256 etc. can be added when an IdP needs them.
            if k.kty != "RSA" {
                continue;
            }
            let (Some(n), Some(e)) = (k.n.as_deref(), k.e.as_deref()) else {
                continue;
            };
            let key = match DecodingKey::from_rsa_components(n, e) {
                Ok(k) => k,
                Err(err) => {
                    tracing::warn!(error = %err, kid = %k.kid, "skip jwks key");
                    continue;
                }
            };
            cache.keys.insert(k.kid, key);
        }
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn key_for_kid(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Hot path: hit the cache.
        {
            let cache = self.cache.lock().await;
            let stale = match cache.fetched_at {
                Some(t) => t.elapsed() > self.cfg.jwks_ttl,
                None => true,
            };
            if !stale {
                if let Some(k) = cache.keys.get(kid) {
                    return Ok(k.clone());
                }
            }
        }
        // Either stale or kid miss — refetch and try once more.
        self.refresh_jwks().await?;
        let cache = self.cache.lock().await;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| AuthError::Invalid(format!("unknown kid: {kid}")))
    }

    fn validation(&self) -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.cfg.issuer]);
        v.set_audience(&[&self.cfg.audience]);
        // jsonwebtoken treats `nbf` as optional and silently skips it
        // unless we opt in.  Tokens minted with a future `nbf` (clock
        // skew, deliberate hold-to-release flows) should be rejected
        // until that wall-clock arrives — we already check `exp` for
        // free; the symmetric `nbf` check belongs here.
        v.validate_nbf = true;
        v
    }
}

#[async_trait]
impl Authenticator for OidcAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<UserIdentity, AuthError> {
        let Some(token) = extract_bearer(headers) else {
            return Err(AuthError::Missing);
        };
        if !looks_like_jwt(&token) {
            return Err(AuthError::Unsupported);
        }
        let header =
            decode_header(&token).map_err(|e| AuthError::Invalid(format!("bad header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::Invalid("missing kid".into()))?;
        let key = self.key_for_kid(&kid).await?;
        let data = decode::<JsonValue>(&token, &key, &self.validation()).map_err(|e| {
            // Surface the JWT's iss/aud claims on validation failure —
            // they're the two knobs that go wrong on first OIDC setup
            // (Auth0 custom domains, mismatched API identifiers, etc.).
            // We re-decode without verification just to read the claims;
            // the original error from the verifier is what we propagate.
            if let Ok(unverified) = jsonwebtoken::dangerous::insecure_decode::<JsonValue>(&token) {
                let iss = unverified
                    .claims
                    .get("iss")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let aud = unverified
                    .claims
                    .get("aud")
                    .map_or_else(|| "?".into(), std::string::ToString::to_string);
                tracing::debug!(
                    error = %e,
                    token_iss = %iss,
                    token_aud = %aud,
                    expected_iss = %self.cfg.issuer,
                    expected_aud = %self.cfg.audience,
                    "oidc verify failed"
                );
            }
            AuthError::Invalid(format!("verify: {e}"))
        })?;
        let claims = data.claims;
        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::Invalid("missing sub".into()))?
            .to_string();
        Ok(UserIdentity {
            subject,
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            display_name: claims
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            source: AuthSource::Oidc,
            claims,
        })
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: String,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[cfg(test)]
#[allow(clippy::items_after_statements)] // test fixtures define helpers inline
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::HeaderValue;
    use axum::routing::get;
    use axum::{Json, Router};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use serde::Serialize;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Build a fresh RSA-2048 keypair, run a mock OIDC discovery + JWKS
    /// server, and return the issuer URL plus a closure that mints valid
    /// JWTs for that issuer.
    struct MockIdP {
        issuer: String,
        encoding_key: EncodingKey,
        kid: String,
        jwks_calls: Arc<AtomicU32>,
    }

    impl MockIdP {
        fn mint(&self, sub: &str, aud: &str, email: Option<&str>) -> String {
            #[derive(Serialize)]
            struct Claims<'a> {
                sub: &'a str,
                iss: &'a str,
                aud: &'a str,
                exp: i64,
                iat: i64,
                #[serde(skip_serializing_if = "Option::is_none")]
                email: Option<&'a str>,
                #[serde(skip_serializing_if = "Option::is_none")]
                name: Option<&'a str>,
            }
            let now = crate::now_secs();
            let claims = Claims {
                sub,
                iss: &self.issuer,
                aud,
                exp: now + 3600,
                iat: now,
                email,
                name: Some(sub),
            };
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(self.kid.clone());
            encode(&header, &claims, &self.encoding_key).unwrap()
        }
    }

    async fn spawn_idp() -> MockIdP {
        let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let n_b64 = base64_url(&pub_key.n().to_bytes_be());
        let e_b64 = base64_url(&pub_key.e().to_bytes_be());
        let der = priv_key.to_pkcs1_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let kid = "test-key-1".to_string();

        let jwks_calls = Arc::new(AtomicU32::new(0));
        let n_for_state = n_b64.clone();
        let kid_for_state = kid.clone();
        let calls_for_state = jwks_calls.clone();

        #[derive(Clone)]
        struct DiscoveryState {
            issuer: String,
            jwks_calls: Arc<AtomicU32>,
            n: String,
            e: String,
            kid: String,
        }

        async fn discovery(State(s): State<DiscoveryState>) -> Json<JsonValue> {
            Json(serde_json::json!({
                "issuer": s.issuer,
                "jwks_uri": format!("{}/jwks", s.issuer),
            }))
        }

        async fn jwks(State(s): State<DiscoveryState>) -> Json<JsonValue> {
            s.jwks_calls.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({
                "keys": [{
                    "kid": s.kid,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": s.n,
                    "e": s.e,
                }]
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let issuer_for_state = issuer.clone();

        let state = DiscoveryState {
            issuer: issuer_for_state.clone(),
            jwks_calls: calls_for_state,
            n: n_for_state,
            e: e_b64,
            kid: kid_for_state,
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockIdP {
            issuer,
            encoding_key,
            kid,
            jwks_calls,
        }
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn headers_with_token(t: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn valid_jwt_resolves_to_identity() {
        let idp = spawn_idp().await;
        let cfg = OidcConfig {
            issuer: idp.issuer.clone(),
            audience: "swarm".into(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(60),
        };
        let auth = OidcAuthenticator::new(cfg).unwrap();
        let token = idp.mint("alice", "swarm", Some("alice@example"));
        let id = auth
            .authenticate(&headers_with_token(&token))
            .await
            .unwrap();
        assert_eq!(id.subject, "alice");
        assert_eq!(id.email.as_deref(), Some("alice@example"));
        assert_eq!(id.source, AuthSource::Oidc);
        assert_eq!(idp.jwks_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn second_token_reuses_cached_jwks() {
        let idp = spawn_idp().await;
        let cfg = OidcConfig {
            issuer: idp.issuer.clone(),
            audience: "swarm".into(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(60),
        };
        let auth = OidcAuthenticator::new(cfg).unwrap();
        for sub in ["a", "b", "c"] {
            let t = idp.mint(sub, "swarm", None);
            auth.authenticate(&headers_with_token(&t)).await.unwrap();
        }
        assert_eq!(idp.jwks_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_audience_is_invalid() {
        let idp = spawn_idp().await;
        let cfg = OidcConfig {
            issuer: idp.issuer.clone(),
            audience: "swarm".into(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(60),
        };
        let auth = OidcAuthenticator::new(cfg).unwrap();
        let t = idp.mint("alice", "different-aud", None);
        let err = auth
            .authenticate(&headers_with_token(&t))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn non_jwt_bearer_is_unsupported() {
        let idp = spawn_idp().await;
        let cfg = OidcConfig {
            issuer: idp.issuer.clone(),
            audience: "swarm".into(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(60),
        };
        let auth = OidcAuthenticator::new(cfg).unwrap();
        let err = auth
            .authenticate(&headers_with_token("opaque-bearer"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Unsupported));
    }

    #[tokio::test]
    async fn missing_header_is_missing() {
        let idp = spawn_idp().await;
        let cfg = OidcConfig {
            issuer: idp.issuer.clone(),
            audience: "swarm".into(),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(60),
        };
        let auth = OidcAuthenticator::new(cfg).unwrap();
        let err = auth.authenticate(&HeaderMap::new()).await.unwrap_err();
        assert!(matches!(err, AuthError::Missing));
    }
}
