//! Opaque-bearer [`Authenticator`] backed by [`UserStore::resolve_api_key`].
//!
//! This is the CI/admin path: a long-lived token minted via
//! `POST /v1/admin/users/:id/keys`. Distinct from OIDC because there's no
//! IdP involved — the token is the credential.
//!
//! The bearer's prefix is configurable so a `ChainAuthenticator` can route
//! between bearer and OIDC without colliding header parsers (e.g. bearer
//! tokens use a `wk-` prefix, JWTs start with `eyJ`).

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::HeaderMap;

use crate::auth::{extract_bearer, looks_like_jwt, AuthError, AuthSource, Authenticator, UserIdentity};
use crate::traits::UserStore;

#[derive(Clone)]
pub struct BearerAuthenticator {
    users: Arc<dyn UserStore>,
    /// If set, only tokens with this prefix are claimed; everything else
    /// returns [`AuthError::Unsupported`] so a chain falls through to the
    /// next authenticator. `None` claims any non-JWT bearer.
    required_prefix: Option<String>,
}

impl BearerAuthenticator {
    pub fn new(users: Arc<dyn UserStore>) -> Self {
        Self {
            users,
            required_prefix: None,
        }
    }

    pub fn with_prefix(users: Arc<dyn UserStore>, prefix: impl Into<String>) -> Self {
        Self {
            users,
            required_prefix: Some(prefix.into()),
        }
    }
}

#[async_trait]
impl Authenticator for BearerAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<UserIdentity, AuthError> {
        let Some(token) = extract_bearer(headers) else {
            return Err(AuthError::Missing);
        };
        if let Some(prefix) = &self.required_prefix {
            if !token.starts_with(prefix) {
                return Err(AuthError::Unsupported);
            }
        } else if looks_like_jwt(&token) {
            return Err(AuthError::Unsupported);
        }
        match self.users.resolve_api_key(&token).await {
            Ok(Some(api)) => {
                // The api-key only carries user_id — fetch the user row for
                // the email/display_name we hand to downstream handlers.
                let user = self
                    .users
                    .get(&api.user_id)
                    .await
                    .map_err(|e| AuthError::Backend(e.to_string()))?
                    .ok_or_else(|| AuthError::Invalid("user_id has no row".into()))?;
                Ok(UserIdentity {
                    subject: user.subject,
                    email: user.email,
                    display_name: user.display_name,
                    source: AuthSource::Bearer,
                    claims: serde_json::Value::Null,
                })
            }
            Ok(None) => Err(AuthError::Invalid("unknown or revoked bearer".into())),
            Err(e) => Err(AuthError::Backend(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    use crate::db::open_in_memory;
    use crate::db::users::SqlxUserStore;
    use crate::envelope::{AgeCipherDirectory, CipherDirectory};
    use crate::traits::{UserRow, UserStatus};

    fn headers(token: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
            );
        }
        h
    }

    /// Test fixture: 32-hex user id required by the envelope's
    /// validate_user_id check.
    fn alice_id() -> String {
        format!("{:032x}", 0xa1u128 | (0xa1u128 << 64))
    }

    async fn build() -> (BearerAuthenticator, Arc<SqlxUserStore>, String, tempfile::TempDir) {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store = Arc::new(SqlxUserStore::new(pool, dir));
        let id = alice_id();
        store
            .create(UserRow {
                id: id.clone(),
                subject: "alice".into(),
                email: Some("alice@example".into()),
                display_name: Some("Alice".into()),
                status: UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
            })
            .await
            .unwrap();
        let token = store.mint_api_key(&id, Some("ci")).await.unwrap();
        let auth = BearerAuthenticator::new(store.clone());
        (auth, store, token, tmp)
    }

    #[tokio::test]
    async fn missing_header_is_missing() {
        let (auth, _, _, _tmp) = build().await;
        let err = auth.authenticate(&headers(None)).await.unwrap_err();
        assert!(matches!(err, AuthError::Missing));
    }

    #[tokio::test]
    async fn unknown_bearer_is_invalid() {
        let (auth, _, _, _tmp) = build().await;
        let err = auth.authenticate(&headers(Some("nope"))).await.unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn known_bearer_resolves_to_subject() {
        let (auth, _, token, _tmp) = build().await;
        let id = auth.authenticate(&headers(Some(&token))).await.unwrap();
        assert_eq!(id.subject, "alice");
        assert_eq!(id.email.as_deref(), Some("alice@example"));
        assert_eq!(id.source, AuthSource::Bearer);
    }

    #[tokio::test]
    async fn revoked_bearer_is_invalid() {
        let (auth, store, token, _tmp) = build().await;
        store.revoke_api_key(&token).await.unwrap();
        let err = auth.authenticate(&headers(Some(&token))).await.unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn jwt_shaped_token_is_unsupported_so_chain_can_handoff() {
        let (auth, _, _, _tmp) = build().await;
        let err = auth
            .authenticate(&headers(Some("eyJhbGciOiJSUzI1NiJ9.foo.bar")))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Unsupported));
    }

    #[tokio::test]
    async fn prefix_filter_routes_other_tokens_to_unsupported() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store = Arc::new(SqlxUserStore::new(pool, dir));
        let auth = BearerAuthenticator::with_prefix(store, "wk-");
        let err = auth
            .authenticate(&headers(Some("not-prefixed")))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Unsupported));
    }
}
