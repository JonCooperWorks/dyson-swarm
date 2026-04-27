//! User middleware.
//!
//! Sits in front of `/v1/*` (except admin sub-routes that the admin-bearer
//! gates separately). Resolves the inbound credential via the configured
//! [`Authenticator`], looks up or auto-creates a `users` row, refuses
//! inactive accounts with 403, and stamps the resolved [`CallerIdentity`]
//! on the request extensions for downstream handlers.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::auth::{AuthError, Authenticator, UserIdentity};
use crate::traits::{UserRow, UserStatus, UserStore};

/// Stamped on request extensions by [`user_middleware`]. Routes read it via
/// the [`CallerExtractor`] (or directly from `req.extensions()`).
#[derive(Clone, Debug)]
pub struct CallerIdentity {
    pub user_id: String,
    pub identity: UserIdentity,
}

#[derive(Clone)]
pub struct UserAuthState {
    pub authenticator: Arc<dyn Authenticator>,
    pub users: Arc<dyn UserStore>,
}

impl UserAuthState {
    pub fn new(authenticator: Arc<dyn Authenticator>, users: Arc<dyn UserStore>) -> Self {
        Self {
            authenticator,
            users,
        }
    }
}

pub async fn user_middleware(
    State(state): State<UserAuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let identity = match state.authenticator.authenticate(req.headers()).await {
        Ok(id) => id,
        Err(AuthError::Missing) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(AuthError::Unsupported) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(AuthError::Invalid(reason)) => {
            tracing::debug!(%reason, "auth invalid");
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(AuthError::Backend(e)) => {
            tracing::warn!(error = %e, "auth backend failure");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let user = match resolve_or_provision(&*state.users, &identity).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "user resolve/provision failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match user.status {
        UserStatus::Active => {}
        UserStatus::Inactive => {
            // Auto-created from a fresh OIDC sub but not yet approved.
            // Distinct status code from "wrong credential" so the UI can
            // show "your account is awaiting approval" rather than
            // implying a credential error.
            return (StatusCode::FORBIDDEN, "account inactive").into_response();
        }
        UserStatus::Suspended => {
            return (StatusCode::FORBIDDEN, "account suspended").into_response();
        }
    }

    // Best-effort touch — failure shouldn't block the request.
    if let Err(e) = state.users.touch_last_seen(&user.id).await {
        tracing::debug!(error = %e, user = %user.id, "touch_last_seen failed");
    }

    req.extensions_mut().insert(CallerIdentity {
        user_id: user.id,
        identity,
    });
    next.run(req).await
}

async fn resolve_or_provision(
    users: &dyn UserStore,
    identity: &UserIdentity,
) -> Result<UserRow, crate::error::StoreError> {
    if let Some(existing) = users.get_by_subject(&identity.subject).await? {
        return Ok(existing);
    }
    // JIT: insert a new row in `inactive` status. An admin must activate
    // it before the user can do anything.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let row = UserRow {
        id: Uuid::new_v4().simple().to_string(),
        subject: identity.subject.clone(),
        email: identity.email.clone(),
        display_name: identity.display_name.clone(),
        status: UserStatus::Inactive,
        created_at: now,
        activated_at: None,
        last_seen_at: None,
    };
    users.create(row.clone()).await?;
    Ok(row)
}

/// Build a `UserAuthState` whose authenticator always returns a fixed
/// identity, and seed an active user row with that subject. Returns the
/// state and the user's `id` so tests can assert against it.
///
/// Test/integration helper. Production builds should use the OIDC + bearer
/// chain assembled in `main.rs`.
pub async fn fixed_user_auth(
    users: Arc<dyn UserStore>,
    subject: &str,
) -> (UserAuthState, String) {
    use crate::auth::{AuthSource, UserIdentity};

    struct Fixed(UserIdentity);

    #[async_trait::async_trait]
    impl crate::auth::Authenticator for Fixed {
        async fn authenticate(
            &self,
            _: &axum::http::HeaderMap,
        ) -> Result<UserIdentity, crate::auth::AuthError> {
            Ok(self.0.clone())
        }
    }

    let id = format!("test-{subject}");
    users
        .create(UserRow {
            id: id.clone(),
            subject: subject.into(),
            email: None,
            display_name: None,
            status: UserStatus::Active,
            created_at: 0,
            activated_at: Some(0),
            last_seen_at: None,
        })
        .await
        .expect("create test user");
    let identity = UserIdentity {
        subject: subject.into(),
        email: None,
        display_name: None,
        source: AuthSource::Bearer,
        claims: serde_json::Value::Null,
    };
    let auth = UserAuthState::new(Arc::new(Fixed(identity)), users);
    (auth, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::{middleware, Router};

    use crate::auth::AuthSource;
    use crate::db::open_in_memory;
    use crate::db::users::SqlxUserStore;

    /// Test authenticator that returns a fixed identity.
    struct FixedIdentity(UserIdentity);

    #[async_trait::async_trait]
    impl Authenticator for FixedIdentity {
        async fn authenticate(&self, _: &HeaderMap) -> Result<UserIdentity, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn id(subject: &str) -> UserIdentity {
        UserIdentity {
            subject: subject.into(),
            email: Some(format!("{subject}@example")),
            display_name: Some(subject.into()),
            source: AuthSource::Bearer,
            claims: serde_json::Value::Null,
        }
    }

    async fn handler(req: Request<Body>) -> Response {
        let caller = req
            .extensions()
            .get::<CallerIdentity>()
            .cloned()
            .expect("middleware ran");
        format!("uid={} sub={}", caller.user_id, caller.identity.subject).into_response()
    }

    async fn spawn(state: UserAuthState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/x", get(handler))
            .layer(middleware::from_fn_with_state(state, user_middleware));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn jit_inactive_user_is_403() {
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = Arc::new(SqlxUserStore::new(pool.clone()));
        let auth: Arc<dyn Authenticator> = Arc::new(FixedIdentity(id("alice")));
        let state = UserAuthState::new(auth, users.clone());
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 403);
        // Row was created but inactive.
        let row = users.get_by_subject("alice").await.unwrap().unwrap();
        assert_eq!(row.status, UserStatus::Inactive);
    }

    #[tokio::test]
    async fn active_user_passes_and_extension_is_set() {
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = Arc::new(SqlxUserStore::new(pool.clone()));
        // Pre-provision an active user.
        users
            .create(UserRow {
                id: "u1".into(),
                subject: "bob".into(),
                email: None,
                display_name: None,
                status: UserStatus::Active,
                created_at: 0,
                activated_at: Some(0),
                last_seen_at: None,
            })
            .await
            .unwrap();
        let auth: Arc<dyn Authenticator> = Arc::new(FixedIdentity(id("bob")));
        let state = UserAuthState::new(auth, users);
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 200);
        let body = r.text().await.unwrap();
        assert_eq!(body, "uid=u1 sub=bob");
    }

    #[tokio::test]
    async fn suspended_user_is_403() {
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = Arc::new(SqlxUserStore::new(pool.clone()));
        users
            .create(UserRow {
                id: "u1".into(),
                subject: "carol".into(),
                email: None,
                display_name: None,
                status: UserStatus::Suspended,
                created_at: 0,
                activated_at: None,
                last_seen_at: None,
            })
            .await
            .unwrap();
        let auth: Arc<dyn Authenticator> = Arc::new(FixedIdentity(id("carol")));
        let state = UserAuthState::new(auth, users);
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 403);
    }

    /// Authenticator that always returns Missing.
    struct AlwaysMissing;

    #[async_trait::async_trait]
    impl Authenticator for AlwaysMissing {
        async fn authenticate(&self, _: &HeaderMap) -> Result<UserIdentity, AuthError> {
            Err(AuthError::Missing)
        }
    }

    #[tokio::test]
    async fn missing_credential_is_401() {
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = Arc::new(SqlxUserStore::new(pool.clone()));
        let state = UserAuthState::new(Arc::new(AlwaysMissing), users);
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 401);
    }
}
