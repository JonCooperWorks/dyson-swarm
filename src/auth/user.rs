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
    match resolve_caller(
        state.authenticator.as_ref(),
        state.users.as_ref(),
        req.headers(),
    )
    .await
    {
        Ok(caller) => {
            req.extensions_mut().insert(caller);
            next.run(req).await
        }
        Err(resp) => resp,
    }
}

/// Resolve the caller's `users.id` directly — same auth + activation
/// logic as [`user_middleware`], but for handlers that aren't part of
/// the middleware chain (e.g. the host-based reverse proxy in
/// [`crate::http::dyson_proxy`] which is the terminal handler, not a
/// gate before downstream routes).  Returns the user's id on success
/// or a ready-to-send error response.
pub async fn resolve_active_user(
    authenticator: &dyn Authenticator,
    users: &dyn UserStore,
    headers: &axum::http::HeaderMap,
) -> Result<String, Response> {
    resolve_caller(authenticator, users, headers).await.map(|c| c.user_id)
}

async fn resolve_caller(
    authenticator: &dyn Authenticator,
    users: &dyn UserStore,
    headers: &axum::http::HeaderMap,
) -> Result<CallerIdentity, Response> {
    let identity = match authenticator.authenticate(headers).await {
        Ok(id) => id,
        Err(AuthError::Missing) => return Err(StatusCode::UNAUTHORIZED.into_response()),
        Err(AuthError::Unsupported) => return Err(StatusCode::UNAUTHORIZED.into_response()),
        Err(AuthError::Invalid(reason)) => {
            tracing::debug!(%reason, "auth invalid");
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        Err(AuthError::Backend(e)) => {
            tracing::warn!(error = %e, "auth backend failure");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    let user = match resolve_or_provision(users, &identity).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "user resolve/provision failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    match user.status {
        UserStatus::Active => {}
        UserStatus::Inactive => {
            return Err((StatusCode::FORBIDDEN, "account inactive").into_response());
        }
        UserStatus::Suspended => {
            return Err((StatusCode::FORBIDDEN, "account suspended").into_response());
        }
    }

    if let Err(e) = users.touch_last_seen(&user.id).await {
        tracing::debug!(error = %e, user = %user.id, "touch_last_seen failed");
    }

    Ok(CallerIdentity {
        user_id: user.id,
        identity,
    })
}

async fn resolve_or_provision(
    users: &dyn UserStore,
    identity: &UserIdentity,
) -> Result<UserRow, crate::error::StoreError> {
    if let Some(existing) = users.get_by_subject(&identity.subject).await? {
        return Ok(existing);
    }
    // Stage 5: JIT-create as Active.  The IdP (Auth0) is the gate for
    // who can sign in — anyone holding a valid JWT for our audience
    // has already been registered + role-assigned upstream.  Pre-Stage-5
    // the row was Inactive and an admin had to flip it; with no
    // admin_token to bootstrap from, that loop deadlocks.  Admin
    // suspend/reactivate via the SPA is still available for ops use.
    let now = crate::now_secs();
    let row = UserRow {
        id: Uuid::new_v4().simple().to_string(),
        subject: identity.subject.clone(),
        email: identity.email.clone(),
        display_name: identity.display_name.clone(),
        status: UserStatus::Active,
        created_at: now,
        activated_at: Some(now),
        last_seen_at: None,
        openrouter_key_id: None,
        openrouter_key_limit_usd: 10.0,
    };
    users.create(row.clone()).await?;
    Ok(row)
}

/// Build a `UserAuthState` whose authenticator always returns a fixed
/// identity, and seed an active user row with that subject. Returns the
/// state and the user's `id` so tests can assert against it.
///
/// `roles` lets a test inject custom claims that look like an OIDC
/// access token's role array.  Pass `None` for an opaque-bearer-style
/// identity (no claims).  When `Some(("claim", &["rol_admin", ...]))`,
/// `caller.identity.claims` becomes `{"<claim>": [...]}`, which is
/// exactly what the OIDC authenticator stamps in production.
///
/// Test/integration helper. Production builds should use the OIDC + bearer
/// chain assembled in `main.rs`.
pub async fn fixed_user_auth(
    users: Arc<dyn UserStore>,
    subject: &str,
) -> (UserAuthState, String) {
    fixed_user_auth_with_roles(users, subject, None).await
}

/// Variant of [`fixed_user_auth`] that injects roles into the
/// caller's claims.  Useful for testing the admin role check.
pub async fn fixed_user_auth_with_roles(
    users: Arc<dyn UserStore>,
    subject: &str,
    roles: Option<(&str, &[&str])>,
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

    // Production user ids are uuid simple form (32 hex).  The envelope
    // module's `validate_user_id` rejects anything else, which would
    // make per-user secret seal/open fail in tests.  Use a fresh uuid
    // per call so concurrent tests don't collide on the users.id PK.
    let id = Uuid::new_v4().simple().to_string();
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
            openrouter_key_id: None,
            openrouter_key_limit_usd: 10.0,
        })
        .await
        .expect("create test user");
    let (source, claims) = match roles {
        Some((claim, vals)) => (
            AuthSource::Oidc,
            serde_json::json!({
                claim: vals.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>()
            }),
        ),
        None => (AuthSource::Bearer, serde_json::Value::Null),
    };
    let identity = UserIdentity {
        subject: subject.into(),
        email: None,
        display_name: None,
        source,
        claims,
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
    use crate::envelope::{AgeCipherDirectory, CipherDirectory};

    /// Build a test SqlxUserStore backed by a throwaway cipher dir.
    /// Tests in this module never exercise the api-key envelope so
    /// the dir's contents don't matter — but the constructor needs
    /// one and we don't want to leak filesystem state.  The TempDir
    /// is intentionally leaked (Box::leak) for the test process
    /// lifetime, which is bounded by the test runner.
    fn test_user_store(pool: sqlx::SqlitePool) -> Arc<dyn UserStore> {
        let tmp = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let dir: Arc<dyn CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        Arc::new(SqlxUserStore::new(pool, dir))
    }

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
    async fn jit_creates_active_user_and_passes() {
        // Stage 5: JIT-created users land Active because the IdP is
        // the gate (anyone with a valid JWT for our audience already
        // passed the upstream signup flow).  Suspended/Inactive are
        // now ops-only states an admin can flip via the SPA.
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = test_user_store(pool.clone());
        let auth: Arc<dyn Authenticator> = Arc::new(FixedIdentity(id("alice")));
        let state = UserAuthState::new(auth, users.clone());
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 200);
        let row = users.get_by_subject("alice").await.unwrap().unwrap();
        assert_eq!(row.status, UserStatus::Active);
        assert!(row.activated_at.is_some());
    }

    #[tokio::test]
    async fn active_user_passes_and_extension_is_set() {
        let pool = open_in_memory().await.unwrap();
        let users: Arc<dyn UserStore> = test_user_store(pool.clone());
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
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
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
        let users: Arc<dyn UserStore> = test_user_store(pool.clone());
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
                openrouter_key_id: None,
                openrouter_key_limit_usd: 10.0,
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
        let users: Arc<dyn UserStore> = test_user_store(pool.clone());
        let state = UserAuthState::new(Arc::new(AlwaysMissing), users);
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/v1/x")).await.unwrap();
        assert_eq!(r.status(), 401);
    }
}
