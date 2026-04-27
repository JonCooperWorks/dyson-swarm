//! Auth.
//!
//! Two layers of identity:
//!
//! 1. **Admin bearer** — pre-existing `--dangerous-no-auth`-aware middleware
//!    that gates `/v1/admin/*` ops endpoints. Lives in [`admin`].
//! 2. **User identity** — pluggable [`Authenticator`] resolves an inbound
//!    request to a [`UserIdentity`] (subject, claims, source). The
//!    [`user::user_middleware`] looks up or auto-creates the matching `users`
//!    row, refuses inactive accounts with 403, and stamps the resolved
//!    `user_id` on the request extensions for downstream handlers.
//!
//! Concrete authenticators:
//! - [`bearer::BearerAuthenticator`] — opaque tokens minted via
//!   `UserStore::mint_api_key`. The CI/admin path that doesn't run an OIDC
//!   flow.
//! - [`oidc::OidcAuthenticator`] — RS256 JWT validation against the IdP's
//!   JWKS, cached and refreshed on `kid` miss. (Phase 4.)
//! - [`chain::ChainAuthenticator`] — tries each in order, returning the
//!   first non-`Unauthenticated` outcome.

pub mod admin;
pub mod bearer;
pub mod chain;
pub mod oidc;
pub mod user;

use async_trait::async_trait;
use axum::http::HeaderMap;
use serde_json::Value as JsonValue;

pub use admin::{admin_bearer, AuthState};

/// Identity returned by an [`Authenticator`]. The `subject` is the IdP-stable
/// id (OIDC `sub` for JWTs, the api_key's `user_id` for bearers).
#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub source: AuthSource,
    /// Raw provider claims for downstream introspection (e.g. groups, roles).
    /// Always an `Object` for OIDC; `Null` for opaque bearers.
    pub claims: JsonValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    /// Validated OIDC JWT.
    Oidc,
    /// Opaque api-key bearer minted by warden.
    Bearer,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No credential found at all (no Authorization header).
    #[error("no credential")]
    Missing,
    /// Credential present but couldn't be validated. Detail kept for
    /// `tracing::debug` only — never surfaced to the client (avoid an oracle
    /// for token-shape probes).
    #[error("invalid credential: {0}")]
    Invalid(String),
    /// The authenticator can't service this credential type — try the next
    /// in a [`chain::ChainAuthenticator`].
    #[error("not handled by this authenticator")]
    Unsupported,
    /// Transport / store error talking to the IdP or the `users` table.
    #[error("auth backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<UserIdentity, AuthError>;
}

pub use user::{user_middleware, CallerIdentity, UserAuthState};

/// Pull the resolved caller out of an `axum::http::Extensions` map. Routes
/// receive this via the `Extension(CallerIdentity)` extractor, but we keep
/// a free function around for tests and middleware plumbing.
pub fn caller_from_extensions(ext: &axum::http::Extensions) -> Option<&CallerIdentity> {
    ext.get::<CallerIdentity>()
}
