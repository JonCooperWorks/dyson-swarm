//! Admin gate for `/v1/admin/*`.
//!
//! Stage 5 replaced the legacy shared `admin_token` bearer with an
//! OIDC role check.  The flow now layers as:
//!
//! 1. `user_middleware` resolves the inbound credential to a
//!    `CallerIdentity` (OIDC JWT or user api-key).
//! 2. [`require_admin_role`] (this module) reads the caller's claims,
//!    checks for the configured admin role id, and 403s if missing.
//!
//! User api-key holders never have OIDC claims, so they're effectively
//! locked out of admin endpoints by design — admin is an
//! IdP-managed role, not a credential type.
//!
//! The `--dangerous-no-auth` flag bypasses both middlewares (set up
//! at the router layer) and stamps an `X-Swarm-Insecure: 1` header
//! on every response so callers can't mistake the deployment posture.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::CallerIdentity;
use crate::config::OidcRoles;

/// Admin-side state.  Two pieces:
///
/// - [`OidcRoles`] (cloned from config) — claim name + admin role id.
/// - `dangerous_no_auth` — when true, every request passes and the
///   response carries `X-Swarm-Insecure: 1`.  Used by `--dangerous-no-auth`
///   for local dev; never set in production.
#[derive(Clone, Debug)]
pub struct AuthState {
    pub roles: Option<OidcRoles>,
    pub dangerous_no_auth: bool,
}

impl AuthState {
    pub fn enforced(roles: OidcRoles) -> Self {
        Self {
            roles: Some(roles),
            dangerous_no_auth: false,
        }
    }

    pub fn dangerous_no_auth() -> Self {
        Self {
            roles: None,
            dangerous_no_auth: true,
        }
    }
}

/// Require the caller's JWT to carry the configured admin role.
/// Expects `user_middleware` to have already stamped a [`CallerIdentity`]
/// on the request extensions; absent → 401 (the auth layer's own
/// rejection class).
///
/// Denial returns **404 Not Found**, not 403.  The admin surface is a
/// privileged path operators don't want to advertise to scanners or
/// half-curious tenants.  A 403 leaks "this endpoint exists, you're
/// just not in the right role"; a 404 collapses denial into the same
/// shape every unmapped path returns and gives nothing away.  The
/// SPA gates the admin link on the `permissions` claim client-side
/// so legitimate admins never see the 404 either.
pub async fn require_admin_role(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Response {
    if auth.dangerous_no_auth {
        let mut resp = next.run(req).await;
        resp.headers_mut()
            .insert("X-Swarm-Insecure", HeaderValue::from_static("1"));
        return resp;
    }

    let Some(roles) = auth.roles.as_ref() else {
        // Production posture but no [oidc.roles] configured — admin
        // is unreachable.  Fail closed; same 404 shape as the
        // missing-role path so a misconfiguration doesn't reveal
        // any more about the admin surface than a regular denial would.
        tracing::warn!(
            "admin route hit but [oidc.roles] not configured — denying"
        );
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(caller) = req.extensions().get::<CallerIdentity>() else {
        // user_middleware didn't run, or the request bypassed it.
        // Either way, no identity → 401.
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if !caller_has_role(caller, &roles.claim, &roles.admin) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

/// Read `claims[claim_name]` as `Vec<&str>` and check if `wanted` is in
/// it.  Tolerates missing claim, non-array shapes, and non-string
/// elements — all return false.  Roles in opaque-bearer identities
/// (where claims is `Null`) always return false; admin requires OIDC.
pub fn caller_has_role(caller: &CallerIdentity, claim_name: &str, wanted: &str) -> bool {
    let Some(arr) = caller.identity.claims.get(claim_name).and_then(|v| v.as_array())
    else {
        return false;
    };
    arr.iter().any(|v| v.as_str() == Some(wanted))
}

/// Body-less response that hooks for tests; kept private.
#[allow(dead_code)]
fn body_only(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static response build")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthSource, UserIdentity};

    fn caller_with_roles(roles: serde_json::Value) -> CallerIdentity {
        CallerIdentity {
            user_id: "u1".into(),
            identity: UserIdentity {
                subject: "alice".into(),
                email: None,
                display_name: None,
                source: AuthSource::Oidc,
                claims: serde_json::json!({
                    "https://dyson.example.com/roles": roles
                }),
            },
        }
    }

    fn caller_bearer() -> CallerIdentity {
        CallerIdentity {
            user_id: "u1".into(),
            identity: UserIdentity {
                subject: "ci-bot".into(),
                email: None,
                display_name: None,
                source: AuthSource::Bearer,
                claims: serde_json::Value::Null,
            },
        }
    }

    #[test]
    fn role_present_grants() {
        let c = caller_with_roles(serde_json::json!(["rol_admin", "rol_free"]));
        assert!(caller_has_role(
            &c,
            "https://dyson.example.com/roles",
            "rol_admin"
        ));
    }

    #[test]
    fn role_absent_denies() {
        let c = caller_with_roles(serde_json::json!(["rol_free"]));
        assert!(!caller_has_role(
            &c,
            "https://dyson.example.com/roles",
            "rol_admin"
        ));
    }

    #[test]
    fn bearer_caller_never_has_role() {
        let c = caller_bearer();
        assert!(!caller_has_role(
            &c,
            "https://dyson.example.com/roles",
            "rol_admin"
        ));
    }

    #[test]
    fn missing_claim_denies() {
        let mut c = caller_with_roles(serde_json::json!(["rol_admin"]));
        c.identity.claims = serde_json::json!({});
        assert!(!caller_has_role(
            &c,
            "https://dyson.example.com/roles",
            "rol_admin"
        ));
    }

    #[test]
    fn non_array_claim_denies() {
        let mut c = caller_with_roles(serde_json::json!(["rol_admin"]));
        c.identity.claims = serde_json::json!({
            "https://dyson.example.com/roles": "rol_admin"  // single string, not array
        });
        assert!(!caller_has_role(
            &c,
            "https://dyson.example.com/roles",
            "rol_admin"
        ));
    }
}
