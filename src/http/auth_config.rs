//! `GET /auth/config` — unauthenticated discovery for the SPA.
//!
//! The React bundle hits this on cold-load to find out (a) whether auth
//! is required and (b) which IdP to redirect to.  For OIDC mode the
//! response carries the issuer + client_id + required scopes; the SPA
//! does the rest of the discovery itself by fetching
//! `<issuer>/.well-known/openid-configuration` (a public, CORS-enabled
//! endpoint at every modern IdP).
//!
//! Three modes:
//! - `none` — `[oidc]` not configured (or `spa_client_id` missing).  The
//!   SPA renders a splash explaining the deployment is admin-bearer-only.
//! - `oidc` — full PKCE flow available.  Response includes everything
//!   the SPA needs to start the Authorization Code redirect.
//!
//! Note: there is intentionally no `bearer` mode in the response — the
//! SPA can't source plaintext bearers for a user, so an opaque-key
//! deployment is functionally equivalent to "no auth path for the UI"
//! (= `none`).  CLI / curl flows are unaffected.

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use super::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum AuthConfig {
    /// No browser-flow auth available; the SPA shows a "use the CLI"
    /// splash.
    None,
    /// Full OIDC + PKCE.  `required_scopes` is what the SPA appends to
    /// `openid` when constructing the authorize URL.
    Oidc {
        issuer: String,
        audience: String,
        client_id: String,
        required_scopes: Vec<String>,
    },
}

impl AuthConfig {
    /// Build from the parsed TOML.  Returns [`AuthConfig::None`] when
    /// either OIDC isn't configured or `spa_client_id` is missing.
    pub fn from_toml(oidc: Option<&crate::config::OidcConfigToml>) -> Self {
        match oidc {
            Some(o) => match &o.spa_client_id {
                Some(id) if !id.trim().is_empty() => AuthConfig::Oidc {
                    issuer: o.issuer.clone(),
                    audience: o.audience.clone(),
                    client_id: id.clone(),
                    required_scopes: o.spa_scopes.clone(),
                },
                _ => AuthConfig::None,
            },
            None => AuthConfig::None,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/auth/config", get(handler)).with_state(state)
}

async fn handler(State(state): State<AppState>) -> Json<AuthConfig> {
    Json((*state.auth_config).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OidcConfigToml;

    #[test]
    fn no_oidc_block_yields_none() {
        let cfg = AuthConfig::from_toml(None);
        assert!(matches!(cfg, AuthConfig::None));
    }

    #[test]
    fn oidc_without_spa_client_id_yields_none() {
        let oidc = OidcConfigToml {
            issuer: "https://idp.example".into(),
            audience: "warden".into(),
            jwks_url: None,
            jwks_ttl_seconds: 86_400,
            spa_client_id: None,
            spa_scopes: vec![],
        };
        let cfg = AuthConfig::from_toml(Some(&oidc));
        assert!(matches!(cfg, AuthConfig::None));
    }

    #[test]
    fn oidc_with_spa_client_id_yields_oidc() {
        let oidc = OidcConfigToml {
            issuer: "https://idp.example".into(),
            audience: "warden".into(),
            jwks_url: None,
            jwks_ttl_seconds: 86_400,
            spa_client_id: Some("warden-spa".into()),
            spa_scopes: vec!["profile".into(), "email".into()],
        };
        let cfg = AuthConfig::from_toml(Some(&oidc));
        match cfg {
            AuthConfig::Oidc { issuer, audience, client_id, required_scopes } => {
                assert_eq!(issuer, "https://idp.example");
                assert_eq!(audience, "warden");
                assert_eq!(client_id, "warden-spa");
                assert_eq!(required_scopes, vec!["profile", "email"]);
            }
            _ => panic!("expected oidc mode"),
        }
    }

    #[test]
    fn empty_spa_client_id_treated_as_unset() {
        let oidc = OidcConfigToml {
            issuer: "https://idp.example".into(),
            audience: "warden".into(),
            jwks_url: None,
            jwks_ttl_seconds: 86_400,
            spa_client_id: Some("   ".into()),
            spa_scopes: vec![],
        };
        let cfg = AuthConfig::from_toml(Some(&oidc));
        assert!(matches!(cfg, AuthConfig::None));
    }

    #[test]
    fn json_shape_for_none_mode() {
        let json = serde_json::to_value(AuthConfig::None).unwrap();
        assert_eq!(json["mode"], "none");
    }

    #[test]
    fn json_shape_for_oidc_mode() {
        let cfg = AuthConfig::Oidc {
            issuer: "https://idp.example".into(),
            audience: "warden".into(),
            client_id: "warden-spa".into(),
            required_scopes: vec!["profile".into()],
        };
        let json = serde_json::to_value(cfg).unwrap();
        assert_eq!(json["mode"], "oidc");
        assert_eq!(json["issuer"], "https://idp.example");
        assert_eq!(json["client_id"], "warden-spa");
        assert_eq!(json["required_scopes"], serde_json::json!(["profile"]));
    }
}
