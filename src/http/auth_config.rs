//! `GET /auth/config` — unauthenticated discovery for the SPA.
//!
//! The React bundle hits this on cold-load to find out (a) whether auth
//! is required and (b) which IdP to redirect to.  For OIDC mode the
//! response carries the issuer + client_id + required scopes; the SPA
//! does the rest of the discovery itself by fetching
//! `<issuer>/.well-known/openid-configuration` (a public, CORS-enabled
//! endpoint at every modern IdP).
//!
//! The response also surfaces a few SPA-tunable defaults (e.g.
//! `default_template_id`) so the React bundle doesn't need to be
//! rebuilt per deployment to ship sensible form pre-fills.
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

/// Auth flow descriptor.  Flattened into [`AuthConfig`] so `mode` lives
/// at the top level alongside the SPA-tunable defaults.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum AuthMode {
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

/// Top-level shape returned by `GET /auth/config`.  `mode` is flattened
/// in so the JSON looks like `{"mode": "oidc", "issuer": ..., "default_template_id": ...}`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthConfig {
    #[serde(flatten)]
    pub mode: AuthMode,
    /// Default cube template id the SPA's hire form pre-fills.  `None`
    /// when the operator hasn't set `default_template_id` in config.toml,
    /// in which case the SPA falls back to its own hardcoded default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_template_id: Option<String>,
    /// Suggested model ids for the SPA's hire-form datalist.  First
    /// entry pre-selected; the input still accepts any other value.
    /// Empty array when the operator hasn't configured any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub default_models: Vec<String>,
}

impl AuthConfig {
    /// Build from the parsed TOML.  Returns mode `None` when either OIDC
    /// isn't configured or `spa_client_id` is missing.
    pub fn from_toml(
        oidc: Option<&crate::config::OidcConfigToml>,
        default_template_id: Option<String>,
        default_models: Vec<String>,
    ) -> Self {
        let mode = match oidc {
            Some(o) => match &o.spa_client_id {
                Some(id) if !id.trim().is_empty() => AuthMode::Oidc {
                    issuer: o.issuer.clone(),
                    audience: o.audience.clone(),
                    client_id: id.clone(),
                    required_scopes: o.spa_scopes.clone(),
                },
                _ => AuthMode::None,
            },
            None => AuthMode::None,
        };
        Self { mode, default_template_id, default_models }
    }

    /// Convenience for tests / fallback paths that just need a "no auth"
    /// descriptor with no SPA defaults.
    pub fn none() -> Self {
        Self { mode: AuthMode::None, default_template_id: None, default_models: vec![] }
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
        let cfg = AuthConfig::from_toml(None, None, vec![]);
        assert!(matches!(cfg.mode, AuthMode::None));
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
        let cfg = AuthConfig::from_toml(Some(&oidc), None, vec![]);
        assert!(matches!(cfg.mode, AuthMode::None));
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
        let cfg = AuthConfig::from_toml(Some(&oidc), None, vec![]);
        match cfg.mode {
            AuthMode::Oidc { issuer, audience, client_id, required_scopes } => {
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
        let cfg = AuthConfig::from_toml(Some(&oidc), None, vec![]);
        assert!(matches!(cfg.mode, AuthMode::None));
    }

    #[test]
    fn json_shape_for_none_mode() {
        let json = serde_json::to_value(AuthConfig::none()).unwrap();
        assert_eq!(json["mode"], "none");
        assert!(json.get("default_template_id").is_none());
    }

    #[test]
    fn json_shape_for_oidc_mode() {
        let cfg = AuthConfig {
            mode: AuthMode::Oidc {
                issuer: "https://idp.example".into(),
                audience: "warden".into(),
                client_id: "warden-spa".into(),
                required_scopes: vec!["profile".into()],
            },
            default_template_id: Some("tpl-abc".into()),
        };
        let json = serde_json::to_value(cfg).unwrap();
        assert_eq!(json["mode"], "oidc");
        assert_eq!(json["issuer"], "https://idp.example");
        assert_eq!(json["client_id"], "warden-spa");
        assert_eq!(json["required_scopes"], serde_json::json!(["profile"]));
        assert_eq!(json["default_template_id"], "tpl-abc");
    }
}
