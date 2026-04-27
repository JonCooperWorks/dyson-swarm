use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub bind: String,
    pub admin_token: String,
    pub db_path: PathBuf,

    /// Public hostname warden answers on, e.g. `"warden.example.com"`.
    /// When set, every Dyson is reachable at
    /// `<instance_id>.<hostname>` — the host-based dispatcher in
    /// [`crate::http::dyson_proxy`] forwards those requests to the
    /// matching CubeSandbox.  Wildcard DNS (`*.<hostname>`) and a
    /// wildcard TLS cert are required for this to work in production.
    /// When unset, the dispatcher is a no-op and the per-Dyson UI is
    /// unreachable from the browser (the rest of warden is unaffected).
    #[serde(default)]
    pub hostname: Option<String>,

    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: i64,
    #[serde(default = "default_probe_interval")]
    pub health_probe_interval_seconds: u64,
    #[serde(default = "default_probe_timeout")]
    pub health_probe_timeout_seconds: u64,

    /// Default cube template id the SPA's hire form pre-fills. Surfaced
    /// via `/auth/config` so the React bundle doesn't need to be
    /// rebuilt per deployment.
    #[serde(default)]
    pub default_template_id: Option<String>,

    pub cube: CubeConfig,
    pub default_policy: DefaultPolicy,
    #[serde(default)]
    pub providers: Providers,
    pub backup: BackupConfig,
    #[serde(default)]
    pub oidc: Option<OidcConfigToml>,
}

/// OIDC issuer configuration, lifted out of [`crate::auth::oidc::OidcConfig`]
/// so the TOML schema is stable independent of the auth module's internal
/// types. Mirrors the runtime config 1:1.
///
/// `spa_client_id` and `spa_scopes` are SPA-only — they're surfaced via
/// the unauthenticated `GET /auth/config` endpoint so the React bundle
/// can run an Authorization Code + PKCE flow against the same IdP.
/// Backend JWT verification doesn't need them.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfigToml {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Default 24h.
    #[serde(default = "default_jwks_ttl")]
    pub jwks_ttl_seconds: u64,
    /// Public OAuth client_id for the web UI's PKCE flow. When unset, the
    /// SPA reports `mode: "none"` and renders a "use the CLI" splash —
    /// admin-bearer / opaque api keys still work, just not the browser
    /// flow.
    #[serde(default)]
    pub spa_client_id: Option<String>,
    /// Extra scopes beyond `openid` to request from the IdP. Most
    /// deployments want at least `profile email`. Default: `[]` (just
    /// `openid`).
    #[serde(default)]
    pub spa_scopes: Vec<String>,
}

fn default_jwks_ttl() -> u64 {
    24 * 60 * 60
}

fn default_ttl() -> i64 {
    86_400
}
fn default_probe_interval() -> u64 {
    60
}
fn default_probe_timeout() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct CubeConfig {
    pub url: String,
    pub api_key: String,
    pub sandbox_domain: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultPolicy {
    pub allowed_providers: Vec<String>,
    pub allowed_models: Vec<String>,
    pub daily_token_budget: Option<u64>,
    pub monthly_usd_budget: Option<f64>,
    pub rps_limit: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Providers {
    pub anthropic: Option<ProviderConfig>,
    pub openai: Option<ProviderConfig>,
    pub gemini: Option<ProviderConfig>,
    pub openrouter: Option<ProviderConfig>,
    pub ollama: Option<ProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub api_key: Option<String>,
    pub upstream: String,
    #[serde(default)]
    pub anthropic_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    pub sink: BackupSinkKind,
    pub local_cache_dir: PathBuf,
    #[serde(default)]
    pub s3: Option<S3Config>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupSinkKind {
    Local,
    S3,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub path_style: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),
    #[error("config file unreadable: {0}")]
    Read(#[source] std::io::Error),
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    #[error(
        "DB file {path} has insecure permissions ({mode:o}); set mode 0600 (chmod 600 {path})"
    )]
    InsecureDbPermissions { path: String, mode: u32 },
    #[error("backup.sink = \"s3\" requires [backup.s3] section")]
    MissingS3Section,
}

impl Config {
    /// Load the config from `path`, apply `WARDEN_*` env overrides, then
    /// validate. `dangerous_no_auth` relaxes the admin-token check.
    pub fn load(
        path: &Path,
        env: &BTreeMap<String, String>,
        dangerous_no_auth: bool,
    ) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        let text = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        let mut cfg: Config = toml::from_str(&text)?;
        cfg.apply_env(env);
        cfg.validate(dangerous_no_auth)?;
        Ok(cfg)
    }

    /// Apply env-var overrides. Convention: `WARDEN_<UPPER_SNAKE_PATH>`
    /// e.g. `WARDEN_CUBE_URL`, `WARDEN_PROVIDERS_ANTHROPIC_API_KEY`.
    /// Implemented by hand — no `figment`.
    fn apply_env(&mut self, env: &BTreeMap<String, String>) {
        if let Some(v) = env.get("WARDEN_BIND") {
            self.bind = v.clone();
        }
        if let Some(v) = env.get("WARDEN_ADMIN_TOKEN") {
            self.admin_token = v.clone();
        }
        if let Some(v) = env.get("WARDEN_DB_PATH") {
            self.db_path = PathBuf::from(v);
        }
        if let Some(v) = env.get("WARDEN_HOSTNAME") {
            self.hostname = if v.is_empty() { None } else { Some(v.clone()) };
        }
        if let Some(v) = env.get("WARDEN_CUBE_URL") {
            self.cube.url = v.clone();
        }
        if let Some(v) = env.get("WARDEN_CUBE_API_KEY") {
            self.cube.api_key = v.clone();
        }
        if let Some(v) = env.get("WARDEN_CUBE_SANDBOX_DOMAIN") {
            self.cube.sandbox_domain = v.clone();
        }

        for (provider, slot) in [
            ("ANTHROPIC", &mut self.providers.anthropic),
            ("OPENAI", &mut self.providers.openai),
            ("GEMINI", &mut self.providers.gemini),
            ("OPENROUTER", &mut self.providers.openrouter),
            ("OLLAMA", &mut self.providers.ollama),
        ] {
            let key = format!("WARDEN_PROVIDERS_{provider}_API_KEY");
            let upstream_key = format!("WARDEN_PROVIDERS_{provider}_UPSTREAM");
            if let Some(p) = slot.as_mut() {
                if let Some(v) = env.get(&key) {
                    p.api_key = Some(v.clone());
                }
                if let Some(v) = env.get(&upstream_key) {
                    p.upstream = v.clone();
                }
            }
        }

        if let Some(v) = env.get("WARDEN_BACKUP_LOCAL_CACHE_DIR") {
            self.backup.local_cache_dir = PathBuf::from(v);
        }
        if let Some(s3) = self.backup.s3.as_mut() {
            if let Some(v) = env.get("WARDEN_BACKUP_S3_ENDPOINT") {
                s3.endpoint = v.clone();
            }
            if let Some(v) = env.get("WARDEN_BACKUP_S3_REGION") {
                s3.region = v.clone();
            }
            if let Some(v) = env.get("WARDEN_BACKUP_S3_BUCKET") {
                s3.bucket = v.clone();
            }
            if let Some(v) = env.get("WARDEN_BACKUP_S3_PREFIX") {
                s3.prefix = v.clone();
            }
            if let Some(v) = env.get("WARDEN_BACKUP_S3_ACCESS_KEY_ID") {
                s3.access_key_id = v.clone();
            }
            if let Some(v) = env.get("WARDEN_BACKUP_S3_SECRET_ACCESS_KEY") {
                s3.secret_access_key = v.clone();
            }
        }
    }

    fn validate(&self, dangerous_no_auth: bool) -> Result<(), ConfigError> {
        if self.bind.trim().is_empty() {
            return Err(ConfigError::EmptyField("bind"));
        }
        if !dangerous_no_auth && self.admin_token.trim().is_empty() {
            return Err(ConfigError::EmptyField("admin_token"));
        }
        if self.db_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyField("db_path"));
        }
        if self.cube.url.trim().is_empty() {
            return Err(ConfigError::EmptyField("cube.url"));
        }
        if self.cube.api_key.trim().is_empty() {
            return Err(ConfigError::EmptyField("cube.api_key"));
        }
        if self.cube.sandbox_domain.trim().is_empty() {
            return Err(ConfigError::EmptyField("cube.sandbox_domain"));
        }
        if matches!(self.backup.sink, BackupSinkKind::S3) && self.backup.s3.is_none() {
            return Err(ConfigError::MissingS3Section);
        }
        check_db_path_permissions(&self.db_path)?;
        Ok(())
    }
}

/// Refuse to start if the DB file exists with permissions accessible to
/// group/world (`mode & 0o077 != 0`). On non-Unix this is a no-op.
pub fn check_db_path_permissions(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let meta = std::fs::metadata(path).map_err(ConfigError::Read)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(ConfigError::InsecureDbPermissions {
                    path: path.display().to_string(),
                    mode,
                });
            }
        }
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_toml() -> &'static str {
        r#"
bind = "0.0.0.0:8080"
admin_token = "secret"
db_path = "/tmp/state.db"

[cube]
url = "http://localhost:3000"
api_key = "k"
sandbox_domain = "cube.app"

[default_policy]
allowed_providers = ["openrouter"]
allowed_models = ["*"]
daily_token_budget = 1000000
monthly_usd_budget = 100.0
rps_limit = 10

[providers.anthropic]
api_key = "a"
upstream = "https://api.anthropic.com"
anthropic_version = "2023-06-01"

[providers.openrouter]
api_key = "o"
upstream = "https://openrouter.ai/api"

[backup]
sink = "local"
local_cache_dir = "/tmp/cache"
"#
    }

    fn write_tmp(name: &str, contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("warden-cfg-test-{}-{name}", std::process::id()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn round_trip() {
        let path = write_tmp("round_trip.toml", example_toml());
        let cfg = Config::load(&path, &BTreeMap::new(), false).expect("loads");
        assert_eq!(cfg.bind, "0.0.0.0:8080");
        assert_eq!(cfg.admin_token, "secret");
        assert_eq!(cfg.cube.api_key, "k");
        assert_eq!(cfg.default_ttl_seconds, 86_400);
        assert_eq!(cfg.health_probe_interval_seconds, 60);
        assert_eq!(cfg.backup.sink, BackupSinkKind::Local);
        assert_eq!(cfg.providers.anthropic.as_ref().unwrap().api_key.as_deref(), Some("a"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn env_override_wins() {
        let path = write_tmp("env_override.toml", example_toml());
        let mut env = BTreeMap::new();
        env.insert("WARDEN_CUBE_URL".into(), "https://override".into());
        env.insert("WARDEN_PROVIDERS_ANTHROPIC_API_KEY".into(), "from-env".into());
        let cfg = Config::load(&path, &env, false).expect("loads");
        assert_eq!(cfg.cube.url, "https://override");
        assert_eq!(
            cfg.providers.anthropic.as_ref().unwrap().api_key.as_deref(),
            Some("from-env")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_admin_token_rejected() {
        let toml = example_toml().replace(r#"admin_token = "secret""#, r#"admin_token = """#);
        let path = write_tmp("no_admin.toml", &toml);
        let err = Config::load(&path, &BTreeMap::new(), false).expect_err("rejects");
        assert!(matches!(err, ConfigError::EmptyField("admin_token")));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn dangerous_no_auth_allows_empty_admin_token() {
        let toml = example_toml().replace(r#"admin_token = "secret""#, r#"admin_token = """#);
        let path = write_tmp("no_admin_ok.toml", &toml);
        let cfg = Config::load(&path, &BTreeMap::new(), true).expect("loads with dangerous flag");
        assert!(cfg.admin_token.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn s3_sink_requires_section() {
        let toml = example_toml().replace(r#"sink = "local""#, r#"sink = "s3""#);
        let path = write_tmp("s3_no_section.toml", &toml);
        let err = Config::load(&path, &BTreeMap::new(), false).expect_err("rejects");
        assert!(matches!(err, ConfigError::MissingS3Section));
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_world_readable_db_file() {
        use std::os::unix::fs::PermissionsExt;
        let db = std::env::temp_dir().join(format!("warden-db-test-{}.db", std::process::id()));
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_db_path_permissions(&db).expect_err("rejects 0644");
        assert!(matches!(err, ConfigError::InsecureDbPermissions { .. }));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        check_db_path_permissions(&db).expect("accepts 0600");
        std::fs::remove_file(&db).ok();
    }
}
