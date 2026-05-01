use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub bind: String,
    pub db_path: PathBuf,

    /// Directory holding per-user age root keys
    /// (`<keys_dir>/<user_id>.age`, mode 0400).  The system-scope key
    /// for provider api_keys / OpenRouter provisioning lives at
    /// `<keys_dir>/system.age`.  Created on first swarm boot.
    /// Defaults to a sibling of `db_path` so a typical
    /// `/var/lib/dyson-swarm/` layout keeps all per-host secret
    /// material under one root.
    #[serde(default)]
    pub keys_dir: Option<PathBuf>,

    /// Public hostname swarm answers on, e.g. `"swarm.example.com"`.
    /// When set, every Dyson is reachable at
    /// `<instance_id>.<hostname>` — the host-based dispatcher in
    /// [`crate::http::dyson_proxy`] forwards those requests to the
    /// matching CubeSandbox.  Wildcard DNS (`*.<hostname>`) and a
    /// wildcard TLS cert are required for this to work in production.
    /// When unset, the dispatcher is a no-op and the per-Dyson UI is
    /// unreachable from the browser (the rest of swarm is unaffected).
    #[serde(default)]
    pub hostname: Option<String>,

    /// `host:port` the cube uses to call swarm's `/llm` proxy back.
    /// Decoupled from `hostname` because the cube cannot reach the
    /// host's own public IP (NAT hairpin: cube SNAT → host_pub_ip
    /// → kernel loops to local socket → reply never DNAT'd back to
    /// the cube's TAP, SYN sits in syn_sent).  Set to the host's
    /// cube-dev gateway IP (e.g. `"192.168.0.1:8080"`) so the cube
    /// reaches swarm directly via local routing — no Caddy, no TLS,
    /// no hairpin.  When unset, falls back to `https://{hostname}/llm`
    /// for back-compat.  Swarm's `cube_client` ships a
    /// `192.168.0.1/32` allow_out so the always-denied
    /// `192.168.0.0/16` doesn't drop the cube's outbound SYN.
    #[serde(default)]
    pub cube_facing_addr: Option<String>,

    #[serde(default = "default_probe_interval")]
    pub health_probe_interval_seconds: u64,
    #[serde(default = "default_probe_timeout")]
    pub health_probe_timeout_seconds: u64,

    /// Default cube template id the SPA's hire form pre-fills. Surfaced
    /// via `/auth/config` so the React bundle doesn't need to be
    /// rebuilt per deployment.  In the multi-profile world this should
    /// be the template id of the first entry in `cube_profiles`;
    /// `bring-up.sh` keeps them in sync, but swarm trusts whatever the
    /// operator wrote in the toml.
    #[serde(default)]
    pub default_template_id: Option<String>,

    /// Cube cell tiering profiles surfaced to the SPA via /auth/config.
    /// Each profile maps a human name (e.g. `default`, `large`) to a
    /// pre-registered Cube template id plus the resources baked into
    /// that template.  The hire form renders a dropdown from this list;
    /// picking a profile fills the `template_id` of the create request.
    /// Empty list = profile picker hidden, hire form falls back to the
    /// legacy single-template UX.
    #[serde(default, rename = "cube_profiles")]
    pub cube_profiles: Vec<CubeProfile>,

    /// Suggested model ids the SPA offers in the hire form, e.g.
    /// `["deepseek/deepseek-v4-pro", "moonshotai/kimi-k2.6"]`. First
    /// entry is pre-selected. Surfaced via `/auth/config`; the input
    /// is a datalist so the user can still type any other id. Empty
    /// list → free-text only.
    #[serde(default)]
    pub default_models: Vec<String>,

    pub cube: CubeConfig,
    pub default_policy: DefaultPolicy,
    #[serde(default)]
    pub providers: Providers,
    pub backup: BackupConfig,
    #[serde(default)]
    pub oidc: Option<OidcConfigToml>,
    /// OpenRouter Provisioning-API config (Stage 6 per-user keys).
    /// When present, swarm mints a unique OR key per tenant on first
    /// `/llm/openrouter/...` call, capped at the user's
    /// `openrouter_key_limit_usd`.  When absent the proxy falls back
    /// to the global `[providers.openrouter].api_key`.
    #[serde(default)]
    pub openrouter: Option<OpenRouterConfig>,

    /// Opt-in startup sweep that snapshot+restores every Live
    /// instance whose cube template is older than
    /// `default_template_id` onto the current default — closes the
    /// gap left by config-only rewires when the fix lives in the
    /// dyson binary itself (new ConfigureBody fields, tool registration
    /// logic, the no-skills-block boot fix, etc.).
    ///
    /// Default `false` because rotation is destructive: it churns the
    /// underlying `cube_sandbox_id` for every outdated instance, so
    /// any client holding an old `<id>.<hostname>` URL gets a 404 and
    /// must rediscover the new id (workspace state survives via the
    /// snapshot).  Operators flip this on when they want a swarm
    /// restart to also propagate a binary-level fix; otherwise leave
    /// it off and run rotation by hand.
    #[serde(default)]
    pub rotate_binary_on_startup: bool,
}

/// One cube cell tiering profile.  Renders to a single
/// `[[server.cube_profiles]]` TOML table; serializes to the same shape
/// in /auth/config so the SPA can render a dropdown without an extra
/// translation step.  Resources are advisory metadata — Cube freezes
/// the actual cell at template-registration time, so two profiles
/// referencing the same `template_id` would surface as duplicates here
/// even though they'd hire identical cubes.  bring-up.sh's
/// `register_all_cube_profiles` enforces unique (name, template_id)
/// pairs upstream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CubeProfile {
    /// Stable, lowercase, DNS-safe label the operator and the SPA show
    /// the user — e.g. `default`, `large`, `xl`.  Embedded in nothing
    /// machine-parsed; pure UX surface.
    pub name: String,
    /// Cube template id (the `tpl-...` string `cubemastercli tpl
    /// create-from-image` mints).  This is what the create request
    /// actually carries; `name` is just the dropdown label.
    pub template_id: String,
    /// Writable disk in GiB (cubemastercli's `--writable-layer-size`).
    pub disk_gb: u32,
    /// CPU millicores baked in at registration (cubemastercli's
    /// `--cpu`).  2000 = 2 vCPU.
    pub cpu_millicores: u32,
    /// RAM in MiB baked in at registration (cubemastercli's
    /// `--memory`).
    pub memory_mb: u32,
}

/// OpenRouter Provisioning configuration.  The provisioning key is a
/// separate credential from a regular OpenRouter API key — only it
/// can mint/list/update/delete per-user keys.
///
/// **Canonical path:** stored encrypted-at-rest via
/// `swarm secrets system-set --stdin openrouter.provisioning_key` and
/// resolved at startup from `system_secrets`.  The legacy inline
/// `provisioning_key` TOML field remains here as a hand-edit fallback
/// for local dev only; the deploy templates no longer render it.
///
/// The `upstream` field defaults to `[providers.openrouter].upstream`
/// when unset, so a deployment using a self-hosted OpenRouter mirror
/// can override both at once.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenRouterConfig {
    #[serde(default)]
    pub provisioning_key: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,
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
    /// Default 1h. Tightened from 24h post-B3: a shorter TTL bounds
    /// the window in which a key rotated out of the IdP's JWKS doc
    /// can still validate cached-key signatures.
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
    /// Role-based admin gate.  When set, `/v1/admin/*` requires the
    /// caller's JWT to carry an admin role in the configured custom
    /// claim.  Unset = `/v1/admin/*` is unreachable in production
    /// (only the `--dangerous-no-auth` mode bypasses this).
    #[serde(default)]
    pub roles: Option<OidcRoles>,
}

/// Where to find authorization data in an OIDC access token, and which
/// value grants admin.
///
/// Recommended setup (Auth0 / Okta / Keycloak — anything that does
/// API-level RBAC): enable "Add Permissions in the Access Token" on
/// the API, define a permission named `admin`, and attach it to your
/// admin role.  The IdP then emits a top-level `permissions` array on
/// every access token; swarm checks for the configured value in it.
/// Config:
///     claim = "permissions"
///     admin = "admin"
///
/// Alternative for IdPs without per-API RBAC: inject a custom claim
/// (e.g. `https://your-host/roles`) via a post-login hook and point
/// `claim` at that URL.  swarm doesn't care which path — just that
/// `claims[claim]` is an array of strings containing `admin`.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcRoles {
    /// JWT claim name to inspect.  Must point at an array of strings.
    pub claim: String,
    /// Role id (or name — whatever the IdP emits) that grants admin.
    pub admin: String,
}

fn default_jwks_ttl() -> u64 {
    60 * 60
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

/// Provider configs keyed by name.  Transparent newtype around a
/// `HashMap` so adding a new upstream (Groq, DeepSeek, xAI, …) is a
/// TOML stanza, not a struct edit:
///
/// ```toml
/// [providers.openai]
/// upstream = "https://api.openai.com"
/// [providers.groq]
/// upstream = "https://api.groq.com/openai"
/// ```
///
/// Provider names are URL path segments (lowercase, no spaces) — they
/// appear directly in `/llm/<name>/...`.  The `byo` slot is reserved
/// for per-user upstream overrides and intentionally has no platform
/// stanza — declaring `[providers.byo]` is harmless but ignored by the
/// proxy because the `byo` resolver demands a per-user blob.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct Providers(pub HashMap<String, ProviderConfig>);

impl Providers {
    pub fn get(&self, name: &str) -> Option<&ProviderConfig> {
        self.0.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut ProviderConfig> {
        self.0.get_mut(name)
    }

    pub fn insert(&mut self, name: impl Into<String>, cfg: ProviderConfig) -> Option<ProviderConfig> {
        self.0.insert(name.into(), cfg)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
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
    /// Resolve the on-disk path for per-user age root keys.
    /// Honours an explicit `keys_dir` from the TOML / env when set;
    /// otherwise defaults to `<db_path parent>/keys`.  Falls back to
    /// `./keys` when `db_path` is malformed (parent-less); validation
    /// rejects that anyway, so this branch is only hit during early
    /// startup before `validate()` has run.
    pub fn resolved_keys_dir(&self) -> PathBuf {
        if let Some(p) = &self.keys_dir {
            return p.clone();
        }
        match self.db_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join("keys"),
            _ => PathBuf::from("keys"),
        }
    }

    /// Load the config from `path`, apply `SWARM_*` env overrides, then
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

    /// Apply env-var overrides. Convention: `SWARM_<UPPER_SNAKE_PATH>`
    /// e.g. `SWARM_CUBE_URL`, `SWARM_PROVIDERS_ANTHROPIC_API_KEY`.
    /// Implemented by hand — no `figment`.
    fn apply_env(&mut self, env: &BTreeMap<String, String>) {
        if let Some(v) = env.get("SWARM_BIND") {
            self.bind.clone_from(v);
        }
        if let Some(v) = env.get("SWARM_DB_PATH") {
            self.db_path = PathBuf::from(v);
        }
        if let Some(v) = env.get("SWARM_KEYS_DIR") {
            self.keys_dir = if v.is_empty() { None } else { Some(PathBuf::from(v)) };
        }
        if let Some(v) = env.get("SWARM_HOSTNAME") {
            self.hostname = if v.is_empty() { None } else { Some(v.clone()) };
        }
        if let Some(v) = env.get("SWARM_CUBE_URL") {
            self.cube.url.clone_from(v);
        }
        if let Some(v) = env.get("SWARM_CUBE_API_KEY") {
            self.cube.api_key.clone_from(v);
        }
        if let Some(v) = env.get("SWARM_CUBE_SANDBOX_DOMAIN") {
            self.cube.sandbox_domain.clone_from(v);
        }

        // Generic env override: `SWARM_PROVIDERS_<NAME>_API_KEY` /
        // `SWARM_PROVIDERS_<NAME>_UPSTREAM` for any provider already
        // declared in TOML.  Walk the env map (not the providers map)
        // so an env var with no matching stanza is a no-op rather
        // than an error — same back-compat semantics as before.
        for (env_key, env_val) in env {
            let Some(rest) = env_key.strip_prefix("SWARM_PROVIDERS_") else { continue };
            let (name_upper, field) = if let Some(n) = rest.strip_suffix("_API_KEY") {
                (n, "api_key")
            } else if let Some(n) = rest.strip_suffix("_UPSTREAM") {
                (n, "upstream")
            } else {
                continue;
            };
            let name = name_upper.to_lowercase();
            let Some(slot) = self.providers.get_mut(&name) else { continue };
            match field {
                "api_key" => slot.api_key = Some(env_val.clone()),
                "upstream" => slot.upstream.clone_from(env_val),
                _ => unreachable!(),
            }
        }

        if let Some(v) = env.get("SWARM_BACKUP_LOCAL_CACHE_DIR") {
            self.backup.local_cache_dir = PathBuf::from(v);
        }
        if let Some(s3) = self.backup.s3.as_mut() {
            if let Some(v) = env.get("SWARM_BACKUP_S3_ENDPOINT") {
                s3.endpoint.clone_from(v);
            }
            if let Some(v) = env.get("SWARM_BACKUP_S3_REGION") {
                s3.region.clone_from(v);
            }
            if let Some(v) = env.get("SWARM_BACKUP_S3_BUCKET") {
                s3.bucket.clone_from(v);
            }
            if let Some(v) = env.get("SWARM_BACKUP_S3_PREFIX") {
                s3.prefix.clone_from(v);
            }
            if let Some(v) = env.get("SWARM_BACKUP_S3_ACCESS_KEY_ID") {
                s3.access_key_id.clone_from(v);
            }
            if let Some(v) = env.get("SWARM_BACKUP_S3_SECRET_ACCESS_KEY") {
                s3.secret_access_key.clone_from(v);
            }
        }
    }

    fn validate(&self, dangerous_no_auth: bool) -> Result<(), ConfigError> {
        if self.bind.trim().is_empty() {
            return Err(ConfigError::EmptyField("bind"));
        }
        // admin_token went away in Stage 5 — admin gate is now a JWT
        // role check, not a shared bearer.  `dangerous_no_auth` keeps
        // working as the local-dev bypass; production requires OIDC.
        let _ = dangerous_no_auth;
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
        let p = std::env::temp_dir().join(format!("swarm-cfg-test-{}-{name}", std::process::id()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn round_trip() {
        let path = write_tmp("round_trip.toml", example_toml());
        let cfg = Config::load(&path, &BTreeMap::new(), false).expect("loads");
        assert_eq!(cfg.bind, "0.0.0.0:8080");
        assert_eq!(cfg.cube.api_key, "k");
        assert_eq!(cfg.health_probe_interval_seconds, 60);
        assert_eq!(cfg.backup.sink, BackupSinkKind::Local);
        assert_eq!(cfg.providers.get("anthropic").unwrap().api_key.as_deref(), Some("a"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn env_override_wins() {
        let path = write_tmp("env_override.toml", example_toml());
        let mut env = BTreeMap::new();
        env.insert("SWARM_CUBE_URL".into(), "https://override".into());
        env.insert("SWARM_PROVIDERS_ANTHROPIC_API_KEY".into(), "from-env".into());
        let cfg = Config::load(&path, &env, false).expect("loads");
        assert_eq!(cfg.cube.url, "https://override");
        assert_eq!(
            cfg.providers.get("anthropic").unwrap().api_key.as_deref(),
            Some("from-env")
        );
        std::fs::remove_file(&path).ok();
    }

    // The legacy `admin_token` field is gone (Stage 5).  Admin gate
    // is now an OIDC role check; `dangerous_no_auth` is the local-dev
    // bypass.  Tests that used to assert on admin_token validation
    // are obsolete.

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
        let db = std::env::temp_dir().join(format!("swarm-db-test-{}.db", std::process::id()));
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_db_path_permissions(&db).expect_err("rejects 0644");
        assert!(matches!(err, ConfigError::InsecureDbPermissions { .. }));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        check_db_path_permissions(&db).expect("accepts 0600");
        std::fs::remove_file(&db).ok();
    }
}
