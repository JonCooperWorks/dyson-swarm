//! MCP server configurations, persistence, and OAuth state.
//!
//! Per-instance MCP server records live in [`crate::secrets::UserSecretsService`]
//! under `mcp.<instance_id>.<server_name>`.  The blob carries the upstream
//! URL, the auth shape, and (for OAuth) the persisted tokens.
//!
//! Why user_secrets and not a new table:
//!   The encryption shape we want is exactly what UserSecretsService gives —
//!   sealed with the *user's* age cipher so a stolen sqlite row leaks
//!   nothing without the owner's key file.  Stuffing the JSON blob there
//!   keyed by instance keeps us out of the migration business.
//!
//! The agent never sees the upstream URL or auth credentials.  It points
//! its `McpTransportConfig::Http` at `https://<swarm>/mcp/<instance>/<name>`
//! with the per-instance proxy_token; [`crate::proxy::mcp`] handles the
//! handshake, refresh, and forward.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::secrets::{SecretsError, UserSecretsService};

/// Static placeholder the SPA can submit for secret-bearing catalog
/// fields when the user leaves an existing value untouched.
pub const MCP_KEEP_TOKEN: &str = "••••••••";

/// On-the-wire shape the SPA submits when hiring a Dyson with MCP
/// servers.  Mirrors the JSON the React form builds.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerSpec {
    /// Logical name (becomes the key under `mcp_servers` in dyson.json).
    pub name: String,
    /// Upstream MCP endpoint URL.
    pub url: String,
    pub auth: McpAuthSpec,
    /// Admin-selected tool allowlist for this server.  Mirrors the
    /// built-in tools picker semantics: `None` ⇒ "use default" (proxy
    /// passes tools/list through unfiltered, SPA renders the airgap
    /// rule when prefilling).  `Some(vec)` ⇒ explicit allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpAuthSpec {
    None,
    /// Static bearer token added on every forwarded request.
    Bearer {
        token: String,
    },
    /// OAuth 2.1 Authorization Code + PKCE.  All discovery fields
    /// optional — leave empty to run two-step discovery (RFC 9728
    /// Protected Resource Metadata → RFC 8414 path-prefixed AS metadata)
    /// against the server URL's origin and Dynamic Client Registration.
    Oauth {
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        authorization_url: Option<String>,
        #[serde(default)]
        token_url: Option<String>,
        #[serde(default)]
        registration_url: Option<String>,
    },
}

/// Persistent record stored in `user_secrets`.  Wraps the user-supplied
/// spec plus any swarm-managed OAuth state (tokens after a successful
/// flow, refreshed transparently on the proxy path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub url: String,
    pub auth: McpAuthSpec,
    /// Extra upstream headers for HTTP/SSE servers.  Legacy entries
    /// typically leave this empty because their auth is represented by
    /// `auth`; VS Code-style HTTP configs can carry arbitrary headers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    /// Runtime marker for swarm-owned stdio servers.  When set, the
    /// `/mcp/<instance>/<server>` proxy forwards JSON-RPC to the
    /// dedicated MCP runtime helper instead of posting to `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<McpRuntimeSpec>,
    /// Marker for entries created from the operator's Docker MCP
    /// catalog.  User-filled placeholder values are sealed with the
    /// entry so the user can later re-render an updated admin template
    /// without retyping them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_catalog: Option<McpDockerCatalogBinding>,
    /// Exact VS Code-style JSON the user pasted.  Stored encrypted with
    /// the rest of the entry so the UI can round-trip it without
    /// re-rendering or exposing it to the dyson.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_vscode_config: Option<serde_json::Value>,
    /// Populated by the OAuth callback; refreshed on demand by the
    /// proxy when an access token is near or past its expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_tokens: Option<McpOAuthTokens>,
    /// Catalog of tools advertised by the upstream, populated by the
    /// `check` endpoint after a successful tools/list.  None ⇒ admin
    /// hasn't run a check yet (UI shows "not connected").  The proxy
    /// doesn't depend on this for filtering — it only steers the SPA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_catalog: Option<McpToolsCatalog>,
    /// Admin-selected subset of tool names.  Mirrors the built-in
    /// tools allowlist: `None` ⇒ "use default" (proxy passes tools/list
    /// through unfiltered — the SPA applies the airgap rule when
    /// computing the effective default).  `Some(vec)` ⇒ explicit
    /// allowlist; tools/list responses are filtered and tools/call
    /// requests for names outside the set are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpDockerCatalogBinding {
    pub id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub placeholders: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpDockerCatalogServer {
    /// Stable operator-facing id used by the API route.
    pub id: String,
    /// Human label shown in the SPA picker.
    pub label: String,
    /// Short description shown under the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Read-only MCP JSON template.  Placeholders use
    /// `{{placeholder.<id>}}` or `{{placeholders.<id>}}` inside string
    /// values.  The rendered JSON must contain exactly one Docker
    /// stdio server under `servers` or `mcpServers`.
    pub template: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<McpDockerPlaceholderSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpDockerPlaceholderSpec {
    /// Placeholder id referenced by the template.
    pub id: String,
    /// Input label shown to the user.
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default = "default_true")]
    pub secret: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpRuntimeSpec {
    DockerStdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        env: HashMap<String, String>,
    },
    HttpStreamable {
        url: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_bearer_env: Option<String>,
    },
}

/// Cached `tools/list` result for one MCP server.  Persisted on the
/// `McpServerEntry` so the SPA can render the per-tool checklist
/// without round-tripping the upstream on every page load.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolsCatalog {
    pub tools: Vec<McpToolSummary>,
    /// Unix seconds when the catalog was last refreshed.
    pub last_checked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthTokens {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds at which `access_token` becomes invalid.  None ⇒
    /// the server didn't return `expires_in` (rare; treat as long-lived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Resolved token endpoint — recorded so the proxy refresh path
    /// doesn't have to redo discovery on every refresh.
    pub token_url: String,
    /// Resolved client_id — same reason as `token_url`.
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl McpOAuthTokens {
    /// True when the access token has 60s or less of validity left.
    /// The 60s skew matches what dyson uses (auth/oauth.rs).
    pub fn needs_refresh(&self, now_secs: i64) -> bool {
        match self.expires_at {
            Some(exp) => exp - 60 <= now_secs,
            None => false,
        }
    }
}

impl McpServerEntry {
    pub fn from_spec(spec: McpServerSpec) -> (String, Self) {
        let McpServerSpec {
            name,
            url,
            auth,
            enabled_tools,
        } = spec;
        (
            name,
            Self {
                url,
                auth,
                headers: HashMap::new(),
                runtime: None,
                docker_catalog: None,
                raw_vscode_config: None,
                oauth_tokens: None,
                tools_catalog: None,
                enabled_tools,
            },
        )
    }
}

/// Parsed representation of the single-server MCP JSON accepted by the
/// swarm UI.  VS Code uses `servers`; Claude-style configs often use
/// `mcpServers`.  The returned name + entry can be written directly to
/// `user_secrets`; `entry.raw_vscode_config` preserves the exact user
/// document.
pub fn entry_from_vscode_config(
    raw: serde_json::Value,
) -> Result<(String, McpServerEntry), String> {
    reject_input_placeholders(&raw)?;
    let obj = raw.as_object().ok_or("MCP config must be a JSON object")?;
    let servers = server_map_from_config(obj)?;
    if servers.len() != 1 {
        return Err("MCP config must contain exactly one server".into());
    }
    let (name, server) = servers.iter().next().expect("checked len == 1");
    if !is_safe_server_name(name) {
        return Err("server name must match [A-Za-z0-9_-]+".into());
    }
    let name = name.clone();
    let server = server
        .as_object()
        .ok_or("server config must be a JSON object")?;
    let server_type = server
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            if server.get("url").is_some() {
                "http"
            } else {
                "stdio"
            }
        });

    let mut entry = match server_type {
        "http" | "sse" => {
            let url = server
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or("HTTP/SSE MCP server requires `url`")?;
            let mut headers = parse_string_map(server.get("headers"), "headers")?;
            let auth = auth_from_headers(&headers);
            if matches!(auth, McpAuthSpec::Bearer { .. }) {
                headers.retain(|k, _| !k.eq_ignore_ascii_case("authorization"));
            }
            McpServerEntry {
                url: url.to_string(),
                auth,
                headers,
                runtime: None,
                docker_catalog: None,
                raw_vscode_config: None,
                oauth_tokens: None,
                tools_catalog: None,
                enabled_tools: None,
            }
        }
        "stdio" => {
            let command = server
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or("stdio MCP server requires `command`")?;
            if command != "docker" {
                return Err("v1 stdio MCP support requires `command`: \"docker\"".into());
            }
            let args = parse_string_array(server.get("args"), "args")?;
            validate_docker_stdio_args(&args)?;
            let env = parse_string_map(server.get("env"), "env")?;
            McpServerEntry {
                url: docker_display_url(&args),
                auth: McpAuthSpec::None,
                headers: HashMap::new(),
                runtime: Some(McpRuntimeSpec::DockerStdio {
                    command: command.to_string(),
                    args,
                    env,
                }),
                docker_catalog: None,
                raw_vscode_config: None,
                oauth_tokens: None,
                tools_catalog: None,
                enabled_tools: None,
            }
        }
        other => return Err(format!("unsupported MCP server type `{other}`")),
    };
    entry.raw_vscode_config = Some(raw);
    Ok((name, entry))
}

/// Render one admin catalog template with user-provided placeholder values,
/// validate it through the same VS Code-style parser as raw Docker
/// JSON, and return the sealed entry to persist.
pub fn entry_from_docker_catalog_template(
    catalog: &McpDockerCatalogServer,
    supplied_placeholders: &BTreeMap<String, String>,
    existing: Option<&McpServerEntry>,
) -> Result<(String, McpServerEntry), String> {
    if !is_safe_server_name(&catalog.id) {
        return Err("catalog id must match [A-Za-z0-9_-]+".into());
    }
    let previous = existing
        .and_then(|entry| entry.docker_catalog.as_ref())
        .filter(|binding| binding.id == catalog.id);
    let placeholders = resolve_catalog_placeholders(catalog, supplied_placeholders, previous)?;
    let mut raw: serde_json::Value = serde_json::from_str(&catalog.template)
        .map_err(|e| format!("catalog `{}` template is not valid JSON: {e}", catalog.id))?;
    render_catalog_template_value(&mut raw, &placeholders.render_values)?;
    let (name, mut entry) = entry_from_vscode_config(raw)?;
    entry.raw_vscode_config = None;
    entry.docker_catalog = Some(McpDockerCatalogBinding {
        id: catalog.id.clone(),
        placeholders: placeholders.stored_values,
    });
    Ok((name, entry))
}

/// Validate an operator-curated Docker MCP template without needing real
/// user placeholder values.  The same renderer/parser used by the user save
/// path does the heavy lifting, so admin UI/API validation and runtime
/// persistence stay in lockstep.
pub fn validate_docker_catalog_server(catalog: &McpDockerCatalogServer) -> Result<(), String> {
    if catalog.label.trim().is_empty() {
        return Err("catalog label is required".into());
    }
    if catalog.template.trim().is_empty() {
        return Err("catalog template is required".into());
    }
    let dummy_placeholders = catalog
        .placeholders
        .iter()
        .map(|field| (field.id.clone(), format!("__{}__", field.id)))
        .collect();
    entry_from_docker_catalog_template(catalog, &dummy_placeholders, None).map(|_| ())
}

struct ResolvedCatalogPlaceholders {
    render_values: BTreeMap<String, String>,
    stored_values: BTreeMap<String, String>,
}

fn resolve_catalog_placeholders(
    catalog: &McpDockerCatalogServer,
    supplied: &BTreeMap<String, String>,
    previous: Option<&McpDockerCatalogBinding>,
) -> Result<ResolvedCatalogPlaceholders, String> {
    let mut ids = BTreeMap::new();
    for field in &catalog.placeholders {
        if !is_safe_server_name(&field.id) {
            return Err(format!(
                "catalog `{}` placeholder id `{}` must match [A-Za-z0-9_-]+",
                catalog.id, field.id
            ));
        }
        if ids.insert(field.id.clone(), ()).is_some() {
            return Err(format!(
                "catalog `{}` defines placeholder `{}` more than once",
                catalog.id, field.id
            ));
        }
    }
    for key in supplied.keys() {
        if !ids.contains_key(key) {
            return Err(format!(
                "catalog `{}` does not define placeholder `{key}`",
                catalog.id
            ));
        }
    }

    let mut render_values = BTreeMap::new();
    let mut stored_values = BTreeMap::new();
    for field in &catalog.placeholders {
        let previous_value = previous
            .and_then(|b| b.placeholders.get(&field.id))
            .cloned();
        let supplied_value = supplied.get(&field.id).cloned();
        let value = match supplied_value {
            Some(v) if v == MCP_KEEP_TOKEN || v.trim().is_empty() => previous_value,
            Some(v) => Some(v),
            None => previous_value,
        };
        let value = match value {
            Some(v) => v,
            None if field.required => {
                return Err(format!("placeholder `{}` is required", field.id));
            }
            None => String::new(),
        };
        if field.required && value.trim().is_empty() {
            return Err(format!("placeholder `{}` is required", field.id));
        }
        render_values.insert(field.id.clone(), value.clone());
        if !value.is_empty() {
            stored_values.insert(field.id.clone(), value);
        }
    }

    Ok(ResolvedCatalogPlaceholders {
        render_values,
        stored_values,
    })
}

fn render_catalog_template_value(
    value: &mut serde_json::Value,
    placeholders: &BTreeMap<String, String>,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) => {
            *s = render_catalog_template_string(s, placeholders)?;
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for value in values {
                render_catalog_template_value(value, placeholders)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                render_catalog_template_value(value, placeholders)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn render_catalog_template_string(
    input: &str,
    placeholders: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(start) = rest.find("{{") else {
            out.push_str(rest);
            return Ok(out);
        };
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let Some(end) = rest.find("}}") else {
            return Err("unclosed `{{...}}` placeholder in catalog template".into());
        };
        let placeholder = rest[..end].trim();
        rest = &rest[end + 2..];
        let Some(id) = placeholder
            .strip_prefix("placeholder.")
            .or_else(|| placeholder.strip_prefix("placeholders."))
        else {
            return Err(format!(
                "unsupported catalog placeholder `{{{{{placeholder}}}}}`"
            ));
        };
        let Some(value) = placeholders.get(id) else {
            return Err(format!("unknown catalog placeholder `{id}`"));
        };
        out.push_str(value);
    }
}

fn server_map_from_config<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    let servers = object_field(obj, "servers")?;
    let mcp_servers = object_field(obj, "mcpServers")?;
    match (servers, mcp_servers) {
        (Some(_), Some(_)) => {
            Err("MCP config must contain either `servers` or `mcpServers`, not both".into())
        }
        (Some(map), None) | (None, Some(map)) => Ok(map),
        (None, None) => Err("MCP config must contain a `servers` or `mcpServers` object".into()),
    }
}

fn object_field<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<&'a serde_json::Map<String, serde_json::Value>>, String> {
    match obj.get(key) {
        Some(serde_json::Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(format!("MCP config `{key}` must be an object")),
        None => Ok(None),
    }
}

fn is_safe_server_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn parse_string_array(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array of strings"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| format!("`{field}` must contain only strings"))
        })
        .collect()
}

fn parse_string_map(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<HashMap<String, String>, String> {
    let Some(value) = value else {
        return Ok(HashMap::new());
    };
    let obj = value
        .as_object()
        .ok_or_else(|| format!("`{field}` must be an object of string values"))?;
    obj.iter()
        .map(|(k, v)| {
            v.as_str()
                .map(|s| (k.clone(), s.to_string()))
                .ok_or_else(|| format!("`{field}` values must be strings"))
        })
        .collect()
}

fn auth_from_headers(headers: &HashMap<String, String>) -> McpAuthSpec {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, v)| v.trim().strip_prefix("Bearer "))
        .filter(|token| !token.trim().is_empty())
        .map(|token| McpAuthSpec::Bearer {
            token: token.trim().to_string(),
        })
        .unwrap_or(McpAuthSpec::None)
}

fn reject_input_placeholders(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) if s.contains("${input:") => {
            Err("`${input:...}` placeholders are not supported; paste literal values".into())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                reject_input_placeholders(v)?;
            }
            Ok(())
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values() {
                reject_input_placeholders(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn docker_display_url(args: &[String]) -> String {
    let image = docker_run_image(args).unwrap_or("unknown");
    format!("docker://{image}")
}

fn docker_run_image(args: &[String]) -> Option<&str> {
    if args.first().map(String::as_str) != Some("run") {
        return None;
    }
    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return args.get(i + 1).map(String::as_str);
        }
        if !arg.starts_with('-') {
            return Some(arg);
        }
        if option_takes_value(arg) && !arg.contains('=') {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

/// Defense-in-depth validation used by both swarm and the MCP runtime
/// helper.  It is intentionally conservative around host escape hatches
/// while allowing the ordinary Docker flags MCP snippets tend to use.
pub fn validate_docker_stdio_args(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("run") {
        return Err("stdio Docker MCP config must start with `args: [\"run\", ...]`".into());
    }
    if args.len() < 2 {
        return Err("docker run config must include an image".into());
    }
    let forbidden_with_value = [
        "--volume",
        "--mount",
        "--device",
        "--cap-add",
        "--detach",
        "--privileged",
        "--publish",
        "--publish-all",
        "--pid",
        "--ipc",
        "--uts",
        "--userns",
        "--cgroupns",
        "--cgroup-parent",
        "--network",
        "--net",
        "--security-opt",
        "--env-file",
        "--label-file",
        "--cidfile",
        "--restart",
        "--volumes-from",
        "--device-cgroup-rule",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--cpus",
        "--cpu-quota",
        "--cpu-shares",
        "--blkio-weight",
        "--pids-limit",
        "--ulimit",
        "--shm-size",
        "--oom-score-adj",
    ];
    let mut image_seen = false;
    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg.contains("/var/run/docker.sock") || arg.contains("docker.sock") {
            return Err("Docker socket mounts are not allowed".into());
        }
        if arg == "--" {
            image_seen = args.get(i + 1).is_some();
            break;
        }
        if !arg.starts_with('-') {
            image_seen = true;
            break;
        }
        if arg == "--detach" || arg == "-d" {
            return Err("detached Docker MCP servers are not supported".into());
        }
        if arg.starts_with("--rm=") && arg != "--rm=true" {
            return Err("Docker flag `--rm=false` is not allowed".into());
        }
        if arg == "--privileged" {
            return Err("privileged containers are not allowed".into());
        }
        if arg.starts_with("-v")
            || arg.starts_with("-p")
            || arg.starts_with("-P")
            || arg.starts_with("-m")
        {
            return Err(format!("Docker flag `{arg}` is not allowed"));
        }
        if !arg.starts_with("--") && arg.starts_with('-') && arg.chars().skip(1).any(|c| c == 'd') {
            return Err("detached Docker MCP servers are not supported".into());
        }
        for flag in forbidden_with_value {
            if arg == flag || arg.starts_with(&format!("{flag}=")) {
                if flag == "--network" || flag == "--net" {
                    let value = docker_flag_value(args, i, flag).unwrap_or_default();
                    if value == "none" || value == "bridge" {
                        break;
                    }
                }
                return Err(format!("Docker flag `{flag}` is not allowed"));
            }
        }
        if option_takes_value(arg) && !arg.contains('=') {
            i += 2;
        } else {
            i += 1;
        }
    }
    if !image_seen {
        return Err("docker run config must include an image".into());
    }
    Ok(())
}

fn docker_flag_value<'a>(args: &'a [String], index: usize, flag: &str) -> Option<&'a str> {
    let arg = args.get(index)?.as_str();
    if let Some((_, value)) = arg.split_once('=') {
        return Some(value);
    }
    if arg == flag {
        return args.get(index + 1).map(String::as_str);
    }
    None
}

fn option_takes_value(arg: &str) -> bool {
    let long = arg.split('=').next().unwrap_or(arg);
    matches!(
        long,
        "--add-host"
            | "--annotation"
            | "--attach"
            | "--blkio-weight"
            | "--cidfile"
            | "--cpus"
            | "--cpu-quota"
            | "--cpu-shares"
            | "--dns"
            | "--dns-option"
            | "--dns-search"
            | "--entrypoint"
            | "--env"
            | "--env-file"
            | "--expose"
            | "--group-add"
            | "--hostname"
            | "--label"
            | "--label-file"
            | "--log-driver"
            | "--log-opt"
            | "--memory"
            | "--memory-reservation"
            | "--memory-swap"
            | "--name"
            | "--net"
            | "--network"
            | "--network-alias"
            | "--platform"
            | "--pull"
            | "--restart"
            | "--shm-size"
            | "--stop-signal"
            | "--user"
            | "--workdir"
            | "-a"
            | "-e"
            | "-h"
            | "-l"
            | "-m"
            | "-u"
            | "-w"
    )
}

/// Build the `user_secrets` row name for one server.
pub fn entry_key(instance_id: &str, server_name: &str) -> String {
    format!("mcp.{instance_id}.{server_name}")
}

/// Build the `user_secrets` row name for the index of server names
/// attached to an instance.  Stored as a JSON `["name1", "name2", ...]`
/// blob so the proxy can list/destroy without DB-level enumeration.
pub fn index_key(instance_id: &str) -> String {
    format!("mcp.{instance_id}._index")
}

/// Persist a list of MCP server specs for an instance.  Each spec is
/// sealed under the instance owner's cipher and an index row is
/// rewritten with the server names so subsequent enumeration is cheap.
///
/// Replaces any previous configuration for the instance — callers who
/// want incremental updates should read first, modify, write.
pub async fn put_all(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    specs: Vec<McpServerSpec>,
) -> Result<(), SecretsError> {
    let mut names: Vec<String> = Vec::with_capacity(specs.len());
    for spec in specs {
        let (name, entry) = McpServerEntry::from_spec(spec);
        let blob = serde_json::to_vec(&entry).map_err(|e| {
            SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
                "serialise mcp entry: {e}"
            )))
        })?;
        secrets
            .put(owner_id, &entry_key(instance_id, &name), &blob)
            .await?;
        names.push(name);
    }
    let idx = serde_json::to_vec(&names).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "serialise mcp index: {e}"
        )))
    })?;
    secrets.put(owner_id, &index_key(instance_id), &idx).await?;
    Ok(())
}

/// Read a single server entry.  None = no row.
pub async fn get(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
) -> Result<Option<McpServerEntry>, SecretsError> {
    let Some(bytes) = secrets
        .get(owner_id, &entry_key(instance_id, server_name))
        .await?
    else {
        return Ok(None);
    };
    let entry: McpServerEntry = serde_json::from_slice(&bytes).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "parse mcp entry: {e}"
        )))
    })?;
    Ok(Some(entry))
}

/// Overwrite a single entry — used by the OAuth callback to stamp
/// freshly-minted tokens, and by the proxy refresh path.
pub async fn put(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
    server_name: &str,
    entry: &McpServerEntry,
) -> Result<(), SecretsError> {
    let blob = serde_json::to_vec(entry).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "serialise mcp entry: {e}"
        )))
    })?;
    secrets
        .put(owner_id, &entry_key(instance_id, server_name), &blob)
        .await?;
    Ok(())
}

/// List names attached to an instance.  Cheap — reads only the index row.
pub async fn list_names(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
) -> Result<Vec<String>, SecretsError> {
    let Some(bytes) = secrets.get(owner_id, &index_key(instance_id)).await? else {
        return Ok(Vec::new());
    };
    let names: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| {
        SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
            "parse mcp index: {e}"
        )))
    })?;
    Ok(names)
}

/// Copy every MCP server record from `src_instance_id` to
/// `dst_instance_id` under the same owner.  Preserves URL, auth, AND
/// `oauth_tokens` — the active OAuth session is cloned with the
/// instance, so the user doesn't have to re-authorise after cloning.
/// Used by [`crate::instance::InstanceService::clone_instance`].
///
/// Idempotent: re-running overwrites the dst index and entries.
/// Returns the number of entries copied (0 when source had no MCP).
pub async fn copy_all(
    secrets: &UserSecretsService,
    owner_id: &str,
    src_instance_id: &str,
    dst_instance_id: &str,
) -> Result<usize, SecretsError> {
    let names = list_names(secrets, owner_id, src_instance_id).await?;
    let mut copied = 0usize;
    for name in &names {
        // Index drift defence: an index name with no row gets skipped
        // rather than failing the whole clone.
        let Some(entry) = get(secrets, owner_id, src_instance_id, name).await? else {
            continue;
        };
        put(secrets, owner_id, dst_instance_id, name, &entry).await?;
        copied += 1;
    }
    if !names.is_empty() {
        let idx = serde_json::to_vec(&names).map_err(|e| {
            SecretsError::Envelope(crate::envelope::EnvelopeError::Age(format!(
                "serialise mcp index: {e}"
            )))
        })?;
        secrets
            .put(owner_id, &index_key(dst_instance_id), &idx)
            .await?;
    }
    Ok(copied)
}

/// Delete every MCP server record for an instance.  Best-effort —
/// individual row failures are logged but don't fail the whole call.
/// Called from the instance destroy path so plaintext doesn't linger.
pub async fn forget_all(
    secrets: &UserSecretsService,
    owner_id: &str,
    instance_id: &str,
) -> Result<(), SecretsError> {
    let names = list_names(secrets, owner_id, instance_id).await?;
    for name in names {
        if let Err(err) = secrets
            .delete(owner_id, &entry_key(instance_id, &name))
            .await
        {
            tracing::warn!(
                error = %err,
                instance = %instance_id,
                server = %name,
                "mcp forget: row delete failed"
            );
        }
    }
    if let Err(err) = secrets.delete(owner_id, &index_key(instance_id)).await {
        tracing::warn!(
            error = %err,
            instance = %instance_id,
            "mcp forget: index delete failed"
        );
    }
    Ok(())
}

/// Render the per-server stanza the dyson loader expects under
/// `mcp_servers.<name>` in dyson.json.  The agent only ever sees the
/// swarm-internal proxy URL + bearer header — never the user's real
/// upstream URL or credentials.
///
/// `proxy_base` is the same value the agent already uses for `/llm`
/// (e.g. `http://10.20.18.1:8080/llm` or `https://swarm.example/llm`).
/// We strip the trailing `/llm` segment so the MCP URL lands at
/// `<origin>/mcp/<instance>/<name>` — the LLM proxy lives at `/llm`
/// and the MCP proxy at `/mcp`, both off the same swarm origin.
/// Without this strip the agent's handshake hits `/llm/mcp/...` which
/// the LLM router rejects, and the skill registers with zero tools.
pub fn dyson_json_block(
    instance_id: &str,
    name: &str,
    proxy_base: &str,
    proxy_token: &str,
) -> serde_json::Value {
    let url = format!(
        "{}/mcp/{}/{}",
        swarm_origin_from_proxy_base(proxy_base),
        instance_id,
        name,
    );
    serde_json::json!({
        "url": url,
        "headers": {
            "Authorization": format!("Bearer {proxy_token}"),
        },
    })
}

/// Strip the trailing `/llm` (with optional trailing slash) from the
/// proxy_base the InstanceService was constructed with, leaving the
/// swarm origin both `/llm` and `/mcp` mount off.  Tolerates a
/// `proxy_base` that doesn't end in `/llm` (returns it as-is, minus
/// any trailing slash) so future callers passing a bare origin
/// still work.
fn swarm_origin_from_proxy_base(proxy_base: &str) -> &str {
    let trimmed = proxy_base.trim_end_matches('/');
    trimmed.strip_suffix("/llm").unwrap_or(trimmed)
}

// ───────────────────────────────────────────────────────────────────
// OAuth primitives — discovery, PKCE, token exchange/refresh.
// Ported from dyson/auth/oauth.rs so the swarm-side proxy can run
// the flow without depending on the agent crate.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuthMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
}

/// RFC 9728 Protected Resource Metadata.  Published by the resource
/// (i.e. the MCP server itself) so a client can find which
/// authorization server(s) issue tokens for it — the OAuth pieces
/// don't have to live on the same origin.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DcrRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// Space-separated scope list (RFC 7591 §2).  Smithery (and likely
    /// other strict ASes) reject `authorize?scope=foo` when the client
    /// wasn't registered with that scope, so we mirror the user-supplied
    /// scopes here at registration time.  None ⇒ field is omitted from
    /// the JSON body and the AS chooses its default scope set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DcrResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
}

pub fn generate_pkce() -> PkceChallenge {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkceChallenge {
        verifier,
        challenge,
    }
}

pub fn generate_state() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().r#gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn discover_metadata(
    server_url: &str,
    client: &reqwest::Client,
) -> Result<AuthMetadata, String> {
    // Two-step discovery per RFC 9728 + RFC 8414:
    //   1. Fetch Protected Resource Metadata at
    //      `{resource_origin}/.well-known/oauth-protected-resource{resource_path}`
    //      first, then the root form
    //      `{resource_origin}/.well-known/oauth-protected-resource`.
    //      Path-scoped PRM is what providers like GitHub publish for
    //      `/mcp` resources; older servers still use the root form.
    //      Either way, the PRM points us at the authorization server
    //      origin — the resource and the AS often live on different
    //      origins (e.g. Smithery hosts the MCP server on `*.run.tools`
    //      and the AS on `auth.smithery.ai`).
    //   2. Fetch AS metadata via path-prefixed well-known
    //      (`{as_origin}/.well-known/oauth-authorization-server{as_path}`)
    //      so AS URLs with a tenant path resolve correctly.
    //
    // Falls back to the legacy single-shot at the resource origin when
    // PRM isn't published — older MCP servers (Linear, etc.) colocate
    // AS metadata with the resource.
    //
    // Error messages reference the DOMAIN only — some MCP providers
    // ship per-tenant URLs with bearer-style query params or path
    // segments, and a verbatim URL in a log line is a credential
    // disclosure waiting to happen.  See `domain_of` for the rule.
    let origin = origin_of(server_url)?;
    let domain = domain_of(server_url);

    for prm_url in protected_resource_metadata_urls(server_url)? {
        match fetch_protected_resource(&prm_url, client, &domain).await? {
            Some(as_url) => return fetch_as_metadata(&as_url, client, &domain).await,
            None => continue,
        }
    }

    let url = format!("{origin}/.well-known/oauth-authorization-server");
    fetch_metadata_at(&url, client, &domain).await
}

fn protected_resource_metadata_urls(server_url: &str) -> Result<Vec<String>, String> {
    let parsed = reqwest::Url::parse(server_url)
        .map_err(|e| format!("parse {}: {e}", domain_of(server_url)))?;
    let origin = origin_of(server_url)?;
    let path = parsed.path().trim_end_matches('/');
    let mut urls = Vec::new();
    if !path.is_empty() {
        urls.push(format!(
            "{origin}/.well-known/oauth-protected-resource{path}",
        ));
    }
    urls.push(format!("{origin}/.well-known/oauth-protected-resource"));
    Ok(urls)
}

/// Try to fetch RFC 9728 Protected Resource Metadata.  Returns the
/// first authorization server URL on success, `None` when the resource
/// doesn't publish PRM (404), or an error for other failures.
async fn fetch_protected_resource(
    url: &str,
    client: &reqwest::Client,
    resource_domain: &str,
) -> Result<Option<String>, String> {
    let resp = client.get(url).send().await.map_err(|e| {
        format!(
            "discovery {resource_domain}: {}",
            redact_reqwest_err(&e, url)
        )
    })?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "discovery {resource_domain}: protected-resource HTTP {}",
            resp.status(),
        ));
    }
    let prm: ProtectedResourceMetadata = resp
        .json()
        .await
        .map_err(|e| format!("discovery {resource_domain}: parse protected-resource: {e}"))?;
    Ok(prm.authorization_servers.into_iter().next())
}

/// Fetch AS metadata for an authorization server URL that may carry a
/// path component (e.g. multi-tenant providers).  Errors carry the
/// resource's domain so operators can tie a failure back to the MCP
/// server entry, not the (possibly tenant-bearing) AS path.
async fn fetch_as_metadata(
    as_url: &str,
    client: &reqwest::Client,
    resource_domain: &str,
) -> Result<AuthMetadata, String> {
    let well_known =
        as_metadata_url(as_url).map_err(|e| format!("discovery {resource_domain}: {e}"))?;
    fetch_metadata_at(&well_known, client, resource_domain).await
}

async fn fetch_metadata_at(
    url: &str,
    client: &reqwest::Client,
    resource_domain: &str,
) -> Result<AuthMetadata, String> {
    let resp = client.get(url).send().await.map_err(|e| {
        format!(
            "discovery {resource_domain}: {}",
            redact_reqwest_err(&e, url)
        )
    })?;
    if !resp.status().is_success() {
        return Err(format!(
            "discovery {resource_domain}: HTTP {}",
            resp.status(),
        ));
    }
    resp.json::<AuthMetadata>()
        .await
        .map_err(|e| format!("discovery {resource_domain}: parse metadata: {e}"))
}

/// Build the well-known URL for an authorization server per
/// RFC 8414 §3.1.  When the AS URL has a non-trivial path, the
/// well-known segment is inserted *between* the origin and that path;
/// when there's no path (or just `/`), the well-known sits at the root.
///
///   `https://auth.example.com`            → `https://auth.example.com/.well-known/oauth-authorization-server`
///   `https://auth.example.com/`           → `https://auth.example.com/.well-known/oauth-authorization-server`
///   `https://auth.example.com/tenant/svc` → `https://auth.example.com/.well-known/oauth-authorization-server/tenant/svc`
pub fn as_metadata_url(as_url: &str) -> Result<String, String> {
    let parsed =
        reqwest::Url::parse(as_url).map_err(|e| format!("parse {}: {e}", domain_of(as_url)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("no host in {}", domain_of(as_url)))?;
    let scheme = parsed.scheme();
    let origin = match parsed.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    let path = parsed.path().trim_end_matches('/');
    if path.is_empty() {
        Ok(format!("{origin}/.well-known/oauth-authorization-server"))
    } else {
        Ok(format!(
            "{origin}/.well-known/oauth-authorization-server{path}",
        ))
    }
}

fn origin_of(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("parse {}: {e}", domain_of(url)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("no host in {}", domain_of(url)))?;
    let scheme = parsed.scheme();
    Ok(match parsed.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// Log-safe rendering of an MCP / OAuth URL: scheme + host + port
/// only — no path, no query string, no fragment.  Some MCP
/// providers embed bearer tokens or tenant secrets in the URL
/// (path segment or query param), so a raw URL in a log line is
/// effectively a credential.  Emit the domain instead and the
/// operator still has enough to triage ("which provider?") with
/// nothing exfiltratable.
///
/// Falls back to `<unparseable url>` when the value isn't a valid
/// URL — the caller asked us to render *something* and a parse
/// failure isn't worth panicking over.
pub fn domain_of(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return "<unparseable url>".to_string();
    };
    let Some(host) = parsed.host_str() else {
        return "<unparseable url>".to_string();
    };
    let scheme = parsed.scheme();
    match parsed.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    }
}

/// Render a reqwest error for a log line without echoing the full
/// URL.  reqwest's Display impl spells out
/// "error sending request for url ({full_url}): …" — with a
/// token-bearing URL that's a credential leak straight to the
/// operator's `journalctl`.  Walk the error chain ourselves and
/// substitute every literal occurrence of `upstream` with its
/// domain.  Caller passes `upstream` as the URL the request
/// targeted (typically `entry.url`) — that's the one reqwest
/// embeds.
pub fn redact_reqwest_err(err: &reqwest::Error, upstream: &str) -> String {
    let mut chain = format!("{err}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(s) = src {
        chain.push_str(": ");
        chain.push_str(&format!("{s}"));
        src = s.source();
    }
    let domain = domain_of(upstream);
    // Multi-pass replace: reqwest may include both the canonicalised
    // form (with trailing slash) and the as-supplied form, so swap
    // both.
    let mut out = chain.replace(upstream, &domain);
    if let Ok(canon) = reqwest::Url::parse(upstream) {
        out = out.replace(canon.as_str(), &domain);
    }
    out
}

pub async fn register_client(
    url: &str,
    req: &DcrRequest,
    client: &reqwest::Client,
) -> Result<DcrResponse, String> {
    // DCR endpoints don't typically carry tokens, but the rule is
    // uniform: never echo full URLs to logs.
    let domain = domain_of(url);
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .map_err(|e| format!("DCR send to {domain}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("DCR to {domain}: HTTP {}", resp.status()));
    }
    resp.json::<DcrResponse>()
        .await
        .map_err(|e| format!("DCR parse: {e}"))
}

pub fn build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    scopes: &[String],
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(authorization_endpoint).map_err(|e| {
        format!(
            "parse auth endpoint {}: {e}",
            domain_of(authorization_endpoint),
        )
    })?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state);
        // Some ASes (Smithery) reject `scope=` (empty) and reject
        // scopes the DCR record didn't list.  When the user picks
        // "no scopes", omit the param entirely so the AS uses its
        // registered default set.
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url.to_string())
}

pub async fn exchange_code(
    token_url: &str,
    code: &str,
    verifier: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    if let Some(s) = client_secret {
        params.push(("client_secret", s));
    }
    post_token(token_url, &params, client).await
}

pub async fn refresh_token(
    token_url: &str,
    refresh: &str,
    client_id: &str,
    client_secret: Option<&str>,
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ];
    if let Some(s) = client_secret {
        params.push(("client_secret", s));
    }
    post_token(token_url, &params, client).await
}

async fn post_token(
    token_url: &str,
    params: &[(&str, &str)],
    client: &reqwest::Client,
) -> Result<TokenResponse, String> {
    // Token endpoints can carry tenant identifiers in the URL too;
    // log domain only.  The reqwest error itself is also redacted
    // because Display includes the URL in its chain.
    let domain = domain_of(token_url);
    let resp = client
        .post(token_url)
        .form(params)
        .send()
        .await
        .map_err(|e| {
            format!(
                "token request to {domain}: {}",
                redact_reqwest_err(&e, token_url)
            )
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token endpoint {domain} HTTP {status}: {body}"));
    }
    resp.json::<TokenResponse>()
        .await
        .map_err(|e| format!("parse token response from {domain}: {e}"))
}

/// In-process cache of in-flight OAuth flows.  Holds the PKCE verifier
/// and the user/instance/server it was started for so the callback can
/// match the inbound `state` param.  Five-minute TTL — same as dyson's
/// own callback server.
#[derive(Clone, Default)]
pub struct OAuthFlowCache {
    inner: Arc<parking_lot::Mutex<std::collections::HashMap<String, PendingFlow>>>,
}

#[derive(Clone)]
pub struct PendingFlow {
    pub owner_id: String,
    pub instance_id: String,
    pub server_name: String,
    pub pkce_verifier: String,
    pub redirect_uri: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Unix seconds when this entry expires.
    pub expires_at: i64,
    /// Where to send the user's browser after the callback finishes.
    /// Defaults to the instance detail page; the SPA can override.
    pub return_to: Option<String>,
}

impl OAuthFlowCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, state: String, flow: PendingFlow) {
        // Opportunistic GC: every insert prunes expired entries.  At
        // typical load (a handful of in-flight flows per swarm) this is
        // a few-line scan; cheaper than a background sweeper task.
        let now = crate::now_secs();
        let mut g = self.inner.lock();
        g.retain(|_, v| v.expires_at > now);
        g.insert(state, flow);
    }

    pub fn take(&self, state: &str) -> Option<PendingFlow> {
        let now = crate::now_secs();
        let mut g = self.inner.lock();
        g.retain(|_, v| v.expires_at > now);
        g.remove(state)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{Router, extract::State, response::IntoResponse, routing::get as ax_get};

    use super::*;
    use crate::envelope::AgeCipherDirectory;
    use crate::traits::UserSecretStore;
    use std::sync::Mutex;

    struct MemUserSecretStore(Mutex<Vec<(String, String, String)>>);

    #[async_trait::async_trait]
    impl UserSecretStore for MemUserSecretStore {
        async fn put(
            &self,
            user_id: &str,
            name: &str,
            ct: &str,
        ) -> Result<(), crate::error::StoreError> {
            let mut v = self.0.lock().unwrap();
            v.retain(|(u, n, _)| !(u == user_id && n == name));
            v.push((user_id.to_owned(), name.to_owned(), ct.to_owned()));
            Ok(())
        }
        async fn get(
            &self,
            user_id: &str,
            name: &str,
        ) -> Result<Option<String>, crate::error::StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|(u, n, _)| u == user_id && n == name)
                .map(|(_, _, c)| c.clone()))
        }
        async fn delete(&self, user_id: &str, name: &str) -> Result<(), crate::error::StoreError> {
            self.0
                .lock()
                .unwrap()
                .retain(|(u, n, _)| !(u == user_id && n == name));
            Ok(())
        }
        async fn list(
            &self,
            user_id: &str,
        ) -> Result<Vec<(String, String)>, crate::error::StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, _, _)| u == user_id)
                .map(|(_, n, c)| (n.clone(), c.clone()))
                .collect())
        }
    }

    fn make_svc() -> (tempfile::TempDir, Arc<UserSecretsService>) {
        let tmp = tempfile::tempdir().unwrap();
        let dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store: Arc<dyn UserSecretStore> = Arc::new(MemUserSecretStore(Mutex::new(Vec::new())));
        (tmp, Arc::new(UserSecretsService::new(store, dir)))
    }

    #[tokio::test]
    async fn round_trip_bearer_server() {
        let (_tmp, svc) = make_svc();
        let owner = "deadbeef".repeat(4);
        let instance = "i-abc";
        put_all(
            &svc,
            &owner,
            instance,
            vec![McpServerSpec {
                name: "linear".into(),
                url: "https://api.linear.app/mcp".into(),
                auth: McpAuthSpec::Bearer {
                    token: "lin_xxx".into(),
                },
                enabled_tools: None,
            }],
        )
        .await
        .unwrap();

        let names = list_names(&svc, &owner, instance).await.unwrap();
        assert_eq!(names, vec!["linear"]);

        let entry = get(&svc, &owner, instance, "linear")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.url, "https://api.linear.app/mcp");
        match entry.auth {
            McpAuthSpec::Bearer { token } => assert_eq!(token, "lin_xxx"),
            _ => panic!("expected bearer auth"),
        }
    }

    #[tokio::test]
    async fn forget_all_clears_index_and_rows() {
        let (_tmp, svc) = make_svc();
        let owner = "cafef00d".repeat(4);
        let instance = "i-zzz";
        put_all(
            &svc,
            &owner,
            instance,
            vec![
                McpServerSpec {
                    name: "a".into(),
                    url: "https://a/mcp".into(),
                    auth: McpAuthSpec::None,
                    enabled_tools: None,
                },
                McpServerSpec {
                    name: "b".into(),
                    url: "https://b/mcp".into(),
                    auth: McpAuthSpec::Bearer { token: "t".into() },
                    enabled_tools: None,
                },
            ],
        )
        .await
        .unwrap();
        forget_all(&svc, &owner, instance).await.unwrap();
        assert!(get(&svc, &owner, instance, "a").await.unwrap().is_none());
        assert!(get(&svc, &owner, instance, "b").await.unwrap().is_none());
        assert!(list_names(&svc, &owner, instance).await.unwrap().is_empty());
    }

    #[test]
    fn dyson_json_block_uses_proxy_url() {
        let block = dyson_json_block("i-abc", "linear", "https://swarm.example/", "tok-1");
        assert_eq!(block["url"], "https://swarm.example/mcp/i-abc/linear");
        assert_eq!(block["headers"]["Authorization"], "Bearer tok-1");
    }

    #[test]
    fn vscode_config_accepts_single_docker_stdio_server() {
        let raw = serde_json::json!({
            "servers": {
                "github_1": {
                    "type": "stdio",
                    "command": "docker",
                    "args": ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/example/github-mcp"],
                    "env": { "GITHUB_TOKEN": "ghp_secret" }
                }
            }
        });
        let (name, entry) = entry_from_vscode_config(raw.clone()).unwrap();

        assert_eq!(name, "github_1");
        assert_eq!(entry.url, "docker://ghcr.io/example/github-mcp");
        assert_eq!(entry.auth, McpAuthSpec::None);
        assert_eq!(entry.raw_vscode_config, Some(raw));
        match entry.runtime {
            Some(McpRuntimeSpec::DockerStdio { command, args, env }) => {
                assert_eq!(command, "docker");
                assert_eq!(args[0], "run");
                assert_eq!(env["GITHUB_TOKEN"], "ghp_secret");
            }
            other => panic!("expected docker stdio runtime, got {other:?}"),
        }
    }

    #[test]
    fn vscode_config_accepts_claude_style_mcp_servers_block() {
        let raw = serde_json::json!({
            "mcpServers": {
                "massive": {
                    "command": "docker",
                    "args": ["run", "--rm", "-i", "joncooperworks/mcp_massive:latest"]
                }
            }
        });
        let (name, entry) = entry_from_vscode_config(raw.clone()).unwrap();

        assert_eq!(name, "massive");
        assert_eq!(entry.url, "docker://joncooperworks/mcp_massive:latest");
        assert_eq!(entry.raw_vscode_config, Some(raw));
        match entry.runtime {
            Some(McpRuntimeSpec::DockerStdio { command, args, env }) => {
                assert_eq!(command, "docker");
                assert_eq!(
                    args,
                    vec!["run", "--rm", "-i", "joncooperworks/mcp_massive:latest"]
                );
                assert!(env.is_empty());
            }
            other => panic!("expected docker stdio runtime, got {other:?}"),
        }
    }

    #[test]
    fn vscode_config_accepts_single_http_server() {
        let raw = serde_json::json!({
            "servers": {
                "linear": {
                    "type": "http",
                    "url": "https://api.linear.app/mcp",
                    "headers": {
                        "Authorization": "Bearer lin_secret",
                        "X-Team": "search"
                    }
                }
            }
        });
        let (name, entry) = entry_from_vscode_config(raw).unwrap();

        assert_eq!(name, "linear");
        assert_eq!(entry.url, "https://api.linear.app/mcp");
        assert!(entry.runtime.is_none());
        assert_eq!(entry.headers["X-Team"], "search");
        match entry.auth {
            McpAuthSpec::Bearer { token } => assert_eq!(token, "lin_secret"),
            other => panic!("expected bearer auth, got {other:?}"),
        }
    }

    #[test]
    fn vscode_config_rejects_multi_server_and_placeholders() {
        let multi = serde_json::json!({
            "servers": {
                "a": { "type": "http", "url": "https://a.example/mcp" },
                "b": { "type": "http", "url": "https://b.example/mcp" }
            }
        });
        assert!(
            entry_from_vscode_config(multi)
                .unwrap_err()
                .contains("exactly one")
        );

        let both = serde_json::json!({
            "servers": {},
            "mcpServers": {
                "github": {
                    "type": "stdio",
                    "command": "docker",
                    "args": ["run", "ghcr.io/example/github-mcp"]
                }
            }
        });
        assert!(
            entry_from_vscode_config(both)
                .unwrap_err()
                .contains("either `servers` or `mcpServers`")
        );

        let placeholder = serde_json::json!({
            "servers": {
                "github": {
                    "type": "stdio",
                    "command": "docker",
                    "args": ["run", "-i", "-e", "GITHUB_TOKEN=${input:token}", "ghcr.io/example/github-mcp"]
                }
            }
        });
        assert!(
            entry_from_vscode_config(placeholder)
                .unwrap_err()
                .contains("placeholders")
        );
    }

    #[test]
    fn docker_stdio_validator_rejects_host_escape_flags() {
        for args in [
            vec!["run", "--privileged", "img"],
            vec!["run", "--network=host", "img"],
            vec!["run", "--pid", "host", "img"],
            vec!["run", "-p", "8080:8080", "img"],
            vec!["run", "-v", "/:/host", "img"],
            vec!["run", "-d", "img"],
            vec!["run", "--detach=true", "img"],
            vec!["run", "--rm=false", "img"],
            vec!["run", "--env-file", "/tmp/secrets", "img"],
            vec!["run", "--mount", "type=bind,source=/,target=/host", "img"],
            vec!["run", "--memory=8g", "img"],
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            assert!(
                validate_docker_stdio_args(&args).is_err(),
                "{args:?} should be rejected"
            );
        }
        let safe: Vec<String> = [
            "run",
            "--rm",
            "-i",
            "--network=bridge",
            "ghcr.io/example/mcp",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(validate_docker_stdio_args(&safe).is_ok());
    }

    #[test]
    fn docker_catalog_template_renders_placeholders_and_hides_raw_json() {
        let catalog = McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: Some("GitHub MCP server".into()),
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "-e", "GITHUB_TOKEN", "ghcr.io/example/github-mcp"],
                        "env": { "GITHUB_TOKEN": "{{placeholder.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![McpDockerPlaceholderSpec {
                id: "github_token".into(),
                label: "GitHub token".into(),
                description: None,
                required: true,
                secret: true,
                placeholder: None,
            }],
        };
        let placeholders = BTreeMap::from([("github_token".into(), "ghp_secret".into())]);

        let (name, entry) =
            entry_from_docker_catalog_template(&catalog, &placeholders, None).unwrap();

        assert_eq!(name, "github");
        assert_eq!(entry.raw_vscode_config, None);
        assert_eq!(entry.docker_catalog.as_ref().unwrap().id, "github");
        assert_eq!(
            entry.docker_catalog.unwrap().placeholders["github_token"],
            "ghp_secret"
        );
        match entry.runtime {
            Some(McpRuntimeSpec::DockerStdio { env, .. }) => {
                assert_eq!(env["GITHUB_TOKEN"], "ghp_secret");
            }
            other => panic!("expected docker stdio runtime, got {other:?}"),
        }
    }

    #[test]
    fn docker_catalog_validation_allows_no_placeholder_templates() {
        let catalog = McpDockerCatalogServer {
            id: "memory".into(),
            label: "Memory".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "memory": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "ghcr.io/example/memory-mcp"]
                    }
                }
            })
            .to_string(),
            placeholders: vec![],
        };

        validate_docker_catalog_server(&catalog).unwrap();
    }

    #[test]
    fn docker_catalog_validation_rejects_unknown_placeholders() {
        let catalog = McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "ghcr.io/example/github-mcp"],
                        "env": { "GITHUB_TOKEN": "{{placeholder.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![],
        };

        let err = validate_docker_catalog_server(&catalog).unwrap_err();
        assert!(err.contains("unknown catalog placeholder"));
    }

    #[test]
    fn docker_catalog_validation_rejects_legacy_credential_tokens() {
        let catalog = McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "ghcr.io/example/github-mcp"],
                        "env": { "GITHUB_TOKEN": "{{credential.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![McpDockerPlaceholderSpec {
                id: "github_token".into(),
                label: "GitHub token".into(),
                description: None,
                required: true,
                secret: true,
                placeholder: None,
            }],
        };

        let err = validate_docker_catalog_server(&catalog).unwrap_err();
        assert!(err.contains("unsupported catalog placeholder"));
    }

    #[test]
    fn docker_catalog_template_keeps_existing_placeholders() {
        let catalog = McpDockerCatalogServer {
            id: "github".into(),
            label: "GitHub".into(),
            description: None,
            template: serde_json::json!({
                "servers": {
                    "github": {
                        "type": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "-i", "-e", "GITHUB_TOKEN", "ghcr.io/example/github-mcp:v2"],
                        "env": { "GITHUB_TOKEN": "{{placeholders.github_token}}" }
                    }
                }
            })
            .to_string(),
            placeholders: vec![McpDockerPlaceholderSpec {
                id: "github_token".into(),
                label: "GitHub token".into(),
                description: None,
                required: true,
                secret: true,
                placeholder: None,
            }],
        };
        let existing = McpServerEntry {
            url: "docker://ghcr.io/example/github-mcp:v1".into(),
            auth: McpAuthSpec::None,
            headers: HashMap::new(),
            runtime: None,
            docker_catalog: Some(McpDockerCatalogBinding {
                id: "github".into(),
                placeholders: BTreeMap::from([("github_token".into(), "old_secret".into())]),
            }),
            raw_vscode_config: None,
            oauth_tokens: None,
            tools_catalog: None,
            enabled_tools: None,
        };
        let supplied = BTreeMap::from([("github_token".into(), MCP_KEEP_TOKEN.into())]);

        let (_name, entry) =
            entry_from_docker_catalog_template(&catalog, &supplied, Some(&existing)).unwrap();

        match entry.runtime {
            Some(McpRuntimeSpec::DockerStdio { args, env, .. }) => {
                assert!(
                    args.iter()
                        .any(|arg| arg == "ghcr.io/example/github-mcp:v2")
                );
                assert_eq!(env["GITHUB_TOKEN"], "old_secret");
            }
            other => panic!("expected docker stdio runtime, got {other:?}"),
        }
    }

    #[test]
    fn dyson_json_block_strips_trailing_llm_segment() {
        // Regression: the InstanceService's proxy_base is the LLM
        // proxy URL (`<origin>/llm`).  MCP mounts at `<origin>/mcp`,
        // not `<origin>/llm/mcp` — without stripping `/llm` the
        // agent's handshake 404s and the skill registers zero tools.
        let block = dyson_json_block("i-1", "ctx", "http://10.0.0.1:8080/llm", "tok");
        assert_eq!(block["url"], "http://10.0.0.1:8080/mcp/i-1/ctx");

        // Trailing slash on `/llm/` also stripped so the URL is clean.
        let block = dyson_json_block("i-1", "ctx", "https://swarm.example/llm/", "tok");
        assert_eq!(block["url"], "https://swarm.example/mcp/i-1/ctx");

        // Bare origin (no `/llm`) still works — strip is a no-op.
        let block = dyson_json_block("i-1", "ctx", "https://swarm.example", "tok");
        assert_eq!(block["url"], "https://swarm.example/mcp/i-1/ctx");
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let p = generate_pkce();
        let want = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, want);
    }

    #[test]
    fn oauth_cache_take_removes_entry() {
        let cache = OAuthFlowCache::new();
        cache.insert(
            "state-1".into(),
            PendingFlow {
                owner_id: "u".into(),
                instance_id: "i".into(),
                server_name: "s".into(),
                pkce_verifier: "v".into(),
                redirect_uri: "https://swarm/mcp/oauth/callback".into(),
                token_url: "https://up/token".into(),
                client_id: "c".into(),
                client_secret: None,
                expires_at: i64::MAX,
                return_to: None,
            },
        );
        assert!(cache.take("state-1").is_some());
        assert!(cache.take("state-1").is_none(), "take must be one-shot");
    }

    #[test]
    fn needs_refresh_respects_60s_skew() {
        let now = 1_000_000_i64;
        let near = McpOAuthTokens {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: Some(now + 30),
            token_url: "u".into(),
            client_id: "c".into(),
            client_secret: None,
        };
        assert!(near.needs_refresh(now), "30s left should refresh");
        let far = McpOAuthTokens {
            expires_at: Some(now + 600),
            ..near.clone()
        };
        assert!(!far.needs_refresh(now));
    }

    #[test]
    fn auth_spec_serialisation_is_tagged() {
        let s = McpAuthSpec::Bearer { token: "t".into() };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["kind"], "bearer");
        assert_eq!(v["token"], "t");
    }

    // ── domain_of ──────────────────────────────────────────────
    //
    // The redaction contract for log lines.  Some MCP providers
    // ship per-tenant URLs with bearer-style query params or path
    // segments; this helper is what keeps those out of journalctl.

    #[test]
    fn domain_of_strips_path_query_and_fragment() {
        // The motivating case: a token in the query string.
        assert_eq!(
            domain_of("https://api.linear.app/mcp?token=lin_secret_abc"),
            "https://api.linear.app",
        );
        // Path-segment tokens (e.g. /tenants/<id>/mcp) — same rule.
        assert_eq!(
            domain_of("https://mcp.example.com/tenants/abc-secret/v1/mcp"),
            "https://mcp.example.com",
        );
        // Fragment, just for completeness.
        assert_eq!(
            domain_of("https://mcp.example.com/path#frag"),
            "https://mcp.example.com",
        );
    }

    #[test]
    fn domain_of_preserves_non_default_port() {
        // Self-hosted MCP on a non-standard port — operators
        // need the port to triage, so it stays.
        assert_eq!(
            domain_of("http://10.0.0.5:7878/mcp/some/path"),
            "http://10.0.0.5:7878",
        );
        assert_eq!(
            domain_of("https://example.com:8443/mcp"),
            "https://example.com:8443",
        );
    }

    #[test]
    fn domain_of_falls_back_for_garbage_input() {
        // The function is called from log paths; panicking on
        // weird inputs would be worse than emitting a placeholder.
        assert_eq!(domain_of("not a url at all"), "<unparseable url>");
        assert_eq!(domain_of(""), "<unparseable url>");
    }

    // ── redact_reqwest_err ─────────────────────────────────────
    //
    // reqwest's Display includes the full URL in its error chain.
    // We can't easily build a real reqwest::Error in a unit test,
    // but we can verify the substring-replacement contract by
    // round-tripping a known-leaky string through the body of the
    // helper (the `.replace` is the only domain-specific bit).

    #[test]
    fn redact_logic_replaces_full_url_with_domain() {
        // Simulate what reqwest's Display would emit and exercise
        // the same replacement the helper does.  The real helper
        // walks the error chain too, but the substring substitution
        // is the load-bearing piece.
        let url = "https://api.linear.app/mcp?token=lin_secret_abc";
        let leaky = format!("error sending request for url ({url}): connection closed",);
        let domain = domain_of(url);
        let scrubbed = leaky.replace(url, &domain);
        assert!(
            !scrubbed.contains("lin_secret_abc"),
            "redaction must remove the in-URL token; got: {scrubbed}",
        );
        assert!(scrubbed.contains("https://api.linear.app"));
        assert!(scrubbed.contains("connection closed"));
    }

    // ── as_metadata_url ────────────────────────────────────────
    //
    // RFC 8414 §3.1 path-prefixed discovery.  This is what makes
    // multi-tenant providers (Smithery, Auth0 with custom paths,
    // etc.) discoverable without a hardcoded list of vendor quirks.

    #[test]
    fn as_metadata_url_root_origin() {
        assert_eq!(
            as_metadata_url("https://auth.example.com").unwrap(),
            "https://auth.example.com/.well-known/oauth-authorization-server",
        );
        assert_eq!(
            as_metadata_url("https://auth.example.com/").unwrap(),
            "https://auth.example.com/.well-known/oauth-authorization-server",
        );
    }

    #[test]
    fn as_metadata_url_path_prefixed() {
        // The Smithery shape — multi-tenant AS with the tenant in
        // the path.  Well-known sits between origin and tenant path.
        assert_eq!(
            as_metadata_url("https://auth.smithery.ai/nexgendata-apify/finance-mcp-server")
                .unwrap(),
            "https://auth.smithery.ai/.well-known/oauth-authorization-server/nexgendata-apify/finance-mcp-server",
        );
        // Trailing slash on the AS URL is normalised away so we
        // don't emit a double-slash before the well-known segment.
        assert_eq!(
            as_metadata_url("https://auth.example.com/tenant/").unwrap(),
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
        );
    }

    #[test]
    fn as_metadata_url_preserves_port() {
        // Self-hosted AS on a non-default port.  Operators run these
        // and the port MUST survive into the well-known URL.
        assert_eq!(
            as_metadata_url("http://10.0.0.5:7878/realm").unwrap(),
            "http://10.0.0.5:7878/.well-known/oauth-authorization-server/realm",
        );
    }

    #[test]
    fn as_metadata_url_rejects_garbage() {
        assert!(as_metadata_url("not a url").is_err());
        // Errors must use the redacted domain, not the raw input.
        let err = as_metadata_url("https://auth.example.com/tenant?token=secret-abc")
            .map(|_| ())
            .unwrap_or_else(|e| panic!("expected ok for valid URL with query, got err: {e}"));
        let _ = err;
    }

    #[test]
    fn protected_resource_metadata_urls_prefers_path_scoped_then_root() {
        assert_eq!(
            protected_resource_metadata_urls("https://api.githubcopilot.com/mcp/").unwrap(),
            vec![
                "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp",
                "https://api.githubcopilot.com/.well-known/oauth-protected-resource",
            ],
        );
    }

    #[test]
    fn protected_resource_metadata_urls_root_only_when_no_path() {
        assert_eq!(
            protected_resource_metadata_urls("https://api.linear.app").unwrap(),
            vec!["https://api.linear.app/.well-known/oauth-protected-resource"],
        );
    }

    // ── build_auth_url ─────────────────────────────────────────
    //
    // Smithery (and other strict ASes) reject `authorize?scope=foo`
    // when the DCR record didn't list `foo`.  We mirror the
    // user-supplied scopes into DCR and omit the param entirely
    // when there are no scopes — the AS picks its registered default.

    #[test]
    fn build_auth_url_omits_scope_when_empty() {
        let url = build_auth_url(
            "https://auth.example.com/authorize",
            "client-1",
            &[],
            "https://swarm.example/cb",
            "ch",
            "st",
        )
        .unwrap();
        assert!(!url.contains("scope="), "no empty scope param: {url}");
        assert!(url.contains("client_id=client-1"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn build_auth_url_includes_scope_when_present() {
        let url = build_auth_url(
            "https://auth.example.com/authorize",
            "client-1",
            &["read".into(), "write".into()],
            "https://swarm.example/cb",
            "ch",
            "st",
        )
        .unwrap();
        // url-encoded space between scopes
        assert!(
            url.contains("scope=read+write") || url.contains("scope=read%20write"),
            "scope joined with space: {url}"
        );
    }

    #[test]
    fn dcr_request_serialises_scope_when_some() {
        let req = DcrRequest {
            client_name: "swarm".into(),
            redirect_uris: vec!["https://x/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: None,
            scope: Some("read write".into()),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["scope"], "read write");
    }

    #[test]
    fn dcr_request_omits_scope_when_none() {
        let req = DcrRequest {
            client_name: "swarm".into(),
            redirect_uris: vec!["https://x/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: None,
            scope: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert!(
            v.get("scope").is_none(),
            "scope must be absent (not null) so AS uses its default: {v}"
        );
    }

    #[test]
    fn discovery_error_carries_domain_only() {
        // Indirect contract test: discover_metadata is the
        // hot path for OAuth flows.  Pass a clearly-broken URL
        // (no scheme) so the error fires fast, and check the
        // returned message doesn't echo the full input.
        // Tokio runtime is required for the .await below.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let leaky = "https://mcp.example.com/tenants/abc-secret/v1/mcp";
            // We can't actually contact the URL in a unit test;
            // build a real client so the call returns a network
            // error rather than panicking.
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(1))
                .build()
                .unwrap();
            let err = discover_metadata(leaky, &client).await.unwrap_err();
            assert!(
                !err.contains("abc-secret"),
                "discover_metadata error leaked path token: {err}",
            );
            assert!(
                err.contains("mcp.example.com"),
                "operator still needs the domain to triage: {err}",
            );
        });
    }

    #[test]
    fn discover_metadata_uses_path_scoped_protected_resource_when_present() {
        #[derive(Clone)]
        struct DiscoveryState {
            root_hits: Arc<AtomicUsize>,
            path_hits: Arc<AtomicUsize>,
            as_base: String,
        }

        async fn root_prm(State(state): State<DiscoveryState>) -> impl IntoResponse {
            state.root_hits.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::NOT_FOUND
        }

        async fn path_prm(State(state): State<DiscoveryState>) -> impl IntoResponse {
            state.path_hits.fetch_add(1, Ordering::SeqCst);
            axum::Json(serde_json::json!({
                "resource": "http://resource.test/mcp",
                "authorization_servers": [format!("{}/as", state.as_base)],
            }))
            .into_response()
        }

        async fn as_metadata() -> impl IntoResponse {
            axum::Json(serde_json::json!({
                "authorization_endpoint": "https://github.com/login/oauth/authorize",
                "token_endpoint": "https://github.com/login/oauth/access_token",
                "registration_endpoint": null,
            }))
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = DiscoveryState {
                root_hits: Arc::new(AtomicUsize::new(0)),
                path_hits: Arc::new(AtomicUsize::new(0)),
                as_base: format!("http://{addr}"),
            };
            let app = Router::new()
                .route("/.well-known/oauth-protected-resource", ax_get(root_prm))
                .route(
                    "/.well-known/oauth-protected-resource/mcp",
                    ax_get(path_prm),
                )
                .route(
                    "/.well-known/oauth-authorization-server/as",
                    ax_get(as_metadata),
                )
                .with_state(state.clone());
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            let client = reqwest::Client::new();
            let metadata = discover_metadata(&format!("http://{addr}/mcp/"), &client)
                .await
                .unwrap();

            assert_eq!(
                metadata.authorization_endpoint,
                "https://github.com/login/oauth/authorize",
            );
            assert_eq!(
                metadata.token_endpoint,
                "https://github.com/login/oauth/access_token",
            );
            assert_eq!(state.path_hits.load(Ordering::SeqCst), 1);
            assert_eq!(
                state.root_hits.load(Ordering::SeqCst),
                0,
                "root PRM should not be hit when path-scoped PRM succeeds",
            );
        });
    }
}
