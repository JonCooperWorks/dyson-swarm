use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::mcp_servers::McpServerSpec;
use crate::network_policy::{self, NetworkPolicy};
use crate::traits::InstanceRow;

#[derive(Debug, Clone)]
pub struct DeletedMcpServer {
    pub owner_id: String,
    pub instance_id: String,
    pub name: String,
    pub runtime: Option<crate::mcp_servers::McpRuntimeSpec>,
}

#[derive(Debug, Clone)]
pub(super) struct RuntimeTokens {
    pub(super) proxy: String,
    pub(super) ingest: String,
    pub(super) state_sync: String,
    pub(super) state_generation: String,
}

#[derive(Debug, Clone)]
pub(super) struct InPlaceSwapPlan {
    pub(super) source: InstanceRow,
    pub(super) old_sandbox_id: String,
    pub(super) target_template_id: String,
    pub(super) target_policy: NetworkPolicy,
    pub(super) resolved_policy: network_policy::ResolvedPolicy,
    pub(super) target_state_generation: String,
}

/// Body sent to dyson's `/api/admin/configure`.  Mirrors the dyson
/// side's `ConfigureBody` — the two structs are intentionally
/// duplicated rather than shared because swarm + dyson are two
/// separate crates and a shared crate just for this would be
/// significant churn for a 4-field struct.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ReconfigureBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_doc: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// The per-instance proxy_token swarm minted at create-time.
    /// Becomes the value of `providers.<agent.provider>.api_key` in
    /// the running dyson's `dyson.json` — the agent uses this as its
    /// bearer when calling swarm's `/llm/...` endpoints.  Without
    /// this push the api_key stays at the boot-time `warmup-placeholder`
    /// (cube's snapshot/restore freezes `/proc/self/environ`, so the
    /// `SWARM_PROXY_TOKEN` swarm injects on create never reaches
    /// the dyson process — same root cause as the missing `models`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_token: Option<String>,
    /// The /llm proxy URL (`https://<hostname>/llm`).  Patched into
    /// `providers.<agent.provider>.base_url` so the dyson's api client
    /// hits Caddy → swarm instead of the loopback URL frozen at
    /// warmup.  Skipped when None (swarm runs without a hostname).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_base: Option<String>,
    /// Name to register the image-generation provider under.  Mirrors
    /// `ConfigureBody::image_provider_name` on the dyson side.  When
    /// set alongside `image_provider_block` the dyson handler inserts
    /// (or replaces) `providers.<image_provider_name>` in dyson.json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_provider_name: Option<String>,
    /// Full provider entry for the image-generation provider — the
    /// JSON body that lands at `providers.<image_provider_name>`.
    /// Same shape as the chat provider entry: `{ type, base_url,
    /// api_key, models }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_provider_block: Option<serde_json::Value>,
    /// Sets `agent.image_generation_provider`.  Usually equal to
    /// `image_provider_name`, but kept independent so a future caller
    /// could point the field at an already-registered provider
    /// without re-uploading its block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_generation_provider: Option<String>,
    /// Sets `agent.image_generation_model`.  Lets swarm bump the
    /// image-gen model id (e.g. preview → ga rename) without forcing
    /// every operator to re-hire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_generation_model: Option<String>,
    /// Reset `skills` to the loader's defaults (every builtin tool
    /// registered).  Older swarm boots wrote
    /// `skills.builtin.tools = []`, which the dyson loader parses as
    /// "register zero builtin tools".  Setting this flag on a sweep
    /// flips toolless instances back to the full toolbox without a
    /// re-hire.  False on every body that doesn't explicitly want
    /// the reset (rename / models-only updates leave skills alone).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reset_skills: bool,
    /// Explicit builtin-tool allowlist.  When `Some`, dyson rewrites
    /// `skills.builtin.tools` to exactly this list.  Empty vec is
    /// meaningful (register zero builtins).  Distinct from
    /// `reset_skills`, which drops the block to inherit defaults.
    /// `tools` wins on the dyson side when both are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Per-server stanzas to write under `mcp_servers.<name>` in
    /// dyson.json.  Each value is the swarm-proxied entry the agent
    /// should talk to: `{ url, headers: { Authorization: "Bearer ..." } }`.
    /// `None` (the default) leaves any existing `mcp_servers` block
    /// untouched; an empty map clears it.  See [`mcp_servers::dyson_json_block`]
    /// for the canonical shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<serde_json::Map<String, serde_json::Value>>,
    /// Full URL the dyson agent's `Output::send_artefact` POSTs to.
    /// Mirrors `SWARM_INGEST_URL` in the env envelope; pushed via
    /// `/api/admin/configure` because the cube's snapshot/restore
    /// freezes `/proc/self/environ` at warmup time, same root cause
    /// as `proxy_token` / `proxy_base` already need a configure-push.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_url: Option<String>,
    /// Per-instance `it_<32hex>` bearer for the ingest endpoint.
    /// Mirrors `SWARM_INGEST_TOKEN` in the env envelope.  None on a
    /// configure-push for an instance that pre-dates the ingest token
    /// (legacy rows: dyson skips the push if the token is unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_token: Option<String>,
    /// Full URL the swarm-mode dyson's state mirror worker POSTs to.
    /// Mirrors `SWARM_STATE_SYNC_URL`; pushed for the same warmup-env
    /// freeze reason as `ingest_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_url: Option<String>,
    /// Per-instance `st_<32hex>` bearer for the state-file endpoint.
    /// Mirrors `SWARM_STATE_SYNC_TOKEN`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreStateFileBody {
    pub namespace: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallSkillBody {
    pub marketplace: String,
    pub skill: String,
    pub force: bool,
    pub package: crate::skill_marketplace::SkillPackageBody,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstallSkillResponse {
    pub installed: bool,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UninstallSkillResponse {
    pub uninstalled: bool,
    pub skill: String,
}

/// Image-generation defaults a swarm-managed dyson should run with.
/// Pushed at `create()` time and re-pushed by the startup runtime
/// config sync so existing instances inherit changes after a swarm
/// redeploy without operator intervention.
///
/// `provider_block` is whatever JSON shape dyson's loader expects for
/// a provider entry; today that's `{ "type", "base_url", "api_key",
/// "models" }`.  The orchestrator templates it with the swarm's
/// `/llm/openrouter` proxy URL and the per-instance proxy_token at
/// the call site so the running dyson can use the same swarm hop the
/// chat path uses.
#[derive(Debug, Clone)]
pub struct ImageGenDefaults {
    pub provider_name: String,
    pub provider_type: String,
    pub model: String,
}

impl ImageGenDefaults {
    /// Default wiring: a second OpenRouter provider entry pointed at
    /// the same `/llm/openrouter` swarm proxy as chat, defaulting to
    /// the Gemini 3 image preview.  Centralised here (and mirrored in
    /// the `dyson swarm` boot writer) so a future bump is a one-line
    /// constant change in two known files.
    pub fn openrouter_gemini3_image() -> Self {
        Self {
            provider_name: "openrouter-image".to_owned(),
            provider_type: "openrouter".to_owned(),
            model: "google/gemini-3-pro-image-preview".to_owned(),
        }
    }

    /// Render the provider block dyson.json expects.  `proxy_base`
    /// already includes the `/openrouter` segment (built by
    /// [`InstanceService::image_proxy_base`]) and `api_key` is the
    /// per-instance proxy_token.  Both pieces are required — without
    /// the swarm hop the dyson would talk to upstream OpenRouter
    /// directly with a token OpenRouter doesn't recognise.
    pub fn provider_block(&self, proxy_base: &str, api_key: &str) -> serde_json::Value {
        serde_json::json!({
            "type": self.provider_type,
            "base_url": proxy_base,
            "api_key": api_key,
            "models": [self.model],
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateRequest {
    pub template_id: String,
    /// Human-readable label for the employee. Optional — defaults to the
    /// short id when unset. Surfaced as `SWARM_NAME` in the sandbox env.
    #[serde(default)]
    pub name: Option<String>,
    /// Free-text task / mission. Optional but strongly recommended;
    /// surfaced as `SWARM_TASK` so the agent reads its job description
    /// at boot.
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    /// Per-instance egress profile.  Default `Open` matches the
    /// pre-feature wire shape — existing callers don't need to change.
    /// See [`crate::network_policy`] for the four profiles.
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    /// Optional MCP servers attached to the dyson at hire time.
    /// Each entry's URL + auth is sealed under the owner's cipher in
    /// `user_secrets`; the agent only ever sees the swarm proxy URL.
    /// Empty (the default) keeps the existing wire shape.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RestoreRequest {
    pub template_id: String,
    /// Path on the Cube host where the snapshot bundle currently lives.
    pub snapshot_path: std::path::PathBuf,
    /// If present, this instance's secrets are copied to the new instance.
    pub source_instance_id: Option<String>,
    /// Carry-over identity. Populated by `SnapshotService::restore` from
    /// the source instance row so the restored employee keeps its name.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    /// Per-instance egress profile, carried from the source row by
    /// `SnapshotService::restore` and the binary-rotation sweep.  A
    /// raw HTTP `POST /v1/instances/:id/restore` from a CLI with no
    /// policy specified gets `NoLocalNet` (the post-A1 default that
    /// blocks RFC1918 / link-local / cloud-metadata egress).
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    /// Model id list, carried from the source row by
    /// `SnapshotService::restore` and the binary-rotation sweep so
    /// the restored employee keeps its model selection.  Empty when
    /// the source row predates the column or a raw HTTP restore
    /// caller didn't supply one — the SPA edit form treats empty as
    /// "user must pick before saving".
    #[serde(default)]
    pub models: Vec<String>,
    /// Positive include list of built-in tools — same carry-over
    /// semantics as `models`.  Empty means "use dyson defaults".
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedInstance {
    pub id: String,
    pub url: String,
    pub bearer_token: String,
    pub proxy_token: String,
}

/// Per-sweep tally returned by [`InstanceService::rotate_binary_all`].
/// `visited` counts every Live-but-outdated instance the sweep
/// considered (whether or not it succeeded); `rotated` counts the
/// ones that reached destroyed-source-and-Live-successor; `failed`
/// preserves a per-row error so an operator can pick up stragglers
/// without grepping logs.  The error string is whatever the failing
/// step returned — kept opaque on purpose so this struct doesn't
/// pin the rotation pipeline to a specific error taxonomy.
#[derive(Debug, Clone, Default)]
pub struct RotateReport {
    pub visited: usize,
    pub rotated: usize,
    pub failed: Vec<(String, String)>,
}
