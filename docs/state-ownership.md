# State Ownership

Swarm is the source of truth for durable, user-visible state. A running Dyson
sandbox keeps local files only as a hot working cache so turns can run quickly
and so existing Dyson internals can keep using filesystem-backed workspace and
chat stores.

When a sandbox is rebuilt, reset, or rotated, swarm uses the available cube
snapshot as the replacement VM's base and then replays durable mirrored state
over it before enabling the state-sync worker again. The snapshot base preserves
local workspace files that are outside the mirror or have not synced yet; the
mirror still wins for paths it has recorded.

Clone and restore follow the same rule. A full clone starts from a Cube
snapshot and also copies Swarm-owned config, secrets, policy, tools, and MCP
records to a fresh instance id. An empty clone skips the snapshot and therefore
only carries Swarm-owned state.

## Ownership Matrix

| State | Authoritative store | VM copy | Notes |
|---|---|---|---|
| Instance identity, task, models, tools, template, network policy, TTL, pinned state | `instances` row in swarm DB | Generated into env and patched into `dyson.json` | The VM's `dyson.json` is generated runtime cache, not source of truth. |
| Provider keys, OpenRouter provisioning, host/operator credentials | `system_secrets` | Not injected as plaintext config | TOML may carry local-dev fallbacks, but production values live in encrypted system secrets. |
| User-owned MCP upstreams, OAuth tokens, BYOK values, webhook secrets | `user_secrets` | Dyson sees only swarm proxy URLs and per-instance bearers | Upstream URLs and real credentials stay on swarm. |
| Agent-visible instance credentials | `agent_secrets` | Dyson can access them only through the Swarm-backed `agent_secrets` built-in tool | Preserved by same-id reset/recreate/rotation, deleted with the instance, and not copied by clone by default. |
| Per-instance proxy, ingest, and state-sync tokens | `proxy_tokens` | Token value is delivered in the env/config envelope | Token rows are revoked with the instance. |
| Workspace identity and memory | `instance_state_files` namespace `workspace` | `/var/lib/dyson/workspace` hot cache | Mirrored durable paths: top-level Markdown, `memory/*.md`, `kb/**`, `skills/**`, and public-channel memory/audit files. |
| Public-channel workspace memory and audit | `instance_state_files` namespace `workspace` under `channels/<id>/...` | `/var/lib/dyson/workspace/channels/<id>` hot cache | Durable files are channel Markdown, `memory/*.md`, and `_audit.jsonl`; generated indexes are disposable. |
| Chat transcripts, archives, media, files, feedback, activity, chat artefact copies | `instance_state_files` namespace `chats` | `/var/lib/dyson/chats` hot cache | Clean non-hidden chat paths are mirrored. Zero-byte transcripts are rejected. |
| Artefact cache and public shares | Swarm artefact tables with sealed body bytes | Optional chat-local artefact copies | Shares read from swarm's cache and survive sandbox reset. |
| Skill inventory | Derived from mirrored `workspace/skills/**` state files | Workspace skill files | Swarm inventory is a read model over mirrored files. Agent-authored skills are private unless an `agent_skill_publications` row explicitly publishes them. |
| `dyson.json` inside the sandbox | Swarm DB/secrets rendered through `/api/admin/configure` | `/var/lib/dyson/dyson.json` generated cache | Never mirror this file as workspace state. Runtime edits that matter must write swarm first or be reflected back through a swarm API path. |
| Workspace `.workspace_version`, `memory.db`, logs, temp audio, configure hash, generated indexes | VM disk | VM disk only | These are rebuildable, local-only, or sensitive implementation details. |
| Cube snapshots | Backup/transition artefact | N/A | Used as the base for migrations and recovery; mirrored swarm state is replayed over the snapshot for paths swarm tracks. |
| Swarm host config | `/etc/dyson-swarm/config.toml` plus encrypted secrets | N/A | Host operational config is outside the agent VM. Production secrets should be in `system_secrets`. |

## Rules

1. A file or setting is durable only if it is in the matrix above with a swarm
   authoritative store.
2. The state-file ingest endpoint must enforce the same allowlist as the Dyson
   state-sync worker; a compromised or buggy VM must not be able to upload
   `dyson.json`, `.env`, indexes, or other local-only files into swarm state.
3. Runtime config changes must update swarm DB/secrets. Patching the VM's
   generated `dyson.json` is only the delivery mechanism to the running
   process.
4. Reset, redeploy, and rotation flows replay mirrored files before enabling
   state sync so an empty fresh VM cannot tombstone durable swarm state.
