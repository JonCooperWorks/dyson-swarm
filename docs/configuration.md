# Configuration

Swarm reads a single TOML file, typically
`/etc/dyson-swarm/config.toml`. The example file in the repo is
[config.example.toml](../config.example.toml).

At startup, selected `SWARM_*` environment variables override the TOML. Common
overrides include `SWARM_BIND`, `SWARM_DB_PATH`, `SWARM_DATABASE_BACKEND`,
`SWARM_DATABASE_URL`, `SWARM_KEYS_DIR`, `SWARM_HOSTNAME`, `SWARM_CUBE_URL`,
`SWARM_CUBE_API_KEY`, `SWARM_CUBE_SANDBOX_DOMAIN`,
`SWARM_NETWORK_ALLOW_INTERNAL_NETWORK_POLICY`, `SWARM_BYO_*`,
`SWARM_BACKUP_LOCAL_CACHE_DIR`, `SWARM_BACKUP_S3_*`, and
`SWARM_PROVIDERS_<NAME>_API_KEY` /
`SWARM_PROVIDERS_<NAME>_UPSTREAM` for provider stanzas already declared in
TOML.

## Required Basics

- `bind`: host:port for the Axum server
- `database_backend`: `sqlite` by default; set to `postgres` for the Postgres stores
- `db_path`: SQLite database path when `database_backend = "sqlite"`
- `database_url`: required Postgres URL when `database_backend = "postgres"`
- `keys_dir`: optional local age KMS key directory; defaults to a `keys/`
  sibling of `db_path`
- `[cube]`: Cube API URL, API key, and sandbox domain
- `[backup]`: backup sink selection and local cache directory

## Important Optional Fields

### `health_probe_interval_seconds` / `health_probe_timeout_seconds`

Control the background instance health probe cadence. Defaults are 60 seconds
between probes and a 5 second probe timeout.

### `hostname`

Public apex hostname, for example `swarm.example.com`.

When set:

- each Dyson is reachable at `<instance_id>.<hostname>`
- the SPA's `open` link points there
- share pages live on `share.<hostname>`
- MCP OAuth can build public callback URLs

When unset:

- the REST API and SPA still work
- host-based per-Dyson browsing is disabled
- MCP OAuth start will fail with a clear message because no callback URL can be built

### `cube_facing_addr`

Host address the sandbox should use to reach swarm’s `/llm` proxy, usually
something like `192.168.0.1:8080`.

This is separate from `hostname` because the sandbox may not be able to hairpin
through the host’s public address cleanly.

### `default_template_id`

Default Cube template id for new hires and the reference point for startup
binary rotation.

### `default_models`

Suggested model ids returned by `/auth/config` for the SPA hire form. The
first model is pre-selected. An empty list leaves the model field free-form.

### `cube_profiles`

Named Cube-template choices surfaced to the SPA. These are operator UX
metadata around pre-registered templates.

### `rotate_binary_on_startup`

Opt-in startup binary rotation for live instances whose Cube template differs
from `default_template_id`. It defaults to false and should stay off for normal
deploys; enable it only for a deliberate binary migration.

## Auth Configuration

### `[oidc]`

Controls backend JWT verification and the SPA browser login flow.

- `issuer`
- `audience`
- optional `jwks_url`
- `jwks_ttl_seconds`
- optional `spa_client_id`
- optional `spa_scopes`
- optional `[oidc.roles]` block for admin-role gating

If `[oidc]` is omitted, swarm can still be used through opaque user API keys,
but browser login and admin-role-based access are unavailable.

`--dangerous-no-auth` bypasses the `/v1/*` auth checks only when
`SWARM_DEV_MODE=1` or `SWARM_DANGEROUS_NO_AUTH_OK=1` is also set. In that
mode, responses include `X-Swarm-Insecure`; do not run it outside a trusted
development network.

## Provider Configuration

`[providers.<name>]` configures upstream LLM providers. In production, the
recommended source of truth for `api_key` is `system_secrets` using the name:

`provider.<name>.api_key`

The TOML value remains as a fallback for local development or unmigrated hosts.

## MCP Runtime

`[mcp_runtime]` enables the optional `dyson-mcp-runtime` Unix-socket helper for
Docker/stdio MCP servers and runtime-managed streamable HTTP sessions.

Fields:

- `socket_path`: Unix socket path, usually `/run/dyson-mcp-runtime/runtime.sock`
- `runtime`: Docker runtime; currently only `runsc` is accepted
- `allow_user_docker_json`: whether users may paste arbitrary Docker stdio MCP
  JSON. Keep this false on public nodes.
- `[[mcp_runtime.docker_catalog]]`: operator-curated Docker MCP templates with
  placeholder fields rendered server-side.

## OpenRouter Provisioning

`[openrouter]` is optional. When configured, swarm can lazily mint a
per-user OpenRouter key on first use instead of sending all users through one
shared global OpenRouter key.

Recommended secret source:

`openrouter.provisioning_key`

set via:

```sh
swarmctl secrets system-set --stdin openrouter.provisioning_key
```

## BYO Upstreams

`[byo]` controls whether users may point a provider at their own
OpenAI-compatible upstream.

- `enabled`
- `allow_localhost`
- `allow_internal`

`allow_localhost = true` is a narrow opt-in for loopback-only targets such as
`localhost`, `127.0.0.1`, or `::1`. It does not open the broader private/LAN
address space.

`allow_internal = true` is an explicit operator opt-in and expands the SSRF
surface by design. Use it only when private-fabric targets are an intended
feature.

## Backups

`[backup]` selects the sink:

- `local`
- `s3`

`[backup.s3]` can be populated inline, but the long-term preferred posture is
to keep credentials in `system_secrets` instead of plaintext TOML.
