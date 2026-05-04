# MCP and OAuth

Swarm proxies MCP servers so the agent never sees upstream MCP credentials or
URLs directly.

## Stored Shape

Each MCP server definition is stored per instance in encrypted user secrets.
The saved entry contains:

- logical server name
- upstream URL
- auth mode (`none`, `bearer`, `oauth`)
- optional OAuth tokens
- optional cached tools catalogue
- optional enabled-tools allowlist
- optional Docker catalog binding for admin-curated stdio servers

Relevant code:

- [mcp_servers.rs](../crates/core/src/mcp_servers.rs)
- [proxy/mcp.rs](../crates/swarm/src/proxy/mcp.rs)

## Docker Catalog

Operators can curate Docker-backed stdio MCP servers in the admin UI. The rows
live in the `mcp_docker_catalog` table; `[[mcp_runtime.docker_catalog]]` entries
in `config.toml` seed config-managed rows at startup.

- `allow_user_docker_json = true` keeps the trusted-node path where users can
  paste one VS Code-style Docker MCP JSON object.
- `allow_user_docker_json = false` (the default) removes that free-form surface; users choose
  from `[[mcp_runtime.docker_catalog]]` presets instead.
- each catalog preset is still the same MCP JSON shape, but credential
  placeholders such as `{{credential.github_token}}` are rendered by swarm
  after the user fills declared credential fields.

The SPA shows the preset JSON as read-only and sends only the selected
`catalog_id` plus credential values. Rendered runtime config and credentials are
sealed into user secrets; the agent still receives only the swarm proxy URL.

## Proxy Surfaces

- `/mcp/:instance/:server/...` — agent-facing JSON-RPC pass-through, authenticated by per-instance bearer
- `/v1/instances/:id/mcp/...` — user-facing management routes inside the SPA/API
- `/mcp/oauth/callback` — public OAuth callback endpoint

## OAuth Flow

For OAuth-backed MCP servers:

1. the user presses `connect` in the SPA
2. swarm starts an Authorization Code + PKCE flow
3. the provider redirects back to `/mcp/oauth/callback`
4. swarm exchanges the code for tokens
5. tokens are sealed into the saved MCP entry
6. future MCP calls refresh the token when needed

## Discovery Behaviour

Swarm supports two protected-resource metadata shapes:

- root-scoped:
  `https://host/.well-known/oauth-protected-resource`
- path-scoped:
  `https://host/.well-known/oauth-protected-resource/<resource-path>`

Path-scoped discovery matters for servers like:

`https://api.githubcopilot.com/mcp/`

which publish metadata for the `/mcp` resource instead of the origin root.

## Dynamic Client Registration

If the provider publishes a registration endpoint, swarm can register a
client dynamically.

If it does not, the operator must provide a pre-registered `client_id`
(and typically `client_secret` too). That is why GitHub’s remote MCP
integration cannot be fully zero-config from swarm’s side today.

## Error Posture

The SPA now translates the common MCP OAuth failures into operator-friendly
messages, including:

- discovery failure
- missing pre-registered client id
- dynamic client registration failure
- invalid authorization endpoint
- refresh failure
- “saved but not authorised yet”

That translation lives in the MCP panel, while the raw server still returns
short machine-shaped errors.
