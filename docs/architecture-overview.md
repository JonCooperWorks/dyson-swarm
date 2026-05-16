# Architecture Overview

`dyson-swarm` is the host-side control plane for Dyson agents running in
Cube sandboxes. Its job is to:

- create, restore, rotate, and destroy sandboxed Dyson instances
- authenticate human callers and per-instance proxy traffic
- proxy outbound LLM and MCP traffic through policy-aware surfaces
- persist encrypted per-user and system secrets
- cache artefacts and mirrored state outside the sandbox lifetime
- serve the operator/user SPA and public share pages

## Workspace Layout

The Rust workspace is intentionally split into five coarse crates:

| Crate | Responsibility |
|---|---|
| `crates/core` | Shared domain logic: config, stores, secrets, snapshots, webhooks, shares, state mirror, OpenRouter provisioning, network policy |
| `crates/swarm` | Main server binary, auth middleware, `/llm/*`, `/mcp/*`, REST routes, embedded web UI |
| `crates/cli` | `swarmctl` host/operator commands |
| `crates/egress-proxy` | Policy-aware HTTP/HTTPS proxy used by sandbox `HTTP_PROXY`/`HTTPS_PROXY` |
| `crates/mcp-runtime` | Local Unix-socket helper for Docker/stdio MCP servers and runtime-managed streamable HTTP sessions |

## Startup Wiring

At process start, `crates/swarm/src/main.rs` wires the system in roughly
this order:

1. load TOML config and apply `SWARM_*` environment overrides
2. open the configured SQLite or Postgres stores and the local age KMS key directory
3. run database and KMS migrations for the active backend
4. construct stores/services (`users`, `instances`, `snapshots`, `shares`, `webhooks`, `channels`, `state_files`, skill marketplaces, etc.)
5. overlay provider API keys from `system_secrets`
6. optionally construct the OpenRouter provisioning client and per-user key resolver
7. build the Dyson reconfigurer used to push `/api/admin/configure` into live agents
8. build the `/llm/*` proxy service
9. build the MCP proxy, OAuth routes, Docker catalog, and optional `dyson-mcp-runtime` socket client
10. build the authenticator chain (opaque bearer first, OIDC second when configured)
11. wire the host egress-policy sync service used after sandbox ids or network policies change
12. start background loops:
   - instance health probing
   - TTL reaping
   - config rewiring sweeps
   - MCP runtime restart sweeps for configured servers
   - state mirror and artefact cache maintenance paths as traffic arrives
   - optional startup binary rotation when explicitly enabled
13. assemble the Axum router, host-based Dyson/share dispatchers, and embedded SPA

## Core Data Flows

### Hire / restore

- `InstanceService` inserts or updates the instance row
- swarm mints per-instance proxy tokens (`pt_...`, `it_...`, `st_...`)
- the row is `configuring` while swarm pushes generated config into Dyson
- the row becomes `live` only after the configure push succeeds
- the sandbox talks back to swarm for LLM, MCP, artefact ingest, state sync,
  Telegram proxying, and runtime webhook delivery
- broad public HTTP/S egress goes through the host `dyson-egress-proxy` only
  for policies that permit generic egress

The host proxy forwards normal user traffic only for `live` rows. `/healthz`
remains available during startup as a liveness check, but it is not a readiness
signal for chat turns.

### LLM requests

- the agent sends requests to `SWARM_PROXY_URL`
- `/llm/*` authenticates the per-instance proxy token
- swarm enforces policy, picks the upstream key source, and forwards
- audit rows record the request, token counts, and key source

### MCP requests

- the agent sees only a swarm MCP URL, not the upstream URL or credentials
- swarm looks up the saved MCP server entry in encrypted user secrets
- for OAuth-backed servers, swarm refreshes tokens when needed
- Docker/stdio servers go through the optional `dyson-mcp-runtime` Unix socket
- `tools/list` results are cached for the SPA, while `tools/call` stays live

### Channels and webhooks

- user-authenticated routes configure task webhooks and Telegram channels
- public webhook ingress verifies the configured secret before delivering a task
- Telegram channel ingress verifies the per-instance webhook token and allowed senders
- delivery rows stay in swarm so channel health survives sandbox replacement

### Public share reads

- the operator mints a signed anonymous capability URL
- public reads hit `share.<hostname>`
- swarm validates the signature, consults its artefact cache first, then the live Dyson if needed

### Restore and clone

- restore creates a fresh instance id from a selected snapshot
- full clone snapshots the source, restores under a fresh id, and copies Swarm-owned config/secrets/MCP records
- empty clone skips the snapshot and carries only Swarm-owned config/secrets/MCP records
- reset, rotate, and network-policy changes keep the same Swarm id while swapping the sandbox underneath

## Why Swarm Keeps State Outside the Sandbox

Sandboxes are disposable. To make that practical, swarm persists the parts
that need to survive rebuilds and restores:

- encrypted per-user secrets
- MCP credential entries in encrypted per-user secrets
- system secrets and local KMS key material
- snapshots and backup metadata
- mirrored state files (`workspace`, `chats`)
- artefact cache
- share metadata and share-access audit rows
- LLM audit rows
- MCP audit rows, KMS secret-access audit rows, and sealed LLM tool-call audit rows
- channel configuration and webhook delivery history

That separation is what lets binary rotation, network-policy changes, and
restore flows rebuild the sandbox without losing the Dyson’s working state.
