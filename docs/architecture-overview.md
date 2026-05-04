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

The Rust workspace is intentionally split into four coarse crates:

| Crate | Responsibility |
|---|---|
| `crates/core` | Shared domain logic: config, stores, secrets, snapshots, webhooks, shares, state mirror, OpenRouter provisioning, network policy |
| `crates/swarm` | Main server binary, auth middleware, `/llm/*`, `/mcp/*`, REST routes, embedded web UI |
| `crates/cli` | `swarmctl` host/operator commands |
| `crates/egress-proxy` | Policy-aware HTTP/HTTPS proxy used by sandbox `HTTP_PROXY`/`HTTPS_PROXY` |

## Startup Wiring

At process start, `crates/swarm/src/main.rs` wires the system in roughly
this order:

1. load TOML config
2. open SQLite and cipher directories
3. construct stores/services (`users`, `instances`, `snapshots`, `shares`, `webhooks`, etc.)
4. overlay provider API keys from `system_secrets`
5. optionally construct the OpenRouter provisioning client and per-user key resolver
6. build the `/llm/*` proxy service
7. build the MCP proxy + MCP user-management routes
8. build the authenticator chain (opaque bearer first, OIDC second when configured)
9. start background loops:
   - instance health probing
   - TTL reaping
   - startup binary rotation / config rewiring sweeps
10. assemble the Axum router and serve

## Core Data Flows

### Hire / restore

- `InstanceService` inserts or updates the instance row
- swarm mints per-instance proxy tokens (`pt_...`, `it_...`, `st_...`)
- swarm pushes the generated config into the Dyson sandbox
- the sandbox talks back to swarm for LLM, artefact ingest, and state sync

### LLM requests

- the agent sends requests to `SWARM_PROXY_URL`
- `/llm/*` authenticates the per-instance proxy token
- swarm enforces policy, picks the upstream key source, and forwards
- audit rows record the request, token counts, and key source

### MCP requests

- the agent sees only a swarm MCP URL, not the upstream URL or credentials
- swarm looks up the saved MCP server entry in encrypted user secrets
- for OAuth-backed servers, swarm refreshes tokens when needed
- `tools/list` results are cached for the SPA, while `tools/call` stays live

### Public share reads

- the operator mints a signed anonymous capability URL
- public reads hit `share.<hostname>`
- swarm validates the signature, consults its artefact cache first, then the live Dyson if needed

## Why Swarm Keeps State Outside the Sandbox

Sandboxes are disposable. To make that practical, swarm persists the parts
that need to survive rebuilds and restores:

- encrypted per-user secrets
- MCP credential entries in encrypted per-user secrets
- snapshots and backup metadata
- mirrored state files (`workspace`, `chats`)
- artefact cache
- share metadata and share-access audit rows
- LLM audit rows

That separation is what lets binary rotation, network-policy changes, and
restore flows rebuild the sandbox without losing the Dyson’s working state.
