# dyson-swarm

The orchestrator side of the Dyson stack. `dyson-swarm` hires, restores,
rotates, snapshots, and reaps `dyson` agents running inside Cube
sandboxes; serves the operator/user web UI; and brokers outbound LLM and
MCP traffic through swarm-managed proxy surfaces.

The agent itself lives in the sibling [dyson](https://github.com/JonCooperWorks/dyson) repo. The two
repos ship independently, which is why swarm owns persistent state,
rotation, and upgrade orchestration.

## Architecture

```mermaid
flowchart TB
    browser["Browser / SPA"] -->|"OIDC PKCE, session cookie, API keys"| swarm["dyson-swarm Axum server"]
    cli["swarmctl"] -->|"host ops, secrets, DB, KMS, mint"| swarm
    webhook_src["Webhook providers"] -->|"signed callbacks"| webhooks["/webhooks and channel webhooks"]
    share_users["Anonymous share readers"] -->|"signed share URLs"| share_host["share.<hostname>"]
    dyson_users["Users opening <instance>.<hostname>"] --> dyson_proxy["host-based Dyson proxy"]

    subgraph host_control["Host Control Plane"]
        swarm --> auth["Auth chain: opaque bearer, OIDC, admin-role gate"]
        swarm --> db[("SQLite or Postgres stores")]
        swarm --> keys["local age KMS keys"]
        swarm --> cache["snapshots, artefacts, state mirror"]
        swarm --> cube["CubeSandbox backend"]
        swarm --> llm_proxy["/llm provider proxy"]
        swarm --> mcp_proxy["/mcp proxy + OAuth"]
        swarm --> mcp_runtime["dyson-mcp-runtime"]
        swarm --> egress_proxy["dyson-egress-proxy<br/>network policy sync"]
        swarm --> telegram_proxy["Telegram proxy"]
        swarm --> reconfig["Dyson reconfiguration API"]
    end

    cube --> agent["dyson agent in sandbox"]
    dyson_proxy --> agent
    reconfig -->|/api/admin/configure| agent
    webhooks -->|"deliver task"| agent

    agent -->|"pt_ runtime token"| llm_proxy
    agent -->|"MCP bearer"| mcp_proxy
    agent -->|"HTTP_PROXY / HTTPS_PROXY"| egress_proxy
    agent -->|"it_ artefact ingest"| cache
    agent -->|"st_ state sync"| cache
    agent -->|"Telegram proxy calls"| telegram_proxy

    llm_proxy --> providers["LLM providers, BYO upstreams, OpenRouter user keys"]
    egress_proxy --> public_net["Allowed public or listed destinations"]
    mcp_proxy --> upstream_mcp["HTTP/SSE MCP upstreams"]
    mcp_proxy --> mcp_runtime
    mcp_runtime --> docker_mcp["Docker/stdio MCP servers"]
    telegram_proxy --> telegram_api["Telegram Bot API"]
    share_host --> cache
    share_host --> agent
    db <--> keys
```

```mermaid
sequenceDiagram
    participant User as Browser or API user
    participant Swarm as dyson-swarm
    participant Store as SQLite/Postgres, KMS keys, encrypted stores
    participant Cube as Cube sandbox
    participant Agent as dyson agent
    participant Upstream as LLM or MCP upstream

    User->>Swarm: Create or restore an instance
    Swarm->>Store: Persist metadata, MCP/user/system secrets, cache indexes
    Swarm->>Cube: Start or reconfigure disposable sandbox
    Cube->>Agent: Run dyson with swarm-issued runtime tokens
    Agent->>Swarm: Call LLM, MCP, ingest, and state-sync surfaces
    Swarm->>Store: Resolve policy, credentials, audit, and cached state
    Swarm->>Upstream: Forward allowed LLM or MCP requests
    Upstream-->>Swarm: Return provider response
    Swarm-->>Agent: Return scoped response without exposing upstream secrets
```

## Workspace Layout

`dyson-swarm` is a Rust workspace with five intentionally coarse crates:

| Crate | Binary/library | Responsibility |
|---|---|---|
| `crates/core` | `dyson_swarm_core` | Shared domain logic: config, stores, instances, snapshots, secrets, webhooks, shares, state mirror, and network policy resolution |
| `crates/swarm` | `swarm`, `dyson_swarm` | Main HTTP server, auth middleware, `/llm/*`, `/mcp/*`, host-based dispatch, and embedded SPA |
| `crates/cli` | `swarmctl` | Host-operator commands that touch the DB or call the server API |
| `crates/egress-proxy` | `dyson-egress-proxy` | Policy-aware HTTP/HTTPS sandbox egress proxy |
| `crates/mcp-runtime` | `dyson-mcp-runtime` | Local Unix-socket helper for Docker/stdio and runtime-managed MCP transports |

## Documentation

Swarm now has a dedicated docs tree, mirroring the structure used in
`dyson`:

- [Documentation Index](docs/README.md)
- [Architecture Overview](docs/architecture-overview.md)
- [Configuration](docs/configuration.md)
- [Auth and Keys](docs/auth-and-keys.md)
- [Controllers and Channels](docs/controllers.md)
- [Artefacts](docs/artefacts.md)
- [Shares](docs/shares.md)
- [Audit](docs/audit.md)
- [LLM Proxy](docs/llm-proxy.md)
- [Restore and Clone](docs/restore-and-clone.md)
- [MCP and OAuth](docs/mcp-and-oauth.md)
- [Network Policies](docs/network-policies.md)
- [State Ownership](docs/state-ownership.md)
- [Storage and Secrets](docs/storage-and-secrets.md)
- [Database Backends](docs/database-backends.md)
- [HTTP and SPA](docs/http-and-spa.md)
- [Operations](docs/operations.md)
- [Testing](docs/testing.md)

## Notes

- `rotate_binary_on_startup` defaults to false. Keep it off for normal
  deploys; enable it only for a deliberate binary migration of live instances.
  See [Operations](docs/operations.md).
- Public share URLs use a signed capability token. The share `jti` is only an
  authenticated API row id; using it as `/v1/<token>` correctly returns 404.
  See [Shares](docs/shares.md).
- The host-side `swarmctl mint-api-key` flow is a break-glass tenant access
  path, not an admin-role override; see [Auth and Keys](docs/auth-and-keys.md).
