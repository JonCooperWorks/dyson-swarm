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
flowchart LR
    browser["Browser / operator SPA"] -->|"OIDC or user API key"| swarm["dyson-swarm HTTP server"]
    cli["swarmctl"] -->|"host ops and recovery"| swarm
    webhooks["External webhook providers"] -->|"signed callbacks"| swarm
    shares["Public share readers"] -->|"signed share URLs"| swarm

    swarm --> db[("SQLite metadata")]
    swarm --> secrets["age-encrypted secrets"]
    swarm --> cache["Local cache"]
    swarm --> cube["Cube sandboxes"]

    cube --> agent["dyson agent runtime"]
    agent -->|"LLM proxy bearer"| llm["/llm proxy"]
    agent -->|"MCP proxy bearer"| mcp["/mcp proxy"]
    agent -->|"ingest and state tokens"| runtime["artefact ingest + state sync"]

    llm --> providers["LLM providers"]
    mcp --> upstream["Upstream MCP servers"]

    secrets -.->|"user scope"| mcp
    secrets -.->|"user and system key sources"| llm
    cache -.->|"snapshots, artefacts, state mirror"| swarm
```

```mermaid
sequenceDiagram
    participant User as Browser or API user
    participant Swarm as dyson-swarm
    participant Store as SQLite and encrypted stores
    participant Cube as Cube sandbox
    participant Agent as dyson agent
    participant Upstream as LLM or MCP upstream

    User->>Swarm: Create or restore an instance
    Swarm->>Store: Persist metadata, sealed secrets, cache indexes
    Swarm->>Cube: Start or reconfigure disposable sandbox
    Cube->>Agent: Run dyson with swarm-issued runtime tokens
    Agent->>Swarm: Call LLM, MCP, ingest, and state-sync surfaces
    Swarm->>Store: Resolve policy, credentials, audit, and cached state
    Swarm->>Upstream: Forward allowed LLM or MCP requests
    Upstream-->>Swarm: Return provider response
    Swarm-->>Agent: Return scoped response without exposing upstream secrets
```

## Workspace Layout

`dyson-swarm` is a Rust workspace with four intentionally coarse crates:

| Crate | Binary/library | Responsibility |
|---|---|---|
| `crates/core` | `dyson_swarm_core` | Shared domain logic: config, stores, instances, snapshots, secrets, webhooks, shares, state mirror, and network policy resolution |
| `crates/swarm` | `swarm`, `dyson_swarm` | Main HTTP server, auth middleware, `/llm/*`, `/mcp/*`, host-based dispatch, and embedded SPA |
| `crates/cli` | `swarmctl` | Host-operator commands that touch the DB or call the server API |
| `crates/egress-proxy` | `dyson-egress-proxy` | Policy-aware HTTP/HTTPS sandbox egress proxy |

## Documentation

Swarm now has a dedicated docs tree, mirroring the structure used in
`dyson`:

- [Documentation Index](docs/README.md)
- [Architecture Overview](docs/architecture-overview.md)
- [Configuration](docs/configuration.md)
- [Auth and Keys](docs/auth-and-keys.md)
- [Artefacts](docs/artefacts.md)
- [Shares](docs/shares.md)
- [LLM Proxy](docs/llm-proxy.md)
- [MCP and OAuth](docs/mcp-and-oauth.md)
- [Network Policies](docs/network-policies.md)
- [Storage and Secrets](docs/storage-and-secrets.md)
- [HTTP and SPA](docs/http-and-spa.md)
- [Operations](docs/operations.md)
- [Testing](docs/testing.md)

## Notes

- `rotate_binary_on_startup` is kept only for backwards compatibility.
  Current swarm treats startup binary rotation as an always-on operational
  behaviour; see [Operations](docs/operations.md).
- The host-side `swarmctl mint-api-key` flow is a break-glass tenant access
  path, not an admin-role override; see [Auth and Keys](docs/auth-and-keys.md).
