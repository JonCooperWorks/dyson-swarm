# dyson-swarm

The orchestrator side of the Dyson stack. `dyson-swarm` hires, restores,
rotates, snapshots, and reaps `dyson` agents running inside Cube
sandboxes; serves the operator/user web UI; and brokers outbound LLM and
MCP traffic through swarm-managed proxy surfaces.

The agent itself lives in the sibling [dyson](https://github.com/JonCooperWorks/dyson) repo. The two
repos ship independently, which is why swarm owns persistent state,
rotation, and upgrade orchestration.

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
