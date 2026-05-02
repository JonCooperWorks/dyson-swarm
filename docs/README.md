# Dyson Swarm Documentation

Technical documentation for `dyson-swarm`, the orchestrator side of the
Dyson stack. Start with the architecture overview, then read outward:
configuration and auth explain how a deployment is wired, the proxy docs
cover the two hot paths (`/llm/*` and `/mcp/*`), network policy explains
what a hired sandbox can reach, and operations/testing cover how to run
and evolve the system safely.

The agent itself lives in the sibling [dyson](https://github.com/JonCooperWorks/dyson) repo. Swarm is
the host-side control plane: it hires and restores agents, enforces auth,
stores encrypted state, brokers LLM and MCP traffic, and serves the web UI.

| Document | Covers |
|----------|--------|
| [Architecture Overview](architecture-overview.md) | Workspace layout, startup wiring, major services, request/data flow |
| [Configuration](configuration.md) | `config.toml`, provider config, OIDC, OpenRouter provisioning, backups, cube profiles |
| [Auth and Keys](auth-and-keys.md) | OIDC, user API keys, proxy tokens, admin-role gate, host-side break-glass mint |
| [LLM Proxy](llm-proxy.md) | `/llm/*` request path, policy enforcement, BYOK, OpenRouter lazy mint, audit |
| [MCP and OAuth](mcp-and-oauth.md) | MCP server storage, proxying, OAuth start/callback, path-scoped discovery, operator expectations |
| [Network Policies](network-policies.md) | `nolocalnet`, `open`, `airgap`, `allowlist`, `denylist`, egress proxy behaviour |
| [Storage and Secrets](storage-and-secrets.md) | SQLite tables, artefact cache, state-file mirror, age envelope encryption, secret scopes |
| [HTTP and SPA](http-and-spa.md) | Route layout, host-based dispatch, embedded React app, per-surface auth |
| [Operations](operations.md) | Startup sweeps, binary rotation, health probes, TTL reaper, deploy posture, operator commands |
| [Testing](testing.md) | Unit/integration/live test layers, main integration suites, MinIO backup test |

## Source Map

The docs above map directly onto the main code seams:

```text
crates/
  core/          domain logic, stores, config, secrets, snapshots, webhooks, shares
  swarm/         HTTP server, auth, LLM proxy, MCP proxy, embedded SPA
  cli/           swarmctl host/operator commands
  egress-proxy/  policy-aware HTTP/HTTPS sandbox egress proxy
```

If you are landing a feature, try to update the relevant document in this
directory in the same PR. Swarm has enough moving parts now that the code
stays much easier to operate when the docs stay close to the seams above.
