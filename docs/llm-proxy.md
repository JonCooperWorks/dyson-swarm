# LLM Proxy

The LLM proxy is Swarm's app-layer outbound path for Dyson model calls. Dyson
instances call `/llm/<provider>/...` with a per-instance `pt_...` token; Swarm
resolves the instance, applies tenant policy, selects credentials, forwards the
request, streams the response, and writes audit rows.

Relevant code:

- [proxy/mod.rs](../crates/swarm/src/proxy/mod.rs)
- [proxy/http.rs](../crates/swarm/src/proxy/http.rs)
- [proxy/byok.rs](../crates/swarm/src/proxy/byok.rs)
- [policy.rs](../crates/core/src/policy.rs)

## Request Path

1. Dyson sends an API-shaped request to `SWARM_PROXY_URL`.
2. Swarm resolves the `pt_...` bearer to an instance.
3. Swarm loads the owner policy and usage snapshot.
4. The proxy buffers the inbound request body so policy and provider-specific
   body rewrites can run before any upstream traffic leaves the host.
5. Swarm chooses a key source and rewrites auth for the selected provider.
6. The upstream response body is streamed back to Dyson.
7. `llm_audit` is written before streaming starts and marked complete after
   the upstream body finishes.

## Key Resolution

The resolver fails closed when no allowed key source exists. Depending on
provider and tenant policy, the usable sources are:

- user BYOK secret
- user-selected BYO upstream and key
- per-user OpenRouter key minted from the operator provisioning key
- configured platform key

OpenRouter is the provider with lazy per-user key minting today.

## Streaming Behaviour

LLM responses can be long-lived SSE streams. The proxy therefore uses a
dedicated 15-minute HTTP timeout for LLM upstream calls, including validated BYO
upstreams. Other internal HTTP clients keep their shorter default timeout.

The proxy also forces upstream `Accept-Encoding: identity`. `reqwest`
auto-decodes compressed response bodies; allowing tenant compression
preferences through to upstream SSE providers can produce stale encoding
headers or decoder failures on long streams. The response path strips
`content-length` because streamed bodies are not length-stable after proxying.

If the upstream connection fails before a response body exists, the client gets
`502 upstream request failed` without the upstream URL or credential-bearing
details. If a body fails mid-stream, the audit row remains incomplete and logs
identify the stream failure.

## Policy Enforcement

The proxy enforces:

- allowed provider and model lists
- daily token budgets
- monthly USD budget placeholder gate
- request-per-second limits
- BYO upstream operator policy

Budgeting is owner-scoped rather than instance-scoped, so restores, clones, and
rotations keep rolling up to the same user.

## Auditing

Audit rows track:

- owner and instance
- provider and model
- prompt/output token counts when known
- upstream status
- key source (`platform`, `byok`, `or_minted`, or BYO)
- whether the response stream completed

Rows are inserted before the response body is fully consumed so a crash or
client disconnect still leaves forensic evidence.

## Relationship To The Egress Proxy

The egress proxy enforces network policy at the destination layer. The LLM
proxy enforces application policy: credentials, provider/model allowlists,
budgets, provider-specific request shaping, and audit.
