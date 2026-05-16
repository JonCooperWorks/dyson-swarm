# Auth and Keys

Swarm uses several different credential types. They look similar from the
outside, but they protect different surfaces.

## Human / Browser Auth

When OIDC is configured:

- browser users authenticate with the IdP
- swarm validates JWTs against the issuer/JWKS
- admin access is decided by a configured role claim

Admin routes do **not** accept ordinary user API keys as a substitute for
OIDC role claims.

Relevant code:

- [oidc.rs](../crates/swarm/src/auth/oidc.rs)
- [admin.rs](../crates/swarm/src/auth/admin.rs)
- [auth_config.rs](../crates/swarm/src/http/auth_config.rs)

## User API Keys

Swarm can mint opaque user API keys (`dy_...`) for tenant-scoped API access.

These keys:

- authenticate to normal `/v1/*` tenant routes
- are stored sealed in `user_api_keys`
- are resolved by prefix lookup + constant-time comparison
- do **not** carry OIDC claims
- therefore do **not** unlock `/v1/admin/*`

Relevant code:

- [users.rs](../crates/core/src/db/sqlite/users.rs)
- [admin_users.rs](../crates/swarm/src/http/admin_users.rs)

## Break-Glass Host Mint

When no normal admin bearer or IdP path is reachable, the host operator can
mint a user API key directly on the machine:

```sh
sudo -u dyson-swarm env SWARM_MINT_API_KEY_OK=1 \
  /usr/local/bin/swarmctl mint-api-key --label "ops-foo" <users.id>
```

This is a deliberate escape hatch:

- it bypasses the HTTP admin API
- it touches the DB and age ciphers directly
- it prints plaintext once to stdout
- it is suitable for recovery/bootstrap, not normal day-to-day usage

It is best thought of as a tenant-access recovery path, not an admin-role
override.

## Per-Instance Proxy Tokens

Swarm also mints tokens for the sandbox itself:

- `pt_...` — LLM proxy bearer
- `it_...` — artefact ingest bearer
- `st_...` — state sync bearer

These are not human-facing credentials. They are stamped into the Dyson
environment and authenticate sandbox-to-swarm calls.

Relevant code:

- [tokens.rs](../crates/core/src/db/sqlite/tokens.rs)
- [instance.rs](../crates/core/src/instance.rs)

## Per-Instance Configure Secrets

Dyson runtime reconfiguration uses a separate per-instance secret stored in
`system_secrets` as `instance.<id>.configure`. Swarm sends it in the
`X-Swarm-Configure` header when calling Dyson's `/api/admin/configure` and
related admin routes. Dyson hashes the first accepted value locally and verifies
later pushes against that hash.

This secret is not a human bearer and is not stamped into the sandbox
environment. It exists so cubeproxy reachability alone is not enough to change
a running Dyson's model, tools, MCP servers, state sync, or channel config.

## OpenRouter Minted Keys

When OpenRouter provisioning is enabled, swarm can mint a per-user upstream
OpenRouter key on first use. That key is distinct from swarm’s own user API
keys:

- it authenticates swarm to OpenRouter
- it is billed and capped per user
- it is stored in encrypted user secrets

Relevant code:

- [openrouter.rs](../crates/core/src/openrouter.rs)
- [byok.rs](../crates/swarm/src/http/byok.rs)

## Recommendations

- Use OIDC + admin-role claims for normal operator access
- Use user API keys for automation and non-browser tenant access
- Keep the host-side `mint-api-key` flow as a break-glass tool
- Avoid `--dangerous-no-auth` in production
