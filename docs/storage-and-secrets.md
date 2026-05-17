# Storage and Secrets

Swarm keeps long-lived state outside the sandbox so sandboxes can be rotated
and rebuilt safely.

For the full source-of-truth matrix, see [State Ownership](state-ownership.md).
For backend selection and SQLite/Postgres transfer, see
[Database Backends](database-backends.md).
For the forensic tables and server-side decrypted Activity view, see
[Audit](audit.md).

## Main Persistence Layers

### Database

The selected database backend, SQLite or Postgres, holds metadata and indexes:

- users
- instances
- user API keys
- proxy tokens
- snapshots
- user policies
- webhooks and webhook deliveries
- share rows and share-access audit
- artefact cache metadata and sealed body bytes
- mirrored state-file metadata
- LLM audit rows
- MCP audit rows
- sealed LLM tool-call audit rows

### Local filesystem cache

The backup/local cache directory holds:

- snapshot bundles
- mirrored state-file bodies

Bodies are encrypted before disk where the service expects secrecy.

## Local KMS v2

Swarm uses the local `age` backend as its default and only KMS backend. New
writes use a versioned JSON envelope around an age ciphertext:

```json
{
  "v": 2,
  "alg": "local-age-x25519",
  "scope": "user_secret",
  "owner_id": "00000000000000000000000000000000",
  "instance_id": "example-agent-000",
  "name": "mcp.github",
  "key_id": "users/00000000000000000000000000000000/mcp",
  "key_version": 1,
  "created_at": 1778880000,
  "ciphertext": "-----BEGIN AGE ENCRYPTED FILE-----..."
}
```

Because age does not expose AEAD associated data, the plaintext sealed inside
the age payload is also structured:

```json
{
  "context": {
    "scope": "user_secret",
    "owner_id": "00000000000000000000000000000000",
    "instance_id": "example-agent-000",
    "name": "mcp.github"
  },
  "secret_b64": "..."
}
```

Every decrypt builds the expected row context and verifies that the outer
envelope and embedded plaintext context match exactly. A mismatch fails closed
and returns no plaintext.

Legacy age-armored rows remain readable so old data can be migrated. On a
successful legacy or stale-version read, supported service paths lazily rewrap
the row into the v2 envelope under the active scoped key.

KMS open/seal call sites carry a typed access reason. Current reasons include
LLM provider proxying, MCP proxy forwarding, MCP OAuth refresh, runtime
configure pushes, system-secret bootstrap, operator CLI, state replay, artefact
reads, migration, and tests.

## Secret Scopes

Swarm uses age envelope encryption for user-owned and operator-owned
credential material. Raw credentials are not injected into the sandbox
environment as per-instance secrets; external tool/service credentials should
be attached through MCP so swarm can proxy and refresh them without exposing
the upstream secret to the agent.

### Agent secrets

Agent secrets are instance-scoped credentials intentionally visible to the
owning agent through Dyson's `agent_secrets` built-in tool. They are not human
vault secrets and are not implemented as MCP. Swarm stores the encrypted value
in `agent_secrets` under `(owner_user_id, instance_id, name)` and exposes
metadata without decrypting values. User API/UI reveal and agent tool `get`
are the only routes that return plaintext values.

Same-id recreate, reset, and template rotation preserve agent secrets because
the Swarm instance id stays stable. Snapshot restore and clone create a fresh
instance id and do not copy agent secrets by default. Destroying an instance
deletes its agent secrets with the instance cleanup.

### Per-user secrets

Encrypted under the user’s own age key:

- MCP server entries
- user BYOK values
- OpenRouter minted per-user keys
- any other user-owned sensitive blobs

### System secrets

Encrypted under the host/system age key:

- provider API keys
- OpenRouter provisioning key
- other host-operator credentials

### Scope-separated key layout

Existing key files are treated as legacy version 1 compatibility keys:

- `keys/system.age`
- `keys/<user_id>.age`

KMS v2 uses deterministic scope key ids below `keys/`, with one active version
file per scope. Version 1 scoped key material is stored as `v1.age`; the active
version is selected by an `active` file next to it and defaults to `1` when the
file is absent.

Representative scoped paths:

- `keys/system/provider/v1.age` for provider/API keys and host credentials
- `keys/system/configure/v1.age` for `/api/admin/configure` secrets
- `keys/users/<user_id>/mcp/v1.age` for MCP and user secret rows
- `keys/users/<user_id>/api_keys/v1.age` for user API keys
- `keys/users/<user_id>/state/v1.age` for mirrored state-file bodies
- `keys/users/<user_id>/artefact/v1.age` for cached artefact bodies
- `keys/users/<user_id>/tool_calls/v1.age` for sealed LLM tool-call audit
- `keys/users/<user_id>/agent_secret/v1.age` for agent-visible instance secrets

This layout provides cryptographic separation by scope. Logical names are still
stored in plaintext where the surrounding table already stores them; KMS v2 does
not hash secret names.

## Secret Access Audit

The `secret_access_audit` table records audited local KMS operations for runtime
and maintenance paths. Events include timestamp, actor kind/id, reason,
operation, scope, owner/instance ids, existing plaintext logical secret names
where already present, key id/version, result, and a redacted error
class/message.

Plaintext secret values are never written to this table.

Owner attribution comes from the KMS context. User-scoped secrets use the user
owner in that context. Runtime proxy tokens are instance-scoped, so new
`runtime_token` audit rows use the matching `instances.owner_id` when the token
belongs to an instance. Migration `0050_secret_access_audit_owner_backfill`
backfills older audit rows from `instances.owner_id` when `instance_id` still
matches a current instance, and leaves system-only rows without an instance
unchanged.

Existing ciphertext compatibility is preserved. Older runtime-token envelopes
sealed with no owner in the KMS context can still be opened; successful legacy
opens are lazily rewrapped with owner-aware context so later audit rows have
complete owner attribution.

See [Audit](audit.md#kms-secret-access-audit) for the admin API and operator
verification queries.

## Sealed Mode

Set `SWARM_KMS_SEALED=1` or `DYSON_SWARM_KMS_SEALED=1` to start with local KMS
operations disabled. Swarm will skip startup secret data migrations and any
secret open/seal attempt returns a clear sealed-mode error.

This is a startup gate, not a live lock/unlock service. Runtime traffic that
needs provider keys, MCP credentials, state replay, artefact reads, or
configure secrets will fail until the process is restarted without sealed mode.

### Legacy per-instance secrets

Older databases may have had an `instance_secrets` table. New migrations drop
that table, and no supported code path reads from or writes to it. Credential
guidance is now:

- use MCP for external tools and service credentials
- use `user_secrets` for user-owned platform credentials
- use `system_secrets` for host/operator credentials

## Why the DB Does Not Store Plaintext Tokens

User API keys and proxy tokens are stored sealed or hashed/selectable in ways
that avoid plaintext-at-rest:

- user API keys: sealed ciphertext + lookup prefix
- proxy tokens: sealed token + SHA-256 lookup key

That keeps the DB useful for lookup and revocation without turning it into a
plaintext secret dump.

## Artefact Cache and State Mirror

Two swarm-side stores matter operationally:

- artefact cache: keeps shared/UI-visible artefacts available even when the
  sandbox has been rebuilt
- state-file mirror: keeps selected workspace/chat state available for restore
  and rotation flows

These are what let rotation and restore preserve useful state while still
treating the sandbox itself as disposable.

## Agent Skill Publication

Skills learned or authored inside an agent are mirrored as normal workspace
state under `instance_state_files`, but they are private by default. They can
contain operator notes, environment details, or credential hints.

The public marketplace projection is gated by `agent_skill_publications`.
Publishing records only the instance id, owner id, skill name, actor, and
timestamp; the skill body continues to come from the encrypted state-file
mirror. A user may publish or unpublish a skill from their own instance, and an
admin may do the same for any non-destroyed instance. Unpublished skills and
destroyed-instance publications are not returned from marketplace catalog or
content endpoints.
