# Operations

This document covers the long-running behaviour that matters most to an
operator.

## Health Probe Loop

Swarm periodically probes live instances and records the last result in the
instance row. The interval and timeout are configurable.

That data drives both UI status and operational visibility.

`/healthz` is a liveness check only. Instance readiness is the row status:
`configuring` means Cube has returned a sandbox id but Dyson has not yet
accepted the runtime config, while `live` means normal user traffic may be
proxied.

## TTL Reaper

Instances with expiries are reaped by a background loop. Pinned or otherwise
protected rows are excluded according to the service rules.

## Startup Binary Rotation

Startup binary rotation is opt-in. When `rotate_binary_on_startup = true`,
swarm restarts sweep live instances whose template lags the current default.
Each matching instance is rotated through snapshot/restore-style orchestration,
then the old sandbox is replaced by a fresh one running the new binary.

Keep `rotate_binary_on_startup = false` for ordinary deploys. Swarm-managed
state is replayed during rotation, but arbitrary local files inside a running
cube are outside that mirror and can be lost if the source sandbox is replaced.

## Startup MCP Runtime Restart

When swarm starts, it enumerates live instances and asks `dyson-mcp-runtime` to
restart every runtime-backed MCP server saved in user secrets. The sweep retries
briefly so it can tolerate systemd starting the runtime socket a few seconds
after swarm.

The runtime helper does not reap idle MCP sessions by default; user servers
remain alive until the helper is restarted or the server configuration is
replaced/deleted.

For Docker stdio MCP servers, secret-bearing environment values are written to
per-session files under `/run/dyson-mcp-runtime/secrets`, bind-mounted read-only
into the container at `/run/secrets`, and exported by a runtime wrapper before
the MCP process starts. Docker argv and container config expose only `KEY_FILE`
paths, not the secret values.

## Runtime Config Sync

On every swarm startup, a background sweep re-pushes desired runtime config to
live Dysons: model list, proxy URL/token, image-generation provider, tool
allowlist/default reset, MCP server blocks, artefact ingest, state sync, and
Telegram proxy config. The sweep is idempotent and best-effort; create/restore
still performs a blocking configure push before a new row becomes `live`.

If the blocking configure push fails during create, swarm destroys the
half-configured sandbox, revokes its runtime tokens, marks the row destroyed,
and returns the error to the caller rather than exposing an instance with
warmup-placeholder config.

## Provider Key Overlay

At startup, swarm overlays provider API keys from `system_secrets` on top of
the TOML provider config. The secret-store value wins when present.

That means key rotation typically requires a swarm restart.

## Local KMS Operations

The local KMS backend is `local-age`. It stores v2 metadata-bound envelopes for
new ciphertext rows while preserving legacy age-row readability long enough to
migrate old data.

Before running a migration on a live host, stop swarm or keep write traffic
quiet, then back up the active database backend and key tree. For the default
SQLite backend:

```sh
sudo systemctl stop dyson-swarm
sudo install -d -m 0700 /var/backups/dyson-swarm
sudo cp -a /var/lib/dyson-swarm/state.db /var/backups/dyson-swarm/state.db.$(date +%Y%m%d%H%M%S)
sudo cp -a /var/lib/dyson-swarm/keys /var/backups/dyson-swarm/keys.$(date +%Y%m%d%H%M%S)
```

Diagnostic commands:

```sh
sudo -u dyson-swarm swarmctl kms status
sudo -u dyson-swarm swarmctl kms doctor
sudo -u dyson-swarm swarmctl kms rewrap --dry-run
sudo -u dyson-swarm swarmctl kms migrate-local --dry-run
```

Migration command:

```sh
sudo -u dyson-swarm swarmctl kms migrate-local
```

`migrate-local` scans legacy and stale v2 rows, decrypts them with the expected
row context, and rewrites them as KMS v2 envelopes under the active scoped local
age key. It is idempotent and reports counts by table and scope. It never prints
plaintext. It fails closed on undecryptable rows or v2 context mismatches.

`rewrap` currently uses the same scanner and rewrite engine as
`migrate-local`; use it when active key versions change.

Rollback means restoring the database and matching key directory backup
together. Do not restore one without the other after a migration or key-version
change.

To verify a dev-server migration:

```sh
sudo -u dyson-swarm swarmctl kms doctor
sudo systemctl start dyson-swarm
systemctl status dyson-swarm
```

To verify KMS secret-access audit owner attribution without reading or printing
secret values:

```sh
sudo sqlite3 /var/lib/dyson-swarm/state.db \
  "SELECT scope, COUNT(*) AS total, SUM(CASE WHEN owner_id IS NULL OR owner_id = '' THEN 1 ELSE 0 END) AS missing_owner FROM secret_access_audit GROUP BY scope ORDER BY total DESC;"
```

Instance-scoped rows that still match an instance should not be missing owner
after startup migrations have run:

```sh
sudo sqlite3 /var/lib/dyson-swarm/state.db \
  "SELECT scope, COUNT(*) FROM secret_access_audit AS saa WHERE (owner_id IS NULL OR owner_id = '') AND instance_id IS NOT NULL AND instance_id != '' AND EXISTS (SELECT 1 FROM instances AS i WHERE i.id = saa.instance_id) GROUP BY scope ORDER BY scope;"
```

System-only scopes with no `instance_id` may legitimately have no `owner_id`.

Then run the normal smoke checks below, including an LLM turn, an MCP tool call,
a state read from a known mirrored file, and a `/api/admin/configure` push by
creating or reconfiguring an instance.

## Useful Operator Commands

```sh
journalctl -u dyson-swarm
journalctl -u dyson-egress-proxy
systemctl status dyson-swarm
systemctl status dyson-egress-proxy
jq . /run/dyson-egress/policies.json
```

## Smoke Checks

After a deploy that touches proxying, sharing, restore, or clone paths:

- run `bring-up.sh smoke`; it hires a fresh instance, checks `/healthz`, checks
  `/llm`, and runs `what is secretpeek?` through a real chat turn
- run a long model turn through a live Dyson and watch for `/llm/*` 502s or
  incomplete `llm_audit` rows
- mint a share and open the returned `share.<hostname>/v1/<token>` URL plus its
  `/raw` form
- verify that `share.<hostname>/v1/<jti>` returns 404; the `jti` is not the
  public capability
- clone a known instance to a fresh host, open the returned
  `<instance_id>.<hostname>` URL, and run a prompt that reads known state
- for MCP-bearing instances, confirm the clone lists the expected MCP tools

## Break-Glass Access

When normal auth is down but you still have host access, use:

```sh
sudo -u dyson-swarm env SWARM_MINT_API_KEY_OK=1 \
  /usr/local/bin/swarmctl mint-api-key --label "ops-foo" <users.id>
```

This is a host-operator recovery path. It does not grant admin-role claims.
