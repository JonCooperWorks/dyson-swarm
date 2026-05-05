# Operations

This document covers the long-running behaviour that matters most to an
operator.

## Health Probe Loop

Swarm periodically probes live instances and records the last result in the
instance row. The interval and timeout are configurable.

That data drives both UI status and operational visibility.

## TTL Reaper

Instances with expiries are reaped by a background loop. Pinned or otherwise
protected rows are excluded according to the service rules.

## Startup Binary Rotation

Swarm now treats binary rotation as a normal startup behaviour, not an
optional one-off sweep.

The important current behaviour is:

- live instances whose template lags the current default are rotated
- rotation is done through snapshot/restore-style orchestration
- user-visible state is preserved through swarm-managed state
- the old sandbox is replaced by a fresh one running the new binary
- the old `rotate_binary_on_startup` config flag is kept only for
  compatibility; the value is ignored

This is different from the older posture where rotation was documented as an
opt-in sweep that stranded the old URL. The current config comments are the
source of truth.

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

## Provider Key Overlay

At startup, swarm overlays provider API keys from `system_secrets` on top of
the TOML provider config. The secret-store value wins when present.

That means key rotation typically requires a swarm restart.

## Useful Operator Commands

```sh
journalctl -u dyson-swarm
journalctl -u dyson-egress-proxy
systemctl status dyson-swarm
systemctl status dyson-egress-proxy
jq . /run/dyson-egress/policies.json
```

## Break-Glass Access

When normal auth is down but you still have host access, use:

```sh
sudo -u dyson-swarm env SWARM_MINT_API_KEY_OK=1 \
  /usr/local/bin/swarmctl mint-api-key --label "ops-foo" <users.id>
```

This is a host-operator recovery path. It does not grant admin-role claims.
