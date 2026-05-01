# dyson-swarm

The orchestrator side of the Dyson stack.  Hires, snapshots, restores,
and reaps `dyson` agents running inside Cube sandboxes; brokers their
outbound LLM traffic through a per-instance proxy.

The agent itself lives in the sibling [dyson](../dyson) repo.  Together
they form one Dyson, but each side ships independently — config and
binary upgrade on different cadences, which is what motivates the
operations note below.

## Operations

### Binary rotation

Some bug fixes live in the `dyson` binary itself: a new
`ConfigureBody` field, a tool-registration change, the no-skills-block
boot fix.  When a fix lands like that, **a config push can't carry it
forward** — the old binary doesn't know about the new field, the new
tool, or the corrected loader path.  Only a fresh sandbox built from
the current cube template runs the new binary.

The startup sweep `InstanceService::rotate_binary_all` snapshot+
restores every Live instance whose `template_id` lags behind the
swarm's `default_template_id`.  Workspace state survives via the
snapshot; `name`, `task`, `owner_id`, and `instance_secrets` carry
through; the source instance is destroyed and the row stays as a
historical anchor with `rotated_to` pointing at its successor.

#### Enabling

```toml
# In swarm.toml
default_template_id = "tpl-2026-04-current"
rotate_binary_on_startup = true
```

The sweep fires on every restart, ~30s after boot (cubeproxy needs to
warm before the configure-push race).  It runs **after** the
image-generation rewire sweep, so the cheaper config-only fix gets
its turn first.

#### What rotation costs

* **`cube_sandbox_id` is destroyed.**  Anyone holding the old
  `<id>.<hostname>` URL gets a 404.  The SPA must refresh the
  per-user instance list after a swarm restart that ran rotation —
  the new id is what the user's UI should resolve to.
* **Snapshot retention grows.**  Each rotated instance produces one
  manual-kind snapshot row that survives the sweep (kept on purpose,
  so an operator can roll back if the new binary turns out to be
  worse than the old).  Operators are responsible for periodic
  pruning.
* **Tenancy is preserved.**  Owner_id, name, task, and carried
  secrets all flow into the new instance.  A re-tenanted dyson would
  be a serious bug — see `rotate_binary_preserves_owner_id`.
* **`llm_audit` history is left stranded** under the old
  `instance_id`.  Per-user budget rollups still work because they
  aggregate by `owner_id`.

#### Re-runnability

The sweep is **not atomic**.  A crash between the snapshot+restore
and the destroy step leaves the `rotated_to` marker on the source
row.  The next sweep notices the marker, skips the snapshot+restore
(the successor already exists), and retries only the destroy.  No
double-rotation, no orphaned successors.

A failed snapshot (cube unreachable, sandbox dead) leaves the source
row Live and the failure surfaces in `RotateReport.failed`; the next
sweep retries the full pipeline.

### Network policies

Every dyson is hired with one of five egress profiles, mapped to
CubeAPI's `allow_internet_access` + `network.allowOut` / `denyOut`:

| Profile     | UI label                          | What the cube enforces |
|-------------|-----------------------------------|------------------------|
| `nolocalnet` | "Open"                           | Default — public internet allowed; private, link-local, loopback, multicast, and reserved ranges denied. |
| `open`      | "Open + LAN"                      | Full internet and internal hosts; explicit opt-in for LAN/internal access. |
| `airgap`    | "Air-gapped (LLM only)"           | No egress except the swarm `/llm` proxy. |
| `allowlist` | "Allowlist (only these networks)" | LLM proxy + listed CIDRs/hostnames. Hostnames resolve at hire time. |
| `denylist`  | "Denylist (block these networks)" | Public internet minus default denies and listed CIDRs/hostnames. |

The new-instance page (`#/new`) carries a profile picker.  `nolocalnet`
is the default; `open` is the compatibility escape hatch for workloads
that intentionally need internal/LAN targets.

Host HTTP(S) proxy egress is enforced by `dyson-egress-proxy`, not
tinyproxy.  Cubes still use `HTTP_PROXY=http://169.254.68.5:3128` and
`HTTPS_PROXY=http://169.254.68.5:3128`; Cube DNATs that address to
`192.168.0.1:3128` on the host.  The proxy reads
`/run/dyson-egress/policies.json` and checks the source sandbox IP plus
every resolved destination IPv4 immediately before dialing.  Unknown
source sandbox IPs fail closed with `403`.

Useful operator commands:

```bash
journalctl -u dyson-egress-proxy
sudo systemctl start dyson-egress-policy.service
jq . /run/dyson-egress/policies.json
```

#### Hostnames in entries

Allowlist and Denylist accept hostnames (`github.com`).  Swarm DNS-
resolves at hire time using the host's resolver (`tokio::net::lookup_host`,
which honours systemd-resolved / `/etc/resolv.conf`).  The resolved
IPv4 set is what the cube enforces; the row preserves both the raw
entry and the resolved CIDRs so the SPA can show "you typed
`github.com` — cube enforces `140.82.121.4/32`."

DNS staleness is the trade-off: a hostname's IPs rotate (CDNs), but
the cube's eBPF map is immutable for the instance's lifetime.  Re-hire
to refresh the resolution.

#### Live policy change

CubeAPI doesn't expose a runtime PATCH for the eBPF egress maps.
"Change network access" on the detail page snapshots the dyson,
restores it onto a new sandbox with the new policy, and destroys the
source — same model as the binary-rotation sweep.  Workspace state
survives via the snapshot, but **the instance ID changes** and the
old `<id>.<hostname>` URL 404s afterwards.  The SPA navigates to the
successor automatically.

Authorisation: instance owner OR admin (`SYSTEM_OWNER` / `"*"`).

#### Configuration requirement

`Airgap` and `Allowlist` need an LLM-proxy CIDR — set
`cube_facing_addr` to an IPv4 (e.g. `"192.168.0.1:8080"`) in
`swarm.toml`.  Hires using those profiles return 400 with a clear
config-help message when it's missing.  `Open` and `Denylist` work
without it (they include `0.0.0.0/0`); `NoLocalNet` does not require
it because public destinations use the default-allow path while local
ranges stay denied.

### Operator escape hatch: minting an api-key without an admin bearer

Some flows assume you already hold a bearer (the SPA mints user
api-keys, the IdP issues admin JWTs).  When neither is reachable —
fresh deploy, IdP outage, you're SSH-only on the host — the swarm
binary mints an opaque user api-key directly through the DB +
cipher, bypassing the HTTP surface entirely:

```sh
sudo -u dyson-swarm env SWARM_MINT_API_KEY_OK=1 \
  /usr/local/bin/swarm mint-api-key --label "ops-foo" <users.id>
```

Prints the plaintext token (e.g. `dy_…`) to stdout; capture it
immediately, never log.  Same posture as `secrets system-set`:
direct DB access, host-operator only.

The token authenticates against tenant routes (`/v1/instances`,
PATCH, DELETE, `/reset`).  It does **not** unlock admin routes —
`/v1/instances/:id/clone` and friends require OIDC role claims and
api-keys carry none, by design (see `auth/admin.rs`).

Revoke with:

```sh
sudo sqlite3 /var/lib/dyson-swarm/state.db \
  "UPDATE user_api_keys SET revoked_at=$(date +%s) WHERE id='<row id>';"
```

Or via the SPA's api-key panel once you have a regular bearer.
