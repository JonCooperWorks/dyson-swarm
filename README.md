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
