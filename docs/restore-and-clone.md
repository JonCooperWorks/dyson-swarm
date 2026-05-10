# Restore And Clone

Swarm treats Cube sandboxes as replaceable runtime containers. Restores,
clones, resets, network changes, and template rotations all create or swap
sandboxes while keeping Swarm-owned metadata authoritative.

Relevant code:

- [instance.rs](../crates/core/src/instance.rs)
- [snapshots.rs](../crates/core/src/snapshot.rs)
- [instances.rs](../crates/swarm/src/http/instances.rs)
- [snapshots.rs](../crates/swarm/src/http/snapshots.rs)

## Snapshot And Restore

`POST /v1/instances/:id/snapshot` asks Cube for a snapshot bundle and records a
snapshot row. `POST /v1/instances/:id/restore` creates a new Swarm instance
from a selected snapshot. Restore returns a new instance id, fresh runtime
tokens, and a new public instance URL.

During restore, Swarm uses the Cube snapshot as the VM base, then replays
mirrored state files before state sync resumes. Mirrored rows win for the paths
Swarm tracks; the snapshot is the fallback for VM-local files outside the
mirror.

## Clone

Admin `POST /v1/instances/:id/clone` creates a new instance from an existing
one.

Default clone:

- snapshots the source
- creates a fresh Swarm id and Cube sandbox from that snapshot
- copies name, task, models, tools, network policy, per-instance secrets, and
  MCP server records
- preserves MCP OAuth token records under the new instance id
- leaves the source instance running

`empty=true` clone:

- skips the snapshot
- boots a clean cube from the target template
- still copies Swarm-owned config, secrets, policy, tools, and MCP records
- does not carry VM workspace files, chat files, kb files, or skills from the
  source disk

Use empty clone when the snapshot path is unavailable or when the operator
intentionally wants a clean workspace with the same Swarm-side setup.

## Reset, Recreate, Rotate, Change Network

Tenant reset keeps the same Swarm id and DNS name but swaps in a clean sandbox.
Swarm-owned config, secrets, MCP records, network policy, bearer token, webhook
URLs, and mirrored state survive. Local files that never reached the state
mirror can be lost.

Operator recreate is the same kind of snapshot-less in-place swap and is meant
as an escape hatch when the snapshot path is broken.

Template rotation and network-policy changes use snapshot-backed in-place
replacement: same Swarm id and public URL, fresh sandbox, snapshot base, then
mirrored-state replay.

## Durability Rule

A path or setting is durable only if Swarm owns it or it is present in the Cube
snapshot used as the restore base. The state mirror is authoritative for the
allowlisted workspace/chat paths listed in [State Ownership](state-ownership.md).
Generated indexes, local logs, temporary files, and unsynced sidecar state are
not durable promises.

## Smoke Checks

After clone or restore:

- open the returned `<instance_id>.<hostname>` URL, not a raw Cube URL
- run a prompt that reads a known mirrored workspace/chat file
- verify MCP tools list if the source had MCP servers
- mint and open a share URL from an artefact when validating public share paths
