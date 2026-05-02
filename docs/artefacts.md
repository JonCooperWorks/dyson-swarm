# Artefacts

Swarm keeps a persistent, owner-scoped cache of Dyson artefacts so useful
outputs survive sandbox churn and stay browseable from one UI surface.

Relevant code:

- [artefacts.rs](../crates/core/src/artefacts.rs)
- [db/artefacts.rs](../crates/core/src/db/artefacts.rs)
- [instance_artefacts.rs](../crates/swarm/src/http/instance_artefacts.rs)
- [internal_ingest.rs](../crates/swarm/src/http/internal_ingest.rs)
- [artefacts.jsx](../crates/swarm/src/http/web/src/components/artefacts.jsx)

## What Swarm Stores

Swarm splits artefact persistence into two layers:

- SQLite metadata in `artefact_cache`
- encrypted body files under `<local_cache_dir>/artefacts/`

That keeps large artefacts like images and PDFs out of SQLite while still
letting the API and SPA page through metadata efficiently.

Bodies are sealed with the artefact owner's age cipher before they hit disk.
A stolen cache directory alone is not enough to read historical artefacts.

## Why the Cache Exists

The artefact cache exists for two reasons:

1. shared artefacts should keep working after a cube is reset or destroyed
2. the swarm UI should be able to show per-instance and global artefact lists
   without fanning out to every live cube on each page load

This is why artefacts are a swarm concern rather than a purely in-sandbox
feature.

## Ingest Path

Dyson writes artefacts back to swarm over the internal ingest surface:

- `POST /v1/internal/ingest/artefact`

Auth for that route uses the per-instance ingest bearer (`it_...`), not user
OIDC or a normal user API key.

At ingest time, swarm stores:

- `instance_id`
- `owner_id`
- `chat_id`
- `artefact_id`
- kind, title, mime, and created timestamp
- optional metadata JSON
- optional body bytes

If the ingest only refreshes metadata, swarm can skip re-uploading the body.

## Read and List Surfaces

User-facing artefact routes live under `/v1/` and use the normal
`user_middleware` chain.

Main endpoints:

- `GET /v1/artefacts` — all cached artefacts for the current user
- `GET /v1/instances/:id/artefacts` — cached artefacts for one instance
- `POST /v1/instances/:id/artefacts/sweep` — import a chat's artefact metadata
- `GET /v1/instances/:id/artefacts/:art_id` — cached metadata only
- `GET /v1/instances/:id/artefacts/:art_id/raw` — body fetch with read-through
- `DELETE /v1/instances/:id/artefacts/:art_id` — delete swarm's cached copy

The list endpoints support `limit` and `offset`. The per-instance list also
accepts `chat_id` so the UI can narrow a large cache to one conversation.

## Cold Reads and Sweep

Swarm treats metadata and body fetches differently.

Metadata lookup is cache-only:

- `GET /v1/instances/:id/artefacts/:art_id`

Body lookup is read-through:

- `GET /v1/instances/:id/artefacts/:art_id/raw`

If the cached body is missing, swarm falls through to the live cube, fetches
the artefact from Dyson, and writes it back into the cache.

`POST /v1/instances/:id/artefacts/sweep` is the explicit "pull everything from
this chat into swarm" path. Sweep imports metadata for the whole chat, but it
does not prefetch all bodies. That keeps a large conversation from turning one
button click into a burst of multi-megabyte downloads.

## Ownership and Tenant Boundaries

Artefact cache rows carry `owner_id`, and the swarm-side read/list/delete paths
stay owner-scoped.

Important consequences:

- one user cannot browse another user's cached artefacts
- deleting a cached artefact does not reveal whether another tenant has an
  artefact with the same id
- the global artefact list is still per-user, not instance-global across the
  deployment

## UI Routes

The embedded SPA exposes three main artefact views:

- `#/artefacts` — all my artefacts
- `#/i/:instance_id/artefacts` — one instance's artefacts
- `#/i/:instance_id/artefacts/:artefact_id` — deep-linked artefact reader page

Those views are backed by swarm's cache-first API, which is why the UI can keep
working even after the original sandbox has been rotated away.
