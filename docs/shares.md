# Shares

Swarm serves anonymous public share URLs for selected artefacts without handing
the browser a direct path to the live Dyson sandbox.

Relevant code:

- [service.rs](../crates/core/src/shares/service.rs)
- [share_public.rs](../crates/swarm/src/http/share_public.rs)
- [render.rs](../crates/core/src/shares/render.rs)
- [artefacts.jsx](../crates/swarm/src/http/web/src/components/artefacts.jsx)

## Host and URL Shape

Public shares are served from:

- `share.<configured_hostname>`

The public path shape is:

- `GET /v1/<token>` — rendered share page
- `GET /v1/<token>/raw` — raw artefact bytes

Anything else returns the same fixed 404 body. Swarm does that deliberately so
expired, revoked, malformed, and unknown tokens are not distinguishable to a
scanner.

## Why Shares Read Through Swarm

Swarm sits in front of shared artefacts so it can:

- verify the HMAC-backed share token
- enforce expiry and revocation
- record access audit rows
- keep the share working after a cube reset by serving from the artefact cache

This means a share URL is stable even when the underlying sandbox is not.

## Cache-First Resolution

The public share path resolves artefacts in this order:

1. verify the share token
2. look for a matching cached artefact row and on-disk body
3. if the cache is cold, fetch from the live cube
4. write the bytes back into the swarm artefact cache
5. serve either raw bytes or a rendered HTML page

That makes shares read-through and write-through on first access.

## Rendering Modes

Swarm chooses a simple renderer based on artefact kind and MIME:

- markdown artefacts render as server-side HTML
- images render inside an image viewer page
- everything else renders as a download-focused page

The `/raw` endpoint always serves the underlying bytes.

## Access Audit

Every successful or failed share resolution that makes it past token
verification records an access row with:

- share id
- remote address, if present
- user agent, if present
- response status

The artefact/share UI surfaces that audit log so operators and users can see
whether a share has actually been used.

## Relationship to Artefacts

Shares are layered on top of the swarm artefact cache, not separate from it.

In practice:

- sharing a cached artefact is immediate
- opening a share can populate the cache if it was cold
- resetting or destroying the source cube does not break a share that swarm has
  already cached

If you are trying to understand why a share still works after an instance is
gone, this cache-first design is the reason.
