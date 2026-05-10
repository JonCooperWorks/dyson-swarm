# Shares

Swarm serves anonymous public share URLs for selected artefacts without handing
the browser a direct path to the live Dyson sandbox. The public URL is a signed
capability; possession of the URL is the read permission until expiry,
revocation, or signing-key rotation.

Relevant code:

- [service.rs](../crates/core/src/shares/service.rs)
- [share_public.rs](../crates/swarm/src/http/share_public.rs)
- [render.rs](../crates/core/src/shares/render.rs)
- [artefacts.jsx](../crates/swarm/src/http/web/src/components/artefacts.jsx)

## URL Shape

Public reads go through `share.<hostname>`:

```text
GET /v1/<token>       rendered share page
GET /v1/<token>/raw   raw artefact bytes
```

`<token>` is not the database `jti`. It is:

```text
base64url(postcard SharePayload).base64url(HMAC tag)
```

The `jti` is a 32-character hex row identifier used by authenticated SPA/API
routes for revoke, reissue, audit-log lookup, and URL re-derivation:

```text
GET    /v1/shares/<jti>/url
DELETE /v1/shares/<jti>
POST   /v1/shares/<jti>/reissue
GET    /v1/shares/<jti>/accesses
```

Opening `https://share.<hostname>/v1/<jti>` returns the fixed 404 body by
design. It is not a public share URL.

## Why 404 Is Deliberately Boring

Malformed tokens, unknown rows, revoked shares, expired shares, and wrong-path
requests all collapse to the same public 404 response. That keeps scanners
from learning whether a share existed, expired, or was mistyped.

Authenticated owner routes can distinguish active, expired, revoked, and
missing rows because they already know the user identity.

## Mint And Re-Derive

Minting a share:

1. ensures the owner has a sealed per-user `share_signing_key`
2. builds a `SharePayload` with instance, chat, artefact, expiry, and random
   `jti`
3. signs it with HMAC-SHA256
4. stores the `jti` row
5. returns both `{ url, jti, expires_at, ... }`

Swarm does not store the full public URL. `GET /v1/shares/<jti>/url`
reconstructs it for an active owner-owned row using the same signing key and
payload fields. Revoked or expired rows return no URL.

## Cache-First Reads

The public share path resolves artefacts in this order:

1. parse and verify the signed token
2. load the matching, non-revoked `jti` row
3. serve from Swarm's artefact cache when present
4. otherwise fetch from the live Dyson instance
5. write the fetched bytes back to the Swarm cache
6. render HTML or return `/raw` bytes

This is why cached shares can survive sandbox reset or destroy.

## Rendering And Audit

Renderers are intentionally simple:

- Markdown becomes server-rendered HTML.
- Images render inside an image viewer page.
- Other MIME types render as download-focused pages.

The `/raw` endpoint always returns the underlying bytes. Share access rows
record the `jti`, remote address when available, user agent when available, and
response status.
