-- Swarm-side cache of artefacts produced by per-instance dyson agents.
--
-- Why this table exists (and why now): cube instances are ephemeral —
-- a reset / template rotation / OOM kill destroys whatever artefacts
-- the agent produced.  Anything we'd already shared via `artefact_shares`
-- and the `share.<apex>` public endpoint then 404s, since the read
-- path proxies through to the live cube which no longer has the bytes.
--
-- This table stores the *swarm copy* (metadata + filesystem-anchored
-- body path) so the share endpoint can fall back to it after the cube
-- is gone.  It's also the foundation for "surface every artefact in
-- the swarm UI": the SPA's artefact list reads from here as soon as
-- a row has been ingested, regardless of whether the source cube is
-- still alive.  Bytes live on disk under `local_cache_dir` keyed by
-- `body_path`; this row holds only metadata + the path.
--
-- (instance_id, chat_id, artefact_id) is the identity tuple — same
-- shape as `artefact_shares` so the join from a share row is a single
-- index lookup.  We intentionally do NOT FK on `instance_id` here:
-- destroying an instance must NOT cascade-delete its cached artefact
-- rows, otherwise the whole point of swarm-side persistence is lost.
-- Operators can prune by hand or by a scheduled GC sweep against
-- `cached_at` — see the `cached_at_idx` below.

CREATE TABLE artefact_cache (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  instance_id   TEXT    NOT NULL,
  owner_id      TEXT    NOT NULL,                 -- denormalised from instances.owner_id at ingest time; survives instance delete
  chat_id       TEXT    NOT NULL,
  artefact_id   TEXT    NOT NULL,
  kind          TEXT    NOT NULL,                 -- "security_review" / "image" / "other" — opaque string, mirrors dyson's ArtefactKind
  title         TEXT    NOT NULL,
  mime          TEXT,                             -- upstream Content-Type at ingest time; NULL when unknown
  bytes         INTEGER NOT NULL DEFAULT 0,       -- size of the on-disk body, for listings
  body_path     TEXT    NOT NULL,                 -- path under `[backup].local_cache_dir/artefacts/...`; relative
  metadata_json TEXT,                             -- raw metadata blob from dyson's listing, opaque
  created_at    INTEGER NOT NULL,                 -- artefact's own created_at as reported by dyson
  cached_at     INTEGER NOT NULL,                 -- when swarm wrote this row
  UNIQUE (instance_id, chat_id, artefact_id)
);

-- Owner-scoped listing (the SPA's "all my artefacts" view).
CREATE INDEX artefact_cache_owner_idx
  ON artefact_cache(owner_id, cached_at DESC);

-- Per-instance listing (the SPA's "this instance's artefacts" panel).
CREATE INDEX artefact_cache_instance_idx
  ON artefact_cache(instance_id, cached_at DESC);

-- Per-chat listing (powers the share-page "title + kind" lookup that
-- previously had to hit the live cube via `/api/conversations/:id/artefacts`).
CREATE INDEX artefact_cache_chat_idx
  ON artefact_cache(instance_id, chat_id, artefact_id);

-- GC sweep target: oldest-first scan for cache eviction by age.
CREATE INDEX artefact_cache_cached_at_idx
  ON artefact_cache(cached_at);
