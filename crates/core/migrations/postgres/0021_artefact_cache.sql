-- Postgres twin of migrations/sqlite/0021_artefact_cache.sql.
-- Body bytes are added by 0036 after the body-path era is removed.

CREATE TABLE artefact_cache (
  id            BIGSERIAL PRIMARY KEY,
  instance_id   TEXT    NOT NULL,
  owner_id      TEXT    NOT NULL,
  chat_id       TEXT    NOT NULL,
  artefact_id   TEXT    NOT NULL,
  kind          TEXT    NOT NULL,
  title         TEXT    NOT NULL,
  mime          TEXT,
  bytes         BIGINT  NOT NULL DEFAULT 0,
  body_path     TEXT    NOT NULL,
  metadata_json TEXT,
  created_at    BIGINT  NOT NULL,
  cached_at     BIGINT  NOT NULL,
  UNIQUE (instance_id, chat_id, artefact_id)
);

CREATE INDEX artefact_cache_owner_idx
  ON artefact_cache(owner_id, cached_at DESC);

CREATE INDEX artefact_cache_instance_idx
  ON artefact_cache(instance_id, cached_at DESC);

CREATE INDEX artefact_cache_chat_idx
  ON artefact_cache(instance_id, chat_id, artefact_id);

CREATE INDEX artefact_cache_cached_at_idx
  ON artefact_cache(cached_at);
