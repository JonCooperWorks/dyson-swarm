-- Postgres twin of migrations/sqlite/0031_skill_marketplace_sources.sql.
-- See the sqlite version for design rationale.

CREATE TABLE IF NOT EXISTS skill_marketplace_sources (
  id                   TEXT   PRIMARY KEY,
  source_type          TEXT   NOT NULL,
  location             TEXT   NOT NULL,
  enabled              BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at           BIGINT NOT NULL,
  updated_at           BIGINT NOT NULL,
  deleted_at           BIGINT,
  last_fetch_at        BIGINT,
  last_success_at      BIGINT,
  last_error           TEXT,
  CONSTRAINT chk_skill_marketplace_source_type CHECK (source_type IN ('file', 'http'))
);

CREATE INDEX IF NOT EXISTS idx_skill_marketplace_sources_visible
  ON skill_marketplace_sources(deleted_at, enabled, id);
