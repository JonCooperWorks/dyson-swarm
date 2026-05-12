-- Postgres twin of migrations/sqlite/0031_skill_marketplace_sources.sql.
-- See the sqlite version for design rationale.

CREATE TABLE IF NOT EXISTS skill_marketplace_sources (
  id                   TEXT   PRIMARY KEY,
  source_type          TEXT   NOT NULL,
  location             TEXT   NOT NULL,
  enabled              BOOLEAN NOT NULL DEFAULT TRUE,
  created_at           BIGINT NOT NULL,
  updated_at           BIGINT NOT NULL,
  default_include_tags JSONB  NOT NULL DEFAULT '[]',
  default_exclude_tags JSONB  NOT NULL DEFAULT '[]',
  priority             BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_skill_marketplace_sources_priority
  ON skill_marketplace_sources(priority DESC, created_at ASC);
