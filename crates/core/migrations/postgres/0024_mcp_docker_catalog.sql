-- Postgres twin of migrations/sqlite/0026_mcp_docker_catalog.sql.
-- See the sqlite version for design rationale.

CREATE TABLE IF NOT EXISTS mcp_docker_catalog (
  id               TEXT   PRIMARY KEY,
  label            TEXT   NOT NULL,
  description      TEXT,
  template         TEXT   NOT NULL,
  credentials_json TEXT   NOT NULL DEFAULT '[]',
  source           TEXT   NOT NULL DEFAULT 'admin',
  created_at       BIGINT NOT NULL,
  updated_at       BIGINT NOT NULL,
  deleted_at       BIGINT
);

CREATE INDEX IF NOT EXISTS idx_mcp_docker_catalog_visible
  ON mcp_docker_catalog(deleted_at, id);
