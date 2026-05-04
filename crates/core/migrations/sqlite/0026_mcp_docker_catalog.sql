-- Operator-managed Docker MCP presets.
--
-- User credentials never live here.  Rows contain only the JSON
-- template plus the placeholder metadata that tells the UI which
-- per-user values can be supplied before the rendered server is sealed
-- into user_secrets.

CREATE TABLE IF NOT EXISTS mcp_docker_catalog (
  id               TEXT    PRIMARY KEY,
  label            TEXT    NOT NULL,
  description      TEXT,
  template         TEXT    NOT NULL,
  credentials_json TEXT    NOT NULL DEFAULT '[]',
  source           TEXT    NOT NULL DEFAULT 'admin',
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL,
  deleted_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_mcp_docker_catalog_visible
  ON mcp_docker_catalog(deleted_at, id);
