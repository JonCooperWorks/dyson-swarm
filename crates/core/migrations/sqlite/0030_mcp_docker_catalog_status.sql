-- Track Docker MCP catalog approval state.
--
-- Existing operator-managed rows become active. User-submitted rows
-- land as pending until an admin reviews and saves them.

ALTER TABLE mcp_docker_catalog
  ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
  CHECK (status IN ('active', 'pending'));

ALTER TABLE mcp_docker_catalog
  ADD COLUMN requested_by_user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_mcp_docker_catalog_status_visible
  ON mcp_docker_catalog(status, deleted_at, id);
