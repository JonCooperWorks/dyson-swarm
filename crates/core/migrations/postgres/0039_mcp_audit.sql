-- Postgres twin of migrations/sqlite/0039_mcp_audit.sql.
-- See the sqlite version for design rationale.

CREATE TABLE IF NOT EXISTS mcp_audit (
  id          BIGSERIAL PRIMARY KEY,
  owner_id    TEXT   NOT NULL,
  instance_id TEXT   NOT NULL,
  server_name TEXT   NOT NULL,
  tool        TEXT,
  status      BIGINT NOT NULL,
  duration_ms BIGINT NOT NULL,
  ts          BIGINT NOT NULL,
  completed   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_mcp_audit_instance
  ON mcp_audit(instance_id, ts DESC);
