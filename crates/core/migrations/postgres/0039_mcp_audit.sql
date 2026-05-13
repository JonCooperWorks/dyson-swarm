-- Postgres twin of migrations/sqlite/0039_mcp_audit.sql.
--
-- Rollback: DROP INDEX idx_mcp_audit_owner_server_ts; DROP TABLE mcp_audit;
-- this loses only MCP audit history and does not mutate live instance state.

CREATE TABLE IF NOT EXISTS mcp_audit (
  id            BIGSERIAL PRIMARY KEY,
  owner_id      TEXT NOT NULL REFERENCES users(id),
  instance_id   TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  server_name   TEXT NOT NULL,
  tool          TEXT,
  status        BIGINT NOT NULL,
  duration_ms   BIGINT NOT NULL,
  ts            BIGINT NOT NULL,
  completed     BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_mcp_audit_owner_server_ts
  ON mcp_audit(owner_id, server_name, ts);
