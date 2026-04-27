-- Postgres twin of migrations/sqlite/0001_init.sql.
--
-- Differences from the SQLite version:
--  * BIGINT instead of INTEGER (SQLite is liberal; Postgres needs the right
--    type from the start to avoid a future ALTER).
--  * BIGSERIAL for the auto-increment audit id.
--  * DOUBLE PRECISION instead of REAL for monthly_usd_budget so usage
--    rollups don't lose precision under aggregation.
--  * BOOLEAN proper instead of INTEGER 0/1 (SQLite stores it as int either
--    way; Postgres has a real type).
--
-- The Pg `db::pg::*` impls (deferred — phase 7 stub only) write the same
-- queries as the sqlite impls modulo `?` -> `$N` placeholder syntax.
--
-- KEEP THIS SCHEMA IN LOCKSTEP WITH migrations/sqlite/0001_init.sql.

CREATE TABLE instances (
  id              TEXT PRIMARY KEY,
  cube_sandbox_id TEXT,
  template_id     TEXT NOT NULL,
  status          TEXT NOT NULL,
  bearer_token    TEXT NOT NULL,
  pinned          BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at      BIGINT,
  last_active_at  BIGINT NOT NULL,
  last_probe_at   BIGINT,
  last_probe_status TEXT,
  created_at      BIGINT NOT NULL,
  destroyed_at    BIGINT
);

CREATE TABLE instance_policies (
  instance_id        TEXT PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
  allowed_providers  TEXT NOT NULL,
  allowed_models     TEXT NOT NULL,
  daily_token_budget BIGINT,
  monthly_usd_budget DOUBLE PRECISION,
  rps_limit          BIGINT
);

CREATE TABLE instance_secrets (
  instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  value       TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  PRIMARY KEY (instance_id, name)
);

CREATE TABLE snapshots (
  id                 TEXT PRIMARY KEY,
  source_instance_id TEXT NOT NULL REFERENCES instances(id),
  parent_snapshot_id TEXT REFERENCES snapshots(id),
  kind               TEXT NOT NULL DEFAULT 'manual',
  path               TEXT NOT NULL,
  host_ip            TEXT NOT NULL,
  remote_uri         TEXT,
  size_bytes         BIGINT,
  created_at         BIGINT NOT NULL,
  deleted_at         BIGINT
);

CREATE TABLE proxy_tokens (
  token       TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES instances(id),
  provider    TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  revoked_at  BIGINT
);

CREATE TABLE llm_audit (
  id            BIGSERIAL PRIMARY KEY,
  instance_id   TEXT NOT NULL,
  provider      TEXT NOT NULL,
  model         TEXT,
  prompt_tokens BIGINT,
  output_tokens BIGINT,
  status_code   BIGINT NOT NULL,
  duration_ms   BIGINT NOT NULL,
  occurred_at   BIGINT NOT NULL
);

CREATE INDEX idx_instances_status ON instances(status);
CREATE INDEX idx_instances_expires ON instances(expires_at) WHERE pinned = FALSE;
CREATE INDEX idx_snapshots_source ON snapshots(source_instance_id);
CREATE INDEX idx_proxy_tokens_instance ON proxy_tokens(instance_id);
CREATE INDEX idx_llm_audit_instance ON llm_audit(instance_id, occurred_at);
