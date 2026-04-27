CREATE TABLE instances (
  id              TEXT PRIMARY KEY,
  cube_sandbox_id TEXT,
  template_id     TEXT NOT NULL,
  status          TEXT NOT NULL,
  bearer_token    TEXT NOT NULL,
  pinned          INTEGER NOT NULL DEFAULT 0,
  expires_at      INTEGER,
  last_active_at  INTEGER NOT NULL,
  last_probe_at   INTEGER,
  last_probe_status TEXT,
  created_at      INTEGER NOT NULL,
  destroyed_at    INTEGER
);

CREATE TABLE instance_policies (
  instance_id        TEXT PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
  allowed_providers  TEXT NOT NULL,
  allowed_models     TEXT NOT NULL,
  daily_token_budget INTEGER,
  monthly_usd_budget REAL,
  rps_limit          INTEGER
);

CREATE TABLE instance_secrets (
  instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  value       TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
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
  size_bytes         INTEGER,
  created_at         INTEGER NOT NULL,
  deleted_at         INTEGER
);

CREATE TABLE proxy_tokens (
  token       TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES instances(id),
  provider    TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER
);

CREATE TABLE llm_audit (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  instance_id   TEXT NOT NULL,
  provider      TEXT NOT NULL,
  model         TEXT,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  status_code   INTEGER NOT NULL,
  duration_ms   INTEGER NOT NULL,
  occurred_at   INTEGER NOT NULL
);

CREATE INDEX idx_instances_status ON instances(status);
CREATE INDEX idx_instances_expires ON instances(expires_at) WHERE pinned = 0;
CREATE INDEX idx_snapshots_source ON snapshots(source_instance_id);
CREATE INDEX idx_proxy_tokens_instance ON proxy_tokens(instance_id);
CREATE INDEX idx_llm_audit_instance ON llm_audit(instance_id, occurred_at);
