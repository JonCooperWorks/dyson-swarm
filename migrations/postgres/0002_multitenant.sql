-- Postgres twin of migrations/sqlite/0002_multitenant.sql.
-- See the sqlite version for rationale.

CREATE TABLE users (
  id              TEXT PRIMARY KEY,
  subject         TEXT NOT NULL UNIQUE,
  email           TEXT,
  display_name    TEXT,
  status          TEXT NOT NULL DEFAULT 'inactive',
  created_at      BIGINT NOT NULL,
  activated_at    BIGINT,
  last_seen_at    BIGINT
);

CREATE INDEX idx_users_subject ON users(subject);
CREATE INDEX idx_users_status ON users(status);

CREATE TABLE user_api_keys (
  token           TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label           TEXT,
  created_at      BIGINT NOT NULL,
  revoked_at      BIGINT
);

CREATE INDEX idx_user_api_keys_user ON user_api_keys(user_id);

INSERT INTO users (id, subject, email, display_name, status, created_at, activated_at)
  VALUES ('legacy', 'legacy', NULL, 'Legacy (pre-tenancy rows)', 'suspended',
          EXTRACT(EPOCH FROM NOW())::BIGINT,
          EXTRACT(EPOCH FROM NOW())::BIGINT);

ALTER TABLE instances ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'legacy'
  REFERENCES users(id);

ALTER TABLE snapshots ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'legacy'
  REFERENCES users(id);

CREATE INDEX idx_instances_owner ON instances(owner_id);
CREATE INDEX idx_snapshots_owner ON snapshots(owner_id);

DROP TABLE instance_policies;

CREATE TABLE user_policies (
  user_id            TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  allowed_providers  TEXT NOT NULL,
  allowed_models     TEXT NOT NULL,
  daily_token_budget BIGINT,
  monthly_usd_budget DOUBLE PRECISION,
  rps_limit          BIGINT
);
