CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  revoked_at   BIGINT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user
  ON sessions(user_id, revoked_at);
