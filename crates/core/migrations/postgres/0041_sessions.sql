-- Opaque SPA sessions for dyson_swarm_session cookies.
--
-- Rollback: DROP INDEX idx_sessions_user; DROP TABLE sessions;

CREATE TABLE sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    BIGINT NOT NULL,
  last_seen_at  BIGINT NOT NULL,
  revoked_at    BIGINT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
