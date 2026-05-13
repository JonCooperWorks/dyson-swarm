-- Postgres twin of migrations/sqlite/0040_admin_audit.sql.
--
-- Rollback: DROP INDEX idx_admin_audit_target_ts; DROP TABLE admin_audit;
-- this loses only admin audit history and does not mutate live user state.

CREATE TABLE IF NOT EXISTS admin_audit (
  id             BIGSERIAL PRIMARY KEY,
  actor_subject  TEXT NOT NULL,
  action         TEXT NOT NULL,
  target_user    TEXT NOT NULL,
  params_hash    TEXT NOT NULL,
  ts             BIGINT NOT NULL
);

CREATE INDEX idx_admin_audit_target_ts
  ON admin_audit(target_user, ts);
