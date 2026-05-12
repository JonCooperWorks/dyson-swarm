-- Postgres twin of migrations/sqlite/0040_admin_audit.sql.
-- See the sqlite version for design rationale.

CREATE TABLE IF NOT EXISTS admin_audit (
  id            BIGSERIAL PRIMARY KEY,
  actor_subject TEXT   NOT NULL,
  action        TEXT   NOT NULL,
  target_user   TEXT   NOT NULL,
  params_hash   TEXT   NOT NULL,
  ts            BIGINT NOT NULL
);
