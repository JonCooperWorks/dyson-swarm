-- Postgres twin of migrations/sqlite/0020_artefact_shares.sql.
-- See the sqlite version for product rationale.

CREATE TABLE artefact_shares (
  jti          TEXT PRIMARY KEY,
  instance_id  TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  chat_id      TEXT NOT NULL,
  artefact_id  TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  created_at   BIGINT NOT NULL,
  expires_at   BIGINT NOT NULL,
  revoked_at   BIGINT,
  label        TEXT
);

CREATE INDEX artefact_shares_instance_idx
  ON artefact_shares(instance_id);

CREATE INDEX artefact_shares_active_idx
  ON artefact_shares(created_by, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE artefact_share_accesses (
  id           BIGSERIAL PRIMARY KEY,
  jti          TEXT NOT NULL,
  accessed_at  BIGINT NOT NULL,
  remote_addr  TEXT,
  user_agent   TEXT,
  status       BIGINT NOT NULL
);

CREATE INDEX artefact_share_accesses_jti_idx
  ON artefact_share_accesses(jti, accessed_at DESC);
