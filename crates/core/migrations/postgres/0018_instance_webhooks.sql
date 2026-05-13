-- Postgres twin of migrations/sqlite/0018_instance_webhooks.sql.
-- See the sqlite version for design rationale.
--
-- Differences from the sqlite version:
--  * BIGINT for unix-epoch timestamps and integer status/latency
--    where Postgres needs the right type from the start.
--  * BIGINT for 0/1 `enabled` / `signature_ok` so the wire transfer path can
--    preserve SQLite values directly.
--
-- KEEP THIS SCHEMA IN LOCKSTEP WITH migrations/sqlite/0018_instance_webhooks.sql.

CREATE TABLE instance_webhooks (
  instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  auth_scheme TEXT NOT NULL,
  secret_name TEXT,
  enabled     BIGINT NOT NULL DEFAULT 1,
  created_at  BIGINT NOT NULL,
  updated_at  BIGINT NOT NULL,
  PRIMARY KEY (instance_id, name)
);

CREATE INDEX instance_webhooks_enabled_idx
  ON instance_webhooks(instance_id, enabled);

CREATE TABLE webhook_deliveries (
  id            TEXT PRIMARY KEY,
  instance_id   TEXT NOT NULL,
  webhook_name  TEXT NOT NULL,
  fired_at      BIGINT NOT NULL,
  status_code   BIGINT NOT NULL,
  latency_ms    BIGINT NOT NULL,
  request_id    TEXT,
  signature_ok  BIGINT NOT NULL,
  error         TEXT,
  FOREIGN KEY (instance_id, webhook_name)
    REFERENCES instance_webhooks(instance_id, name) ON DELETE CASCADE
);

CREATE INDEX webhook_deliveries_lookup_idx
  ON webhook_deliveries(instance_id, webhook_name, fired_at DESC);
