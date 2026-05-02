-- Keep webhook delivery audit rows after the task/webhook is deleted.
--
-- The original table keyed deliveries to instance_webhooks with
-- ON DELETE CASCADE.  That made cleanup tidy, but it also erased the
-- audit trail at the exact moment an operator removed a URL.  Audit
-- belongs to the instance history, so rows should survive task
-- deletion and disappear only when the instance itself is removed.

ALTER TABLE webhook_deliveries RENAME TO webhook_deliveries_old;
DROP INDEX IF EXISTS webhook_deliveries_lookup_idx;

CREATE TABLE webhook_deliveries (
  id            TEXT PRIMARY KEY,
  instance_id   TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  webhook_name  TEXT NOT NULL,
  fired_at      INTEGER NOT NULL,
  status_code   INTEGER NOT NULL,
  latency_ms    INTEGER NOT NULL,
  request_id    TEXT,
  signature_ok  INTEGER NOT NULL,
  error         TEXT,
  body          BLOB,
  body_size     INTEGER,
  content_type  TEXT
);

INSERT INTO webhook_deliveries (
  id, instance_id, webhook_name, fired_at, status_code,
  latency_ms, request_id, signature_ok, error,
  body, body_size, content_type
)
SELECT
  id, instance_id, webhook_name, fired_at, status_code,
  latency_ms, request_id, signature_ok, error,
  body, body_size, content_type
FROM webhook_deliveries_old;

DROP TABLE webhook_deliveries_old;

CREATE INDEX webhook_deliveries_lookup_idx
  ON webhook_deliveries(instance_id, webhook_name, fired_at DESC);
