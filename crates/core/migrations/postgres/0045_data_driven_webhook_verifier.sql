-- Postgres twin of migrations/sqlite/0045_data_driven_webhook_verifier.sql.
--
-- Rollback: DROP INDEX idx_wds_first_seen; DROP TABLE webhook_deliveries_seen;
-- ALTER TABLE instance_webhooks/webhook_deliveries DROP COLUMN ... for each
-- verifier metadata column added here.

ALTER TABLE instance_webhooks
  ADD COLUMN verifier_mode TEXT NOT NULL DEFAULT 'legacy_hmac';
ALTER TABLE instance_webhooks
  ADD COLUMN signature_algo TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN signature_encoding TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN signature_prefix TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN signature_separator TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN signature_value_split TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN timestamp_header TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN timestamp_skew_secs BIGINT;
ALTER TABLE instance_webhooks
  ADD COLUMN payload_template TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN idempotency_header TEXT;
ALTER TABLE instance_webhooks
  ADD COLUMN bearer_path_token TEXT;

UPDATE instance_webhooks
SET verifier_mode = CASE auth_scheme
  WHEN 'bearer' THEN 'legacy_bearer'
  WHEN 'none' THEN 'none'
  ELSE 'legacy_hmac'
END;

ALTER TABLE webhook_deliveries
  ADD COLUMN verify_error TEXT;
ALTER TABLE webhook_deliveries
  ADD COLUMN request_headers TEXT;
ALTER TABLE webhook_deliveries
  ADD COLUMN replayed_from_delivery_id TEXT;
ALTER TABLE webhook_deliveries
  ADD COLUMN replayed_by_user_id TEXT;

CREATE TABLE IF NOT EXISTS webhook_deliveries_seen (
  webhook_row_id  TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  first_seen_at   BIGINT NOT NULL,
  PRIMARY KEY (webhook_row_id, idempotency_key)
);

CREATE INDEX idx_wds_first_seen
  ON webhook_deliveries_seen(first_seen_at);
