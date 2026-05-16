-- Add vendor preset identity for inbound webhook verifier configs.
-- Rollback: ALTER TABLE instance_webhooks DROP COLUMN preset_id;

ALTER TABLE instance_webhooks
  ADD COLUMN preset_id TEXT;
