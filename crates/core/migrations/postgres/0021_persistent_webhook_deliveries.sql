-- Keep webhook delivery audit rows after the task/webhook is deleted.
-- Rows remain scoped to the instance and cascade only when the
-- instance itself is removed.

ALTER TABLE webhook_deliveries
  DROP CONSTRAINT IF EXISTS webhook_deliveries_instance_id_webhook_name_fkey;

ALTER TABLE webhook_deliveries
  ADD CONSTRAINT webhook_deliveries_instance_id_fkey
  FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE;
