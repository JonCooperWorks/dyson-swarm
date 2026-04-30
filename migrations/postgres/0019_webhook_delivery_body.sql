-- Postgres twin of migrations/sqlite/0019_webhook_delivery_body.sql.
-- KEEP IN LOCKSTEP.

ALTER TABLE webhook_deliveries ADD COLUMN body BYTEA;
ALTER TABLE webhook_deliveries ADD COLUMN body_size INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN content_type TEXT;
