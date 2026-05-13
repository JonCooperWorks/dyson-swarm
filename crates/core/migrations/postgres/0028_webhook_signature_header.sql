-- Postgres twin of migrations/sqlite/0028_webhook_signature_header.sql.

ALTER TABLE instance_webhooks
  ADD COLUMN signature_header TEXT NOT NULL DEFAULT 'x-swarm-signature';
