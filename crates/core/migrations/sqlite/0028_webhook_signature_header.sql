ALTER TABLE instance_webhooks
  ADD COLUMN signature_header TEXT NOT NULL DEFAULT 'x-swarm-signature';
