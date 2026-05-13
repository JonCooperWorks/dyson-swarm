-- Per-instance sandbox secrets are no longer a supported credential path.
-- External service credentials should flow through MCP/user/system secret
-- storage, not raw environment material injected into agent sandboxes.
DROP INDEX IF EXISTS idx_instance_secrets_instance;
DROP TABLE IF EXISTS instance_secrets;
