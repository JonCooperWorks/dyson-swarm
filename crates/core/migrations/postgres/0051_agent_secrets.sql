CREATE TABLE agent_secrets (
  owner_user_id TEXT NOT NULL,
  instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  last_read_at BIGINT,
  PRIMARY KEY(owner_user_id, instance_id, name)
);

CREATE INDEX idx_agent_secrets_instance
  ON agent_secrets(instance_id, name);

