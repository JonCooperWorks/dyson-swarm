CREATE TABLE agent_secrets (
  owner_user_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  name TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_read_at INTEGER,
  PRIMARY KEY(owner_user_id, instance_id, name),
  FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

CREATE INDEX idx_agent_secrets_instance
  ON agent_secrets(instance_id, name);

