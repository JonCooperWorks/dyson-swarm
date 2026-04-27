ALTER TABLE llm_audit ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX idx_llm_audit_owner ON llm_audit(owner_id, occurred_at);
