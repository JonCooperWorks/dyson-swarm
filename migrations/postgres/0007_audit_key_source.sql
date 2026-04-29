-- Stage 7: BYOK + multi-provider expansion.  See sqlite/0010 for rationale.
ALTER TABLE llm_audit ADD COLUMN key_source TEXT NOT NULL DEFAULT 'platform';
CREATE INDEX idx_llm_audit_key_source
    ON llm_audit(owner_id, key_source, occurred_at);
