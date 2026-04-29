-- Stage 7: BYOK + multi-provider expansion.
--
-- `key_source` records WHICH credential the proxy used to make each
-- upstream call — needed so operators can attribute spend correctly
-- now that any single LLM call could be billed to the user (BYOK),
-- the operator (platform), or an OR-minted per-user key the platform
-- still pays for.
--
-- Closed enum:
--   'platform'  — global `[providers.<name>].api_key` from TOML
--   'byok'      — user-pasted key from `user_secrets[byok_<provider>]`
--   'or_minted' — OpenRouter Provisioning-API key minted for this user
--
-- Default 'platform' so existing rows (pre-Stage-7) report sensibly:
-- before BYOK, every call used the operator's key.

ALTER TABLE llm_audit ADD COLUMN key_source TEXT NOT NULL DEFAULT 'platform';

CREATE INDEX idx_llm_audit_key_source
    ON llm_audit(owner_id, key_source, occurred_at);
