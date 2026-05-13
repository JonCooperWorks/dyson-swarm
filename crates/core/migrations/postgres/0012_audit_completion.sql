-- Postgres twin of migrations/sqlite/0012_audit_completion.sql.
-- See the sqlite version for the design rationale.
--
ALTER TABLE llm_audit ADD COLUMN completed BIGINT NOT NULL DEFAULT 1;
