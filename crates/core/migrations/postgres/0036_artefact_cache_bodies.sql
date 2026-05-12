-- Postgres twin of migrations/sqlite/0036_artefact_cache_bodies.sql.
-- See the sqlite version for design rationale.
--
-- Translation: BLOB → BYTEA.

ALTER TABLE artefact_cache ADD COLUMN body_ciphertext BYTEA;
