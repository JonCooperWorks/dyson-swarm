-- Postgres twin of migrations/sqlite/0036_artefact_cache_bodies.sql.

ALTER TABLE artefact_cache ADD COLUMN body_ciphertext BYTEA;
