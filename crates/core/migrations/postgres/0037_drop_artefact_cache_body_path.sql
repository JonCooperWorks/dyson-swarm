-- Postgres twin of migrations/sqlite/0037_drop_artefact_cache_body_path.sql.

ALTER TABLE artefact_cache DROP COLUMN body_path;
