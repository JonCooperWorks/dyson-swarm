-- Postgres twin of migrations/sqlite/0015_instance_models.sql.
-- Same JSON-as-TEXT shape — the sqlx code path treats both backends
-- identically, decoding via serde_json regardless of column type.
ALTER TABLE instances ADD COLUMN models TEXT NOT NULL DEFAULT '[]';
