-- Postgres twin of migrations/sqlite/0017_instance_tools.sql.
ALTER TABLE instances ADD COLUMN tools TEXT NOT NULL DEFAULT '[]';
