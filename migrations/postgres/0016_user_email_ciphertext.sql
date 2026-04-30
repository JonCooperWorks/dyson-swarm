-- Postgres twin of migrations/sqlite/0016_user_email_ciphertext.sql.
ALTER TABLE users ADD COLUMN email_ciphertext TEXT;
