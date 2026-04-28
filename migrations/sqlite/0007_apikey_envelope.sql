-- Stage 4: envelope-encrypt user_api_keys.
--
-- Bearer tokens minted via /v1/admin/users/:id/keys are now stored as
-- ciphertext sealed with the OWNING USER's age key (same per-user envelope
-- pattern user_secrets uses).  A short fixed-width prefix is kept in
-- plaintext as the lookup oracle: on resolve, the auth path reads all
-- live rows whose prefix matches the bearer's first 8 hex chars, opens
-- each candidate's ciphertext, and constant-time-compares the decrypted
-- plaintext against the bearer.  Prefix collisions are statistically
-- negligible (32-bit space, single-digit lifetime keys per user) so the
-- expected per-resolve cost is one age open.
--
-- Token format: `dy_<32 hex>`.  The `dy_` literal makes warden-issued
-- tokens unmistakable in logs / dashboards (also gates the prefix-router
-- in BearerAuthenticator before any DB hit).
--
-- Existing rows are dropped: this migration lands before any production
-- bearer ships, and the old plaintext storage was the bug we're fixing.

DROP INDEX IF EXISTS idx_user_api_keys_user;
DROP TABLE user_api_keys;

CREATE TABLE user_api_keys (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  prefix      TEXT NOT NULL,        -- first 8 hex chars of the random part
  ciphertext  TEXT NOT NULL,        -- age-armored sealed token (per-user key)
  label       TEXT,
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER
);

CREATE INDEX idx_user_api_keys_prefix ON user_api_keys(prefix);
CREATE INDEX idx_user_api_keys_user ON user_api_keys(user_id);
