ALTER TABLE proxy_tokens ADD COLUMN token_lookup TEXT;

CREATE INDEX idx_proxy_tokens_lookup_live
  ON proxy_tokens(token_lookup)
  WHERE revoked_at IS NULL AND token_lookup IS NOT NULL;
