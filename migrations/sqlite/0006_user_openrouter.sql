-- Per-user OpenRouter API keys.
--
-- Each tenant gets their own OR-side key, minted lazily on first /llm
-- call.  Two columns:
--   * `openrouter_key_id` — stable identifier returned by OR's
--     Provisioning API (POST /v1/keys → data.id).  We keep it on the
--     user row so PATCH /limit and DELETE on suspend can address the
--     same key without round-tripping the (sealed) plaintext.
--   * `openrouter_key_limit_usd` — admin-configurable USD cap.
--     Default $10 — enough for the agent to do something useful while
--     limiting blast radius from a leaked key.  Admins raise per
--     tenant via PATCH /v1/admin/users/:id/openrouter_limit.
--
-- The plaintext OR key itself lives in `user_secrets` under
-- `name = 'openrouter_key'`, sealed via the user's envelope cipher
-- (one age key per user, keys_dir).  warden never logs it; the proxy
-- decrypts it on each LLM call and substitutes for the global
-- provider api_key when forwarding to OpenRouter.

ALTER TABLE users ADD COLUMN openrouter_key_id TEXT;
ALTER TABLE users ADD COLUMN openrouter_key_limit_usd REAL NOT NULL DEFAULT 10.0;

CREATE INDEX idx_users_openrouter_key_id ON users(openrouter_key_id)
  WHERE openrouter_key_id IS NOT NULL;
