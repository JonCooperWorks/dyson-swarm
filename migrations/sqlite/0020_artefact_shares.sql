-- Anonymous link sharing for artefacts produced by per-instance dyson agents.
--
-- The URL itself is the capability: a postcard-encoded payload + an
-- HMAC-SHA256 signature, the signature key being a per-user 32-byte
-- secret stored in user_secrets under name `share_signing_key` (sealed
-- with the user's own age cipher).  Verification is stateless until
-- this table is consulted for revocation, so expired and bad-sig URLs
-- never reach SQLite.  This table indexes what's been issued (so the
-- SPA can list/revoke) and serves as the revocation oracle on the hot
-- path.
--
-- Why on swarm and not inside dyson: dyson holds the artefact bytes
-- behind its own per-instance bearer; swarm already holds that bearer
-- (instances.bearer_token) and proxies on the user's behalf.  Putting
-- shares here means dyson keeps zero unauthenticated paths and
-- distributed share state across N MicroVMs is avoided.
--
-- CASCADE on instance delete: destroying an instance kills its
-- shares atomically.  Audit rows survive the cascade so an operator
-- can still see "this share was hit before the instance was killed."

CREATE TABLE artefact_shares (
  jti          TEXT PRIMARY KEY,                     -- 32 hex of payload.jti, the revocation lookup key
  instance_id  TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  chat_id      TEXT NOT NULL,
  artefact_id  TEXT NOT NULL,
  created_by   TEXT NOT NULL,                        -- user_id; matches payload.user_id on the URL
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,                     -- mirrors payload.exp; in the row for UI listing/cleanup
  revoked_at   INTEGER,
  label        TEXT
);

CREATE INDEX artefact_shares_instance_idx
  ON artefact_shares(instance_id);

-- Useful for "list my live shares" and for a future GC sweep.  Filtered
-- on revoked_at IS NULL so the index stays small as revocations age.
CREATE INDEX artefact_shares_active_idx
  ON artefact_shares(created_by, expires_at)
  WHERE revoked_at IS NULL;

-- Audit trail.  Written only after a request has proven possession of
-- a valid signature on a real jti (steps 5+ of the hot path) — bad-sig
-- and expired requests do NOT generate rows here, by design, so a
-- flood of garbage URLs cannot write-amplify into this table.
--
-- `jti` is not an FK: rows survive instance/share deletion so an
-- operator can still answer "who hit this link before we revoked it?"

CREATE TABLE artefact_share_accesses (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  jti          TEXT NOT NULL,
  accessed_at  INTEGER NOT NULL,
  remote_addr  TEXT,
  user_agent   TEXT,
  status       INTEGER NOT NULL
);

CREATE INDEX artefact_share_accesses_jti_idx
  ON artefact_share_accesses(jti, accessed_at DESC);
