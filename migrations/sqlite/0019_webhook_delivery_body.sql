-- Audit storage for inbound webhook payloads.
--
-- The earlier delivery log captured metadata only (status, latency,
-- signature_ok, request_id, error).  This adds the request body as
-- a BLOB column so an operator can replay or audit a delivery
-- after the fact — useful when the agent's response is unexpected
-- and the operator needs to see exactly what came in.
--
-- Two columns rather than one so an oversize payload that's caught
-- and rejected up the stack still records its content-type +
-- length without forcing the bytes column to grow unbounded.  The
-- service layer caps `body` at MAX_WEBHOOK_BODY (4 MiB), the same
-- cap dyson's `/turn` enforces — past that the request is 413'd
-- before reaching the store.
--
-- The SPA never reads these columns.  Operator access is via the
-- swarm CLI (`swarm webhook deliveries body <id>`) or direct SQL —
-- the table is intentionally write-mostly, read-rarely.

ALTER TABLE webhook_deliveries ADD COLUMN body BLOB;
ALTER TABLE webhook_deliveries ADD COLUMN body_size INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN content_type TEXT;
