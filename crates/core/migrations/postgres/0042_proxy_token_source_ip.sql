ALTER TABLE proxy_tokens ADD COLUMN expected_src_ip TEXT;

-- Rollback: intentionally not dropping expected_src_ip here. Dropping a
-- column in the same rollout that starts writing it would strand mixed-version
-- swarms; remove it only in a dedicated backward-incompatible migration.
