-- Rows written before state bodies moved from body_path files into
-- body_ciphertext cannot be replayed after body_path was dropped.
-- Keep explicit tombstones, but discard non-deleted metadata-only rows
-- so they cannot suppress snapshot fallback or clear identity fields.
DELETE FROM instance_state_files
WHERE deleted_at IS NULL
  AND body_ciphertext IS NULL;
