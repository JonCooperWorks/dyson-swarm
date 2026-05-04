-- Postgres twin of migrations/sqlite/0025_webhook_secrets_user_scope.sql.
-- See the sqlite version for design rationale.

INSERT INTO user_secrets (user_id, name, ciphertext, created_at, updated_at)
SELECT
  i.owner_id,
  'webhook:' || w.instance_id || ':' || w.name,
  s.ciphertext,
  s.created_at,
  s.updated_at
FROM instance_webhooks w
JOIN instances i
  ON i.id = w.instance_id
JOIN instance_secrets s
  ON s.instance_id = w.instance_id
 AND s.name = w.secret_name
WHERE w.secret_name LIKE '\_webhook\_%' ESCAPE '\'
ON CONFLICT(user_id, name) DO UPDATE SET
  ciphertext = excluded.ciphertext,
  updated_at = excluded.updated_at;

DELETE FROM instance_secrets s
WHERE s.name LIKE '\_webhook\_%' ESCAPE '\'
  AND EXISTS (
    SELECT 1
    FROM instance_webhooks w
    WHERE w.instance_id = s.instance_id
      AND w.secret_name = s.name
  );

UPDATE instance_webhooks
SET secret_name = 'webhook:' || instance_id || ':' || name
WHERE secret_name LIKE '\_webhook\_%' ESCAPE '\';
