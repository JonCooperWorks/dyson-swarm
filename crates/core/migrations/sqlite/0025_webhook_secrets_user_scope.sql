-- Move webhook verifier keys out of instance_secrets.
--
-- `instance_secrets` is agent runtime environment.  Webhook HMAC /
-- bearer verifier keys are infrastructure auth material and must not
-- be readable by the agent, so from this point forward `secret_name`
-- points into user_secrets under `webhook:<instance_id>:<webhook_name>`.

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

DELETE FROM instance_secrets
WHERE name LIKE '\_webhook\_%' ESCAPE '\'
  AND EXISTS (
    SELECT 1
    FROM instance_webhooks w
    WHERE w.instance_id = instance_secrets.instance_id
      AND w.secret_name = instance_secrets.name
  );

UPDATE instance_webhooks
SET secret_name = 'webhook:' || instance_id || ':' || name
WHERE secret_name LIKE '\_webhook\_%' ESCAPE '\';
