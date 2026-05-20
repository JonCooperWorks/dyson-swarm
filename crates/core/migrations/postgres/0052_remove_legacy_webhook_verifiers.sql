-- Postgres twin of migrations/sqlite/0052_remove_legacy_webhook_verifiers.sql.

UPDATE instance_webhooks
SET verifier_mode = 'hmac_v2',
    signature_algo = COALESCE(signature_algo, 'sha256'),
    signature_encoding = COALESCE(signature_encoding, 'hex'),
    signature_value_split = COALESCE(signature_value_split, '='),
    payload_template = COALESCE(payload_template, '{{body}}')
WHERE verifier_mode = 'legacy_hmac';

UPDATE instance_webhooks
SET verifier_mode = 'operator_action_required'
WHERE verifier_mode = 'legacy_bearer';
