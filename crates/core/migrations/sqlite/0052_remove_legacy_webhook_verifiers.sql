-- Remove old webhook verifier modes from live rows.
--
-- HMAC rows move to the data-driven verifier with the same raw-body SHA-256
-- semantics. Bearer header rows cannot be converted safely because the modern
-- bearer verifier uses an unguessable URL path token; those rows require an
-- operator/user re-save to mint a new path token.

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
