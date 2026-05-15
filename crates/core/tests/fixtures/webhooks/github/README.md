GitHub-style HMAC fixture for Dyson Swarm verifier tests.

The body is signed with HMAC-SHA256 using `secret.txt`.

Expected legacy header:

`X-Hub-Signature-256: sha256=1ae84c7f758faa88395f24d75a762947277389c2071f1c3c478492f6a2112d0d`

Source model: GitHub webhook signatures use the request body with `X-Hub-Signature-256`.
