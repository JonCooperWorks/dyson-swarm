Slack-style HMAC fixture for Dyson Swarm verifier tests.

Headers:

`X-Slack-Request-Timestamp: 1700000000`
`X-Slack-Signature: v0=2fe4647cd9c1970d385177f613fee537c122efa6a48011ed5270b7e5a1b8f1c0`

The signed payload is `v0:1700000000:<raw body>` using HMAC-SHA256 and
hex output.
