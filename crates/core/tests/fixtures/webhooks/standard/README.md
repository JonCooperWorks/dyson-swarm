Standard Webhooks fixture for Dyson Swarm verifier tests.

Headers:

`webhook-id: msg_123`
`webhook-timestamp: 1700000000`
`webhook-signature: v1,wra4YjTmfmlGzjR8dmrWdQ/P1d0y1bbdInTre89XmGs=`

The signed payload is `msg_123.1700000000.<raw body>` using HMAC-SHA256
and base64 output.
