AgentMail fixture for Dyson Swarm verifier tests.

AgentMail documents Svix-based webhook verification:

- https://docs.agentmail.to/webhook-verification
- https://www.svix.com/guides/receiving/receive-webhooks-with-svix-cli/

Headers:

`svix-id: msg_agentmail_1`
`svix-timestamp: 1700000000`
`svix-signature: v1,oug8mHA2dpffa4PvUVQusImcR2iyw0xgEzhxwzfti4w=`

The signed payload is `msg_agentmail_1.1700000000.<raw body>`. The
secret uses the Svix `whsec_` form; the verifier decodes the base64
portion after the prefix and uses those bytes as the HMAC key.
