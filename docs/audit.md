# Audit

Swarm keeps forensic audit state on the host, not inside the cube. Sandboxes
are disposable; audit rows live with the durable swarm state and survive
instance rotation, recreate, and cube replacement.

## Audit Surfaces

The main audit surfaces are:

- `llm_audit`: one row per proxied LLM request, including provider, model,
  status, token counts when available, and completion state.
- `mcp_audit`: one row per MCP proxy transport call, including owner,
  instance, server, tool, status, duration, and completion state.
- `llm_tool_call`: one row per model-emitted tool call, with the sealed
  tool input and the sealed result attached after the following turn.

Do not fold these tables together. They answer related but different
questions: "which model call happened?", "which MCP transport call happened?",
and "which tool did the model ask the agent to run, with what input/result?"

## LLM Tool-Call Audit

`llm_tool_call` captures every `tool_use -> tool_result` pair that passes
through the LLM proxy:

- native tools such as `bash` and editor tools
- MCP-routed tools named as `mcp__{server}__{tool}`
- Anthropic SSE `tool_use` blocks
- OpenAI/OpenRouter SSE `choices[].delta.tool_calls[]` function calls

The call side is inserted while streaming the model response. The result side
is attached from the next request body when Dyson sends the prior
`tool_result` back to the model. Until the result arrives, `resulted_at` and
`is_error` are null.

Payload size is capped before sealing. Oversized input or result JSON is
replaced with a sealed JSON marker containing `_truncated: true` and a UTF-8
prefix. There is no plaintext payload search index.

## Encryption Model

Tool-call input and result payloads are sealed with the owner's age identity,
using the same envelope pattern as user secrets. Metadata stays plaintext:

- owner id
- instance id
- tool use id
- tool name
- MCP server name when parsed from `mcp__...`
- timestamps
- status/error bit
- foreign keys to `llm_audit` and best-effort `mcp_audit`

This is IDOR, SQL injection, and database-exfiltration protection. It is not
operator protection: a host operator with access to the per-owner age identity
can decrypt payloads through the normal server-side paths.

## MCP Cross-Linking

For tool names that start with `mcp__`, swarm parses the server and tool name
and tries to link the `llm_tool_call` row to the matching `mcp_audit` row.

The link is best effort. The LLM tool-call row and MCP transport row are
written from different request paths, so swarm retries the link briefly and
does not fail user traffic if no transport row is found.

## API

Tenant-authenticated per-instance routes:

```text
GET /v1/instances/:id/audit/tool-calls
GET /v1/instances/:id/audit/tool-calls/export
GET /v1/instances/:id/audit/tool-calls/facets
GET /v1/instances/:id/audit/tool-calls/stream
```

Supported list/export query parameters:

- `tool=<name>`
- `status=all|ok|err`
- `server=<mcp_server>`
- `q=<substring>`
- `before=<row_id>`
- `limit=<n>`; default 100, max 500

The server enforces instance ownership before reading rows. Decryption happens
server-side; the browser and API client receive plaintext JSON only after auth
and ownership checks pass.

`/stream` is SSE. It sends the last 50 matching rows in follow order, then
polls for new rows every second and emits `event: tool_call`. It sends a
heartbeat comment every 15 seconds.

`/export` returns NDJSON for the current filters. It is intentionally explicit
and uses the same decrypted row shape as the list endpoint.

`/facets` returns instance-wide distinct tool names and MCP server names. The
Activity UI uses it to populate searchable filter suggestions even when the
current `status`, `tool`, `server`, or payload search filter has no matching
rows.

## Web UI

The instance detail page has an Activity tab. It shows a live timeline of tool
calls with searchable filters for tool, status, MCP server, and decrypted
payload search. Filter no-match states keep the controls visible; only a truly
empty audit history shows the first-run empty state.

Rows show call time, tool name, duration when paired, status, and a short input
preview. Opening a row shows the full decrypted input/result JSON plus MCP
transport status and duration when a matching `mcp_audit` row was linked.

The UI keeps only a bounded in-memory tail. It is an operator/user visibility
surface, not the retention policy.

## What This Does Not Capture

This audit is specifically for tools invoked through model tool-use protocol
messages. It does not capture:

- arbitrary shell commands run outside an LLM `tool_use`
- cross-instance rollups
- retention or TTL decisions
- blind indexes or searchable encrypted payload columns

Those can be added later without changing the `llm_tool_call` contract.

## Operational Checks

After deploying a change in this area:

1. Run `cargo test -p dyson-swarm recording_body::tests`.
2. Run `cargo test -p dyson-swarm http::tests::tool_call_audit`.
3. Run the web tests for `activity.test.jsx` or `npm run build` in
   `crates/swarm/src/http/web`.
4. Redeploy swarm and verify:

```sh
curl -fsS -H "Authorization: Bearer $SWARM_API_KEY" \
  "http://$DYSON_CUBE_GATEWAY_IP:$DYSON_SWARM_PORT/v1/instances/$INSTANCE_ID/audit/tool-calls?limit=5"
```

An idle instance may legitimately return an empty `items` array. A forced or
real model tool call should create a row within a few seconds, and the next
request carrying the matching `tool_result` should attach the result side.
