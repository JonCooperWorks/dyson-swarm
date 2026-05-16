# Controllers and Channels

Swarm owns the hosted controller surfaces that sit outside a Dyson cube. For
Telegram channels, this is intentionally more than UI plumbing: swarm stores the
BotFather token, validates and configures the webhook, authenticates inbound
Telegram traffic, and proxies every Telegram API call for the agent.

The important boundary is that the bot token must never enter the Dyson agent
process. If the token reaches the cube, it can reach config files, logs,
workspace state, tools, transcripts, and LLM context. Swarm-owned Telegram
channels are designed so the cube only sees swarm proxy URLs and its normal
per-instance proxy bearer.

## Telegram Channel Lifecycle

The "Channels" tab on an instance currently supports one Telegram bot per
agent. There is no bot reuse across instances in v1.

When a user connects a bot:

1. The browser validates the token shape before submitting.
2. Swarm calls Telegram `getMe` with the raw token.
3. Swarm extracts the bot username and displays it as `@handle`.
4. Swarm generates a random webhook secret token.
5. Swarm calls Telegram `setWebhook` with:
   - `url = https://<swarm-host>/v1/channels/telegram/<instance_id>/webhook`
   - `secret_token = <generated secret>`
   - `allowed_updates = ["message", "edited_message", "callback_query", "channel_post"]`
6. Only after both Telegram calls succeed, swarm seals the bot token and
   webhook secret in `user_secrets`.
7. Swarm writes the `instance_channels` row.
8. Swarm reconfigures the Dyson cube with a token-free Telegram proxy config.

The connect panel can save the initial sender allowlist in the same request as
the token. If the list is empty, the UI warns that anyone who can find or
message the bot can talk to the agent and requires explicit confirmation before
connecting or saving that open state.

Failed `getMe` or `setWebhook` calls persist nothing. Disconnecting best-effort
calls Telegram `deleteWebhook`, deletes both sealed secrets, deletes the channel
row, and reconfigures the cube back out of Telegram mode. Pausing a channel keeps
the Telegram webhook configured but makes swarm acknowledge and drop inbound
updates.

## Storage

The durable channel row lives in `instance_channels`:

- `instance_id` identifies the owning cube.
- `kind` is currently `telegram`.
- `handle` stores the display handle, for example `@my_bot`.
- `secret_name` points to the sealed BotFather token.
- `webhook_secret_name` points to the sealed Telegram webhook secret token.
- `enabled` controls pause/resume.
- `allowed_senders` stores a JSON array of normalized Telegram user IDs and
  usernames allowed to drive the bot. Leading `@` is accepted in the UI/API but
  stripped before storage. Empty means anyone who can message the
  bot is allowed.
- `last_inbound_at` updates on webhook delivery.

Secrets are stored through `UserSecretsService` with fixed names:

```text
channel:telegram:<instance_id>:bot-token
channel:telegram:<instance_id>:webhook-secret
```

Recent inbound deliveries are stored separately for the debugging panel. They
include timestamp, status, and a redacted text preview. They do not store sender
identity or Telegram message IDs.

## Inbound Webhook Flow

Telegram posts updates to swarm:

```text
User phone
  -> Telegram
  -> POST /v1/channels/telegram/<instance_id>/webhook
  -> swarm verifies X-Telegram-Bot-Api-Secret-Token
  -> swarm looks up the live instance and channel row
  -> swarm forwards the JSON body to POST /webhook/telegram in the cube
  -> Dyson authenticates the instance bearer
  -> Dyson enqueues the update into its Telegram controller
```

Swarm compares the Telegram secret header against the sealed webhook secret
without data-dependent early exit. Missing or wrong secrets return 401. If the
channel is paused, swarm returns 200 and records a dropped delivery without
forwarding to the cube.

After the secret check, swarm applies the optional sender allowlist. The
allowlist accepts numeric Telegram user IDs and usernames; a leading `@` is
stripped, entries are lowercased and deduplicated when saved. When the list is
non-empty, swarm
extracts `message.from`, `edited_message.from`, `callback_query.from`, or
`channel_post.from` from the update JSON and compares only the sender ID and
username. Non-matching updates are acknowledged with 200 so Telegram does not
retry, recorded in Recent messages with status 403, and never forwarded into
the cube.

The forwarded request is deliberately small:

- body: the original Telegram JSON bytes
- header: `Content-Type`, when present
- auth: `Authorization: Bearer <instance proxy bearer>`

Telegram-side headers are not forwarded. The bot token and webhook secret are
never forwarded.

## Outbound Telegram Proxy

The cube sees a Telegram-shaped API rooted at swarm:

```text
https://<swarm-host>/v1/proxy/telegram/<instance_id>/<method>
https://<swarm-host>/v1/proxy/telegram/<instance_id>/file/<file_path>
```

Dyson's Telegram controller calls those URLs with the instance proxy bearer. The
swarm proxy:

1. Authenticates the bearer and ensures it belongs to the requested instance.
2. Loads the sealed bot token from `user_secrets`.
3. Rewrites method calls to
   `https://api.telegram.org/bot<TOKEN>/<method>`.
4. Rewrites file downloads to
   `https://api.telegram.org/file/bot<TOKEN>/<file_path>`.
5. Strips the inbound `Authorization` header before calling Telegram.
6. Streams Telegram's response back with the original status, body, and content
   type.

Only Telegram-shaped method and file paths are forwarded. The proxy does not
accept arbitrary upstream URLs, and swarm's own egress policy must allow
`api.telegram.org`.

## Cube Reconfiguration

Swarm configures Dyson with webhook mode and a proxy block, not a bot token:

```json
{
  "telegram_proxy": {
    "base_url": "https://<swarm-host>/v1/proxy/telegram/<instance_id>",
    "file_base_url": "https://<swarm-host>/v1/proxy/telegram/<instance_id>/file",
    "bearer": "<instance proxy bearer>",
    "enabled": true
  }
}
```

Dyson turns that into a Telegram controller config with:

```json
{
  "type": "telegram",
  "mode": "webhook",
  "allow_all_chats": true,
  "proxy": {
    "base_url": "...",
    "file_base_url": "...",
    "bearer": "..."
  }
}
```

The legacy direct-token Telegram mode remains available to non-swarm Dyson
users, but swarm-owned instances must use the proxy shape. `bot_token` and
`proxy` are mutually exclusive in Dyson's Telegram controller config.

## UI Surface

The instance editor has a "Channels" tab with three states:

- Empty state: a Telegram connect card.
- Connect panel: BotFather instructions, a password-style token input, and the
  initial sender allowlist on one page, local token-shape validation, and
  connect feedback from Telegram.
- Connected state: handle, status dot, last message time, open-in-Telegram,
  pause/resume, sender allowlist, recent deliveries, and disconnect.

The token input is never populated from server data. The server returns the
handle and metadata, never the token.

## Operational Checks

After deploy, existing live instances need to be destroyed and recreated to pick
up the Dyson image that knows how to receive `/webhook/telegram` and use the
proxy BotApi.

The key integrity check is a real-token log grep against the cube:

```sh
grep -R '<real bot token>' <cube logs>
```

The command must produce no output. A match means the token crossed the boundary
and the deployment is unsafe.
