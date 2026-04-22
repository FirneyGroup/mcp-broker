# Slack Native Connector Setup

## How It Works

The Slack connector is a **native connector** — it implements MCP tools in-process using the Slack Web API via httpx, rather than proxying to a remote MCP server.

When a user installs the Slack app:

1. **Redirect** — Broker redirects to `slack.com/oauth/v2/authorize` with the requested bot scopes.
2. **Consent** — User approves the scopes in their Slack workspace and selects where the app can post.
3. **Token Exchange** — Broker exchanges the auth code at `slack.com/api/oauth.v2.access` (client_secret_post, the broker default).
4. **Storage** — The returned `xoxb-...` bot token is encrypted and stored per-app in the broker's token store.

All outbound messages post **as the bot app** (whatever name you set in the Slack app), never as the installing user.

## 1. Create the Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** → **From scratch**.
2. Name the app (e.g. "Acme Bot") and pick the workspace to develop in, then click **Create App**. You'll land on the **Basic Information** page.

## 2. Configure OAuth & Permissions

From the left sidebar, click **OAuth & Permissions**.

**Add the Redirect URL.** Scroll to **Redirect URLs** → **Add New Redirect URL** → paste:

- Deployed broker: `https://your-broker-domain/oauth/slack/callback`
- Local broker on your laptop: `http://localhost:8002/oauth/slack/callback`

Click **Add**, then **Save URLs**. Slack requires HTTPS for non-localhost redirects — if the broker lives behind Cloudflare / ngrok / similar, use the HTTPS public URL, not the raw internal one.

**Add the Bot Token Scopes.** Scroll to **Scopes** → **Bot Token Scopes** → **Add an OAuth Scope** for each of these:

- `chat:write` — post messages and delete the bot's own messages
- `chat:write.public` — post to public channels without joining them
- `im:write` — open DM channels with users
- `users:read` — resolve @handles and names
- `channels:read` — resolve public channel names
- `groups:read` — resolve private channel names (only if the bot will be invited to private channels)

## 3. Copy App Credentials

From the left sidebar, go back to **Basic Information** → **App Credentials**. Copy the **Client ID** and click **Show** next to **Client Secret** to copy that too.

Optionally, set a display name and icon under **Basic Information** → **Display Information** — this is how the bot appears in Slack.

## 4. Configure Environment

Add the credentials to your broker's `.env`:

```bash
# Slack (from api.slack.com/apps → Basic Information → App Credentials)
SLACK_CLIENT_ID=your-client-id-here
SLACK_CLIENT_SECRET=your-client-secret-here
```

No optional dependencies — `httpx` is a core broker dependency.

## 5. Configure Settings

Add `slack` to the broker's connector list, to each app's `allowed_connectors`, and to the per-app credential block in `settings.yaml`:

```yaml
broker:
  connectors:
    - slack
    # ... other connectors

clients:
  my_company:
    app1:
      allowed_connectors: [slack]  # or add slack to existing list

apps:
  my_company:
    app1:
      slack:
        client_id: ${SLACK_CLIENT_ID}
        client_secret: ${SLACK_CLIENT_SECRET}
```

## 6. Restart the Broker

`.env` is read at broker startup — new variables don't take effect until the process restarts.

- Local dev: `./start start` picks up `.env` on each run.
- Docker: `docker restart <broker-container>` (e.g. `docker restart mcp-broker`).
- systemd / other supervisors: restart the unit.

## 7. Install the App to Your Workspace

```bash
./start connect                          # broker on this machine
./start connect https://your-broker-url  # broker reachable via a public URL
```

Pick **Slack** from the connector list. The script opens your browser for OAuth consent; approve in Slack and wait for the "connected" confirmation.

## 8. Verify Connection

Set `BROKER_URL` to the broker you're targeting (`http://localhost:8002` for local, or your public URL), then:

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "$BROKER_URL/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "slack", "connected": true, "token_valid": true`.

## 9. Test MCP Proxy

```bash
# List available tools
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "$BROKER_URL/proxy/slack/mcp" | python3 -m json.tool

# DM the bot owner (replace @handle with your Slack handle)
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"send_dm","arguments":{"recipient":"@your.handle","text":"hello from the broker"}}}' \
  "$BROKER_URL/proxy/slack/mcp" | python3 -m json.tool

# Post into a public channel the bot has not joined (tests chat:write.public)
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"send_message","arguments":{"channel":"#random","text":"bot post"}}}' \
  "$BROKER_URL/proxy/slack/mcp" | python3 -m json.tool
```

## Available MCP Tools

| Tool | Description | Required Scope |
|------|-------------|----------------|
| `send_dm` | DM a user (by id / @handle / name) | `chat:write`, `im:write`, `users:read` |
| `send_message` | Post to a channel (by id / name / #name) | `chat:write`, `chat:write.public`, `channels:read` |
| `update_message` | Edit a previously-posted message | `chat:write` |
| `delete_message` | Delete a previously-posted message (bot's own) | `chat:write` |
| `find_user` | List candidate users matching a query | `users:read` |
| `find_channel` | List candidate channels matching a query | `channels:read`, `groups:read` |

## Slack OAuth Specifics

| Behaviour | Detail |
|-----------|--------|
| **Connector type** | Native (in-process via httpx, no remote MCP server) |
| **Auth method** | `client_secret_post` — credentials in POST body (broker default) |
| **Authorize URL** | `https://slack.com/oauth/v2/authorize` |
| **Token URL** | `https://slack.com/api/oauth.v2.access` |
| **Scopes** | `chat:write`, `chat:write.public`, `im:write`, `users:read`, `channels:read`, `groups:read` |
| **PKCE** | Enabled (broker default; Slack supports S256) |
| **Bot token** | `xoxb-...` — returned in the top-level `access_token` field of the OAuth response |
| **Token TTL** | Non-expiring unless token rotation is enabled in the Slack app config (leave off for simplicity) |
| **Redirect URI** | Must be HTTPS (no localhost exception for non-localhost). Exact-match or subdirectory only — no wildcards |

## Security Notes

- **URL unfurling disabled by default.** All `chat.postMessage` calls set `unfurl_links=false, unfurl_media=false`. This mitigates the URL-unfurling-as-exfiltration side channel surfaced by the archived Anthropic Slack MCP CVE. Do not opt in to unfurling for messages containing user-supplied URLs.
- **Bot identity only.** The connector does not accept `as_user=true`. Messages cannot be posted as the installing user.
- **No history/read scopes.** The bot cannot read messages, threads, or reactions. If an Events API subscription is added later, treat inbound content as untrusted — the `chat.postMessage` code path is outbound-only and safe today.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `invalid_redirect_uri` during OAuth | Slack rejects the redirect URI — verify the Slack app's OAuth & Permissions → Redirect URLs exactly matches `{broker.public_url}/oauth/slack/callback`, HTTPS, no trailing slash on the `public_url` unless Slack has it too. |
| `missing_scope` on a tool call | Token was issued without one of the scopes. Re-install via `./start connect` after updating the Slack app's Bot Token Scopes. |
| `not_in_channel` on `send_message` | Channel is private or the bot hasn't been invited. Either invite the bot or confirm `chat:write.public` is present (for public channels). |
| `user_not_visible` / `user_disabled` on `send_dm` | Recipient is a guest user or deactivated member. DM to full workspace members only. |
| `ambiguous_name` from `send_dm` | Two users share the same real/display name. Use `find_user` to see candidates and pass a `@handle` or Slack user ID instead. |
| `channel_not_found` | The channel name doesn't exist or `conversations.list` cache is stale. Wait 5 minutes for TTL or call `find_channel` to repopulate. |
| `msg_too_long` | Message exceeds 4,000 characters. Split into multiple messages or use Block Kit. |
| `token_revoked` / `invalid_auth` | Bot was uninstalled from the Slack workspace. Re-run `./start connect`. |
