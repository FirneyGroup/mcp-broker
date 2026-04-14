# Google Workspace MCP Connector Setup

## How It Works

The Google Workspace connector uses a **sidecar architecture** — a community MCP server ([google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp)) runs in a Docker container with `EXTERNAL_OAUTH21_PROVIDER=true`. The broker manages Google OAuth per-app and injects Bearer tokens on each proxied request.

When a user clicks "Connect Google Workspace":

1. **Redirect** — Broker redirects to `accounts.google.com/o/oauth2/v2/auth` with PKCE challenge
2. **Consent** — User approves Google Workspace scopes (Gmail, Drive, Calendar, Docs, Sheets)
3. **Token Exchange** — Broker exchanges the auth code at `oauth2.googleapis.com/token`
4. **Storage** — Tokens are encrypted and stored per-app
5. **Proxy** — Each proxied request includes `Authorization: Bearer ya29.*`, validated by the sidecar

## 1. Create a Google Cloud OAuth Client

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a project (or select an existing one)
3. Enable these APIs (APIs & Services > Library):
   - Gmail API
   - Google Drive API
   - Google Calendar API
   - Google Docs API
   - Google Sheets API
4. Configure the OAuth consent screen (APIs & Services > OAuth consent screen):
   - User type: External (or Internal for Workspace orgs)
   - App name: anything (e.g. "Workspace MCP")
   - Add your email as a test user
5. Create credentials (APIs & Services > Credentials):
   - Click **+ CREATE CREDENTIALS** > **OAuth client ID**
   - Application type: **Web application**
   - Add authorized redirect URI: `http://localhost:8002/oauth/workspace_mcp/callback`
   - Click **CREATE**
6. Copy the **Client ID** and **Client Secret**

## 2. Configure Environment

Add credentials to **both** the broker's `.env` and the sidecar's `.env`:

```bash
# In mcp-broker/.env (broker uses these for OAuth flows)
GOOGLE_OAUTH_CLIENT_ID=your-client-id-here
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret-here

# In sidecars/workspace-mcp/.env (sidecar uses these for token validation)
GOOGLE_OAUTH_CLIENT_ID=your-client-id-here
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret-here
```

Both must be the **same credentials**.

## 3. Start the Sidecar

```bash
docker network create sidecar-internal  # once
cd sidecars/workspace-mcp
docker compose build && docker compose up -d
```

## 4. Configure Settings

Ensure `settings.yaml` has `workspace_mcp` in the connectors list and credentials mapped under `apps`:

```yaml
broker:
  connectors:
    - workspace_mcp
    # ... other connectors

apps:
  my_company:
    app1:
      workspace_mcp:
        client_id: ${GOOGLE_OAUTH_CLIENT_ID}
        client_secret: ${GOOGLE_OAUTH_CLIENT_SECRET}
```

## 5. Connect via Browser

Open in your browser:

```
http://localhost:8002/oauth/workspace_mcp/connect?app_key=my_company:app1&broker_key=YOUR_BROKER_KEY
```

Authorize on Google's consent screen. The broker stores the token and refreshes it automatically.

## 6. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "workspace_mcp", "connected": true, "token_valid": true`.

## 7. Test MCP Proxy

MCP Streamable HTTP requires a session. Initialize first, then call tools:

```bash
# Initialize (note the Accept header — required by Streamable HTTP)
curl -s -D - -X POST http://localhost:8002/proxy/workspace_mcp/ \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
# Note the Mcp-Session-Id header in the response

# Search Gmail (use the session ID from above)
curl -s -X POST http://localhost:8002/proxy/workspace_mcp/ \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: YOUR_SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"search_gmail_messages","arguments":{"query":"is:inbox","page_size":3}}}'
```

## Multi-App Setup

Each app gets its own Google account. To add workspace_mcp for a second app:

1. Add the app's broker key to `settings.yaml` under `broker.app_keys`
2. Add `workspace_mcp` credentials under `apps.{client}.{app}.workspace_mcp`
3. Have the user authorize via `/oauth/workspace_mcp/connect?app_key={app_key}`

Tokens are stored per-app — each app has its own Google account and token.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `search_gmail_messages` | Search Gmail by query (supports Gmail search operators) |
| `get_gmail_message_content` | Read full email content by message ID |
| `send_gmail_message` | Send an email |
| `list_drive_files` | List files in Google Drive |
| `read_drive_file` | Read file content from Drive |
| `list_calendar_events` | List upcoming calendar events |
| `create_calendar_event` | Create a calendar event |
| `read_spreadsheet` | Read data from Google Sheets |
| `update_spreadsheet` | Write data to Google Sheets |

See the [workspace-mcp repo](https://github.com/taylorwilsdon/google_workspace_mcp) for the full tool list.

## Google OAuth Specifics

These are handled automatically by `WorkspaceMcpConnector` — documented here for reference.

| Behaviour | Detail |
|-----------|--------|
| **OAuth type** | Google OAuth 2.0 (Web application) |
| **Auth method** | `client_secret_post` — credentials in POST body (default `BaseConnector` behavior) |
| **Endpoints** | `accounts.google.com/o/oauth2/v2/auth` and `oauth2.googleapis.com/token` |
| **MCP URL** | `http://workspace-mcp:8000/mcp` (Docker) or `http://localhost:8010/mcp` (local dev) |
| **MCP transport** | Streamable HTTP |
| **Scopes** | `openid email profile gmail.modify drive calendar documents spreadsheets` |
| **PKCE** | Supported (S256) — broker sends PKCE on all flows |
| **Refresh tokens** | `access_type=offline` + `prompt=consent` in authorize params |
| **Sidecar mode** | `EXTERNAL_OAUTH21_PROVIDER=true` — sidecar validates tokens, doesn't run OAuth |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OAuth redirect fails | Check redirect URI in GCP Console matches `http://localhost:8002/oauth/workspace_mcp/callback` |
| "App not verified" warning | Expected for test users — click "Continue" in Google's consent screen |
| Sidecar won't start | Check `docker compose logs` — may need `MCP_ENABLE_OAUTH21=true` |
| "OAuth 2.1 mode requires authenticated user" | Sidecar missing `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` in its `.env` |
| 404 from proxy | Use `/proxy/workspace_mcp/` not `/proxy/workspace_mcp/mcp/` — `mcp_url` already includes `/mcp` |
| 401 from proxy | No token stored — connect via `/oauth/workspace_mcp/connect` |
| Token expired | Broker refreshes automatically. If refresh fails, re-connect |
| 502 "Cannot reach" | Sidecar is down — check `docker compose ps` and restart if needed |
