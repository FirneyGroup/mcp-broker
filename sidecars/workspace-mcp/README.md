# Google Workspace MCP Sidecar

Community MCP server for Google Workspace (Drive, Calendar, Gmail, Docs, Sheets). Runs as a stateless HTTP server that trusts Bearer tokens injected by the broker.

The **broker manages Google OAuth per-app** — the sidecar runs in External OAuth Provider mode and uses the same Google OAuth credentials for token validation only (not for running OAuth flows).

## Setup

### 1. Create Google Cloud OAuth credentials

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

### 2. Configure credentials

The same Google OAuth credentials are needed in **two places**:

**Broker's `.env`** — used to run OAuth flows and obtain tokens:
```bash
# In mcp-broker/.env
GOOGLE_OAUTH_CLIENT_ID=your-client-id-here
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret-here
```

**Sidecar's `.env`** — used to validate incoming Bearer tokens:
```bash
# In sidecars/workspace-mcp/.env
GOOGLE_OAUTH_CLIENT_ID=your-client-id-here
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret-here
```

Both must use the same credentials. Ensure `workspace_mcp` is in the broker's `settings.yaml` connectors list and apps section (see `settings.example.yaml`).

### 3. Create the shared network (once)

```bash
docker network create sidecar-internal
```

### 4. Start the sidecar

```bash
cd sidecars/workspace-mcp
docker compose build && docker compose up -d
```

### 5. Start the broker

```bash
WORKSPACE_MCP_URL=http://localhost:8010/mcp PYTHONPATH=src uvicorn broker.main:app --port 8002
```

### 6. Connect a Google account

Open in your browser:

```
http://localhost:8002/oauth/workspace_mcp/connect?app_key=my_company:app1&broker_key=YOUR_BROKER_KEY
```

This redirects to Google's consent screen. After authorizing, the broker stores the token and all subsequent proxy requests include it automatically.

### 7. Verify

```bash
# Check container health
docker compose ps

# Check broker sees it
curl http://localhost:8002/health
# workspace_mcp should show auth_mode: "broker"

# List tools via broker (note: /proxy/workspace_mcp/ not /proxy/workspace_mcp/mcp/)
curl -X POST http://localhost:8002/proxy/workspace_mcp/ \
  -H "X-App-Id: my_company:app1" \
  -H "X-Broker-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## Multi-App Setup

Each app gets its own Google account. To add workspace_mcp for a new app:

1. Add the app's broker key to `settings.yaml` under `broker.app_keys`
2. Add `workspace_mcp` credentials under `apps.{client}.{app}.workspace_mcp`
3. Have the user authorize via `/oauth/workspace_mcp/connect?app_key={app_key}`

Tokens are stored per-app in the broker's encrypted SQLite store. Token refresh happens automatically.

## Local Dev

When running the broker outside Docker, the sidecar publishes port 8010 to the host via `HOST_PORT` in `.env`. Start the broker with:

```bash
WORKSPACE_MCP_URL=http://localhost:8010/mcp PYTHONPATH=src uvicorn broker.main:app --port 8002
```

In production (broker in Docker), clear `HOST_PORT=` — the broker reaches the sidecar via `workspace-mcp:8000` on the `sidecar-internal` network.

## Troubleshooting

- **Container won't start**: `docker compose logs`
- **Broker can't reach sidecar**: Ensure both are on `sidecar-internal` network
- **"App not verified" warning**: Expected for test users — click "Continue"
- **401 from proxy**: No token stored — connect via `/oauth/workspace_mcp/connect`
- **Token expired**: Broker refreshes automatically. If refresh fails, re-connect.
