# Twitter/X Native Connector Setup

## How It Works

The Twitter connector is a **native connector** — it implements MCP tools in-process using the [xdk](https://pypi.org/project/xdk/) Python SDK instead of proxying to a remote MCP server.

When a user clicks "Connect Twitter":

1. **Redirect** — Broker redirects to `x.com/i/oauth2/authorize` with PKCE challenge
2. **Consent** — User approves read/write scopes on X's consent page
3. **Token Exchange** — Broker exchanges the auth code at `api.x.com/2/oauth2/token` using HTTP Basic Auth
4. **Storage** — Tokens are encrypted and stored per-app

## 1. Create an X Developer App

1. Go to [X Developer Portal](https://developer.x.com/)
2. Create a new **Project** and **App**
3. Under **User authentication settings**, enable **OAuth 2.0**
4. Set type to **Confidential client**
5. Set the callback URL:
   - Local: `http://localhost:8002/oauth/twitter/callback`
   - Production: `https://your-broker-domain/oauth/twitter/callback`
6. Copy the **Client ID** and **Client Secret**

## 2. Configure Environment

Add the credentials to your `.env`:

```bash
# Twitter/X (OAuth 2.0 Confidential Client)
# Redirect URI: http://localhost:8002/oauth/twitter/callback
TWITTER_OAUTH2_CLIENT_ID=your-client-id-here
TWITTER_OAUTH2_CLIENT_SECRET=your-client-secret-here
```

Install the optional xdk dependency:

```bash
pip install -e ".[twitter]"
```

## 3. Configure Settings

Add Twitter credentials under `apps` in `settings.yaml`:

```yaml
apps:
  my_company:
    app1:
      twitter:
        client_id: ${TWITTER_OAUTH2_CLIENT_ID}
        client_secret: ${TWITTER_OAUTH2_CLIENT_SECRET}
```

## 4. Connect via Script

```bash
PYTHONPATH=src python scripts/connect.py --app "my_company:app1"
```

Select Twitter from the connector list. The script opens your browser for OAuth consent, then polls until connected.

## 5. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "twitter", "connected": true, "token_valid": true`.

## 6. Test MCP Proxy

```bash
# List available tools
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/twitter/mcp" | python3 -m json.tool

# Get authenticated user profile
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": {"name": "get_me", "arguments": {}}}' \
  "http://localhost:8002/proxy/twitter/mcp" | python3 -m json.tool
```

Should return a list of Twitter MCP tools, then the authenticated user's profile.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `post_tweet` | Post a tweet (max 280 chars) |
| `get_me` | Get authenticated user's profile (id, name, username) |
| `delete_tweet` | Delete a tweet by ID |
| `get_my_tweets` | Get the authenticated user's recent tweets (default 10, max 100) |
| `search_tweets` | Search recent public tweets by query (requires Basic tier — $200/mo) |

## Twitter/X OAuth Specifics

These are handled automatically by `TwitterConnector` — documented here for reference.

| Behaviour | Detail |
|-----------|--------|
| **Connector type** | Native (in-process via xdk SDK, no remote MCP server) |
| **Auth method** | `client_secret_basic` — HTTP Basic Auth header (base64-encoded `client_id:client_secret`) |
| **Authorize URL** | `https://x.com/i/oauth2/authorize` |
| **Token URL** | `https://api.x.com/2/oauth2/token` |
| **Scopes** | `tweet.read`, `tweet.write`, `users.read`, `offline.access` |
| **PKCE** | Required (S256) — the broker sends PKCE on all flows automatically |
| **Token refresh** | Supported via `offline.access` scope — broker refreshes automatically |
| **SDK** | [xdk](https://pypi.org/project/xdk/) — sync/requests-based, wrapped in `run_in_executor` |
| **Free tier limits** | 500 posts/month write, 10k reads/month, no search |
| **Basic tier** ($200/mo) | 3k posts/month, 50k reads/month, search recent (7 days) |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OAuth redirect fails | Check callback URL in X Developer Portal matches exactly |
| "Unauthorized" on /connect | Missing or wrong `X-Broker-Key` header for your app |
| Token exchange fails (401) | Verify `TWITTER_OAUTH2_CLIENT_ID` and `TWITTER_OAUTH2_CLIENT_SECRET` in `.env` |
| `search_tweets` returns 400 | Your X app is on Free tier — search requires Basic ($200/mo) |
| `post_tweet` returns 403 | Check your app has write permissions enabled in X Developer Portal |
| Tweet exceeds 280 chars | Connector validates locally before calling X API |
| Token expired | Broker auto-refreshes via `offline.access` scope. If still failing, reconnect |
| `ImportError: xdk` | Run `pip install -e ".[twitter]"` to install the optional dependency |

## Sources

- [X API v2 Documentation](https://developer.x.com/en/docs/x-api)
- [X OAuth 2.0 with PKCE](https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code)
- [xdk Python SDK](https://pypi.org/project/xdk/)
