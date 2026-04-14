# Reddit Native Connector Setup

## How It Works

The Reddit connector is a **native connector** — it implements MCP tools in-process using the Reddit API via httpx instead of proxying to a remote MCP server.

When a user clicks "Connect Reddit":

1. **Redirect** — Broker redirects to `reddit.com/api/v1/authorize` with PKCE challenge
2. **Consent** — User approves read/write/edit scopes on Reddit's consent page
3. **Token Exchange** — Broker exchanges the auth code at `reddit.com/api/v1/access_token` using HTTP Basic Auth
4. **Storage** — Tokens are encrypted and stored per-app

## 1. Create a Reddit App

1. Go to [Reddit App Preferences](https://www.reddit.com/prefs/apps/)
2. Click **"create another app..."** at the bottom
3. Set type to **web app**
4. Set the redirect URI:
   - Local: `http://localhost:8002/oauth/reddit/callback`
   - Production: `https://your-broker-domain/oauth/reddit/callback`
5. Copy the **Client ID** (under the app name) and **Client Secret** (labeled "secret")

## 2. Configure Environment

Add the credentials to your `.env`:

```bash
# Reddit (OAuth 2.0 Web App)
# Redirect URI: http://localhost:8002/oauth/reddit/callback
REDDIT_CLIENT_ID=your-client-id-here
REDDIT_CLIENT_SECRET=your-client-secret-here
```

No optional dependencies needed — httpx is a core broker dependency.

## 3. Configure Settings

Add Reddit credentials under `apps` in `settings.yaml`:

```yaml
apps:
  my_company:
    app1:
      reddit:
        client_id: ${REDDIT_CLIENT_ID}
        client_secret: ${REDDIT_CLIENT_SECRET}
```

## 4. Connect via Script

```bash
PYTHONPATH=src python scripts/connect.py --app "my_company:app1"
```

Select Reddit from the connector list. The script opens your browser for OAuth consent, then polls until connected.

## 5. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "reddit", "connected": true, "token_valid": true`.

## 6. Test MCP Proxy

```bash
# List available tools
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/reddit/mcp" | python3 -m json.tool

# Get authenticated user profile
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": {"name": "get_me", "arguments": {}}}' \
  "http://localhost:8002/proxy/reddit/mcp" | python3 -m json.tool
```

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `get_me` | Get authenticated user's profile (username, karma) |
| `submit_post` | Submit a text or link post to a subreddit (title max 300 chars) |
| `add_comment` | Reply to a post or comment (max 10000 chars) |
| `search` | Search Reddit for posts, optionally within a subreddit |
| `get_subreddit_posts` | Get posts from a subreddit (hot/new/top/rising) |
| `get_post_comments` | Get comments on a post with nested replies |
| `delete` | Delete own post or comment by fullname |

## Reddit OAuth Specifics

| Behaviour | Detail |
|-----------|--------|
| **Connector type** | Native (in-process via httpx, no remote MCP server) |
| **Auth method** | `client_secret_basic` — HTTP Basic Auth header |
| **Authorize URL** | `https://www.reddit.com/api/v1/authorize` |
| **Token URL** | `https://www.reddit.com/api/v1/access_token` |
| **Scopes** | `identity`, `read`, `submit`, `edit` |
| **PKCE** | Not supported by Reddit (broker sends it, Reddit ignores) |
| **Token refresh** | Via `duration=permanent` param — broker refreshes automatically |
| **API base** | `https://oauth.reddit.com` (different from auth URLs) |
| **Rate limit** | 100 req/min per OAuth app; connector retries once on 429 |
| **User-Agent** | Required format — Reddit blocks generic UAs |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OAuth redirect fails | Check redirect URI in Reddit App Preferences matches exactly |
| "Unauthorized" on /connect | Missing or wrong `X-Broker-Key` header for your app |
| Token exchange fails (401) | Verify `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` in `.env` |
| No refresh token | Ensure `duration=permanent` is being sent (check connector's `customize_authorize_params`) |
| 429 Rate Limited | Connector auto-retries once. If persistent, reduce request frequency |
| `submit_post` returns 403 | Check Reddit app has correct permissions and subreddit allows posting |
| Post title exceeds 300 chars | Connector validates locally before calling Reddit API |
