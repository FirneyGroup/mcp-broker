# LinkedIn Native Connector Setup

## How It Works

The LinkedIn connector is a **native connector** — it implements MCP tools in-process using the LinkedIn API via httpx instead of proxying to a remote MCP server.

When a user clicks "Connect LinkedIn":

1. **Redirect** — Broker redirects to `linkedin.com/oauth/v2/authorization` (no PKCE — LinkedIn rejects it)
2. **Consent** — User approves the requested scopes on LinkedIn's consent page
3. **Token Exchange** — Broker exchanges the auth code at `linkedin.com/oauth/v2/accessToken` using form body params (`client_secret_post`)
4. **Storage** — Tokens are encrypted and stored per-app

## 1. Create a LinkedIn App

1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Click **"Create app"**
3. Fill in the app name, associate it with a **LinkedIn Company Page** (required for org tools)
4. Under **Products**, request access to:

   **Minimum (self-serve, instant — enables member posting):**
   - **Sign In with LinkedIn using OpenID Connect** — `openid`, `profile` scopes
   - **Share on LinkedIn** — `w_member_social` scope (create/delete member posts)

   **Full (requires LinkedIn approval — enables org tools + analytics):**
   - **Community Management API** — `r_organization_social`, `w_organization_social`, `rw_organization_admin`, etc.

5. Under the **Auth** tab, add the redirect URI:
   - Local: `http://localhost:8002/oauth/linkedin/callback`
   - Production: `https://your-broker-domain/oauth/linkedin/callback`
6. Copy the **Client ID** and **Client Secret** from the Auth tab

> **Note:** With just the self-serve products, 3 of 10 tools work: `get_me`, `create_post` (as member), `delete_post` (own posts). The remaining 7 tools (org posts, comments, reactions, analytics) require Community Management API approval, which typically takes 1–5 business days.

## 2. Configure Environment

Add the credentials to your `.env`:

```bash
# LinkedIn (from LinkedIn Developer Portal)
# Create app at: https://developer.linkedin.com/
# Redirect URI: http://localhost:8002/oauth/linkedin/callback
LINKEDIN_CLIENT_ID=your-client-id-here
LINKEDIN_CLIENT_SECRET=your-client-secret-here
```

No optional dependencies needed — httpx is a core broker dependency.

## 3. Configure Settings

Add LinkedIn credentials under `apps` in `settings.yaml`:

```yaml
apps:
  my_company:
    app1:
      linkedin:
        client_id: ${LINKEDIN_CLIENT_ID}
        client_secret: ${LINKEDIN_CLIENT_SECRET}
```

Also add `linkedin` to the connector list and `allowed_connectors`:

```yaml
broker:
  connectors:
    - linkedin  # add alongside other connectors

clients:
  my_company:
    app1:
      allowed_connectors: [linkedin]  # or add to existing list
```

## 4. Connect via Script

```bash
./start connect
```

Select LinkedIn from the connector list when prompted. The script opens your browser for OAuth consent, then polls until connected.

## 5. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "linkedin", "connected": true, "token_valid": true`.

## 6. Test MCP Proxy

```bash
# List available tools
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/linkedin/mcp" | python3 -m json.tool

# Get authenticated user profile
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": {"name": "get_me", "arguments": {}}}' \
  "http://localhost:8002/proxy/linkedin/mcp" | python3 -m json.tool
```

## Available MCP Tools

| Tool | Description | Required Product |
|------|-------------|-----------------|
| `get_me` | Get authenticated user's profile | Sign In with LinkedIn |
| `create_post` | Create a text post (member or org) | Share on LinkedIn |
| `delete_post` | Delete a post by URN | Share on LinkedIn |
| `get_org_posts` | Get recent posts from an org page | Community Management API |
| `get_managed_orgs` | List organizations you administer | Community Management API |
| `create_comment` | Comment on a post | Community Management API |
| `react_to_post` | React to a post (LIKE, PRAISE, etc.) | Community Management API |
| `get_post_comments` | Get comments on a post | Community Management API |
| `get_org_analytics` | Get org follower and page statistics | Community Management API |
| `get_post_analytics` | Get post engagement metrics | Community Management API |

## LinkedIn OAuth Specifics

| Behaviour | Detail |
|-----------|--------|
| **Connector type** | Native (in-process via httpx, no remote MCP server) |
| **Auth method** | `client_secret_post` — credentials sent as form body params (broker default) |
| **Authorize URL** | `https://www.linkedin.com/oauth/v2/authorization` |
| **Token URL** | `https://www.linkedin.com/oauth/v2/accessToken` |
| **Scopes** | `openid`, `profile`, `w_member_social`, `w_member_social_feed`, `r_organization_social`, `w_organization_social`, `r_organization_social_feed`, `w_organization_social_feed`, `rw_organization_admin` |
| **PKCE** | Disabled — LinkedIn's standard OAuth flow rejects `code_verifier` |
| **Access token TTL** | 60 days |
| **Refresh token TTL** | 365 days |
| **API version header** | `Linkedin-Version: 202501` (required on all requests) |
| **No Basic Auth override** | Unlike Twitter/Reddit, LinkedIn uses body params — no `build_token_request_auth` override needed |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| 403 "API product not approved" | Community Management API approval is pending — wait for LinkedIn review or check the Products tab in your app |
| 403 "insufficient scope" | Re-connect via `./start connect` to re-authorize with the full scope set |
| 401 "token expired" | Re-connect via `./start connect` |
| "No organization found" | The authenticated user must be an admin of a LinkedIn Company Page |
| OAuth redirect mismatch | Ensure the redirect URI in the LinkedIn app Auth tab matches exactly (including `http://` vs `https://`) |
| Token exchange fails (400) | Verify `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET` in `.env` are from the Auth tab, not the app overview |
