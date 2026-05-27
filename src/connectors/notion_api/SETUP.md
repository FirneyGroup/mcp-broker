# Notion API Native Connector Setup

## How It Works

The `notion_api` connector is a **native connector** — it implements MCP tools in-process using the
Notion REST API (`api.notion.com`) via httpx. It is distinct from the `notion` connector, which
is a passthrough to `mcp.notion.com` (Notion's hosted MCP server): that connector withholds
row-query tools and uses OAuth discovery; this connector exposes the full REST surface directly
with static-credential OAuth.

When a user clicks "Connect Notion API":

1. **Redirect** — Broker redirects to `api.notion.com/v1/oauth/authorize` with `owner=user`
2. **Consent** — User selects which pages and databases to share on Notion's consent page
3. **Token Exchange** — Broker exchanges the auth code at `api.notion.com/v1/oauth/token`
   using HTTP Basic Auth (credentials in the `Authorization` header, not the body)
4. **Storage** — Tokens are encrypted and stored per-app; the refresh token rotates on
   every token response and is always overwritten

> **Security note — PKCE waiver:** The broker's security invariants require PKCE (S256) on all
> OAuth flows. This connector intentionally waives that invariant because `api.notion.com` does
> not accept `code_challenge` or `code_challenge_method` parameters at all — the upstream does
> not support PKCE. This is an upstream limitation, not a design choice. The connector sets
> `supports_pkce=False` in `ConnectorMeta` with a code comment citing this note.

## 1. Create a Notion Public Integration

You need a **public** Notion integration — internal integrations and personal API tokens (PAT)
cannot perform the OAuth authorization_code flow.

1. Go to [notion.so/profile/integrations](https://www.notion.so/profile/integrations)
2. Click **"New integration"** and set type to **Public**
3. Under **Capabilities**, enable all of the following:
   - Read content
   - Update content
   - Insert content
   - Read comments
   - Insert comments
   - Read user information including email
4. Under **OAuth Domain & URIs**, register both redirect URIs:
   - Local: `http://localhost:8002/oauth/notion_api/callback`
   - Production: `https://your-broker-domain/oauth/notion_api/callback`
5. From the integration's **Secrets** tab, copy the **OAuth client ID** and **OAuth client secret**

## 2. Configure Environment

Add the credentials to your `.env`:

```bash
# Notion API (public OAuth integration)
# Create at: notion.so/profile/integrations → Public integration
# Redirect URIs: http://localhost:8002/oauth/notion_api/callback
#                https://your-broker-domain/oauth/notion_api/callback
NOTION_API_CLIENT_ID=your-client-id-here
NOTION_API_CLIENT_SECRET=your-client-secret-here
```

No additional dependencies needed — httpx is a core broker dependency.

## 3. Configure Settings

Add `notion_api` to the connectors list and add credentials under the app in `settings.yaml`:

```yaml
broker:
  connectors:
    - notion_api  # add to existing list

clients:
  my_company:
    app1:
      allowed_connectors: [notion_api]  # add to existing list

apps:
  my_company:
    app1:
      notion_api:
        client_id: ${NOTION_API_CLIENT_ID}
        client_secret: ${NOTION_API_CLIENT_SECRET}
```

## 4. Start the OAuth Flow

```bash
PYTHONPATH=src python scripts/connect.py --app "my_company:app1"
```

Select `notion_api` from the connector list. The script opens your browser for Notion's
consent page (user selects which pages/databases to share), then polls until connected.

Alternatively, hit the endpoint directly:

```
GET http://localhost:8002/oauth/notion_api/connect?app_key=my_company:app1
Header: X-Broker-Key: <your-per-app-broker-key>
```

After granting access, Notion redirects to the callback which stores the token and shows a
success page.

## 5. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "notion_api", "connected": true, "token_valid": true`.

## 6. Test MCP Proxy

```bash
# List available tools
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/notion_api/mcp" | python3 -m json.tool

# Call a tool (verify the authorized user)
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": {"name": "get_users", "arguments": {}}}' \
  "http://localhost:8002/proxy/notion_api/mcp" | python3 -m json.tool
```

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `query_data_source` | Query a Notion database with filters and sorts |
| `fetch` | Fetch a page's properties and block content |
| `get_block_children` | Get child blocks of a page or block (first level only) |
| `get_page_property` | Get a single property value from a page |
| `search` | Search pages and databases by title |
| `get_users` | List workspace users (OAuth) or return the bot identity; a PAT cannot list users (Notion 403) so the tool falls back to the bot. Optional `max_users`. |
| `create_pages` | Create a new page or database row |
| `update_page_properties` | Update properties on an existing page |
| `archive_page` | Archive (soft-delete) a page |
| `append_blocks` | Append block children to a page or block |
| `update_page_content` | Replace a page's block content |
| `create_database` | Create a new database with a property schema |
| `update_data_source` | Add, rename, or remove properties on a database |
| `create_view` | Create a view (table, board, calendar, etc.) on a database |
| `update_view` | Update a view's name or layout |
| `move_pages` | Move a page to a new parent (page or database) |
| `create_comment` | Add a comment to a page or reply to a discussion |
| `get_comments` | List comments on a page, grouped by discussion |
| `upload_file` | Upload a file and attach it to a page or property |

## Notion API OAuth Specifics

| Behaviour | Detail |
|-----------|--------|
| **Connector type** | Native (in-process via httpx, no remote MCP server) |
| **Auth method** | `client_secret_basic` — HTTP Basic Auth header for all token requests |
| **Authorize URL** | `https://api.notion.com/v1/oauth/authorize` |
| **Token URL** | `https://api.notion.com/v1/oauth/token` |
| **Scopes** | None — Notion uses integration-level capabilities set in the integration settings |
| **PKCE** | **Not supported** on `api.notion.com` — upstream limitation; connector sets `supports_pkce=False` |
| **`expires_in`** | Absent from token responses — Notion does not publish token lifetime |
| **Synthetic TTL** | Connector injects a 50-minute synthetic TTL so the broker refreshes proactively before the real (unpublished) lifetime elapses |
| **Refresh token** | Rotates on every token response (both exchange and refresh grant) — broker overwrites stored value each time |
| **`Notion-Version` header** | Required on every API call — connector pins `2025-09-03` |
| **`owner` param** | `owner=user` is required in the authorize URL |
| **`get_users` list** | Listing users requires an OAuth token; a PAT returns 403 and the tool falls back to the bot identity (`/me`) |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "not a public integration" error at OAuth start | Internal integrations cannot do the OAuth flow — create a new **Public** integration at notion.so/profile/integrations |
| OAuth redirect fails | Check both redirect URIs are registered in the integration settings; scheme and host must match exactly |
| Token exchange 401 | Credentials must be in the `Authorization: Basic ...` header — verify `NOTION_API_CLIENT_ID` and `NOTION_API_CLIENT_SECRET` in `.env` |
| "Unauthorized" on `/connect` | Missing or wrong `X-Broker-Key` header for your app |
| `get_users` returns `list_available: false` | Listing users requires an OAuth token — internal PATs are blocked by Notion, so the tool returns the bot identity instead; complete the OAuth flow for full list access |
| Pages not appearing in `search` results | Notion's search index has a lag; newly created or shared pages may not be indexed immediately |
| File upload fails at `complete` step | The `complete` call is multi-part-only; single-part uploads skip it. Check the upload was created with `mode="single_part"` |
