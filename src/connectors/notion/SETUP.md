# Notion MCP Connector Setup

## How It Works

The Notion connector uses **MCP OAuth Discovery** (RFC 8414 + RFC 7591) — no manual Notion integration setup required.

When a user clicks "Connect Notion" for the first time:

1. **Discovery** — Broker discovers OAuth endpoints from `mcp.notion.com/.well-known/oauth-protected-resource`
2. **Dynamic Registration** — Broker registers itself as an OAuth client at the discovered registration endpoint
3. **Authorization** — User is redirected to Notion's consent page to select which pages to share
4. **Token Exchange** — Broker exchanges the auth code for access + refresh tokens
5. **Storage** — Tokens are encrypted and stored per-app

All of this is automatic. The only setup required is broker configuration.

## 1. Configure Broker

Ensure `settings.yaml` has the Notion connector's `mcp_oauth_url` (this is already set in the default `NotionConnector` class). No `client_id` or `client_secret` entries are needed in `settings.yaml` for Notion — credentials come from dynamic registration.

Ensure your `.env` has the encryption and state secrets:

```bash
BROKER_ENCRYPTION_KEY=your-fernet-key-here
BROKER_STATE_SECRET=your-state-secret-here
```

## 2. Start the OAuth Flow

The `/connect` endpoint triggers the full discovery + registration + authorization flow:

```
GET http://localhost:8002/oauth/notion/connect?app_key=my_company:app1
Header: X-Broker-Key: <your-per-app-broker-key>
```

The user will see Notion's page picker UI — they select specific pages to share
(Notion doesn't grant blanket workspace access).

After granting access, Notion redirects to the callback which stores the token
and shows a success page.

## 3. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "notion", "connected": true`.

## 4. Test MCP Proxy

```bash
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/notion/mcp" | python3 -m json.tool
```

Should return a list of Notion MCP tools.

## Notion OAuth Specifics

These are handled automatically by `NotionConnector` — documented here for reference.

| Behaviour | Detail |
|-----------|--------|
| **Auth method** | HTTP Basic Auth for token exchange (`base64(client_id:client_secret)` in Authorization header), not POST body credentials |
| **Dynamic registration** | Client credentials obtained via RFC 7591 — no Notion dashboard setup needed |
| **Page picker** | Users select specific pages during auth, not blanket workspace access |
| **Scopes** | None — Notion uses integration-level permissions |
| **Token response** | Returns extra fields (`workspace_id`, `bot_id`, `owner`, `workspace_name`) — `parse_token_response()` extracts only standard OAuth2 fields |
| **Refresh tokens** | Supported — refreshing returns both new access and refresh tokens |
| **PKCE** | Supported (S256) — the broker sends PKCE on all flows automatically |
| **Notion-Version header** | Required for MCP proxy requests — added by `build_auth_header()` |
| **MCP transport** | Streamable HTTP at `https://mcp.notion.com/mcp` |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Discovery failed" at startup | Check network connectivity to `mcp.notion.com` — `.well-known` endpoints must be reachable |
| "Dynamic registration failed" | Registration endpoint may be temporarily unavailable — check broker logs for HTTP status |
| OAuth redirect fails | Check redirect URI matches the callback URL the broker generates (scheme, host, port) |
| "Unauthorized" on /connect | Missing or wrong `X-Broker-Key` header for your app |
| Token exchange 401 | Notion requires Basic Auth — ensure `NotionConnector.build_token_request_auth()` is being called |
| Token not stored after callback | Check broker logs for state validation errors |
| "Image/file uploads not supported" | Known Notion MCP limitation — on their roadmap |

## Sources

- [Notion OAuth Authorization](https://developers.notion.com/docs/authorization)
- [Notion MCP Getting Started](https://developers.notion.com/guides/mcp/get-started-with-mcp)
- [Notion MCP Overview](https://developers.notion.com/docs/mcp)
- [RFC 8414 — OAuth Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [RFC 7591 — OAuth Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
