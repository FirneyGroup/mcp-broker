# HubSpot MCP Connector Setup

## How It Works

The HubSpot connector uses **MCP Auth Apps** — a HubSpot-specific OAuth flow at `mcp.hubspot.com` (not the legacy HubSpot API OAuth at `app.hubspot.com`).

When a user clicks "Connect HubSpot":

1. **Redirect** — Broker redirects to `mcp.hubspot.com/oauth/authorize` with PKCE challenge
2. **Consent** — User approves scopes on HubSpot's consent page (scopes auto-determined by the MCP server)
3. **Token Exchange** — Broker exchanges the auth code at `mcp.hubspot.com/oauth/v3/token`
4. **Storage** — Tokens are encrypted and stored per-app

## 1. Create an MCP Auth App

1. Go to [HubSpot Developer Portal](https://developers.hubspot.com/)
2. Navigate to **Apps** > **MCP Auth Apps** (not the regular "Apps" section)
3. Create a new MCP Auth App
4. Set the redirect URI to your broker's callback URL:
   - Local: `http://localhost:8002/oauth/hubspot/callback`
   - Production: `https://your-broker-domain/oauth/hubspot/callback`
5. Copy the **Client ID** and **Client Secret**

## 2. Configure Environment

Add the credentials to your `.env`:

```bash
# HubSpot (MCP Auth App)
# Redirect URI: http://localhost:8002/oauth/hubspot/callback
HUBSPOT_CLIENT_ID=your-client-id-here
HUBSPOT_CLIENT_SECRET=your-client-secret-here
```

Ensure your `.env` also has the encryption and state secrets:

```bash
BROKER_ENCRYPTION_KEY=your-fernet-key-here
BROKER_STATE_SECRET=your-state-secret-here
```

## 3. Configure Settings

Ensure `settings.yaml` has the HubSpot credentials mapped under `apps`:

```yaml
apps:
  my_company:
    app1:
      hubspot:
        client_id: ${HUBSPOT_CLIENT_ID}
        client_secret: ${HUBSPOT_CLIENT_SECRET}
```

## 4. Connect via Script

```bash
PYTHONPATH=src python scripts/connect.py --app "my_company:app1"
```

Select HubSpot from the connector list. The script opens your browser for OAuth consent, then polls until connected.

## 5. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "hubspot", "connected": true, "token_valid": true`.

## 6. Test MCP Proxy

```bash
curl -s -X POST \
  -H "X-Broker-Key: $BROKER_KEY" \
  -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' \
  "http://localhost:8002/proxy/hubspot/mcp" --compressed | python3 -m json.tool
```

Should return a list of HubSpot MCP tools.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `search_crm_objects` | Search/filter CRM records (contacts, companies, deals, etc.) |
| `get_crm_objects` | Batch fetch records by ID |
| `get_properties` | Property definitions with data types and enum values |
| `search_properties` | Keyword search for property names |
| `search_owners` | List/search HubSpot users and owners |
| `get_user_details` | Token permissions, account info, object type availability |
| `manage_crm_objects` | Create and update CRM records (requires write permissions) |

## HubSpot OAuth Specifics

These are handled automatically by `HubSpotConnector` — documented here for reference.

| Behaviour | Detail |
|-----------|--------|
| **OAuth type** | MCP Auth App (not legacy HubSpot API OAuth) |
| **Auth method** | `client_secret_post` — credentials sent in POST body (default `BaseConnector` behavior) |
| **Endpoints** | `mcp.hubspot.com/oauth/authorize` and `mcp.hubspot.com/oauth/v3/token` |
| **MCP URL** | `https://mcp.hubspot.com` |
| **MCP transport** | SSE (Server-Sent Events) |
| **Scopes** | Auto-determined by the MCP server — empty list in connector config |
| **PKCE** | Supported (S256) — the broker sends PKCE on all flows automatically |
| **Write access** | Requires write scopes to be approved during consent — check with `get_user_details` |

## Permissions

After connecting, call `get_user_details` through the MCP proxy to check read/write availability per CRM object type. Each object type has separate `read` and `write` statuses:

- `AVAILABLE` — ready to use
- `NOT_AVAILABLE` — not enabled for this connection
- `REQUIRES_REAUTHORIZATION` — disconnect and reconnect to request new scopes

If write access shows `NOT_AVAILABLE`, you may need to re-authorize with write permissions enabled in the MCP Auth App settings.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OAuth redirect fails | Check redirect URI in MCP Auth App matches the broker callback URL exactly |
| "Unauthorized" on /connect | Missing or wrong `X-Broker-Key` header for your app |
| Token exchange fails | Verify `HUBSPOT_CLIENT_ID` and `HUBSPOT_CLIENT_SECRET` in `.env` |
| `manage_crm_objects` not in tools/list | Write tool may require re-authorization with write scopes |
| All write statuses `NOT_AVAILABLE` | Re-authorize — disconnect via `/oauth/hubspot/disconnect` and reconnect |
| Gzipped response from proxy | Use `--compressed` flag with curl |
| 404 from MCP proxy | Verify `mcp_url` in adapter is `https://mcp.hubspot.com` (root, no path suffix) |

## Sources

- [HubSpot MCP Auth Apps](https://developers.hubspot.com/docs/guides/apps/authentication/mcp-auth-apps)
- [HubSpot MCP Tools Documentation](https://developers.hubspot.com/docs/guides/apps/marketplace/mcp-server)
