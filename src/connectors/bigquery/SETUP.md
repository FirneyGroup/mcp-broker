# BigQuery MCP Connector Setup

## How It Works

The BigQuery connector uses a **sidecar architecture** — Google's [MCP Toolbox for Databases](https://github.com/googleapis/genai-toolbox) runs in a Docker container with `useClientOAuth: true`. The broker manages Google OAuth per-app and injects Bearer tokens on each proxied request.

This follows the same pattern as the Workspace MCP connector — the sidecar trusts injected tokens and forwards them to BigQuery. The Toolbox provides `writeMode: blocked` (read-only), row limits, and dataset whitelisting out of the box.

## 1. Enable BigQuery API

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/library)
2. Enable **BigQuery API** (if not already enabled)

## 2. Add BigQuery Scope to OAuth Consent Screen

1. Go to APIs & Services > OAuth consent screen
2. Add scope: `https://www.googleapis.com/auth/bigquery.readonly`
3. Save

No new OAuth credentials needed — reuses the same Google OAuth client as Workspace MCP.

## 3. Add Redirect URI

1. Go to APIs & Services > Credentials > your OAuth 2.0 Client
2. Add authorized redirect URI: `http://localhost:8002/oauth/bigquery/callback`
3. Save

## 4. Start the Sidecar

```bash
docker network create sidecar-internal  # once
cd sidecars/bigquery-toolbox
docker compose up -d
```

Verify: `curl http://localhost:5000/` — should respond.

## 5. Configure Settings

Ensure `settings.yaml` has `bigquery` in the connectors list and credentials mapped under `apps`:

```yaml
broker:
  connectors:
    - bigquery
    # ... other connectors

apps:
  my_company:
    app1:
      bigquery:
        client_id: ${GOOGLE_OAUTH_CLIENT_ID}
        client_secret: ${GOOGLE_OAUTH_CLIENT_SECRET}
```

## 6. Connect via OAuth

```bash
./start connect  # Select bigquery → opens browser → Google consent
```

## 7. Verify Connection

```bash
curl -s -H "X-Broker-Key: $BROKER_KEY" \
  "http://localhost:8002/status?app_key=my_company:app1" | python3 -m json.tool
```

Should show `"connector": "bigquery", "connected": true, "token_valid": true`.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `list_datasets` | List all dataset IDs in the project |
| `list_tables` | List table IDs in a dataset |
| `get_dataset_info` | Get metadata for a dataset |
| `get_table_info` | Get schema and metadata for a table |
| `execute_sql` | Execute a read-only SQL query |
| `conversational_analytics` | Ask questions about data in natural language |
| `forecast` | Forecast time series data |
| `analyze_contribution` | Analyze key drivers and contributions |
| `search_catalog` | Search for tables and datasets in the catalog |

## Google OAuth Specifics

| Behaviour | Detail |
|-----------|--------|
| **OAuth type** | Google OAuth 2.0 (Web application) — same credentials as Workspace MCP |
| **Endpoints** | `accounts.google.com/o/oauth2/v2/auth` and `oauth2.googleapis.com/token` |
| **MCP URL** | `http://bigquery-toolbox:5000/mcp` (Docker) or `http://localhost:5000/mcp` (local dev) |
| **Scopes** | `bigquery.readonly` |
| **Write protection** | `writeMode: blocked` in Toolbox config — INSERT/UPDATE/DELETE rejected |
| **Row limit** | `maxQueryResultRows: 100` — configurable in `tools.yaml` |

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OAuth redirect fails | Check redirect URI matches `http://localhost:8002/oauth/bigquery/callback` |
| Sidecar won't start | Check `docker compose logs` — may need `platform: linux/amd64` on Apple Silicon |
| 401 from proxy | No token stored — connect via `./start connect` |
| Query timeout | Increase the request timeout in your MCP client config (default 30s) |
| "Access Denied" from BigQuery | User's Google account needs BigQuery access in the GCP project |
