# FILL_ME_IN — OAuth Setup (Discovery)

Discovery connectors use RFC 8414 endpoint discovery and RFC 7591 dynamic registration. No OAuth app registration is required up-front — the broker registers itself per-app on first connect.

## Prerequisites

Confirm the provider supports discovery. All three must succeed:

```bash
curl -fsSL {MCP_BASE_URL}/.well-known/oauth-authorization-server
# 200, JSON body includes `registration_endpoint`

curl -fsSL {MCP_BASE_URL}/.well-known/oauth-protected-resource
# 200

curl -fsS -X POST {REGISTRATION_ENDPOINT} \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost"],"client_name":"probe"}'
# 201 or well-formed error
```

If any fail, use the Static template instead.

## Broker Configuration

1. Add to `settings.yaml`:
   ```yaml
   broker:
     connectors: [..., FILL_ME_IN]
   ```

   No `apps` entry needed — credentials are minted dynamically.

2. Connect: `./start connect FILL_ME_IN --app-key {key}`

## Required Scopes

<!-- TODO: list scopes. Even for discovery, some providers still require you to
     declare scopes at registration time. Justify any privileged scope. -->

## Provider Quirks

<!-- TODO: document any hook override you added and why. See the Notion
     connector for a real example: it uses HTTP Basic Auth for token exchange
     and injects a Notion-Version header on every request. -->

## Known Limitations

<!-- TODO: e.g. "dynamic client secrets expire after N days — requires re-registration" -->
