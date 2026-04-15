# FILL_ME_IN — OAuth & SDK Setup (Native)

Native connectors wrap a provider's SDK or REST API in-process. The broker handles OAuth; you implement tools as `async def` methods.

## OAuth App Registration

1. Sign in to the provider's developer console.
2. Create an OAuth application.
3. Set the redirect URI to `{BROKER_PUBLIC_URL}/oauth/FILL_ME_IN/callback`.
4. Record the client ID and client secret.
5. Confirm PKCE (S256) is supported — the broker requires it.

## Required Scopes

<!-- TODO: list each scope and what tool uses it. Justify anything privileged. -->

## Tool Surface

List the tools your connector exposes. Keep the set minimal — each additional tool is another thing the LLM has to choose between.

<!-- TODO:
| Tool | Description | Scopes required |
|------|-------------|-----------------|
| foo  | ...         | `scope.read`    |
-->

## SDK Notes

<!-- TODO: is the SDK sync or async?
     - Sync: every call MUST go through run_in_executor (see template adapter.py).
     - Async: await directly; no executor needed.
   Does the SDK accept access_token per-call or per-client? -->

## Broker Configuration

1. Add credentials to `.env`:
   ```
   FILL_ME_IN_CLIENT_ID=...
   FILL_ME_IN_CLIENT_SECRET=...
   ```

2. Add to `settings.yaml`:
   ```yaml
   broker:
     connectors: [..., FILL_ME_IN]
   apps:
     your_app_id:
       connectors:
         FILL_ME_IN:
           client_id: ${FILL_ME_IN_CLIENT_ID}
           client_secret: ${FILL_ME_IN_CLIENT_SECRET}
   ```

3. Connect: `./start connect FILL_ME_IN --app-key {key}`
