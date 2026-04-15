# FILL_ME_IN — OAuth Setup

Replace this entire file when you copy the template. Operators read this to register your OAuth app and start the broker.

## OAuth App Registration

1. Sign in to the provider's developer console.
2. Create a new OAuth application.
3. Set the redirect URI to `{BROKER_PUBLIC_URL}/oauth/FILL_ME_IN/callback`.
4. Record the client ID and client secret.

## Required Scopes

<!-- TODO: list each scope and what it grants. Justify any privileged scope. -->

- `scope.read` — what this grants
- `scope.write` — what this grants (if applicable)

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

## Provider Quirks

<!-- TODO: document any override you added in adapter.py and why. Examples:
     - "Token exchange requires HTTP Basic Auth → overrode build_token_request_auth"
     - "Requires X-Api-Version header on every MCP request → overrode build_auth_header"
     - "Requires access_type=offline to get a refresh token → overrode customize_authorize_params"
-->

## Known Limitations

<!-- TODO: e.g. "no refresh tokens issued — sessions expire in 1 hour" -->
