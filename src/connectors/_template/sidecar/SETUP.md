# FILL_ME_IN — Sidecar Setup

Sidecar connectors require both an adapter (`src/connectors/{name}/`) and a Docker container (`sidecars/{name}/`). This file covers the adapter side; see `sidecars/_template/README.md` for the container side.

## Choosing auth_mode

| Mode | Who holds credentials | Use when |
|------|----------------------|----------|
| `broker` | Broker — injects `Authorization: Bearer {token}` on each request | The sidecar accepts an OAuth Bearer token and trusts it (run with `EXTERNAL_OAUTH21_PROVIDER=true` or equivalent). |
| `sidecar` | Sidecar itself — has its own `.env` with provider credentials | The sidecar manages its own OAuth flow (e.g. uses a long-lived API key or runs its own OAuth UI). |

Pick once and stick with it. Changing later requires re-consenting every app.

## Broker-Managed OAuth (auth_mode="broker")

1. Register an OAuth app with the upstream provider. Set redirect URI to `{BROKER_PUBLIC_URL}/oauth/FILL_ME_IN/callback`.
2. Record client ID and secret.
3. Add to `.env`:
   ```
   FILL_ME_IN_CLIENT_ID=...
   FILL_ME_IN_CLIENT_SECRET=...
   ```
4. Add to `settings.yaml`:
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
5. Run `./start connect` to complete OAuth (interactive — select FILL_ME_IN from the menu). For a non-default app, add `--app {client_id:app_id}`.

## Sidecar-Managed Auth (auth_mode="sidecar")

1. The sidecar container owns its OAuth flow — configure per its docs.
2. The broker's `settings.yaml` only needs the connector name in `broker.connectors`. No `apps` entry.
3. Incoming requests are proxied to the sidecar without token injection.

## Docker Compose

See `sidecars/{name}/docker-compose.yml` — must join `firney-net` so the broker can reach it by service name.

## Required Scopes

<!-- TODO: list scopes, justify any privileged scope -->
