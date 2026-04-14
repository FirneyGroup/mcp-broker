# Sidecar Template

Use this template to add a new stdio MCP server as a sidecar.

## Steps

1. **Copy this directory**: `cp -r sidecars/_template sidecars/my-sidecar`
2. **Fill in `.env`**: Copy `.env.example` to `.env`, set `CONTAINER_NAME` and `MCP_COMMAND`
3. **Create connector adapter**: Add `src/connectors/my_sidecar/adapter.py` with `auth_mode="sidecar"`
4. **Add to settings**: Add the connector name to `broker.connectors` in `settings.yaml`
5. **Create network** (once): `docker network create sidecar-internal`
6. **Start**: `cd sidecars/my-sidecar && docker compose up -d`

## Credential Storage

If the sidecar needs persistent credentials (OAuth tokens, API keys), they should be stored in `./config/` which is volume-mounted to `/root/.config` in the container. Add `config/` to `.gitignore`.
