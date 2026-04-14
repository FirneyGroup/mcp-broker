# Sidecar Template

Use this template to add a new MCP server as a sidecar — a Docker container that runs alongside the broker and speaks MCP over HTTP.

## What's in this directory

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Generic supergateway-based sidecar. Wraps any stdio MCP server as Streamable HTTP. |
| `.env.example` | Environment variables: container name, command to wrap, port. |
| `adapter.example.py` | Example connector adapter. Shows both `broker` and `sidecar` auth modes. |

## Steps

1. **Copy the template:**
   ```bash
   cp -r sidecars/_template sidecars/my-sidecar
   cp sidecars/my-sidecar/.env.example sidecars/my-sidecar/.env
   ```

2. **Edit `.env`** — set `CONTAINER_NAME` (must match the hostname you'll put in the connector's `mcp_url`) and `MCP_COMMAND` (the stdio command supergateway should wrap, e.g. `npx -y some-mcp-server`).

3. **Create the connector adapter:**
   ```bash
   mkdir -p src/connectors/my_sidecar
   cp sidecars/my-sidecar/adapter.example.py src/connectors/my_sidecar/adapter.py
   rm sidecars/my-sidecar/adapter.example.py
   ```
   Edit `src/connectors/my_sidecar/adapter.py` — pick one auth mode, delete the other, update the ConnectorMeta values.

4. **Register the connector** — add its name to the `connectors` list in `settings.yaml`.

5. **Create the shared network** (once per host):
   ```bash
   docker network create sidecar-internal
   ```

6. **Start the sidecar:**
   ```bash
   cd sidecars/my-sidecar && docker compose up -d
   ```

7. **Verify** — hit `GET /health` on the broker and your connector should appear in the registered list.

## Auth Modes

| Mode | Who handles auth | When to use |
|------|------------------|-------------|
| `broker` | Broker runs OAuth, injects `Authorization: Bearer <token>` | Upstream is OAuth 2.1 and the sidecar trusts external Bearer tokens (e.g. `EXTERNAL_OAUTH21_PROVIDER=true` on workspace-mcp) |
| `sidecar` | Sidecar reads its own credentials (API key, service account, etc.) | Sidecar has its own credential management and does not want broker interference |

## Credential Storage

If the sidecar needs persistent credentials (OAuth tokens, service-account JSON, etc.), store them under `./config/` which is volume-mounted to `/root/.config` in the container. Add `sidecars/my-sidecar/config/` to `.gitignore`.

## Using a Native HTTP MCP Server Instead

The supergateway-based `docker-compose.yml` in this template wraps stdio servers. If the MCP server you're integrating already speaks Streamable HTTP natively (like `workspace-mcp`), replace the `image: supercorp/supergateway` block with a direct `build:` pointing at the upstream project. See `sidecars/workspace-mcp/docker-compose.yml` for a worked example.
