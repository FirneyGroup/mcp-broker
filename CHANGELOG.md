# Changelog

All notable changes to `mcp-broker` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [API Stability](README.md#api-stability) for pre-1.0 compatibility policy.

## [Unreleased]

### Added

- **Inbound OAuth 2.1 AS for claude.ai-style MCP clients** — opt-in via `broker.oauth.enabled=true` (default `false`). New endpoints:
  - `POST /oauth/register` — RFC 7591 Dynamic Client Registration with per-IP sliding-window rate limit.
  - `GET/POST /oauth/authorize` — PKCE S256 + RFC 8707 resource indicators; consent page with `X-Frame-Options: DENY` and `frame-ancestors 'none'` CSP.
  - `POST /oauth/token` — `authorization_code` + `refresh_token` grants; atomic refresh rotation with family revoke on replay (OAuth 2.1 §4.3.1).
  - `POST /oauth/revoke` — RFC 7009 silent-success semantics.
  - `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-protected-resource/{path}` — RFC 8414 + RFC 9728 discovery, cached for 1 hour.
- **Bearer-token validation on `/proxy/*`** — `Authorization: Bearer mcp_at_...` tokens are validated against the inbound auth store with audience binding to the request connector. SHA-256-hashed at rest; compared via `hmac.compare_digest`.
- **`broker.oauth` config section** — `enabled`, `app_key`, `db_path`, TTL knobs, DCR rate limit knobs. Cross-field validator rejects an `app_key` that does not exist in `clients`.
- **Cascade delete** — `DELETE /admin/keys/{app_key}` now also drops inbound OAuth state for the app (DCR codes + access/refresh tokens) so re-provisioning a compromised key cannot silently regain bearer access.
- **Slack connector** (Native) — bot-identity messaging via Slack OAuth v2.
- **Notion (REST) connector** (`notion_api`, Native) — direct Notion REST API access exposing 19 tools, including database row queries with filters/sorts (`query_data_source`) that the hosted Notion MCP withholds. Additive alongside the existing `notion` passthrough.
- **Broker module entrypoint** (`python -m broker`) — validates settings before uvicorn boots, so config errors exit cleanly instead of propagating from the async lifespan.
- **`GET /oauth/success`** — built-in landing page after a successful outbound OAuth connect, served at a stable URL on the broker. Accepts an optional `?connector=` query param to customize the heading. Auth-exempt; no protected state.

### Changed

- **Grouped config errors** — missing environment variables are reported together with their `settings.yaml` path, instead of failing on the first miss.
- **`success_redirect_url` defaults to `/oauth/success` on the broker.** When `broker.success_redirect_url` is unset, the OAuth callback now redirects to `{public_url}/oauth/success?connector={connector_name}` rather than rendering inline HTML at the callback URL. Operators with a real dashboard still override via `success_redirect_url` — unchanged behavior. The example settings no longer hardcode `http://localhost:3000`, which left a dead-end UX for any deployment without a local dashboard running.

### Security

- Inbound bearer tokens, refresh tokens, and DCR client secrets are SHA-256-hashed at rest; raw values surface only at issuance and never again. Token comparison uses `hmac.compare_digest`.
- Inbound `Authorization: Bearer` header is removed from the request before any downstream handler runs (defense in depth on top of the existing proxy strip list).
- Refresh-token replay triggers immediate cascade revoke of every token in the family.
- DCR rate-limit `X-Forwarded-For` trust is now gated by `broker.oauth.trusted_proxy_ips` (default empty). Previously the DCR rate limiter trusted `X-Forwarded-For` unconditionally, letting a direct-access attacker bypass the per-IP cap by cycling forwarded values. With the gate, XFF is honored only when `request.client.host` is in the configured trusted-proxy allowlist; otherwise the rate-limit key is the immediate client.

## [0.1.0] — 2026-04-14

Initial public release.

### Added

- **OAuth 2.1 + PKCE** for all broker-managed connectors (S256 code challenge)
- **Discovery connectors** — automatic endpoint discovery per RFC 8414 and dynamic client registration per RFC 7591; no client credentials required in YAML
- **Static connectors** — manually-configured OAuth credentials in `settings.yaml`
- **Sidecar connectors** — proxying to local Docker MCP servers with either broker-managed OAuth (`auth_mode="broker"`) or sidecar-managed credentials (`auth_mode="sidecar"`)
- **Shipped connectors**: Notion, HubSpot, Google Workspace, LinkedIn, Reddit, Twitter/X, BigQuery
- **Per-app broker keys** — SHA-256 hashed at rest, managed via admin API and `./start` CLI; raw key shown once on creation
- **Admin API** — create, list, rotate, delete keys; create single-use browser OAuth tokens; trigger token refresh
- **Encrypted token storage** — MultiFernet with key rotation support
- **Signed OAuth state** — HMAC-signed nonces with single-use enforcement and 10-minute TTL
- **Automatic token refresh** — on-demand with per-connection locking, plus background refresh of tokens expiring within 10 minutes
- **Streaming proxy** — transparent pass-through of SSE and Streamable HTTP responses
- **Connect tokens** — single-use, 5-minute TTL tokens for browser OAuth (keeps raw broker keys out of URLs, browser history, and proxy logs)
- **Cascade deletion** — deleting a broker key drops every OAuth token for the app so re-provisioning cannot silently regain third-party access
- **SSRF protection** — OAuth discovery rejects private, loopback, and link-local addresses
- **Scope enforcement** — `proxy` and `status` scopes plus optional `allowed_connectors` allowlists per app
- **Identity substitution prevention** — middleware cross-checks verified broker key against the claimed `X-App-Id`
- **Docker Compose setup** with opt-in sidecar network overlay
- **OSS community files**: LICENSE (Apache 2.0), CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, issue and PR templates
- **CI**: ruff lint and format, pyright type-check, pytest, gitleaks secret scan, pip-audit dependency scan

### Security

- MultiFernet encryption for access tokens, refresh tokens, and dynamic registration client secrets at rest
- `hmac.compare_digest` for admin key validation
- Internal headers (`X-Broker-Key`, `X-App-Id`, `Authorization`, `Cookie`, `X-Forwarded-*`) stripped before forwarding to upstream MCP servers
- Response headers (`Set-Cookie` and other hop-by-hop) stripped before returning to clients

[Unreleased]: https://github.com/FirneyGroup/mcp-broker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FirneyGroup/mcp-broker/releases/tag/v0.1.0
