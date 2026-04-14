# Changelog

All notable changes to `mcp-broker` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [API Stability](README.md#api-stability) for pre-1.0 compatibility policy.

## [Unreleased]

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
