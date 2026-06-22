# Changelog

All notable changes to `mcp-broker` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [API Stability](README.md#api-stability) for pre-1.0 compatibility policy.

## [Unreleased]

### Fixed

- **`./start mcp-config` / `connect` now print the broker's public URL for connector URLs.** The `claude mcp add-json` URL and the `oauth url` are built from `broker.public_url` (the externally-reachable address, e.g. behind Cloudflare) instead of the admin `--broker-url` (typically `localhost`), so the printed config is usable from any client — claude.ai, Cursor, an operator laptop — not just on the host running the CLI. Falls back to `--broker-url` when `public_url` is unset.

### Added

- **`auth_mode='none'` connectors** — a connector targeting an open API (or one it authenticates to with its own static credential) can set `ConnectorMeta.auth_mode='none'` to skip the broker's OAuth connection gate entirely (no `resolve_oauth`, no stored token, no `/oauth/connect`). Native handlers receive an empty `access_token`/`provider_metadata` and self-source any credential from their own config. New `ConnectorMeta.requires_oauth` property is `False` for `'none'` and `'sidecar'`. Existing connectors default to `'broker'` — no behaviour change. The `./start connect` wizard shows such connectors as **Open (no connect needed)** and skips the OAuth flow; `./start mcp-config` includes them (clients still authenticate to the broker via inbound auth, so they belong in the client config); and `/oauth/{connector}/connect` returns a clear 400 instead of a misleading 404.

- **External connector discovery via the `mcp_broker.connectors` entry-point group** — a connector can ship as a separately-installed pip package instead of living in-tree (e.g. a private connector kept out of this repo). `_load_connectors` resolves each name in `broker.connectors` through the entry-point group first, falling back to the in-tree `connectors.{name}.adapter` convention; a name resolvable both ways is a hard error so an external package cannot shadow a reviewed in-tree connector. Behaviour is unchanged when no external connector package is installed.
- **Per-connection `provider_metadata`** — `AppConnection` carries a non-secret per-connection identifier (e.g. a company/realm id) captured from the OAuth callback via the new `BaseConnector.parse_callback_params` hook and forwarded to native tool handlers that opt in by signature. Preserved across token refresh; round-trips through the token store.
- **Pluggable Firestore storage backend** — `store.backend: sqlite | firestore` (default `sqlite`) with a new `[store.firestore]` section (`project_id`, `database`, `collection_prefix`). Firestore Native-mode implementations of the token store, broker-key store, and inbound OAuth auth store let the broker keep **persistent** state off the local filesystem for Cloud Run. Outbound tokens stay MultiFernet-encrypted at rest; codes/tokens/keys stay SHA-256-hashed; inbound refresh rotation is atomic with replay→family-revoke. Re-provisioning cascade moves to **purge-on-create**. Ephemeral flow state (outbound nonces/PKCE verifiers, connect tokens, DCR rate limiting) is also Firestore-backed when this backend is selected, so the `WEB_CONCURRENCY=1` guard applies only to the `sqlite` backend.
- **Inbound OAuth 2.1 AS for claude.ai-style MCP clients** — opt-in via `broker.oauth.enabled=true` (default `false`). New endpoints:
  - `POST /oauth/register` — RFC 7591 Dynamic Client Registration with per-IP sliding-window rate limit.
  - `GET/POST /oauth/authorize` — PKCE S256 + RFC 8707 resource indicators; consent page with `X-Frame-Options: DENY` and `frame-ancestors 'none'` CSP.
  - `POST /oauth/token` — `authorization_code` + `refresh_token` grants; atomic refresh rotation with family revoke on replay (OAuth 2.1 §4.3.1).
  - `POST /oauth/revoke` — RFC 7009 silent-success semantics.
  - `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-protected-resource/{path}` — RFC 8414 + RFC 9728 discovery, cached for 1 hour.
- **Bearer-token validation on `/proxy/*`** — `Authorization: Bearer mcp_at_...` tokens are validated against the inbound auth store with audience binding to the request connector. SHA-256-hashed at rest; compared via `hmac.compare_digest`.
- **`broker.oauth` config section** — `enabled`, `app_key`, `db_path`, TTL knobs, DCR rate limit knobs. Cross-field validator rejects an `app_key` that does not exist in `clients`.
- **Cascade delete** — `DELETE /admin/keys/{app_key}` now also drops inbound OAuth state for the app (DCR codes + access/refresh tokens) so re-provisioning a compromised key cannot silently regain bearer access.
- **Operator-initiated disconnect** — two admin endpoints to disconnect a connected MCP service without destroying the broker key. `POST /admin/oauth/revoke/{app_key}` wipes an app's inbound OAuth tokens (forces a connected claude.ai-style client to re-authorize) while leaving the broker key and YAML config intact — distinct from `DELETE /admin/keys/{app_key}`, which is the all-or-nothing teardown. `DELETE /admin/connections/{app_key}/{connector}` is the admin-authenticated equivalent of `POST /oauth/{connector}/disconnect`, deleting an app's stored upstream connector token. Both require `X-Admin-Key`.
- **Distributed flow-state stores on the Firestore backend** — `FirestoreConnectTokenStore`, `FirestoreOutboundOAuthStateStore`, and `FirestoreDCRRateLimiter` share connect tokens, outbound OAuth nonces/PKCE verifiers, and DCR rate limiting across workers and instances when `store.backend: firestore`. The single-worker startup abort (`broker.oauth.enabled` + `WEB_CONCURRENCY>1`) now fires only for non-Firestore backends. The in-memory defaults remain for `sqlite` deployments, injected behind the existing ABCs.
- **`NativeConnector.is_tool_available(tool_name)`** — overridable hook letting native connectors hide scope-gated tools from `tools/list`; calls to a hidden tool fail identically to an unknown tool. LinkedIn uses it to withhold its 7 organization tools until the Community Management API scope tier is granted.
- **Slack connector** (Native) — bot-identity messaging via Slack OAuth v2.
- **Notion (REST) connector** (`notion_api`, Native) — direct Notion REST API access exposing 19 tools, including database row queries with filters/sorts (`query_data_source`) that the hosted Notion MCP withholds. Additive alongside the existing `notion` passthrough.
- **File URLs on `notion_api` reads** — attached-file URLs are now surfaced on both read paths, so an asset attached to a page/row can be fetched back by a reader (previously the reductions dropped the URL). A **`files` property** (e.g. a "Media" column) reduces to a list of its file URLs via `query_data_source` / `get_page_property`; **file-bearing blocks** (`image`, `file`, `pdf`, `video`, `audio`) gain a `url` field via `fetch` / `get_block_children` / `append_blocks` and the block-content tools. Both resolve Notion-hosted files (`file.url`) and external ones (`external.url`). The Notion-hosted URL is signed and short-lived (~1h), so callers must read fresh at use time; a not-yet-resolved upload contributes no URL. Additive — other property/block types and existing fields are unchanged.
- **Twitter/X thread + reply tools** (`twitter`, Native) — `post_thread` posts an ordered list of tweets chained as replies (batch-validated up front, max 25 per thread, partial-state preserved on a mid-thread failure); `reply_to_tweet` replies to an existing tweet by ID. Additive alongside the existing five Twitter tools.
- **Twitter/X image post tool** (`twitter`, Native) — `post_image_tweet` posts a tweet with 1–4 attached images (PNG/JPG/GIF/WEBP) supplied as base64, uploading each via X's media endpoint and attaching the returned `media_ids`. Decoded bytes are size-checked (5 MB/image) and the MIME is sniffed before upload. Adds the `media.write` scope to the connector, so **an existing Twitter connection must reconnect to grant it** before this tool works — the other Twitter tools are unaffected. Additive alongside the existing Twitter tools.
- **LinkedIn image + document post tools** (`linkedin`, Native) — `create_image_post` and `create_document_post` publish a post with an attached image (PNG/JPG/GIF) or document (PDF/PPT/DOCX) supplied as base64 bytes; a multi-page document renders as a swipeable carousel in the feed. Both use LinkedIn's versioned `/rest/images` and `/rest/documents` upload flow (initialize upload → PUT bytes → reference the returned URN in `/rest/posts`) and post as the authenticated member by default. Decoded bytes are size-checked before upload (10 MB images, 100 MB documents), and the upload URL returned by LinkedIn is restricted to LinkedIn's own domains before the token-bearing PUT. Additive alongside the existing LinkedIn tools.
- **Broker module entrypoint** (`python -m broker`) — validates settings before uvicorn boots, so config errors exit cleanly instead of propagating from the async lifespan.
- **`GET /oauth/success`** — built-in landing page after a successful outbound OAuth connect, served at a stable URL on the broker. Accepts an optional `?connector=` query param to customize the heading. Auth-exempt; no protected state.
- **`./start mcp-config --auth=apikey|oauth|both`** — `mcp-config` (and the post-connect summary in `./start connect`) prints a compact, command-first list of connected connectors: a legend once at the top, then per connector a ready-to-run `claude mcp add-json <connector>-broker '{"type":"http",…}'` command (shell-quoted, carrying the `X-App-Id` / `X-Broker-Key` / CF-Access headers — for trusted internal callers like the gateway and ADK) and a one-line `oauth url:` to paste as a custom connector in third-party MCP clients (claude.ai, Cursor, Cline). `--auth` filters to just the command, just the URL, or both (default `both`). The once-printed legend also surfaces `broker.oauth.enabled` state and the configured `allowed_redirect_uris`.

### Changed

- **`ConnectorMeta.scopes` is now `tuple[str, ...]`** — immutable so a holder of a connector reference cannot widen the OAuth scope string; list literals in connector definitions coerce, so existing adapters keep working unchanged.
- **Twitter `post_tweet` returns the created tweet object** (`{id, text, ...}`) like the other twitter tools, instead of the raw `{data, errors}` envelope; an X-reported creation failure now raises a sanitized error. Tweet length is validated with X's weighted counting (scheme URLs count 23, wide characters 2) instead of `len()`.
- **Grouped config errors** — missing environment variables are reported together with their `settings.yaml` path, instead of failing on the first miss.
- **`success_redirect_url` defaults to `/oauth/success` on the broker.** When `broker.success_redirect_url` is unset, the OAuth callback now redirects to `{public_url}/oauth/success?connector={connector_name}` rather than rendering inline HTML at the callback URL. Operators with a real dashboard still override via `success_redirect_url` — unchanged behavior. The example settings no longer hardcode `http://localhost:3000`, which left a dead-end UX for any deployment without a local dashboard running.

### Security

- **Dependency CVE fixes** — bumped `cryptography` 46.0.7→49.0.0 (GHSA-537c-gmf6-5ccf), `python-multipart` 0.0.28→0.0.32 (CVE-2026-53538 / -53539 / -53540), `starlette` 1.1.0→1.3.1 (CVE-2026-54282 / -54283; pinned directly as a security floor since it is a transitive dependency of FastAPI), `pip` 26.1.1→26.1.2 (PYSEC-2026-196), and `msgpack` 1.1.2→1.2.1 (GHSA-6v7p-g79w-8964; dev-only, pulled transitively by `pip-audit`). `pip-audit` now reports no known vulnerabilities.
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
