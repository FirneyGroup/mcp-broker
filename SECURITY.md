# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email **security@firney.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We will acknowledge receipt within 48 hours and aim to provide an initial assessment within 5 business days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Model

This project is an OAuth token broker that sits in the security-critical path between agents and remote APIs. It runs in two roles: **broker-as-client** (outbound — proxying to upstream MCP servers like Notion or HubSpot) and, optionally, **broker-as-AS** (inbound — accepting OAuth from remote MCP clients like claude.ai, opt-in via `broker.oauth.enabled=true`).

### Outbound (broker-as-client)

- **Tokens encrypted at rest** using MultiFernet with key rotation support
- **PKCE (S256)** for all OAuth authorization code flows
- **HMAC-signed OAuth state** with single-use nonces and 10-minute expiry
- **SSRF protection** on OAuth discovery endpoints (blocks private IPs, IMDS, loopback)

### Inbound (broker-as-AS)

- **Bearer + refresh tokens SHA-256-hashed at rest** — inbound tokens are validate-only (the broker IS the AS, so no decrypt-for-replay is needed). Raw values appear exactly once in the `/oauth/token` response; client secrets returned by `/oauth/register` follow the same one-shot pattern.
- **PKCE S256 required** at `/oauth/authorize`; `plain` rejected per OAuth 2.1
- **Audience binding** via RFC 8707 resource indicators — a token issued for one connector cannot be replayed on another (a `/proxy/notion` token returns 401 on `/proxy/hubspot`)
- **Atomic refresh rotation** via SQLite `BEGIN IMMEDIATE` + conditional `UPDATE used_at WHERE used_at IS NULL`; replay triggers cascade-revoke of the entire token family (OAuth 2.1 §4.3.1)
- **Strict `redirect_uri` allowlist** — only `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback`; no loopback, no wildcard. With no identity layer at `/oauth/authorize`, the allowlist + PKCE + the client's own `state` validation IS the security boundary.
- **DCR rate limit** — sliding-window 10 registrations per IP per 15 minutes. `X-Forwarded-For` honored only when the immediate peer is in `broker.oauth.trusted_proxy_ips` (default empty); otherwise the rate-limit key is the direct client.
- **Single-use authorization codes** with 60-second TTL, redirect_uri rebinding at `/oauth/token`, and PKCE verifier required
- **Inbound `Authorization` header stripped** from the request scope after bearer validation, before the proxy forwards upstream
- **RFC-mandated `Cache-Control: no-store`** on `/oauth/token` and `/oauth/register` responses to keep credentials out of shared caches

### Shared

- **Per-app key isolation** — compromised broker key only affects that app's tokens
- **Cascade deletion** — deleting a broker key drops the app's outbound OAuth tokens AND inbound OAuth state (auth codes + bearer/refresh tokens) so re-provisioning a key under the same `app_key` cannot silently regain access
- **Internal headers stripped** before forwarding to upstream MCP servers (`X-Broker-Key`, `X-App-Id`, `Authorization`, `Cookie`, `X-Forwarded-*`)
- **Response headers** strip `Set-Cookie` and hop-by-hop headers before returning to clients
- **Timing-safe comparison** (`hmac.compare_digest`) for all key, secret, and token validation

## Known Limitations

- No built-in rate limiting on admin endpoints or outbound OAuth flows. Inbound DCR has per-IP rate limiting (`broker.oauth.dcr_rate_limit_*`).
- Single-instance nonce storage (in-memory) — multi-instance deployments need shared nonce storage. Inbound OAuth has the analogous constraint: the DCR rate limiter is process-local, so `WEB_CONCURRENCY=1` is enforced at startup when `broker.oauth.enabled=true`.
- SQLite token store is single-instance only. Inbound OAuth state lives in its own `data/inbound_oauth.db` file with the same single-instance constraint.
