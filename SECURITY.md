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

This project is an OAuth token broker that sits in the security-critical path between agents and remote APIs. The security design includes:

- **Tokens encrypted at rest** using MultiFernet with key rotation support
- **PKCE (S256)** for all OAuth authorization code flows
- **HMAC-signed OAuth state** with single-use nonces and 10-minute expiry
- **Per-app key isolation** — compromised broker key only affects that app's tokens
- **Cascade deletion** — deleting a broker key also drops every stored OAuth token for that app, so re-provisioning a key under the same `app_key` cannot silently regain access to previously-linked third-party accounts
- **Internal headers stripped** before forwarding to remote servers
- **Timing-safe comparison** for all key validation
- **SSRF protection** on OAuth discovery endpoints (blocks private IPs, IMDS, loopback)

## Known Limitations

- No built-in rate limiting on OAuth or admin endpoints
- Single-instance nonce storage (in-memory) — multi-instance deployments need shared nonce storage
- SQLite token store is single-instance only
