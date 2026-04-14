# AGENTS.md — mcp-broker

Project invariants for AI reviewers and contributors. Rules are imperative one-liners with a `**Rationale:**` footer so they can be cited with a reason.

For install / quickstart / tutorials see [README.md](README.md); for vulnerability reporting see [SECURITY.md](SECURITY.md); for dev setup and code style see [CONTRIBUTING.md](CONTRIBUTING.md).

## Mechanical Gates (CI already catches these)

Don't suggest changes that would be rejected or auto-fixed by CI. The following are enforced on every PR — no need to flag them in review:

- **ruff** — formatting, import ordering, unused imports, `S` (security) rules including `S101/S105/S106/S608` (asserts, hardcoded passwords, SQL string formatting), `B` (flake8-bugbear), `PLR0913` (>4 args), `PLR0915` (>25 statements), `SIM` (simplifications)
- **pyright** — type checking on `src/`
- **gitleaks** — secret scanning across git history
- **pip-audit** — dependency CVE scanning
- **pre-commit** — yaml/toml validation, trailing whitespace, `uv lock --check`

Flag only things outside these gates: project-specific invariants, logic bugs, cross-file concerns, security-model violations.

## Architecture Rules (MUST / MUST NOT)

- The broker MUST NOT import from any agent-framework SDK. **Rationale:** it speaks MCP over HTTP; which framework calls it is not its concern. Coupling to a specific SDK breaks the neutrality that lets any MCP client use the broker.
- Connectors MUST subclass `BaseConnector`. They auto-register via `__init_subclass__` — do NOT call `register()` manually. **Rationale:** the registry lookup assumes every connector arrived via the subclass hook. Manual registration creates two registration paths and the health check / listing endpoints become inconsistent.
- Runtime configuration MUST live in `settings.yaml`. `.env` holds secrets only, referenced via `${VAR}` interpolation in YAML. **Rationale:** separating structure from secrets lets operators commit settings.yaml while keeping .env local. Inline secrets in YAML leak into logs and version control.
- Config Pydantic models MUST use `ConfigDict(extra="forbid")`. **Rationale:** unknown keys are almost always typos. Silently ignoring them means a misspelled field silently reverts to the default.
- Use Pydantic, never dataclasses. **Rationale:** the codebase depends on `ConfigDict(frozen=True)`, `extra="forbid"`, field validators, and `model_dump_json` throughout — dataclasses don't provide any of these.
- Every `# noqa` and `# type: ignore` MUST include an inline justification. **Rationale:** a bare `# noqa: S101` is indistinguishable from "I forgot to fix this". A justification lets the next reader see why the exception exists.

## Security Invariants (MUST)

- Tokens MUST be encrypted at rest via `MultiFernet`, not plain `Fernet`. **Rationale:** key rotation is required — `MultiFernet` tries each key in order, so an operator can add a new key today and remove the old one later without downtime.
- Key validation MUST use `hmac.compare_digest`. **Rationale:** `==` short-circuits on first mismatch, leaking timing information. `compare_digest` is constant-time.
- OAuth flows MUST use PKCE (S256). **Rationale:** prevents code-interception attacks where an attacker intercepts the authorization code. Without PKCE, a stolen code can be redeemed by anyone.
- OAuth state MUST be HMAC-signed with single-use nonces and a ≤10-minute TTL. **Rationale:** unsigned state enables CSRF; replayable state enables login-fixation. Short TTL bounds the replay window.
- Internal headers MUST be stripped before forwarding upstream: `X-Broker-Key`, `X-App-Id`, `Authorization`, `Cookie`, `X-Forwarded-*`, `Forwarded`, `Host`. **Rationale:** these expose broker-internal credentials or caller identity to third-party MCP servers. Leakage here is the worst-case outcome of this project.
- Response headers MUST strip `Set-Cookie` and hop-by-hop headers before returning to clients. **Rationale:** a malicious or compromised upstream MCP server could set cookies on the broker's domain, hijacking the client's session.
- API keys MUST be SHA-256 hashed at rest. Raw keys MUST be shown once on creation and never retrievable. **Rationale:** a DB dump without hashing hands attackers every key. One-shot display means we don't have to store the raw value anywhere after creation.
- Connect tokens MUST be single-use and time-limited (≤5-minute TTL). **Rationale:** they appear in URLs that end up in browser history and proxy logs. Short-lived and single-use means a leaked URL is useless.
- Auth middleware MUST cross-check the verified broker key against the claimed `X-App-Id`. **Rationale:** without the cross-check, any valid key authenticates any app — a compromised key for app A could impersonate app B.
- OAuth discovery MUST reject private, loopback, and link-local addresses. **Rationale:** an attacker-controlled upstream could redirect discovery to `169.254.169.254` (cloud metadata) or internal services. SSRF defence.
- Log statements MUST NOT include tokens, keys, secrets, or decrypted credentials — even at DEBUG level. **Rationale:** operators enable DEBUG in production to chase issues. Secrets in DEBUG logs end up in log aggregators, alerts, and screenshots.

## Known Gotchas

1. **Encrypted fields** — If you add a new field to `AppConnection` that holds sensitive data, you MUST extend `_encrypt_connection` and `_decrypt_connection` in `src/broker/services/store.py`. **Rationale:** the encryption layer operates on specific named fields, not the whole model. New fields default to plaintext unless explicitly added.
2. **Cascade deletion** — Deleting a broker key cascades to OAuth tokens via `TokenStore.delete_all_for_app`. If you add new per-app persisted state elsewhere, the cascade MUST cover it too. **Rationale:** re-provisioning the same `app_key` after a compromise silently regains access to any leaked-then-retained state.
3. **Exempt paths** — Entries in `middleware/auth.py`'s exempt-path list are security decisions. New exemptions require explicit justification in the PR description. **Rationale:** an exempt path bypasses all auth. Every addition is a direct security-model change.
4. **In-memory state** — `_consumed_nonces`, `_pkce_verifiers`, and `ConnectTokenStore` are process-local. Any new in-memory state added to middleware or services MUST be called out. **Rationale:** horizontal scaling requires moving state to a shared backing. Single-instance assumptions leak into code as `dict` or `set` without the author realising.
5. **Streaming proxy** — The proxy forwards SSE and Streamable HTTP responses unbuffered. New code on the proxy path MUST use `httpx` streaming consistently. **Rationale:** buffering a response before forwarding breaks MCP sessions — clients time out waiting for the first chunk.
6. **Identity binding** — `app_key` is sourced exclusively from `request.state.identity` (set by middleware). Routes MUST NOT accept `app_key` from query params, bodies, or client-supplied headers. **Rationale:** any path that lets a client supply `app_key` bypasses the middleware's key-to-identity cross-check and enables impersonation.

## Connector Rules (MUST)

- New connectors MUST subclass `BaseConnector` and set a `meta = ConnectorMeta(...)` class attribute. **Rationale:** the registry discovers connectors by reading `meta` on each subclass.
- The connector name MUST appear in `settings.example.yaml` under `broker.connectors`. **Rationale:** auto-registration happens on import, but the connectors list controls which are actually loaded. A missing entry means the class exists but is inactive.
- Static connectors MUST have `{CONNECTOR}_CLIENT_ID` and `{CONNECTOR}_CLIENT_SECRET` entries in `.env.example` with the canonical env var names. **Rationale:** operators copy `.env.example` to `.env`. Missing entries mean silent failure at OAuth time with no hint about what's missing.
- Every new connector MUST ship `src/connectors/{name}/SETUP.md` covering OAuth registration, redirect URI, and required scopes. **Rationale:** OAuth provider setup is always connector-specific. Without SETUP.md, operators have to read your adapter code to guess the scopes.
- Discovery connectors MUST set `mcp_oauth_url` in `ConnectorMeta` and MUST NOT have YAML app credentials. **Rationale:** discovery connectors use RFC 7591 dynamic registration — credentials are minted per app, not shared. YAML credentials would be unused and misleading.
- Sidecar connectors MUST declare `auth_mode` explicitly (`"broker"` or `"sidecar"`). **Rationale:** the two modes behave oppositely — `broker` injects Bearer tokens, `sidecar` doesn't. A missing `auth_mode` means a silent default that likely isn't what the operator wants. See `sidecars/_template/` for the worked pattern.

## Config Contract

- `settings.yaml` has exactly four top-level sections: `broker`, `store`, `clients`, `apps`. Don't add new top-level sections without updating the loader and this contract. **Rationale:** the loader has explicit handling per section. New sections are silently ignored.
- New config fields MUST have type annotations and live on a Pydantic model with `extra="forbid"`. **Rationale:** see the Architecture Rule — typos would otherwise be silently ignored.
- YAML references to env vars use `${VAR_NAME}` syntax. No inline defaults in YAML — defaults live on the Pydantic model. **Rationale:** two sources of truth for defaults (YAML and Python) drift. The Pydantic model is authoritative.
- Per-app broker keys are NEVER stored in `settings.yaml` or `.env`. They live in SQLite (`broker_keys.db`) as SHA-256 hashes, managed via the admin API. **Rationale:** YAML and .env are operator-visible; key rotation would require file edits. The admin API keeps the raw-key surface to a single one-shot response.

## Breaking Changes + CHANGELOG

Any breaking change to the public surface MUST add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md). **Rationale:** the project is pre-1.0 and users pin to tags. The CHANGELOG is how they decide whether a minor bump is safe to apply.

The public surface:

- HTTP API paths (`/proxy`, `/oauth`, `/admin`, `/status`, `/health`)
- The `BaseConnector` / `ConnectorMeta` contract
- `settings.yaml` schema and field names
- `.env` variable names
- `./start` CLI subcommands and output formats

Patch-level changes (bug fixes, docstring edits, internal refactors) don't need CHANGELOG entries.

## See also

- [README.md](README.md) — install, quickstart, connector examples, deployment
- [SECURITY.md](SECURITY.md) — security model and vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, PR process, code style
- [CHANGELOG.md](CHANGELOG.md) — release history
