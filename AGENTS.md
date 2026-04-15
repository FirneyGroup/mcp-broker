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

## Connector Architecture

The broker has four connector flavours, all subclassing `BaseConnector`. Flavour is derived from `ConnectorMeta` field values — not declared. The `meta.is_native`, `meta.uses_discovery`, and `meta.is_sidecar_managed` properties compute flavour from fields.

| Flavour | Trigger | Dispatch |
|---------|---------|----------|
| **Static** | `mcp_url` set, `mcp_oauth_url` unset | Proxy forwards to `mcp_url` with `Authorization: Bearer {token}` injected |
| **Discovery** | `mcp_oauth_url` set | Same as Static, but authorize/token URLs discovered at first connect via RFC 8414; client credentials minted via RFC 7591 |
| **Sidecar** | Deployment convention: `mcp_url` resolves to a Docker service on `firney-net`. Not a distinct dispatch path — the code picks based on `auth_mode`, not on the hostname | `auth_mode="broker"` → Static dispatch (broker injects tokens). `auth_mode="sidecar"` (→ `meta.is_sidecar_managed`) → upstream forward with no `Authorization` header |
| **Native** | `mcp_url` is `None` (→ `meta.is_native == True`) | Broker serves MCP in-process via `NativeConnector.handle_mcp_request`; tool handlers receive `access_token` as a keyword argument |

**Registration.** Connectors are loaded at startup by `_load_connectors` in `src/broker/main.py`, which iterates `settings.broker.connectors` and calls `importlib.import_module("connectors.{name}.adapter")` for each entry. The import triggers `BaseConnector.__init_subclass__`, which validates URL fields and calls `ConnectorRegistry.auto_register(cls)` to instantiate and store the class (one instance per connector name). A class whose name isn't in the `connectors` list is never imported — templates and half-written connectors stay dormant.

**Dispatch.** The route `/proxy/{connector_name}/{path:path}` (in `src/broker/main.py`) looks up the connector via `ConnectorRegistry.get(name)`, then branches in `src/broker/services/proxy.py`: `isinstance(connector, NativeConnector)` → `handle_mcp_request()`; otherwise → httpx streaming forward to `meta.mcp_url` with `build_auth_header(access_token)` applied. Typical MCP clients POST to `/proxy/{name}/mcp`, but the `{path:path}` catch-all lets the proxy forward any subpath the upstream exposes.

**Extension points on `BaseConnector`** — override only to handle provider deviations from standard OAuth 2.1:

- `customize_authorize_params(params)` — add provider-specific authorize-URL params (e.g. Google's `access_type=offline`, `prompt=consent`).
- `build_auth_header(access_token)` — default `Authorization: Bearer {token}`. Override to add sibling headers (e.g. Notion's `Notion-Version`).
- `build_token_request_auth(credentials)` — default puts `client_id`/`client_secret` in the POST body (`client_secret_post`). Override to use HTTP Basic Auth (`client_secret_basic`, e.g. Notion).
- `parse_token_response(raw)` — default pass-through. Override when the provider returns extra fields outside the OAuth 2 standard (e.g. Notion's `workspace_id`).

**Data contracts** (see `src/broker/models/connector_config.py`):

- `ConnectorMeta` — frozen class variable. One per connector class. Fields beyond the flavour-determining ones worth knowing: `mcp_transport` (`"streamable_http"` default; set to `"sse"` for SSE-only upstreams like HubSpot), `supports_pkce` (default True; if the upstream does not support PKCE S256, the broker cannot connect to it), `allowed_mcp_methods` (JSON-RPC allowlist — override if an upstream exposes methods beyond the standard MCP set).
- `AppConnectorCredentials` — per-app `client_id`/`client_secret` loaded from `settings.yaml`'s `apps` section at request time.
- `DynamicRegistration` — persisted RFC 7591 registration result (Discovery flavour only). Stored encrypted alongside tokens.
- `NativeToolMeta` — JSON Schema wrapper for each `@native_tool`-decorated method. Becomes the `tools/list` response.

## Connector Rules (MUST)

Flavour is determined by `ConnectorMeta` field values per the Architecture table above — not by directory structure. A connector with `mcp_oauth_url` set is Discovery regardless of which other fields it populates; evaluate Discovery rules against it, not Static rules. Same logic for Native (`mcp_url is None`) and Sidecar (`auth_mode="sidecar"` disables token injection).

### All flavours

- New connectors MUST subclass `BaseConnector` (directly, or via `NativeConnector`) and set `meta = ConnectorMeta(...)` as a class attribute. Do NOT call `ConnectorRegistry.auto_register` manually. **Rationale:** the registry lookup assumes every connector arrived via `__init_subclass__`. Manual registration creates two paths and health-check output diverges.
- The connector name MUST appear in `settings.example.yaml` under `broker.connectors`. **Rationale:** auto-registration happens on import, but the connectors list controls which are actually loaded. A missing entry means the class exists but is inert.
- Every new connector MUST ship `src/connectors/{name}/SETUP.md` covering OAuth registration, redirect URI, and minimum required scopes. **Rationale:** OAuth provider setup is always provider-specific. Without SETUP.md, operators have to read adapter code to guess the scopes.
- Every new connector MUST ship at least one test in `tests/test_{name}_connector.py` asserting: (a) it auto-registers, (b) `meta` validates, (c) any overridden hook returns the expected structure. **Rationale:** without a test, nothing catches a silent meta-validation change or a forgotten override.

### Static

- Static connectors MUST have `{CONNECTOR}_CLIENT_ID` and `{CONNECTOR}_CLIENT_SECRET` entries in `.env.example`, referenced from `settings.example.yaml`'s `apps` section via `${VAR}` interpolation. **Rationale:** operators copy `.env.example` to `.env`. Missing entries mean silent failure at OAuth time with no hint about what's missing.
- Static connectors MUST leave `mcp_oauth_url` unset. **Rationale:** setting both static URLs and a discovery URL triggers the discovery path and ignores the static config — reviewers expect unused fields to be absent, not misleading placeholders.

### Discovery

- Discovery connectors MUST set `mcp_oauth_url` in `ConnectorMeta` and MUST NOT have YAML app credentials. **Rationale:** discovery connectors use RFC 7591 dynamic registration — credentials are minted per app, not shared. YAML credentials would be unused and misleading.
- Discovery connectors SHOULD still set `oauth_authorize_url` and `oauth_token_url` for documentation, with a comment noting they are ignored when `mcp_oauth_url` is present. **Rationale:** reviewers reading the adapter need to see the static fallback URLs even though the discovery path takes precedence.

### Sidecar

- Sidecar connectors MUST declare `auth_mode` explicitly (`"broker"` or `"sidecar"`). **Rationale:** the two modes behave oppositely — `broker` injects Bearer tokens, `sidecar` doesn't. A missing `auth_mode` defaults to `"broker"`, which is likely wrong for a sidecar running its own OAuth.
- Sidecar connectors with `auth_mode="broker"` MUST point `mcp_url` at a Docker service name (e.g. `http://workspace-mcp:8000/mcp`) and the sidecar container MUST run with `EXTERNAL_OAUTH21_PROVIDER=true` (or equivalent). **Rationale:** the sidecar must trust the injected `Authorization` header instead of performing its own OAuth — otherwise you have two OAuth flows competing for the same request.
- Every sidecar MUST ship `sidecars/{name}/docker-compose.yml` joining the `firney-net` network. **Rationale:** the broker reaches sidecars via Docker DNS; a sidecar on a different network is unreachable. See `sidecars/_template/` for the worked pattern.

### Native

- Native connectors MUST subclass `NativeConnector` (not `BaseConnector` directly) and MUST leave `mcp_url` unset. **Rationale:** `NativeConnector` wires up the `@native_tool` decorator collection and JSON-RPC dispatch. Subclassing `BaseConnector` directly skips both and the connector has no tools. `mcp_url is None` is what makes the proxy route dispatch in-process.
- Every tool method MUST be decorated with `@native_tool(NativeToolMeta(...))` and MUST be `async def name(self, *, access_token: str, ...) -> list[dict[str, Any]]`. **Rationale:** `_dispatch_tool` invokes handlers with `access_token` as a keyword argument and expects MCP content blocks back. A positional `access_token`, a missing decorator, or a sync function all silently de-register the tool.
- Synchronous SDK calls inside tool methods MUST be wrapped in `asyncio.get_running_loop().run_in_executor(...)`. **Rationale:** the proxy path is async; a blocking SDK call stalls the entire event loop, freezing every concurrent proxy request across every connector. See `src/connectors/twitter/adapter.py` for the pattern.
- Tool input schemas (`NativeToolMeta.input_schema`) MUST have `"type": "object"` at the top level. Include a `"required"` list when the tool has mandatory parameters; omit it for tools with only optional or no parameters. **Rationale:** MCP `tools/list` delivers this schema to LLMs verbatim; a malformed top-level shape degrades tool-selection accuracy. `required` is only meaningful when something is actually required (see `src/connectors/twitter/adapter.py:56` — `get_me` has no required fields and correctly omits the list).
- Tool handlers MUST NOT log, persist, or include `access_token` in their return value. **Rationale:** tokens belong to the broker's in-memory flow only. A handler leaking the token into logs or MCP responses breaks the security model.

## Provider Onboarding

Use this algorithm when adding a connector for a new OAuth provider. Each step has a mechanical probe — don't skip to a flavour by guessing.

1. **Does the upstream expose an MCP server you can proxy?**
   - Check PyPI, Docker Hub, and the provider's docs for an existing MCP server implementation.
   - **Yes, hosted remotely** → go to step 2 (Static or Discovery).
   - **Yes, but only as a package you run yourself** → **Sidecar**. Package it under `sidecars/{name}/docker-compose.yml`.
   - **No MCP server exists** → **Native**. Wrap the provider's REST API or SDK in-process. Skip to step 4.

2. **Does the remote MCP server support OAuth 2.1 discovery (RFC 8414 + RFC 7591)?** Probe in order:

   ```bash
   curl -fsSL {base}/.well-known/oauth-authorization-server
   # 200 with a JSON body containing registration_endpoint → discovery works
   curl -fsSL {base}/.well-known/oauth-protected-resource
   # 200 → MCP server declares itself OAuth-protected
   curl -fsS -X POST {registration_endpoint} \
     -H 'Content-Type: application/json' \
     -d '{"redirect_uris":["http://localhost"],"client_name":"probe"}'
   # 201 or well-formed error → RFC 7591 dynamic registration works
   ```

   - **All three pass** → **Discovery**. No client credentials needed in `settings.yaml`.
   - **Otherwise** → **Static**. Go to step 3.

3. **For Static, determine the OAuth contract from provider docs:**
   - `oauth_authorize_url` and `oauth_token_url`.
   - PKCE support — broker requires S256. If the provider doesn't support PKCE, the connector is not usable; stop and flag this.
   - Token-exchange auth method — body (`client_secret_post`, default) or HTTP Basic Auth (`client_secret_basic`, requires `build_token_request_auth` override).
   - Scopes — minimum necessary for the tools you expose. Document any privileged scope in `SETUP.md` with justification.
   - Refresh-token support — if the provider doesn't issue refresh tokens, OAuth sessions are short-lived. Document in `SETUP.md`.
   - MCP transport — default `mcp_transport="streamable_http"`. Set to `"sse"` if the provider serves only Server-Sent Events (HubSpot does; check provider docs).
   - Non-standard JSON-RPC methods — default `allowed_mcp_methods` covers the MCP standard. If the upstream exposes provider-specific methods you need to call, override `allowed_mcp_methods` in `ConnectorMeta` to extend the allowlist.

4. **For Native, determine the tool surface and SDK contract from provider docs:**
   - Which operations map to tools (one tool per operation; keep handlers small).
   - SDK is sync or async — sync requires `run_in_executor` wrapping.
   - Does the SDK accept `access_token` per-call or per-client? Per-call is simpler — reconstruct the client inside each handler.
   - JSON Schema for each tool's input. Keep it minimal; every property should map to a provider API parameter.

5. **Judgment calls the probes cannot answer** — document in `SETUP.md`, not in code:
   - Whether the provider's ToS permits your use case.
   - Scope minimization when a single broad scope exists — justify adopting it over multiple narrow ones.
   - Whether to expose write tools or restrict to read-only.

Scaffolding for each flavour lives in `src/connectors/_template/{static,discovery,sidecar,native}/`. Copy the directory, fill in the `TODO` markers, run the test.

## Config Contract

- `settings.yaml` has exactly four top-level sections: `broker`, `store`, `clients`, `apps`. Don't add new top-level sections without updating the loader and this contract. **Rationale:** the loader has explicit handling per section. New sections are silently ignored.
- New config fields MUST have type annotations and live on a Pydantic model with `extra="forbid"`. **Rationale:** see the Architecture Rule — typos would otherwise be silently ignored.
- YAML references to env vars use `${VAR_NAME}` syntax. No inline defaults in YAML — defaults live on the Pydantic model. **Rationale:** two sources of truth for defaults (YAML and Python) drift. The Pydantic model is authoritative.
- Per-app broker keys are NEVER stored in `settings.yaml` or `.env`. They live in SQLite (`broker_keys.db`) as SHA-256 hashes, managed via the admin API. **Rationale:** YAML and .env are operator-visible; key rotation would require file edits. The admin API keeps the raw-key surface to a single one-shot response.

## Testing Rules (MUST)

- Tests MUST exercise real crypto (`MultiFernet`, HMAC signing, PKCE), real SQLite stores (`TokenStore`, `BrokerKeyStore`, `ConnectTokenStore`), and real middleware. Mock only outbound HTTP to upstream MCP servers and OAuth providers. **Rationale:** the broker's security properties live in these components. A test that mocks `TokenStore.get` cannot catch the encryption bug it was written to prevent, and a test that mocks the auth middleware cannot catch the key-to-identity cross-check failing.
- Tests MUST assert on observable behaviour — HTTP responses, persisted state, log records via `caplog` — not on internal method calls via `mock.assert_called_with`. **Rationale:** interaction-based assertions break on every refactor without catching real bugs. Behavioural assertions survive refactoring and verify the contract the caller actually depends on.
- Every new Security Invariant MUST land with a regression test that fails without the fix. **Rationale:** invariants decay when the only thing enforcing them is reviewer memory. A failing test promotes the rule from "please remember" to a machine-checkable gate.

## Commit Messages (MUST)

- Commit subjects MUST follow [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <description>`. Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`. Scope is a connector name (`notion`, `hubspot`), a subsystem (`proxy`, `oauth`, `auth`, `store`, `admin`), or `deps`. **Rationale:** scoped conventional commits make the hand-maintained CHANGELOG parseable, let reviewers filter PRs by area, and let tooling auto-draft release notes.
- Breaking changes MUST mark the subject with `!` after the scope (e.g. `feat(proxy)!: reject app_key from query params`) AND include a `BREAKING CHANGE:` footer describing the migration. **Rationale:** the `!` marker is what tooling and reviewers grep for to spot breaking changes. Without it, a breaking change silently lands as a minor feature and ships to pinned users unannounced.
- Commit messages MUST NOT reference AI assistants, Claude, or any code-generation tool. **Rationale:** the commit log is the project's history of human decisions. Authorship noise from tooling degrades `git blame` and `git log` without adding signal.

## Breaking Changes + CHANGELOG

Any breaking change to the public surface MUST add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) and use the `!` marker in its commit subject (see Commit Messages). **Rationale:** the project is pre-1.0 and users pin to tags. The CHANGELOG is how they decide whether a minor bump is safe to apply.

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
