"""OAuth 2.1 authorization server endpoints (RFC 6749/7009/7591/7636/8414/8707).

This module implements the AS role. The broker is both AS and resource server
(co-located per claude.ai bug #82 — claude.ai derives /authorize from the MCP
base URL rather than reading authorization_servers from AS metadata).

WARNING: The in-memory DCR rate limiter is single-process. Multi-worker
deployments need a shared backing store; ``broker/__main__.py`` aborts startup
when ``WEB_CONCURRENCY > 1`` AND ``broker.oauth.enabled`` is true.
"""

from __future__ import annotations

import html
import secrets
import time
from collections.abc import Callable
from http import HTTPStatus
from typing import Literal
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict

from broker.config import OAuthInboundConfig
from broker.models.inbound_auth import (
    InboundToken,
    OAuthClient,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RotatedTokenPair,
    TokenResponse,
)
from broker.services.inbound_auth_store import (
    InvalidGrantError,
    SQLiteInboundAuthStore,
    generate_access_token,
    generate_family_id,
    generate_refresh_token,
)
from broker.services.inbound_oauth_helpers import (
    audit_log_oauth_event,
    connector_from_resource,
    hash_prefix,
    is_acceptable_redirect_uri,
    normalize_resource,
    parse_basic_auth,
    sha256_hex,
    verify_pkce_s256,
)

# === CONSTANTS ===

# 43..128 base64url chars — PKCE S256, RFC 7636 §4.2
_CODE_CHALLENGE_MIN_LEN = 43
_CODE_CHALLENGE_MAX_LEN = 128

_BEARER_TOKEN_TYPE = "Bearer"  # noqa: S105 -- RFC 6749 §5.1 token_type value, not a credential

_GRANT_AUTH_CODE = "authorization_code"
_GRANT_REFRESH = "refresh_token"  # noqa: S105 -- OAuth 2.0 §6 grant_type value, not a credential

_VALID_RESPONSE_TYPE = "code"
_VALID_CODE_CHALLENGE_METHOD = "S256"

# RFC 7591 §2.3 — public clients send token_endpoint_auth_method="none".
_PUBLIC_CLIENT_AUTH_METHOD = "none"


# Consent page is intentionally minimal — without an identity layer it's a
# ceremonial confirmation. Defense-in-depth headers are set on the response.
CONSENT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Authorize {client_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        max-width: 480px; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ font-size: 1.4rem; margin-bottom: 1rem; }}
.detail {{ background: #f4f4f4; border-radius: 6px; padding: 1rem; margin: 1rem 0;
           font-size: 0.9rem; word-break: break-all; }}
.actions {{ display: flex; gap: 0.5rem; margin-top: 1.5rem; }}
button {{ flex: 1; padding: 0.75rem 1rem; border-radius: 6px; border: 0;
          font-size: 1rem; cursor: pointer; font-weight: 600; }}
.approve {{ background: #0a66c2; color: #fff; }}
.deny {{ background: #e5e5e5; color: #1a1a1a; }}
</style>
</head>
<body>
<h1>Authorize {client_name}</h1>
<p>This will grant <strong>{client_name}</strong> bearer-token access via the
broker to:</p>
<div class="detail"><strong>Resource:</strong> {resource}</div>
<div class="detail"><strong>Scope:</strong> {scope}</div>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="code_challenge_method" value="S256">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="resource" value="{resource}">
<div class="actions">
<button class="approve" name="action" value="approve">Approve</button>
<button class="deny" name="action" value="deny">Deny</button>
</div>
</form>
</body>
</html>
"""

# Consent page headers — defense-in-depth against clickjacking. CSP is the
# load-bearing one; X-Frame-Options exists for older browser shims.
_CONSENT_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'; form-action 'self'",
    "Cache-Control": "no-store",
}

# RFC 6749 §5.1 (token endpoint) and RFC 7591 §3.2.1 (registration response with
# client_secret) both MUST emit no-store. Pragma included for HTTP/1.0 caches.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


# === RATE LIMITER ===


class _DCRRateLimiter:
    """In-memory sliding-window rate limiter for /oauth/register.

    Single-process only — mirrors ``ConnectTokenStore`` caveat. Multi-worker
    deployments would have per-worker limits equal to (cap × N), which is why
    ``broker/__main__.py`` blocks ``WEB_CONCURRENCY > 1`` when OAuth is on.
    """

    def __init__(self, max_per_window: int, window_seconds: int) -> None:
        self._max_per_window = max_per_window
        self._window_seconds = window_seconds
        self._events: dict[str, list[float]] = {}

    def allow(self, client_ip: str) -> bool:
        """True if the IP is under the cap; records the event when True."""
        now_ts = time.time()
        events = self._events.setdefault(client_ip, [])
        events[:] = [ts for ts in events if now_ts - ts < self._window_seconds]
        if len(events) >= self._max_per_window:
            return False
        events.append(now_ts)
        return True


class _NewFamilyContext(BaseModel):
    """Consumed code + freshly-minted token IDs shared by the two row builders.

    Bundled into one object so ``_new_access_row`` and ``_new_refresh_row`` stay
    within the 4-arg limit while still receiving every value they need.
    Internal — not a public model.
    """

    consumed: OAuthCode
    client_id: str
    family_id: str
    access_hash: str
    refresh_hash: str
    now_ts: int

    model_config = ConfigDict(frozen=True, extra="forbid")


# === ENDPOINTS ===


class OAuthServerEndpoints:
    """Class-based handlers for the four OAuth AS endpoints.

    Construct once in lifespan; mount each method as a FastAPI route in
    ``main.py`` (mirrors the ``AdminEndpoints`` shape so module-level state
    stays out of the handlers).
    """

    def __init__(
        self,
        inbound_auth_store: SQLiteInboundAuthStore,
        config: OAuthInboundConfig,
        connector_names_provider: Callable[[], list[str]],
        public_url: str,
    ) -> None:
        self._inbound_auth_store = inbound_auth_store
        self._config = config
        self._connector_names_provider = connector_names_provider
        # ``public_url`` carries the operator's trailing slash for OAuth-callback
        # concatenation; we want the bare issuer form here.
        self._public_url = public_url.rstrip("/")
        self._dcr_rate_limiter = _DCRRateLimiter(
            max_per_window=config.dcr_rate_limit_per_ip,
            window_seconds=config.dcr_rate_limit_window_seconds,
        )

    # --- /oauth/register ---

    async def register(self, request: Request) -> Response:
        """RFC 7591 Dynamic Client Registration."""
        if not self._config.enabled:
            return _not_found()
        client_ip = self._client_ip(request)
        if not self._dcr_rate_limiter.allow(client_ip):
            return _oauth_error(
                HTTPStatus.TOO_MANY_REQUESTS, "invalid_request", "registration rate limit exceeded"
            )

        registration, error = await _parse_registration_request(request)
        if error is not None:
            return error
        assert registration is not None  # noqa: S101 -- guaranteed by error short-circuit above

        redirect_error = _validate_registration_redirects(registration.redirect_uris)
        if redirect_error is not None:
            return redirect_error

        response_payload = await self._inbound_auth_store.create_client(
            registration, client_ip=client_ip
        )
        return JSONResponse(
            response_payload.model_dump(exclude_none=True),
            status_code=HTTPStatus.CREATED,
            headers=_NO_STORE_HEADERS,
        )

    # --- /oauth/authorize (GET) ---

    async def authorize_get(self, request: Request) -> Response:
        """RFC 6749 §4.1.1 authorization request — render consent HTML on success."""
        if not self._config.enabled:
            return _not_found()
        params = dict(request.query_params)
        client_or_error = await self._resolve_pre_redirect(params)
        if isinstance(client_or_error, Response):
            return client_or_error

        connector_or_error = self._resolve_post_redirect_target(params, client_or_error)
        if isinstance(connector_or_error, Response):
            return connector_or_error
        # connector_or_error is the connector name (str) — currently only used
        # for audit logging; resource binding is enforced by the matching above.
        audit_log_oauth_event(
            "authorize_view",
            client_id=params["client_id"],
            resource=params["resource"],
            scope=params.get("scope", ""),
            ip=self._client_ip(request),
        )
        return _render_consent(params, client_or_error.client_name)

    # --- /oauth/authorize (POST) ---

    async def authorize_post(self, request: Request) -> Response:
        """Consent submission — mints code + redirects, or redirects with error."""
        if not self._config.enabled:
            return _not_found()
        body = await request.form()
        params = {key: str(value) for key, value in body.items()}
        client_or_error = await self._resolve_pre_redirect(params)
        if isinstance(client_or_error, Response):
            return client_or_error

        connector_or_error = self._resolve_post_redirect_target(params, client_or_error)
        if isinstance(connector_or_error, Response):
            return connector_or_error

        action = params.get("action")
        if action == "deny":
            audit_log_oauth_event("authorize_deny", client_id=params["client_id"])
            return _redirect_with_error(
                params["redirect_uri"], params.get("state", ""), "access_denied"
            )
        # Explicit allowlist: only "approve" mints a code. Empty or unknown
        # action values previously fell through to mint — harmless under PKCE
        # (the code is useless without the verifier) but the intent is clearly
        # approve-or-deny and the fallthrough was surprising.
        if action != "approve":
            return _bad_request_html("action must be 'approve' or 'deny'")

        return await self._mint_authorization_code(params)

    # --- /oauth/token ---

    async def token(self, request: Request) -> Response:
        """RFC 6749 §4.1.3 / §6 — dispatch by ``grant_type``."""
        if not self._config.enabled:
            return _not_found()
        form = await request.form()
        params = {key: str(value) for key, value in form.items()}
        grant_type = params.get("grant_type", "")
        client_or_error = await self._authenticate_token_client(request, params)
        if isinstance(client_or_error, Response):
            return client_or_error

        if grant_type == _GRANT_AUTH_CODE:
            return await self._token_authorization_code(params, client_or_error)
        if grant_type == _GRANT_REFRESH:
            return await self._token_refresh(params, client_or_error)
        return _oauth_error(
            HTTPStatus.BAD_REQUEST,
            "unsupported_grant_type",
            f"grant_type '{grant_type}' not supported",
        )

    # --- /oauth/revoke ---

    async def revoke(self, request: Request) -> Response:
        """RFC 7009 §2.2 — always 200, regardless of token existence."""
        if not self._config.enabled:
            return _not_found()
        form = await request.form()
        params = {key: str(value) for key, value in form.items()}
        client_or_error = await self._authenticate_token_client(request, params)
        if isinstance(client_or_error, Response):
            # RFC 7009 §2.2: invalid clients still get 200 to avoid leaking
            # which client_ids exist. Authentication failures translate to a
            # silent no-op rather than the standard 401.
            return Response(status_code=HTTPStatus.OK)

        raw_token = params.get("token", "").strip()
        if not raw_token:
            return Response(status_code=HTTPStatus.OK)
        token_hash = sha256_hex(raw_token)
        kinds = _kinds_from_hint(params.get("token_type_hint", ""))
        for token_kind in kinds:
            await self._inbound_auth_store.revoke_token(
                token_hash, client_or_error, kind=token_kind
            )
        return Response(status_code=HTTPStatus.OK)

    # --- INTERNAL: validation pipeline ---

    async def _resolve_pre_redirect(self, params: dict[str, str]) -> OAuthClient | Response:
        """Validate authorize request fields that MUST 400 (pre-redirect).

        Returns the matched ``OAuthClient`` on success, an error ``Response``
        otherwise.
        """
        if params.get("response_type") != _VALID_RESPONSE_TYPE:
            return _bad_request_html("response_type must be 'code'")
        client_id = params.get("client_id", "")
        if not client_id:
            return _bad_request_html("client_id is required")
        client_record = await self._inbound_auth_store.get_client(client_id)
        if client_record is None:
            return _bad_request_html("client_id not registered")
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri not in client_record.redirect_uris or not is_acceptable_redirect_uri(
            redirect_uri
        ):
            return _bad_request_html("redirect_uri not registered for this client")
        return client_record

    def _resolve_post_redirect_target(
        self,
        params: dict[str, str],
        client_record: OAuthClient,
    ) -> str | Response:
        """Validate fields that must redirect-with-error if invalid (RFC 6749 §4.1.2.1)."""
        del client_record  # signature-only — kept for symmetry with future scope checks
        redirect_uri = params["redirect_uri"]
        state = params.get("state", "")
        challenge_error = _validate_pkce(params)
        if challenge_error is not None:
            return _redirect_with_error(redirect_uri, state, challenge_error)
        if not state:
            return _redirect_with_error(redirect_uri, "", "invalid_request")
        connector_names = self._connector_names_provider()
        connector, error_code = self._validate_resource_and_connector(
            params.get("resource", ""), connector_names
        )
        if error_code is not None:
            return _redirect_with_error(redirect_uri, state, error_code)
        assert connector is not None  # noqa: S101 -- guaranteed by error_code is None
        scope_error = _validate_scope(params.get("scope", ""), connector)
        if scope_error is not None:
            return _redirect_with_error(redirect_uri, state, scope_error)
        return connector

    def _validate_resource_and_connector(
        self,
        resource_param: str,
        connector_names: list[str],
    ) -> tuple[str | None, str | None]:
        """Return ``(connector_name, None)`` on success, or ``(None, error_code)`` on failure.

        ``error_code`` is one of: ``"invalid_request"``, ``"invalid_target"``.
        Empty/malformed resource → ``invalid_request``; unknown connector → ``invalid_target``.
        """
        try:
            resource_norm = normalize_resource(resource_param)
        except ValueError:
            return None, "invalid_request"
        connector = connector_from_resource(resource_norm, self._public_url, connector_names)
        if connector is None:
            return None, "invalid_target"
        return connector, None

    # --- INTERNAL: token endpoint helpers ---

    async def _authenticate_token_client(
        self,
        request: Request,
        params: dict[str, str],
    ) -> str | Response:
        """Return the authenticated ``client_id`` or an error ``Response``.

        Confidential clients MUST authenticate via Basic auth header or POST
        body (``client_id`` + ``client_secret``); public clients pass only
        ``client_id``. Mismatched auth method → 401 ``invalid_client``.
        """
        client_id, supplied_secret = _extract_client_credentials(request, params)
        if not client_id:
            return _oauth_error(HTTPStatus.UNAUTHORIZED, "invalid_client", "client_id required")
        client_record = await self._inbound_auth_store.get_client(client_id)
        if client_record is None:
            return _oauth_error(
                HTTPStatus.UNAUTHORIZED, "invalid_client", "client_id not registered"
            )
        if client_record.token_endpoint_auth_method == _PUBLIC_CLIENT_AUTH_METHOD:
            return client_id
        return await self._authenticate_confidential_client(client_id, supplied_secret)

    async def _authenticate_confidential_client(
        self, client_id: str, supplied_secret: str
    ) -> str | Response:
        """Verify a confidential client's secret against the store's stored hash."""
        if not supplied_secret:
            return _oauth_error(HTTPStatus.UNAUTHORIZED, "invalid_client", "client_secret required")
        valid = await self._inbound_auth_store.verify_client_secret(client_id, supplied_secret)
        if not valid:
            return _oauth_error(HTTPStatus.UNAUTHORIZED, "invalid_client", "client_secret mismatch")
        return client_id

    async def _token_authorization_code(
        self,
        params: dict[str, str],
        client_id: str,
    ) -> Response:
        """RFC 6749 §4.1.3 — exchange auth code for tokens."""
        grant_or_error = _validate_code_grant_params(params)
        if isinstance(grant_or_error, Response):
            return grant_or_error
        code, verifier, redirect_uri, resource = grant_or_error
        code_hash = sha256_hex(code)
        consumed = await self._inbound_auth_store.consume_code(code_hash, client_id)
        if consumed is None:
            return _oauth_error(
                HTTPStatus.BAD_REQUEST, "invalid_grant", "authorization code invalid"
            )
        if consumed.redirect_uri != redirect_uri:
            return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_grant", "redirect_uri mismatch")
        if not verify_pkce_s256(verifier, consumed.code_challenge):
            return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_grant", "PKCE verification failed")
        target_error = _check_resource_against_stored(resource, consumed.resource)
        if target_error is not None:
            return target_error
        pair = await self._mint_initial_pair(consumed, client_id)
        return _token_json(pair, consumed.scope, self._config.access_token_ttl_seconds)

    async def _token_refresh(
        self,
        params: dict[str, str],
        client_id: str,
    ) -> Response:
        """RFC 6749 §6 + OAuth 2.1 §4.3.1 — atomic refresh rotation."""
        refresh_token = params.get("refresh_token", "")
        if not refresh_token:
            return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_request", "refresh_token required")
        token_hash = sha256_hex(refresh_token)

        rotation_or_error = await self._rotate_refresh_with_scope_check(
            params, client_id, token_hash
        )
        if isinstance(rotation_or_error, Response):
            return rotation_or_error
        return _token_json(
            rotation_or_error, rotation_or_error.access.scope, self._config.access_token_ttl_seconds
        )

    async def _rotate_refresh_with_scope_check(
        self, params: dict[str, str], client_id: str, token_hash: str
    ) -> RotatedTokenPair | Response:
        """Look up the prior token, enforce scope ⊆, then rotate atomically.

        Reading the prior row first lets us reject scope widening with an
        explicit ``invalid_scope`` rather than letting the rotation succeed
        with the widened scope.
        """
        prior_row = await self._inbound_auth_store.get_refresh_row(token_hash)
        # client_id mismatch must return the SAME error as "not found" so an
        # attacker who happens to know another client's token_hash cannot use
        # the response shape (invalid_scope vs invalid_grant) as a confirmation
        # oracle for whether that hash exists in the store.
        if prior_row is None or prior_row.client_id != client_id:
            return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_grant", "refresh_token invalid")
        scope_or_error = _resolve_rotation_scope(params.get("scope"), prior_row.scope)
        if isinstance(scope_or_error, Response):
            return scope_or_error
        rotation_request = self._build_rotation_request(prior_row, client_id, scope_or_error)
        try:
            return await self._inbound_auth_store.rotate_refresh(rotation_request)
        except InvalidGrantError as exc:
            return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_grant", str(exc))

    def _build_rotation_request(
        self, prior_row: InboundToken, client_id: str, scope: str
    ) -> RefreshRotationRequest:
        """Bundle rotation inputs + config-driven TTLs into the store contract."""
        return RefreshRotationRequest(
            token_hash=prior_row.token_hash,
            client_id=client_id,
            resource=prior_row.resource,
            scope=scope,
            access_ttl_seconds=self._config.access_token_ttl_seconds,
            refresh_ttl_seconds=self._config.refresh_token_ttl_seconds,
        )

    # --- INTERNAL: mint code + initial token pair ---

    async def _mint_authorization_code(
        self,
        params: dict[str, str],
    ) -> Response:
        """Persist a freshly-minted auth code and redirect to claude.ai callback."""
        raw_code = secrets.token_urlsafe(32)
        code_hash = sha256_hex(raw_code)
        await self._persist_code(code_hash, params)
        callback = (
            params["redirect_uri"]
            + "?"
            + urlencode({"code": raw_code, "state": params.get("state", "")})
        )
        return RedirectResponse(callback, status_code=HTTPStatus.FOUND)

    async def _persist_code(self, code_hash: str, params: dict[str, str]) -> None:
        """Build the OAuthCode row, write it to the store, and emit an audit event."""
        # Storage keeps the RAW resource string the client sent (RFC 8707
        # normalization-vs-storage policy documented in normalize_resource).
        oauth_code = OAuthCode(
            client_id=params["client_id"],
            app_key=self._config.app_key or "",
            redirect_uri=params["redirect_uri"],
            resource=params["resource"],
            scope=params.get("scope", ""),
            code_challenge=params["code_challenge"],
            expires_at=int(time.time()) + self._config.code_ttl_seconds,
        )
        await self._inbound_auth_store.create_code(code_hash, oauth_code)
        audit_log_oauth_event(
            "authorize_approve",
            client_id=params["client_id"],
            app_key=oauth_code.app_key,
            code_hash_prefix=hash_prefix(code_hash),
        )

    async def _mint_initial_pair(
        self,
        consumed: OAuthCode,
        client_id: str,
    ) -> RotatedTokenPair:
        """Mint and persist the first (access, refresh) pair for an auth code grant."""
        pair = self._build_token_pair(consumed, client_id)
        await self._inbound_auth_store.create_token_pair(pair)
        return pair

    def _build_token_pair(self, consumed: OAuthCode, client_id: str) -> RotatedTokenPair:
        """Construct a fresh access+refresh pair in a new token family.

        Tokens are generated here (raw + hash); only the hashes plus metadata
        reach the database via ``create_token_pair``. The raw strings travel
        on the returned ``RotatedTokenPair`` so the caller can return them once.
        """
        raw_access, access_hash = generate_access_token()
        raw_refresh, refresh_hash = generate_refresh_token()
        ctx = _NewFamilyContext(
            consumed=consumed,
            client_id=client_id,
            family_id=generate_family_id(),
            access_hash=access_hash,
            refresh_hash=refresh_hash,
            now_ts=int(time.time()),
        )
        return RotatedTokenPair(
            access=self._new_access_row(ctx),
            refresh=self._new_refresh_row(ctx),
            raw_access_token=raw_access,
            raw_refresh_token=raw_refresh,
        )

    def _new_access_row(self, ctx: _NewFamilyContext) -> InboundToken:
        """Build the access-token row for a new family. TTL from config."""
        return InboundToken(
            token_hash=ctx.access_hash,
            token_kind="access",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=ctx.refresh_hash,
            family_id=ctx.family_id,
            client_id=ctx.client_id,
            app_key=ctx.consumed.app_key,
            resource=ctx.consumed.resource,
            scope=ctx.consumed.scope,
            expires_at=ctx.now_ts + self._config.access_token_ttl_seconds,
            issued_at=ctx.now_ts,
        )

    def _new_refresh_row(self, ctx: _NewFamilyContext) -> InboundToken:
        """Build the refresh-token row for a new family. TTL from config."""
        return InboundToken(
            token_hash=ctx.refresh_hash,
            token_kind="refresh",  # noqa: S106 -- discriminator literal, not a credential
            family_id=ctx.family_id,
            client_id=ctx.client_id,
            app_key=ctx.consumed.app_key,
            resource=ctx.consumed.resource,
            scope=ctx.consumed.scope,
            expires_at=ctx.now_ts + self._config.refresh_token_ttl_seconds,
            issued_at=ctx.now_ts,
        )

    # --- INTERNAL: rate-limit key ---

    def _client_ip(self, request: Request) -> str:
        """Resolve the rate-limit key for a request.

        Trusts ``X-Forwarded-For`` only when the immediate client is in the
        configured ``trusted_proxy_ips`` list. Otherwise uses
        ``request.client.host`` directly. This prevents direct-access attackers
        from cycling fake XFF values to bypass DCR rate limiting.
        """
        immediate_ip = request.client.host if request.client else ""
        if immediate_ip in self._config.trusted_proxy_ips:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",", 1)[0].strip()
        return immediate_ip or "unknown"


# === MODULE-LEVEL HELPERS ===


def _not_found() -> Response:
    """404 used when ``broker.oauth.enabled=false`` — keeps the OAuth surface
    invisible to clients that probe without checking ``.well-known/`` first."""
    return JSONResponse({"error": "not_found"}, status_code=HTTPStatus.NOT_FOUND)


def _oauth_error(status_code: int, code: str, description: str) -> Response:
    """RFC 6749 §5.2 error payload as JSON."""
    return JSONResponse({"error": code, "error_description": description}, status_code=status_code)


def _bad_request_html(description: str) -> Response:
    """Pre-redirect authorize errors: HTML 400 so the human user sees a hint."""
    body = (
        "<!DOCTYPE html><html><body><h1>Authorization request rejected</h1>"
        f"<p>{html.escape(description)}</p></body></html>"
    )
    return HTMLResponse(body, status_code=HTTPStatus.BAD_REQUEST, headers=_CONSENT_HEADERS)


def _redirect_with_error(redirect_uri: str, state: str, error: str) -> Response:
    """Post-redirect errors flow through the redirect URI per RFC 6749 §4.1.2.1."""
    query = urlencode({"error": error, "state": state} if state else {"error": error})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=HTTPStatus.FOUND)


async def _parse_registration_request(
    request: Request,
) -> tuple[RegistrationRequest | None, Response | None]:
    """Parse JSON body into ``RegistrationRequest`` or return a 400 ``Response``."""
    try:
        raw = await request.json()
    except (ValueError, UnicodeDecodeError):
        return None, _oauth_error(
            HTTPStatus.BAD_REQUEST, "invalid_request", "request body must be JSON"
        )
    try:
        return RegistrationRequest(**raw), None
    except (TypeError, ValueError) as exc:
        return None, _oauth_error(
            HTTPStatus.BAD_REQUEST, "invalid_request", f"invalid registration: {exc}"
        )


def _validate_registration_redirects(redirect_uris: list[str]) -> Response | None:
    """Reject fragments (RFC 7591 §2) and anything outside the v1 allowlist."""
    for uri in redirect_uris:
        if "#" in uri:
            return _oauth_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri must not contain a fragment",
            )
        if not is_acceptable_redirect_uri(uri):
            return _oauth_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_redirect_uri",
                f"redirect_uri '{uri}' not allowed (claude.ai callbacks only in v1)",
            )
    return None


def _validate_pkce(params: dict[str, str]) -> str | None:
    """Return an RFC-6749 error code if PKCE is missing/wrong; ``None`` on success."""
    method = params.get("code_challenge_method", "")
    if method != _VALID_CODE_CHALLENGE_METHOD:
        return "invalid_request"
    challenge = params.get("code_challenge", "")
    if not _CODE_CHALLENGE_MIN_LEN <= len(challenge) <= _CODE_CHALLENGE_MAX_LEN:
        return "invalid_request"
    return None


def _extract_client_credentials(request: Request, params: dict[str, str]) -> tuple[str, str]:
    """Pull ``(client_id, client_secret)`` from Basic auth header or POST body.

    RFC 6749 §2.3.1 allows either form; Basic header wins when present. Returns
    empty strings when neither carries a value — caller surfaces the right
    OAuth error.
    """
    basic = parse_basic_auth(request.headers.get("authorization", ""))
    if basic is not None:
        return basic
    return params.get("client_id", ""), params.get("client_secret", "")


def _validate_code_grant_params(
    params: dict[str, str],
) -> tuple[str, str, str, str] | Response:
    """Extract ``(code, verifier, redirect_uri, resource)`` from the /token form.

    Returns an ``invalid_request`` error response when any of code, code_verifier,
    or redirect_uri are missing — these three are mandatory at exchange time.
    """
    code = params.get("code", "")
    verifier = params.get("code_verifier", "")
    redirect_uri = params.get("redirect_uri", "")
    resource = params.get("resource", "")
    if not code or not verifier or not redirect_uri:
        return _oauth_error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "code, code_verifier, and redirect_uri required",
        )
    return code, verifier, redirect_uri, resource


def _validate_scope(scope: str, connector_name: str) -> str | None:
    """Every ``mcp:proxy:X`` scope MUST match the connector this token will bind to."""
    if not scope:
        return None
    for entry in scope.split():
        if entry == "mcp:status":
            continue
        if entry == f"mcp:proxy:{connector_name}":
            continue
        return "invalid_scope"
    return None


def _kinds_from_hint(token_type_hint: str) -> tuple[Literal["access", "refresh"], ...]:
    """Map RFC 7009 ``token_type_hint`` to the list of token kinds to revoke.

    The hint is advisory per §2.1; servers SHOULD attempt the other type if the
    hint misses. We always try both unless the hint is one of the two
    well-known values.
    """
    if token_type_hint == "access_token":  # noqa: S105 -- RFC 7009 §2.1 hint value, not a credential
        return ("access",)
    if token_type_hint == "refresh_token":  # noqa: S105 -- RFC 7009 §2.1 hint value, not a credential
        return ("refresh",)
    return ("access", "refresh")


def _scope_is_subset(requested: str, granted: str) -> bool:
    """Refresh scope MUST be ⊆ the originally-granted scope (no widening)."""
    requested_set = set(requested.split())
    granted_set = set(granted.split())
    return requested_set.issubset(granted_set)


def _resolve_rotation_scope(requested_scope: str | None, granted_scope: str) -> str | Response:
    """Narrow scope to the requested subset of the prior grant, or reject widening.

    Returns the effective scope string on success, or an ``invalid_scope`` error
    response when the requested scope is not a subset of the granted scope.
    """
    effective_scope = requested_scope or granted_scope
    if not _scope_is_subset(effective_scope, granted_scope):
        return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_scope", "scope widening rejected")
    return effective_scope


def _check_resource_against_stored(
    requested_resource: str,
    stored_resource: str,
) -> Response | None:
    """RFC 8707 §2.2 — the ``resource`` at /token must match the one bound at /authorize."""
    if not requested_resource:
        # Some clients omit `resource` at /token even though they sent it at
        # /authorize. Accept and bind to the stored value rather than rejecting.
        return None
    try:
        requested_norm = normalize_resource(requested_resource)
        stored_norm = normalize_resource(stored_resource)
    except ValueError:
        return _oauth_error(
            HTTPStatus.BAD_REQUEST, "invalid_target", "resource normalization failed"
        )
    if requested_norm != stored_norm:
        return _oauth_error(HTTPStatus.BAD_REQUEST, "invalid_target", "resource mismatch")
    return None


def _render_consent(params: dict[str, str], client_name: str) -> Response:
    """Render the consent HTML with all dynamic values ``html.escape``'d."""
    body = CONSENT_HTML_TEMPLATE.format(
        client_name=html.escape(client_name),
        client_id=html.escape(params["client_id"]),
        redirect_uri=html.escape(params["redirect_uri"]),
        state=html.escape(params.get("state", "")),
        code_challenge=html.escape(params["code_challenge"]),
        scope=html.escape(params.get("scope", "")),
        resource=html.escape(params["resource"]),
    )
    return HTMLResponse(body, headers=_CONSENT_HEADERS)


def _token_json(
    pair: RotatedTokenPair,
    scope: str,
    access_ttl_seconds: int,
) -> Response:
    """Build the RFC 6749 §5.1 token endpoint JSON response."""
    payload = TokenResponse(
        access_token=pair.raw_access_token,
        token_type=_BEARER_TOKEN_TYPE,
        expires_in=access_ttl_seconds,
        refresh_token=pair.raw_refresh_token,
        scope=scope,
    )
    return JSONResponse(
        payload.model_dump(exclude_none=True),
        status_code=HTTPStatus.OK,
        headers=_NO_STORE_HEADERS,
    )
