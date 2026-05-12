"""OAuth 2.1 authorization server endpoints (RFC 6749/7009/7591/7636/8414/8707).

This module implements the AS role. The broker is both AS and resource server
(co-located per claude.ai bug #82 — claude.ai derives /authorize from the MCP
base URL rather than reading authorization_servers from AS metadata).

WARNING: The in-memory DCR rate limiter is single-process. Multi-worker
deployments need a shared backing store; ``broker/__main__.py`` aborts startup
when ``WEB_CONCURRENCY > 1`` AND ``broker.oauth.enabled`` is true.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import secrets
import sqlite3
import time
from collections.abc import Callable
from typing import Literal
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

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
    verify_pkce_s256,
)

logger = logging.getLogger(__name__)


# === CONSTANTS ===

# 43..128 base64url chars — PKCE S256, RFC 7636 §4.2
_CODE_CHALLENGE_MIN_LEN = 43
_CODE_CHALLENGE_MAX_LEN = 128

_HTTP_OK = 200
_HTTP_CREATED = 201
_HTTP_BAD_REQUEST = 400
_HTTP_UNAUTHORIZED = 401
_HTTP_TOO_MANY = 429

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
        client_ip = _client_ip(request)
        if not self._dcr_rate_limiter.allow(client_ip):
            return _oauth_error(
                _HTTP_TOO_MANY, "invalid_request", "registration rate limit exceeded"
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
            response_payload.model_dump(exclude_none=True), status_code=_HTTP_CREATED
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
            ip=_client_ip(request),
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

        if params.get("action") == "deny":
            audit_log_oauth_event("authorize_deny", client_id=params["client_id"])
            return _redirect_with_error(
                params["redirect_uri"], params.get("state", ""), "access_denied"
            )

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
            _HTTP_BAD_REQUEST, "unsupported_grant_type", f"grant_type '{grant_type}' not supported"
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
            return Response(status_code=_HTTP_OK)

        raw_token = params.get("token", "").strip()
        if not raw_token:
            return Response(status_code=_HTTP_OK)
        token_hash = _sha256_hex(raw_token)
        kinds = _kinds_from_hint(params.get("token_type_hint", ""))
        for token_kind in kinds:
            await self._inbound_auth_store.revoke_token(
                token_hash, client_or_error, kind=token_kind
            )
        return Response(status_code=_HTTP_OK)

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
        connector_or_error = self._validate_resource_and_connector(params)
        if isinstance(connector_or_error, str) and connector_or_error.startswith("__error__:"):
            return _redirect_with_error(
                redirect_uri, state, connector_or_error.removeprefix("__error__:")
            )
        if not isinstance(connector_or_error, str):
            return _redirect_with_error(redirect_uri, state, "invalid_target")
        scope_error = _validate_scope(params.get("scope", ""), connector_or_error)
        if scope_error is not None:
            return _redirect_with_error(redirect_uri, state, scope_error)
        return connector_or_error

    def _validate_resource_and_connector(self, params: dict[str, str]) -> str:
        """Return matched connector name OR an `__error__:` sentinel string."""
        raw_resource = params.get("resource", "")
        if not raw_resource:
            return "__error__:invalid_request"
        try:
            normalized = normalize_resource(raw_resource)
        except ValueError:
            return "__error__:invalid_request"
        connector_names = self._connector_names_provider()
        match = connector_from_resource(normalized, self._public_url, connector_names)
        if match is None:
            return "__error__:invalid_target"
        return match

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
        basic = parse_basic_auth(request.headers.get("authorization", ""))
        if basic is not None:
            client_id, supplied_secret = basic
        else:
            client_id = params.get("client_id", "")
            supplied_secret = params.get("client_secret", "")
        if not client_id:
            return _oauth_error(_HTTP_UNAUTHORIZED, "invalid_client", "client_id required")
        client_record = await self._inbound_auth_store.get_client(client_id)
        if client_record is None:
            return _oauth_error(_HTTP_UNAUTHORIZED, "invalid_client", "client_id not registered")
        if client_record.token_endpoint_auth_method == _PUBLIC_CLIENT_AUTH_METHOD:
            return client_id
        # Confidential client — verify secret against stored hash via raw SQL
        # because the store doesn't expose a hash-comparison method (matches
        # the pattern in ``SQLiteInboundAuthStore.get_access``).
        if not supplied_secret:
            return _oauth_error(_HTTP_UNAUTHORIZED, "invalid_client", "client_secret required")
        valid = await _verify_client_secret(self._inbound_auth_store, client_id, supplied_secret)
        if not valid:
            return _oauth_error(_HTTP_UNAUTHORIZED, "invalid_client", "client_secret mismatch")
        return client_id

    async def _token_authorization_code(
        self,
        params: dict[str, str],
        client_id: str,
    ) -> Response:
        """RFC 6749 §4.1.3 — exchange auth code for tokens."""
        code = params.get("code", "")
        verifier = params.get("code_verifier", "")
        redirect_uri = params.get("redirect_uri", "")
        resource = params.get("resource", "")
        if not code or not verifier or not redirect_uri:
            return _oauth_error(
                _HTTP_BAD_REQUEST,
                "invalid_request",
                "code, code_verifier, and redirect_uri required",
            )
        code_hash = _sha256_hex(code)
        consumed = await self._inbound_auth_store.consume_code(code_hash, client_id)
        if consumed is None:
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_grant", "authorization code invalid")
        if consumed.redirect_uri != redirect_uri:
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_grant", "redirect_uri mismatch")
        if not verify_pkce_s256(verifier, consumed.code_challenge):
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_grant", "PKCE verification failed")
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
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_request", "refresh_token required")
        token_hash = _sha256_hex(refresh_token)

        rotation_or_error = await self._rotate_refresh_with_scope_check(
            params, client_id, token_hash
        )
        if isinstance(rotation_or_error, Response):
            return rotation_or_error
        return _token_json(
            rotation_or_error, rotation_or_error.access.scope, self._config.access_token_ttl_seconds
        )

    async def _rotate_refresh_with_scope_check(
        self,
        params: dict[str, str],
        client_id: str,
        token_hash: str,
    ) -> RotatedTokenPair | Response:
        """Look up the prior token, enforce scope ⊆, then rotate atomically.

        The store doesn't expose a refresh-row read (rotation is its public
        API), so we read directly via ``_fetch_refresh_row``. Reading first
        lets us reject scope widening with an explicit ``invalid_scope`` rather
        than letting the rotation succeed with the widened scope.
        """
        prior_row = await _fetch_refresh_row(self._inbound_auth_store, token_hash)
        if prior_row is None:
            # Unknown OR already used — both surface as invalid_grant per RFC 6749 §5.2.
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_grant", "refresh_token invalid")
        requested_scope = params.get("scope") or prior_row.scope
        if not _scope_is_subset(requested_scope, prior_row.scope):
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_scope", "scope widening rejected")
        rotation_request = RefreshRotationRequest(
            token_hash=token_hash,
            client_id=client_id,
            resource=prior_row.resource,
            scope=requested_scope,
        )
        try:
            return await self._inbound_auth_store.rotate_refresh(rotation_request)
        except InvalidGrantError as exc:
            return _oauth_error(_HTTP_BAD_REQUEST, "invalid_grant", str(exc))

    # --- INTERNAL: mint code + initial token pair ---

    async def _mint_authorization_code(
        self,
        params: dict[str, str],
    ) -> Response:
        """Persist a freshly-minted auth code and redirect to claude.ai callback."""
        raw_code = secrets.token_urlsafe(32)
        code_hash = _sha256_hex(raw_code)
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
        callback = (
            params["redirect_uri"]
            + "?"
            + urlencode({"code": raw_code, "state": params.get("state", "")})
        )
        return RedirectResponse(callback, status_code=302)

    async def _mint_initial_pair(
        self,
        consumed: OAuthCode,
        client_id: str,
    ) -> RotatedTokenPair:
        """Mint and persist the first (access, refresh) pair for an auth code grant."""
        family_id = generate_family_id()
        raw_access, access_hash = generate_access_token()
        raw_refresh, refresh_hash = generate_refresh_token()
        now_ts = int(time.time())
        access_row = InboundToken(
            token_hash=access_hash,
            token_kind="access",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=refresh_hash,
            family_id=family_id,
            client_id=client_id,
            app_key=consumed.app_key,
            resource=consumed.resource,
            scope=consumed.scope,
            expires_at=now_ts + self._config.access_token_ttl_seconds,
            issued_at=now_ts,
        )
        refresh_row = InboundToken(
            token_hash=refresh_hash,
            token_kind="refresh",  # noqa: S106 -- discriminator literal, not a credential
            family_id=family_id,
            client_id=client_id,
            app_key=consumed.app_key,
            resource=consumed.resource,
            scope=consumed.scope,
            expires_at=now_ts + self._config.refresh_token_ttl_seconds,
            issued_at=now_ts,
        )
        pair = RotatedTokenPair(
            access=access_row,
            refresh=refresh_row,
            raw_access_token=raw_access,
            raw_refresh_token=raw_refresh,
        )
        await self._inbound_auth_store.create_token_pair(pair)
        return pair


# === MODULE-LEVEL HELPERS ===


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest — mirrors ``inbound_auth_store._sha256_hex`` for parity."""
    return hashlib.sha256(value.encode()).hexdigest()


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Trust ``X-Forwarded-For`` only when the broker is
    deployed behind a known proxy — for the rate limiter this is "good enough"
    (the failure mode is over-counting from shared NATs, not bypass)."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _not_found() -> Response:
    """404 used when ``broker.oauth.enabled=false`` — keeps the OAuth surface
    invisible to clients that probe without checking ``.well-known/`` first."""
    return JSONResponse({"error": "not_found"}, status_code=404)


def _oauth_error(status_code: int, code: str, description: str) -> Response:
    """RFC 6749 §5.2 error payload as JSON."""
    return JSONResponse({"error": code, "error_description": description}, status_code=status_code)


def _bad_request_html(description: str) -> Response:
    """Pre-redirect authorize errors: HTML 400 so the human user sees a hint."""
    body = (
        "<!DOCTYPE html><html><body><h1>Authorization request rejected</h1>"
        f"<p>{html.escape(description)}</p></body></html>"
    )
    return HTMLResponse(body, status_code=_HTTP_BAD_REQUEST, headers=_CONSENT_HEADERS)


def _redirect_with_error(redirect_uri: str, state: str, error: str) -> Response:
    """Post-redirect errors flow through the redirect URI per RFC 6749 §4.1.2.1."""
    query = urlencode({"error": error, "state": state} if state else {"error": error})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)


async def _parse_registration_request(
    request: Request,
) -> tuple[RegistrationRequest | None, Response | None]:
    """Parse JSON body into ``RegistrationRequest`` or return a 400 ``Response``."""
    try:
        raw = await request.json()
    except (ValueError, UnicodeDecodeError):
        return None, _oauth_error(_HTTP_BAD_REQUEST, "invalid_request", "request body must be JSON")
    try:
        return RegistrationRequest(**raw), None
    except (TypeError, ValueError) as exc:
        return None, _oauth_error(
            _HTTP_BAD_REQUEST, "invalid_request", f"invalid registration: {exc}"
        )


def _validate_registration_redirects(redirect_uris: list[str]) -> Response | None:
    """Reject fragments (RFC 7591 §2) and anything outside the v1 allowlist."""
    for uri in redirect_uris:
        if "#" in uri:
            return _oauth_error(
                _HTTP_BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri must not contain a fragment",
            )
        if not is_acceptable_redirect_uri(uri):
            return _oauth_error(
                _HTTP_BAD_REQUEST,
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
        return _oauth_error(_HTTP_BAD_REQUEST, "invalid_target", "resource normalization failed")
    if requested_norm != stored_norm:
        return _oauth_error(_HTTP_BAD_REQUEST, "invalid_target", "resource mismatch")
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
    return JSONResponse(payload.model_dump(exclude_none=True), status_code=_HTTP_OK)


async def _verify_client_secret(
    store: SQLiteInboundAuthStore,
    client_id: str,
    supplied_secret: str,
) -> bool:
    """Constant-time compare of supplied secret against the stored SHA-256 hash."""
    conn = sqlite3.connect(store._db_path)  # noqa: SLF001 -- private path access mirrors store internals
    try:
        row = conn.execute(
            "SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row or row[0] is None:
        return False
    return hmac.compare_digest(row[0], _sha256_hex(supplied_secret))


async def _fetch_refresh_row(
    store: SQLiteInboundAuthStore,
    token_hash: str,
) -> InboundToken | None:
    """Look up a refresh row by hash regardless of ``used_at`` state.

    Used at /token refresh to read prior scope BEFORE calling ``rotate_refresh``
    so we can reject scope widening with a precise ``invalid_scope`` error.
    The replay branch needs this read to RETURN the row (with ``used_at`` set)
    so that the subsequent rotation call can detect replay and revoke the
    family — filtering on ``used_at IS NULL`` here would mask replay attempts.
    """
    conn = sqlite3.connect(store._db_path)  # noqa: SLF001 -- private path access mirrors store internals
    try:
        row = conn.execute(
            "SELECT token_hash, token_kind, parent_refresh_hash, family_id, client_id, "
            "app_key, resource, scope, expires_at, issued_at, used_at "
            "FROM inbound_tokens "
            "WHERE token_kind = 'refresh' AND token_hash = ?",
            (token_hash,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return InboundToken(
        token_hash=row[0],
        token_kind=row[1],
        parent_refresh_hash=row[2],
        family_id=row[3],
        client_id=row[4],
        app_key=row[5],
        resource=row[6],
        scope=row[7],
        expires_at=row[8],
        issued_at=row[9],
        used_at=row[10],
    )
