"""
Per-app auth middleware.

Validates X-Broker-Key + X-App-Id headers against the BrokerKeyStore.
Sets request.state.identity (BrokerAppIdentity) on success. Returns 401 on failure.

Browser OAuth flow: /oauth/*/connect accepts a single-use connect_token query param
(created via POST /admin/connect-token). This avoids exposing the raw broker key
in browser history, proxy logs, and Referer headers.

The middleware accepts get_* callables (not direct references) because FastAPI
requires middleware registration before lifespan runs, but stores are created
during lifespan. When a callable returns None, returns 503 Service Unavailable.

Inbound OAuth (opt-in via `oauth_enabled=True`): /proxy/* accepts
`Authorization: Bearer mcp_at_...` from claude.ai and similar clients. The
bearer branch fires FIRST when enabled — legacy X-App-Id/X-Broker-Key still
works on the same paths, and bearer wins if both are present. Audience binding
prevents a token issued for one connector being replayed on another.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from broker.services.inbound_oauth_helpers import (
    audit_log_oauth_event,
    build_bearer_challenge,
    connector_from_request_path,
    hash_prefix,
    normalize_resource,
    resource_matches_connector,
)

if TYPE_CHECKING:
    from broker.models.inbound_auth import InboundToken
    from broker.services.api_key_store import BrokerAppIdentity, BrokerKeyStore, ConnectTokenStore
    from broker.services.client_registry import BrokerClientRegistry

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_KEY_LENGTH = 128

# Matches /oauth/{connector_name}/connect
_OAUTH_CONNECT_PATTERN = re.compile(r"^/oauth/[^/]+/connect$")

# Paths that should emit a Bearer WWW-Authenticate challenge on 401 instead of
# a bare 401 — claude.ai and other MCP clients rely on this to discover the AS.
_BEARER_CHALLENGE_PREFIXES = ("/proxy/", "/status")

# Inbound OAuth AS endpoints — public per RFC 6749/7591/7009.
# See PR description for per-path security justification (AGENTS.md Known Gotcha #3).
_OAUTH_PUBLIC_PATHS = frozenset(
    {"/oauth/register", "/oauth/authorize", "/oauth/token", "/oauth/revoke"}
)

# Discovery endpoints — RFC 8414 + RFC 9728 require unauthenticated access.
_WELLKNOWN_OAUTH_PREFIX = "/.well-known/oauth-"

# Bearer-failure audit reasons. Descriptions are deliberately coarse so an
# attacker can't distinguish "expired" from "not_found" from the 401 body, but
# operators get the precise reason from the audit log. `revoked_app` shares the
# same coarse description for the same reason — a probe via a deleted app's
# leaked token must not reveal that the app once existed.
_BEARER_FAIL_DESCRIPTIONS = {
    "not_found": "bearer token invalid or expired",
    "expired": "bearer token invalid or expired",
    "unknown_connector": "resource not bound to a known connector",
    "audience_mismatch": "token audience does not match request connector",
    "revoked_app": "bearer token invalid or expired",
}


class BrokerAuthMiddleware(BaseHTTPMiddleware):
    """Validates broker keys and injects BrokerAppIdentity into request.state."""

    def __init__(  # noqa: PLR0913 — middleware init needs all deps; new args default to disabled
        self,
        app,
        get_key_store: Callable[[], BrokerKeyStore | None],
        get_client_registry: Callable[[], BrokerClientRegistry | None],
        get_connect_token_store: Callable[[], ConnectTokenStore | None],
        exempt_prefixes: tuple[str, ...] = ("/health", "/admin"),
        exempt_paths: tuple[str, ...] = (),
        *,
        oauth_enabled: bool = False,
        public_url: str = "",
        get_inbound_auth_store: Callable[[], Any | None] = lambda: None,
        get_connector_names: Callable[[], list[str]] = lambda: [],
    ) -> None:
        super().__init__(app)
        self._get_key_store = get_key_store
        self._get_client_registry = get_client_registry
        self._get_connect_token_store = get_connect_token_store
        self._exempt_prefixes = exempt_prefixes
        self._exempt_paths = exempt_paths
        self._oauth_enabled = oauth_enabled
        self._public_url = public_url
        self._get_inbound_auth_store = get_inbound_auth_store
        self._get_connector_names = get_connector_names

    async def dispatch(self, request: Request, call_next):
        """Validate auth or skip for exempt paths."""
        path = request.url.path

        if self._is_exempt(path):
            return await call_next(request)

        key_store = self._get_key_store()
        client_registry = self._get_client_registry()
        if not key_store or not client_registry:
            return _service_unavailable()

        identity = await self._extract_and_verify(request, path, key_store, client_registry)
        if isinstance(identity, Response):
            return identity

        request.state.identity = identity
        return await call_next(request)

    def _is_exempt(self, path: str) -> bool:
        """Check if the path is exempt from auth.

        OAuth callbacks are always exempt — signed state protects them.
        Inbound OAuth AS endpoints and discovery are exempt per RFC requirements
        (each handler self-authenticates; see PR description for justifications).
        """
        if path in self._exempt_paths:
            return True
        if path.startswith("/oauth/") and path.endswith("/callback"):
            return True
        if path in _OAUTH_PUBLIC_PATHS:
            return True
        if path.startswith(_WELLKNOWN_OAUTH_PREFIX):
            return True
        return any(path.startswith(prefix) for prefix in self._exempt_prefixes)

    # --- Credential extraction + verification ---

    async def _extract_and_verify(
        self,
        request: Request,
        path: str,
        key_store: BrokerKeyStore,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity | Response:
        """Extract credentials, verify key, and build identity.

        When `oauth_enabled=True`, an `Authorization: Bearer ...` header is
        consumed by the inbound OAuth branch FIRST. Anything without that
        header falls through to the legacy X-App-Id/X-Broker-Key path so that
        existing API clients keep working during the rollout.
        """
        if self._oauth_enabled:
            bearer_or_legacy = await self._maybe_verify_bearer(request, path, client_registry)
            if bearer_or_legacy is not None:
                return bearer_or_legacy

        app_key_claim = request.headers.get("x-app-id")
        broker_key = request.headers.get("x-broker-key")

        # Browser OAuth connect — use single-use connect token (not raw broker key)
        if not app_key_claim and _OAUTH_CONNECT_PATTERN.match(path):
            return self._verify_connect_token(request, client_registry)

        if not app_key_claim or not broker_key:
            return self._unauthorized_for_path(path)

        if len(app_key_claim) > MAX_KEY_LENGTH or len(broker_key) > MAX_KEY_LENGTH:
            return self._unauthorized_for_path(path)

        # Verify key and confirm it matches the claimed identity
        verified_app_key = await key_store.verify(broker_key)
        if not verified_app_key:
            return self._unauthorized_for_path(path)

        if verified_app_key != app_key_claim:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(
                "[Auth] Key/identity mismatch: claimed=%s verified=%s ip=%s",
                app_key_claim,
                verified_app_key,
                client_host,
            )
            return self._unauthorized_for_path(path)

        return self._build_identity(verified_app_key, client_registry)

    async def _maybe_verify_bearer(
        self,
        request: Request,
        path: str,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity | Response | None:
        """Return identity/Response if an `Authorization: Bearer` header is present.

        Returns None when no bearer header is present (caller falls through to
        legacy auth). Bearer wins over X-App-Id/X-Broker-Key when both are
        supplied on the same request.
        """
        authz = request.headers.get("authorization", "")
        if not authz.startswith("Bearer "):
            return None
        return await self._verify_bearer(request, path, authz, client_registry)

    async def _verify_bearer(
        self,
        request: Request,
        path: str,
        authz_header: str,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity | Response:
        """Validate a bearer token, enforce audience, and build identity."""
        raw_token = authz_header[len("Bearer ") :].strip()
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        store = self._get_inbound_auth_store()
        if store is None:
            # Fail closed — operator enabled OAuth but the store didn't come up.
            return _oauth_store_unavailable()

        token_row = await store.get_access(token_hash)
        if token_row is None:
            return self._bearer_audit_fail(path, token_hash, "not_found")
        if token_row.expires_at <= int(time.time()):
            return self._bearer_audit_fail(path, token_hash, "expired")

        connector_name = connector_from_request_path(path, self._get_connector_names())
        if connector_name is None:
            return self._bearer_audit_fail(path, token_hash, "unknown_connector")

        # `normalize_resource` raises ValueError on fragment / non-https / empty
        # host. No current write path produces such a stored value, but DB
        # restore from a foreign source or a future bug could — collapse to the
        # existing audience_mismatch failure rather than 500.
        try:
            resource_norm = normalize_resource(token_row.resource)
        except ValueError:
            return self._bearer_audit_fail(path, token_hash, "audience_mismatch")
        if not resource_matches_connector(resource_norm, self._public_url, connector_name):
            return self._bearer_audit_fail(path, token_hash, "audience_mismatch")

        # Revoked-app check lives here (not in _bearer_build_identity) so we can
        # route the failure through _bearer_audit_fail with the token_hash in
        # scope — same audit trail + WWW-Authenticate challenge as the other
        # bearer failures, instead of a bare 401.
        if client_registry.get(token_row.app_key) is None:
            return self._bearer_audit_fail(path, token_hash, "revoked_app")

        identity = self._bearer_build_identity(token_row, connector_name, client_registry)
        _strip_authorization_header(request)
        audit_log_oauth_event(
            "bearer_validate_ok",
            app_key=token_row.app_key,
            hash_prefix=hash_prefix(token_hash),
            connector=connector_name,
        )
        return identity

    @staticmethod
    def _bearer_build_identity(
        token_row: InboundToken,
        connector_name: str,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity:
        """Resolve scopes via the client registry; narrow access to the bound connector.

        Caller MUST have verified ``client_registry.get(token_row.app_key)`` is
        non-None — this method assumes the lookup succeeds.
        """
        from broker.services.api_key_store import BrokerAppIdentity

        app_config = client_registry.get(token_row.app_key)
        assert app_config is not None  # noqa: S101 -- caller guarantees per docstring
        return BrokerAppIdentity(
            app_key=token_row.app_key,
            scopes=app_config.scopes,
            allowed_connectors=[connector_name],
        )

    def _bearer_401_for_path(
        self,
        path: str,
        error: str,
        error_description: str,
    ) -> Response:
        """401 with `WWW-Authenticate: Bearer ...` pointing at the path's PRM URL."""
        resource_metadata_url = self._resource_metadata_url_for(path)
        return _bearer_401(
            resource_metadata_url=resource_metadata_url,
            error=error,
            error_description=error_description,
        )

    def _bearer_audit_fail(self, path: str, token_hash: str, reason: str) -> Response:
        """Emit the plan-mandated `bearer_validate_fail` audit log + build the 401."""
        audit_log_oauth_event(
            "bearer_validate_fail",
            path=path,
            hash_prefix=hash_prefix(token_hash),
            reason=reason,
        )
        return self._bearer_401_for_path(
            path,
            error="invalid_token",
            error_description=_BEARER_FAIL_DESCRIPTIONS[reason],
        )

    def _unauthorized_for_path(self, path: str) -> Response:
        """Choose between bare 401 (legacy paths) and bearer-challenge 401.

        Bearer-protected paths (`/proxy/*`, `/status`) need a `WWW-Authenticate`
        header so claude.ai can find the PRM URL and re-discover the AS.
        Other 401s stay bare to match the historical legacy-only behavior.
        """
        if self._oauth_enabled and _bearer_protected_path(path):
            return self._bearer_401_for_path(
                path,
                error="invalid_token",
                error_description="bearer token required",
            )
        return _unauthorized()

    def _resource_metadata_url_for(self, path: str) -> str:
        """Build the RFC 9728 PRM URL for the connector inferred from `path`."""
        connector_name = connector_from_request_path(path, self._get_connector_names())
        public_url = self._public_url.rstrip("/")
        if connector_name is None:
            return f"{public_url}/.well-known/oauth-protected-resource"
        return f"{public_url}/.well-known/oauth-protected-resource/proxy/{connector_name}"

    def _verify_connect_token(
        self,
        request: Request,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity | Response:
        """Validate a single-use connect token for browser OAuth flows."""
        connect_token = request.query_params.get("connect_token")
        if not connect_token or len(connect_token) > MAX_KEY_LENGTH:
            return _unauthorized()

        token_store = self._get_connect_token_store()
        if not token_store:
            return _service_unavailable()

        # Consume token (single-use — deleted after validation)
        verified_app_key = token_store.consume(connect_token)
        if not verified_app_key:
            return _unauthorized()

        return self._build_identity(verified_app_key, client_registry)

    def _build_identity(
        self,
        verified_app_key: str,
        client_registry: BrokerClientRegistry,
    ) -> BrokerAppIdentity | Response:
        """Look up app config and construct identity. Returns 401 if app not found."""
        from broker.services.api_key_store import BrokerAppIdentity

        app_config = client_registry.get(verified_app_key)
        if not app_config:
            return _unauthorized()

        return BrokerAppIdentity(
            app_key=verified_app_key,
            scopes=app_config.scopes,
            allowed_connectors=app_config.allowed_connectors,
        )


# =============================================================================
# RESPONSE HELPERS
# =============================================================================


def _bearer_protected_path(path: str) -> bool:
    """Paths where a missing/invalid bearer must surface a WWW-Authenticate challenge."""
    return any(path.startswith(prefix) for prefix in _BEARER_CHALLENGE_PREFIXES)


def _strip_authorization_header(request: Request) -> None:
    """Remove the inbound `Authorization` header from the ASGI scope.

    Defense-in-depth: `services/proxy.py` already strips `authorization` from
    its forwarded headers, but stripping here means any future handler that
    bypasses that strip list still doesn't see the bearer (AGENTS.md Security
    Invariant — internal credentials never leave the broker).
    """
    headers = request.scope.get("headers")
    if not headers:
        return
    request.scope["headers"] = [
        (name, value) for name, value in headers if name.lower() != b"authorization"
    ]


def _unauthorized() -> Response:
    """Return a 401 JSON response."""
    return Response(
        status_code=401,
        content=json.dumps({"error": "Unauthorized"}),
        media_type="application/json",
    )


def _bearer_401(
    resource_metadata_url: str,
    error: str,
    error_description: str,
    scope: str | None = None,
) -> Response:
    """Return a 401 JSON response with `WWW-Authenticate: Bearer ...` challenge.

    `error_description` is required (not optional) so callers always emit a
    parseable diagnostic — symmetric with the 403 `insufficient_scope` case.
    """
    challenge = build_bearer_challenge(
        resource_metadata_url=resource_metadata_url,
        scope=scope,
        error=error,
        error_description=error_description,
    )
    return Response(
        status_code=401,
        content=json.dumps({"error": error, "error_description": error_description}),
        media_type="application/json",
        headers={"WWW-Authenticate": challenge},
    )


def _service_unavailable() -> Response:
    """Return a 503 JSON response (auth store not yet initialized)."""
    return Response(
        status_code=503,
        content=json.dumps({"error": "Service starting up"}),
        media_type="application/json",
    )


def _oauth_store_unavailable() -> Response:
    """503 when oauth.enabled=true but the inbound auth store is missing.

    Distinguished from the generic startup 503 so operators can tell which
    backing store failed to come up.
    """
    return Response(
        status_code=503,
        content=json.dumps({"error": "oauth_store_unavailable"}),
        media_type="application/json",
    )
