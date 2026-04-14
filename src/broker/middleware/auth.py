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
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    from broker.services.api_key_store import BrokerAppIdentity, BrokerKeyStore, ConnectTokenStore
    from broker.services.client_registry import BrokerClientRegistry

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_KEY_LENGTH = 128

# Matches /oauth/{connector_name}/connect
_OAUTH_CONNECT_PATTERN = re.compile(r"^/oauth/[^/]+/connect$")


class BrokerAuthMiddleware(BaseHTTPMiddleware):
    """Validates broker keys and injects BrokerAppIdentity into request.state."""

    def __init__(  # noqa: PLR0913 — middleware init needs all deps
        self,
        app,
        get_key_store: Callable[[], BrokerKeyStore | None],
        get_client_registry: Callable[[], BrokerClientRegistry | None],
        get_connect_token_store: Callable[[], ConnectTokenStore | None],
        exempt_prefixes: tuple[str, ...] = ("/health", "/admin"),
        exempt_paths: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self._get_key_store = get_key_store
        self._get_client_registry = get_client_registry
        self._get_connect_token_store = get_connect_token_store
        self._exempt_prefixes = exempt_prefixes
        self._exempt_paths = exempt_paths

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
        """
        if path in self._exempt_paths:
            return True
        if path.startswith("/oauth/") and path.endswith("/callback"):
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

        Browser OAuth connect uses single-use connect tokens (not raw broker keys)
        to avoid key exposure in URLs. Standard API calls use X-Broker-Key headers.
        """
        app_key_claim = request.headers.get("x-app-id")
        broker_key = request.headers.get("x-broker-key")

        # Browser OAuth connect — use single-use connect token (not raw broker key)
        if not app_key_claim and _OAUTH_CONNECT_PATTERN.match(path):
            return self._verify_connect_token(request, client_registry)

        if not app_key_claim or not broker_key:
            return _unauthorized()

        if len(app_key_claim) > MAX_KEY_LENGTH or len(broker_key) > MAX_KEY_LENGTH:
            return _unauthorized()

        # Verify key and confirm it matches the claimed identity
        verified_app_key = await key_store.verify(broker_key)
        if not verified_app_key:
            return _unauthorized()

        if verified_app_key != app_key_claim:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(
                "[Auth] Key/identity mismatch: claimed=%s verified=%s ip=%s",
                app_key_claim,
                verified_app_key,
                client_host,
            )
            return _unauthorized()

        return self._build_identity(verified_app_key, client_registry)

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


def _unauthorized() -> Response:
    """Return a 401 JSON response."""
    return Response(
        status_code=401,
        content=json.dumps({"error": "Unauthorized"}),
        media_type="application/json",
    )


def _service_unavailable() -> Response:
    """Return a 503 JSON response (auth store not yet initialized)."""
    return Response(
        status_code=503,
        content=json.dumps({"error": "Service starting up"}),
        media_type="application/json",
    )
