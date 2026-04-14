"""
Admin API — API key management, connect tokens, and token refresh.

All endpoints require X-Admin-Key header (bootstrap secret from env).
App definitions come from YAML (BrokerClientRegistry) — this API only manages keys.

POST   /admin/keys                      — Create key for a YAML-defined app
GET    /admin/keys                      — List all YAML apps with has_key status
POST   /admin/keys/{app_key}/rotate     — Rotate key, return new key
DELETE /admin/keys/{app_key}            — Delete key for an app
POST   /admin/connect-token             — Create single-use browser OAuth token
POST   /admin/refresh                   — Refresh expiring tokens
"""

from __future__ import annotations

import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from starlette.responses import Response

if TYPE_CHECKING:
    from broker.services.api_key_store import BrokerKeyStore, ConnectTokenStore
    from broker.services.client_registry import BrokerClientRegistry
    from broker.services.store import TokenStore

# Type for the refresh callback injected from main.py
RefreshCallback = Callable[[], Awaitable[dict[str, int]]]

logger = logging.getLogger(__name__)


# =============================================================================
# SHARED AUTH
# =============================================================================


def verify_admin_key(request: Request, admin_key: str) -> bool:
    """Verify X-Admin-Key header against bootstrap secret."""
    key = request.headers.get("x-admin-key", "")
    if not admin_key or not key:
        return False
    return hmac.compare_digest(key, admin_key)


# =============================================================================
# RESPONSE HELPER
# =============================================================================


def _json_response(status_code: int, body: dict) -> Response:
    """Return a JSON response with the given status code."""
    return Response(
        status_code=status_code,
        content=json.dumps(body),
        media_type="application/json",
    )


# =============================================================================
# ADMIN ENDPOINTS
# =============================================================================


class AdminEndpoints:
    """Handles admin API endpoints for API key management."""

    def __init__(  # noqa: PLR0913 — admin endpoints need all deps
        self,
        key_store: BrokerKeyStore,
        admin_key: str,
        client_registry: BrokerClientRegistry,
        connect_token_store: ConnectTokenStore,
        token_store: TokenStore | None = None,
        refresh_callback: RefreshCallback | None = None,
    ) -> None:
        self._key_store = key_store
        self._admin_key = admin_key
        self._client_registry = client_registry
        self._connect_token_store = connect_token_store
        self._token_store = token_store
        self._refresh_callback = refresh_callback

    # --- Auth ---

    def _verify_admin(self, request: Request) -> bool:
        """Verify X-Admin-Key header against bootstrap secret."""
        return verify_admin_key(request, self._admin_key)

    # --- Helpers ---

    async def _parse_validated_app_key(self, request: Request) -> tuple[str, Response | None]:
        """Parse JSON body and validate app_key against registry.

        Returns (app_key, None) on success, or ("", error_response) on failure.
        """
        try:
            body = await request.json()
        except (ValueError, UnicodeDecodeError):
            return "", _json_response(400, {"error": "Invalid JSON"})

        app_key = (body.get("app_key") or "").strip()
        if not app_key:
            return "", _json_response(400, {"error": "app_key is required"})

        if self._client_registry.get(app_key) is None:
            return "", _json_response(400, {"error": f"App '{app_key}' not found in registry"})

        return app_key, None

    # --- Endpoints ---

    async def create_key(self, request: Request) -> Response:
        """Create a key for a YAML-defined app."""
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        app_key, error_response = await self._parse_validated_app_key(request)
        if error_response:
            return error_response

        try:
            raw_key = await self._key_store.create_key(app_key)
        except ValueError as exc:
            return _json_response(409, {"error": str(exc)})

        logger.info("[Admin] Created key for app: %s", app_key)
        return _json_response(201, {"app_key": app_key, "api_key": raw_key})

    async def list_keys(self, request: Request) -> Response:
        """List all YAML-defined apps, each with has_key true/false."""
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        registry_apps = self._client_registry.list_apps()
        key_records = await self._key_store.list_keys()
        key_record_map = {record["app_key"]: record for record in key_records}

        merged = []
        for entry in registry_apps:
            record = key_record_map.get(entry["app_key"])
            app_summary = {
                "app_key": entry["app_key"],
                "scopes": entry["scopes"],
                "allowed_connectors": entry["allowed_connectors"],
                "has_key": record is not None,
            }
            if record:
                app_summary["created_at"] = record.get("created_at")
                app_summary["rotated_at"] = record.get("rotated_at")
            merged.append(app_summary)

        return _json_response(200, {"apps": merged})

    async def rotate_key(self, app_key: str, request: Request) -> Response:
        """Rotate the API key for an app."""
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        # Warn if app is no longer in registry — rotated key would be unusable
        if self._client_registry.get(app_key) is None:
            return _json_response(
                400, {"error": f"App '{app_key}' not in registry — key would be unusable"}
            )

        raw_key = await self._key_store.rotate(app_key)
        if not raw_key:
            return _json_response(404, {"error": "App not found"})

        logger.info("[Admin] Rotated key for app: %s", app_key)
        return _json_response(200, {"app_key": app_key, "api_key": raw_key})

    async def delete_key(self, app_key: str, request: Request) -> Response:
        """Delete the API key for an app.

        Cascades to any stored OAuth tokens for the app so that re-provisioning
        a key under the same app_key cannot silently regain access to
        previously-linked third-party accounts.
        """
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        deleted = await self._key_store.delete_key(app_key)
        if not deleted:
            return _json_response(404, {"error": "App not found"})

        tokens_deleted = 0
        if self._token_store is not None:
            tokens_deleted = await self._token_store.delete_all_for_app(app_key)

        logger.info(
            "[Admin] Deleted key for app: %s (cascade: %d tokens)", app_key, tokens_deleted
        )
        return _json_response(
            200, {"app_key": app_key, "deleted": True, "tokens_deleted": tokens_deleted}
        )

    async def create_connect_token(self, request: Request) -> Response:
        """Create a single-use, short-lived token for browser OAuth connect.

        Avoids exposing the raw broker key in browser history and proxy logs.
        """
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        app_key, error_response = await self._parse_validated_app_key(request)
        if error_response:
            return error_response

        # Verify the app actually has a broker key provisioned
        if not await self._key_store.has_key(app_key):
            return _json_response(
                400, {"error": f"App '{app_key}' has no API key — create one first"}
            )

        token = self._connect_token_store.create(app_key)
        return _json_response(201, {"app_key": app_key, "connect_token": token, "ttl_seconds": 300})

    async def refresh_tokens(self, request: Request) -> Response:
        """Proactively refresh expiring tokens."""
        if not self._verify_admin(request):
            return _json_response(401, {"error": "Unauthorized"})

        if not self._refresh_callback:
            return _json_response(501, {"error": "Refresh not configured"})

        results = await self._refresh_callback()
        logger.info("[Admin] Token refresh: %s", results)
        return _json_response(200, results)


# =============================================================================
# ROUTER FACTORY
# =============================================================================


def create_admin_router(  # noqa: PLR0913 — router factory needs all deps
    key_store: BrokerKeyStore,
    admin_key: str,
    client_registry: BrokerClientRegistry,
    connect_token_store: ConnectTokenStore,
    token_store: TokenStore | None = None,
    refresh_callback: RefreshCallback | None = None,
) -> APIRouter:
    """Create a FastAPI router with admin endpoints."""
    endpoints = AdminEndpoints(
        key_store,
        admin_key,
        client_registry,
        connect_token_store,
        token_store,
        refresh_callback,
    )
    router = APIRouter()
    router.add_api_route("/admin/keys", endpoints.create_key, methods=["POST"])
    router.add_api_route("/admin/keys", endpoints.list_keys, methods=["GET"])
    router.add_api_route(
        "/admin/keys/{app_key:path}/rotate", endpoints.rotate_key, methods=["POST"]
    )
    router.add_api_route("/admin/keys/{app_key:path}", endpoints.delete_key, methods=["DELETE"])
    router.add_api_route("/admin/connect-token", endpoints.create_connect_token, methods=["POST"])
    router.add_api_route("/admin/refresh", endpoints.refresh_tokens, methods=["POST"])
    return router
