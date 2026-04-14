"""
MCP Reverse Proxy

Forwards MCP requests from ADK to remote MCP servers with OAuth token injection.
Handles authentication, token refresh, header stripping, and response streaming.

Critical: MCP Streamable HTTP is stateful -- sessions use Mcp-Session-Id headers,
SSE streams are long-lived. The proxy must:
- Use httpx streaming for ALL responses (not buffer then check content-type)
- Maintain persistent httpx.AsyncClient per connector (connection pooling)
- Pass through Mcp-Session-Id headers bidirectionally
- Use asyncio.Lock per connection to prevent token refresh race conditions
"""

import asyncio
import json
import logging
import posixpath
import time
from urllib.parse import urlparse

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from broker.config import BrokerSettings
from broker.connectors.base import _CONTROL_CHAR_PATTERN, BaseConnector
from broker.connectors.native import NativeConnector
from broker.connectors.registry import ConnectorRegistry
from broker.models.connection import AppConnection
from broker.models.connector_config import ResolvedOAuth
from broker.services.discovery import OAuthDiscovery, resolve_oauth
from broker.services.oauth import TOKEN_REFRESH_BUFFER, OAuthHandler
from broker.services.store import TokenStore

logger = logging.getLogger(__name__)


# =============================================================================
# MODULE STATE (initialized by main.py lifespan)
# =============================================================================

# Persistent HTTP clients -- created at startup, not per request
clients: dict[str, httpx.AsyncClient] = {}

# Refresh locks -- prevent thundering herd on token refresh
_refresh_locks: dict[str, asyncio.Lock] = {}

# Max request body size (1 MB) — MCP is JSON-RPC, bodies should be small
_MAX_BODY_BYTES = 1_048_576


# =============================================================================
# TOKEN MANAGEMENT
# =============================================================================


def _needs_refresh(connection: AppConnection) -> bool:
    """Check if a token needs refreshing based on expiry and buffer."""
    if not connection.expires_at:
        return False
    return connection.expires_at <= time.time() + TOKEN_REFRESH_BUFFER


async def _try_refresh(  # noqa: PLR0913 — refresh needs token context + all service deps
    app_key: str,
    connector_name: str,
    connector: BaseConnector,
    connection: AppConnection,
    resolved: ResolvedOAuth,
    store: TokenStore,
    oauth_handler: OAuthHandler,
) -> AppConnection:
    """Attempt token refresh, falling back to existing token on failure."""
    try:
        refreshed = await oauth_handler.refresh_if_expired(connector, connection, resolved)
    except Exception:  # noqa: BLE001
        logger.exception("[Proxy] Token refresh failed for %s/%s", app_key, connector_name)
        return connection

    if refreshed is not connection:
        await store.save(app_key, connector_name, refreshed)
        logger.info("[Proxy] Token refreshed: app=%s connector=%s", app_key, connector_name)
        return refreshed

    return connection


async def get_valid_token(  # noqa: PLR0913 — token lookup + refresh requires all params
    app_key: str,
    connector_name: str,
    connector: BaseConnector,
    resolved: ResolvedOAuth,
    store: TokenStore,
    oauth_handler: OAuthHandler,
) -> AppConnection | None:
    """Get token, refreshing if expired. Lock prevents concurrent refresh race.

    Returns None if no connection exists for this app + connector.
    """
    lock_key = f"{app_key}:{connector_name}"
    lock = _refresh_locks.setdefault(lock_key, asyncio.Lock())

    async with lock:
        connection = await store.get(app_key, connector_name)
        if not connection:
            return None

        if _needs_refresh(connection):
            return await _try_refresh(
                app_key, connector_name, connector, connection, resolved, store, oauth_handler
            )

        return connection


# =============================================================================
# PROXY HELPERS
# =============================================================================

# Headers to strip before forwarding to remote MCP server
_STRIP_REQUEST_HEADERS = {
    "x-app-id",
    "x-broker-key",
    "host",
    "content-length",
    "transfer-encoding",
    "authorization",
    "cookie",  # Prevent leaking ADK auth to remote MCP servers
    # Hop-by-hop + forwarding headers — prevent host header injection
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
}

# Hop-by-hop headers to strip from upstream responses (RFC 7230 Section 6.1).
# content-length stripped because we stream via aiter_raw() — Starlette uses
# chunked transfer encoding instead. Passing through the upstream content-length
# causes h11 "Too much data for declared Content-Length" when body size differs.
_STRIP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "te",
    "trailer",
    "upgrade",
    "set-cookie",
}


def _extract_app_key(request: Request) -> str | JSONResponse:
    """Extract app_key from middleware-set identity.

    Auth is handled by BrokerAuthMiddleware — this just reads the result.
    Returns the app_key string on success, or a JSONResponse on failure.
    """
    identity = getattr(request.state, "identity", None)
    if not identity:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return identity.app_key


def _build_upstream_headers(
    request: Request,
    connector: BaseConnector,
    access_token: str,
    upstream_url: str,
) -> dict[str, str]:
    """Build headers for upstream MCP request.

    Strips internal headers, injects OAuth auth, sets correct Host.
    """
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _STRIP_REQUEST_HEADERS
    }
    headers.update(connector.build_auth_header(access_token))
    headers["host"] = urlparse(upstream_url).netloc
    return headers


def _build_passthrough_headers(request: Request, upstream_url: str) -> dict[str, str]:
    """Build headers for sidecar-managed connectors (no auth injection)."""
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in _STRIP_REQUEST_HEADERS
    }
    headers["host"] = urlparse(upstream_url).netloc
    return headers


# =============================================================================
# MCP METHOD VALIDATION
# =============================================================================

# HTTP methods allowed by MCP transports (Streamable HTTP + SSE)
_ALLOWED_HTTP_METHODS = frozenset({"GET", "POST", "DELETE"})


def _validate_mcp_payload(
    body: bytes,
    connector: BaseConnector,
) -> JSONResponse | None:
    """Validate JSON-RPC payload against connector's method allowlist.

    Returns None if valid, or JSONResponse with error details if blocked.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"error": "Invalid JSON in request body"}, status_code=400)

    # JSON-RPC batch (array of requests) — validate each
    payloads = payload if isinstance(payload, list) else [payload]

    for entry in payloads:
        if not isinstance(entry, dict):
            return JSONResponse({"error": "Invalid JSON-RPC 2.0 payload"}, status_code=400)

        method = entry.get("method", "")
        if method not in connector.meta.allowed_mcp_methods:
            logger.warning(
                "[Proxy] Blocked method=%s for connector=%s",
                method,
                connector.meta.name,
            )
            return JSONResponse(
                {"error": f"MCP method not allowed: {method}"},
                status_code=403,
            )

    return None


# =============================================================================
# NATIVE CONNECTOR DISPATCH
# =============================================================================


async def _dispatch_native_request(
    request: Request,
    connector: NativeConnector,
    connection: AppConnection,
) -> JSONResponse:
    """Dispatch JSON-RPC request to a native (in-process) connector.

    Parses the JSON-RPC body, delegates to connector.handle_mcp_request(),
    and returns the result as a JSONResponse. Token passed directly.
    """
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        return JSONResponse(
            {"error": f"Request body too large ({len(body)} bytes, max {_MAX_BODY_BYTES})"},
            status_code=413,
        )
    validation_error = _validate_mcp_payload(body, connector)
    if validation_error:
        return validation_error

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"error": "Invalid JSON in request body"}, status_code=400)

    if not isinstance(payload, dict):
        return JSONResponse(
            {"error": "Native connectors do not support batch requests"}, status_code=400
        )

    mcp_response = await connector.handle_mcp_request(
        method=payload.get("method", ""),
        params=payload.get("params", {}),
        request_id=payload.get("id"),
        access_token=connection.access_token,
    )
    if not mcp_response:
        return JSONResponse(content="", status_code=204)
    return JSONResponse(mcp_response)


# =============================================================================
# PROXY HANDLER
# =============================================================================


async def _resolve_connection(  # noqa: PLR0913 — OAuth resolution requires all params
    connector_name: str,
    connector: BaseConnector,
    app_key: str,
    store: TokenStore,
    oauth_handler: OAuthHandler,
    settings: BrokerSettings,
    discovery: OAuthDiscovery | None,
) -> AppConnection | JSONResponse:
    """Resolve OAuth credentials and get a valid token for the connector.

    Returns AppConnection on success, or JSONResponse on failure.
    """
    try:
        callback_url = f"{settings.broker.public_url}oauth/{connector_name}/callback"
        resolved = await resolve_oauth(connector, app_key, callback_url, settings, store, discovery)
    except KeyError as missing_key:
        return JSONResponse({"error": str(missing_key)}, status_code=404)

    connection = await get_valid_token(
        app_key, connector_name, connector, resolved, store, oauth_handler
    )
    if not connection:
        return JSONResponse(
            {
                "error": f"No {connector.meta.display_name} connection for {app_key}. "
                f"Connect via /oauth/{connector_name}/connect?app_key={app_key}"
            },
            status_code=401,
        )

    return connection


async def _build_and_stream(  # noqa: PLR0913 — path forwarding requires all params
    request: Request,
    connector: BaseConnector,
    connector_name: str,
    *,
    connection: AppConnection | None = None,
    path: str = "",
) -> StreamingResponse | JSONResponse:
    """Build upstream request and stream the response back.

    When connection is None (sidecar-managed), headers are forwarded without auth.
    When connection is provided (broker-managed), OAuth token is injected.
    """
    # Reject unsupported HTTP methods
    if request.method not in _ALLOWED_HTTP_METHODS:
        return JSONResponse(
            {"error": f"HTTP method not allowed: {request.method}"}, status_code=405
        )

    # Validate path — reject traversal sequences that could escape the MCP endpoint
    if path and ".." in posixpath.normpath(path).split("/"):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    upstream_url = connector.meta.mcp_url
    if not upstream_url:
        return JSONResponse(
            {"error": f"Connector {connector_name} has no upstream URL"}, status_code=500
        )

    base_url = upstream_url.rstrip("/")
    upstream_url = f"{base_url}/{path}" if path else base_url

    if connection:
        if _CONTROL_CHAR_PATTERN.search(connection.access_token):
            return JSONResponse({"error": "Invalid token"}, status_code=422)
        headers = _build_upstream_headers(request, connector, connection.access_token, upstream_url)
    else:
        headers = _build_passthrough_headers(request, upstream_url)

    client = clients.get(connector_name)
    if not client:
        logger.error("[Proxy] No HTTP client for connector: %s", connector_name)
        return JSONResponse(
            {"error": f"Connector not initialized: {connector_name}"}, status_code=500
        )

    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        return JSONResponse(
            {"error": f"Request body too large ({len(body)} bytes, max {_MAX_BODY_BYTES})"},
            status_code=413,
        )

    # Validate JSON-RPC method on POST (GET/DELETE have no JSON-RPC payload)
    if request.method == "POST" and body:
        validation_error = _validate_mcp_payload(body, connector)
        if validation_error:
            return validation_error

    upstream_request = client.build_request(
        method=request.method, url=upstream_url, headers=headers, content=body
    )
    return await _send_and_stream(client, upstream_request, connector.meta.display_name)


async def proxy_mcp_request(  # noqa: PLR0913
    connector_name: str,
    request: Request,
    store: TokenStore,
    oauth_handler: OAuthHandler,
    settings: BrokerSettings,
    discovery: OAuthDiscovery | None = None,
    path: str = "",
) -> StreamingResponse | JSONResponse:
    """Proxy an MCP request to a remote server with OAuth token injection.

    Sidecar-managed connectors skip token lookup — the sidecar handles auth internally.
    """
    app_key_or_error = _extract_app_key(request)
    if isinstance(app_key_or_error, JSONResponse):
        return app_key_or_error
    app_key = app_key_or_error

    connector = ConnectorRegistry.get(connector_name)
    if not connector:
        return JSONResponse({"error": f"Unknown connector: {connector_name}"}, status_code=404)

    # Sidecar-managed — proxy without token injection
    if connector.meta.is_sidecar_managed:
        client_host = request.client.host if request.client else "unknown"
        logger.info(
            "[Proxy] Sidecar passthrough: app=%s connector=%s method=%s ip=%s",
            app_key,
            connector_name,
            request.method,
            client_host,
        )
        return await _build_and_stream(request, connector, connector_name, path=path)

    # Broker-managed — resolve OAuth token
    connection_or_error = await _resolve_connection(
        connector_name, connector, app_key, store, oauth_handler, settings, discovery
    )
    if isinstance(connection_or_error, JSONResponse):
        return connection_or_error

    client_host = request.client.host if request.client else "unknown"
    logger.info(
        "[Proxy] Token accessed: app=%s connector=%s method=%s ip=%s",
        app_key,
        connector_name,
        request.method,
        client_host,
    )

    # Native connector — dispatch in-process instead of forwarding upstream
    if isinstance(connector, NativeConnector):
        return await _dispatch_native_request(request, connector, connection_or_error)

    return await _build_and_stream(
        request, connector, connector_name, connection=connection_or_error, path=path
    )


async def _send_and_stream(
    client: httpx.AsyncClient,
    upstream_request: httpx.Request,
    display_name: str,
) -> StreamingResponse | JSONResponse:
    """Send a pre-built request upstream and stream the response back."""
    try:
        upstream_response = await client.send(upstream_request, stream=True)

        if upstream_response.status_code >= 400:  # noqa: PLR2004 — HTTP status boundary
            logger.warning(
                "[Proxy] Upstream %s returned %d",
                upstream_request.url,
                upstream_response.status_code,
            )

        response_headers = {
            name: value
            for name, value in upstream_response.headers.items()
            if name.lower() not in _STRIP_RESPONSE_HEADERS
        }

        return StreamingResponse(
            upstream_response.aiter_raw(),
            status_code=upstream_response.status_code,
            headers=response_headers,
            background=BackgroundTask(upstream_response.aclose),
        )

    except httpx.ConnectError as connect_error:
        logger.error("[Proxy] Connection failed to %s: %s", upstream_request.url, connect_error)
        return JSONResponse(
            {"error": f"Cannot reach {display_name} MCP server"},
            status_code=502,
        )
    except httpx.TimeoutException as timeout_error:
        logger.error("[Proxy] Timeout connecting to %s: %s", upstream_request.url, timeout_error)
        return JSONResponse(
            {"error": f"Timeout reaching {display_name} MCP server"},
            status_code=504,
        )
    except httpx.HTTPError as http_error:
        logger.error("[Proxy] HTTP error proxying to %s: %s", upstream_request.url, http_error)
        return JSONResponse(
            {"error": f"Error communicating with {display_name} MCP server"},
            status_code=502,
        )
