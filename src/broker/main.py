"""
MCP Broker

Lightweight reverse proxy between agents and remote MCP servers.
Handles OAuth flows and credential injection transparently.
"""

import asyncio
import contextlib
import html
import importlib
import logging
import time
from contextlib import asynccontextmanager
from http import HTTPStatus
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from broker.api.admin import AdminEndpoints
from broker.api.oauth_server import OAuthServerEndpoints
from broker.api.wellknown import (
    handle_authorization_server_metadata,
    handle_broker_protected_resource_metadata,
    handle_protected_resource_metadata,
)
from broker.config import BrokerSettings, load_settings
from broker.connectors.base import BaseConnector
from broker.connectors.native import NativeConnector
from broker.connectors.registry import ConnectorRegistry
from broker.middleware.auth import BrokerAuthMiddleware
from broker.models.connection import AppConnection
from broker.services.api_key_store import BrokerKeyStore, ConnectTokenStore
from broker.services.client_registry import BrokerClientRegistry
from broker.services.discovery import OAuthDiscovery, resolve_oauth
from broker.services.inbound_auth_store import SQLiteInboundAuthStore
from broker.services.oauth import OAuthHandler
from broker.services.proxy import clients, get_valid_token, proxy_mcp_request
from broker.services.sqlite_api_key_store import SQLiteBrokerKeyStore
from broker.services.store import TokenStore, create_token_store

logger = logging.getLogger(__name__)

# Module-level references (set during lifespan startup)
_store: TokenStore | None = None
_oauth_handler: OAuthHandler | None = None
_settings: BrokerSettings | None = None
_discovery: OAuthDiscovery | None = None
_key_store: BrokerKeyStore | None = None
_client_registry: BrokerClientRegistry | None = None
_connect_token_store: ConnectTokenStore | None = None
_inbound_auth_store: SQLiteInboundAuthStore | None = None
_oauth_endpoints: OAuthServerEndpoints | None = None


def _get_settings() -> BrokerSettings:
    """Return settings. Raises if lifespan has not started."""
    if _settings is None:
        raise RuntimeError("BrokerSettings not initialized — lifespan not started")
    return _settings


def _get_store() -> TokenStore:
    """Return token store. Raises if lifespan has not started."""
    if _store is None:
        raise RuntimeError("TokenStore not initialized — lifespan not started")
    return _store


def _get_oauth_handler() -> OAuthHandler:
    """Return OAuth handler. Raises if lifespan has not started."""
    if _oauth_handler is None:
        raise RuntimeError("OAuthHandler not initialized — lifespan not started")
    return _oauth_handler


def _get_discovery() -> OAuthDiscovery | None:
    """Return OAuth discovery instance (None if no discovery connectors)."""
    return _discovery


def _get_key_store() -> BrokerKeyStore | None:
    """Return key store (None before lifespan init — middleware returns 503)."""
    return _key_store


def _get_client_registry() -> BrokerClientRegistry | None:
    """Return client registry (None before lifespan init — middleware returns 503)."""
    return _client_registry


def _get_connect_token_store() -> ConnectTokenStore | None:
    """Return connect token store (None before lifespan init — middleware returns 503)."""
    return _connect_token_store


def _get_inbound_auth_store() -> SQLiteInboundAuthStore | None:
    """Return inbound OAuth auth store (None when ``broker.oauth.enabled=false``).

    Middleware fails closed on ``None`` only when ``oauth_enabled`` is also true;
    otherwise the legacy auth path continues to work unchanged.
    """
    return _inbound_auth_store


# =============================================================================
# LIFESPAN HELPERS
# =============================================================================


def _load_connectors(connector_names: list[str]) -> None:
    """Import connector adapter modules from the connectors list in settings.

    Each name maps to `connectors.{name}.adapter`. Import triggers auto-registration
    via BaseConnector.__init_subclass__.
    """
    for name in connector_names:
        if not name.isidentifier():
            raise ValueError(f"Invalid connector name: {name!r} (must be a Python identifier)")
        module_path = f"connectors.{name}.adapter"
        try:
            importlib.import_module(module_path)
        except Exception:
            logger.error("[Broker] Failed to load connector: %s (%s)", name, module_path)
            raise


def _start_token_refresh(settings: BrokerSettings) -> asyncio.Task[None] | None:
    """Start the background token refresh loop if enabled. Returns the task or None."""
    if not settings.broker.token_refresh_enabled:
        logger.info("[Broker] Background token refresh disabled")
        return None
    base_url = settings.broker.public_url
    return asyncio.create_task(
        _token_refresh_loop(base_url, settings.broker.token_refresh_interval_seconds)
    )


async def _run_discovery(discovery: OAuthDiscovery, connectors: list[BaseConnector]) -> None:
    """Discover OAuth metadata for discovery-enabled connectors. Logs failures."""
    for connector in connectors:
        if not connector.meta.uses_discovery:
            continue
        mcp_oauth_url = connector.meta.mcp_oauth_url
        if not mcp_oauth_url:
            logger.warning(
                "[Broker] Discovery connector %s has no mcp_oauth_url", connector.meta.name
            )
            continue
        try:
            await discovery.discover_metadata(connector.meta.name, mcp_oauth_url)
        except Exception:  # noqa: BLE001
            logger.exception(
                "[Broker] Discovery failed for %s — /connect will fail", connector.meta.name
            )


# =============================================================================
# LIFESPAN
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: PLR0915 — startup sequence, all steps are required
    global \
        _store, \
        _oauth_handler, \
        _settings, \
        _discovery, \
        _key_store, \
        _client_registry, \
        _connect_token_store, \
        _inbound_auth_store, \
        _oauth_endpoints

    # 1. Load settings. Validation already ran synchronously in broker/__main__.py
    #    before uvicorn started, so a failure here means either (a) settings.yaml
    #    was edited during --reload into a broken state, or (b) someone imported
    #    this app directly bypassing the entrypoint. Either way, let the error
    #    propagate — uvicorn will log it and restart the worker.
    _settings = load_settings()

    # 2. Configure logging from settings
    logging.basicConfig(
        level=getattr(logging, _settings.broker.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    logger.info("[Broker] Starting MCP Broker")

    # 3. Build client registry from YAML clients config
    _client_registry = BrokerClientRegistry(_settings.clients)

    # 4. Create and initialize API key store
    key_store = SQLiteBrokerKeyStore(db_path=_settings.store.sqlite.key_db_path)
    await key_store.setup()
    _key_store = key_store

    # 4b. Inbound OAuth auth store — only initialize when the operator opted in.
    #     Leaving it None keeps the broker's surface area unchanged for users
    #     who haven't flipped `broker.oauth.enabled`.
    if _settings.broker.oauth.enabled:
        inbound_store = SQLiteInboundAuthStore(db_path=_settings.broker.oauth.db_path)
        await inbound_store.setup()
        _inbound_auth_store = inbound_store
        # OAuthServerEndpoints owns the in-memory `_DCRRateLimiter` — it MUST be
        # a singleton across requests, otherwise the rate-limiter's `_events`
        # dict resets on every call and the 10/15min/IP cap is unenforceable.
        _oauth_endpoints = OAuthServerEndpoints(
            inbound_auth_store=inbound_store,
            config=_settings.broker.oauth,
            connector_names_provider=ConnectorRegistry.list_names,
            public_url=_settings.broker.public_url,
        )
        logger.info("[Broker] Inbound OAuth enabled (db=%s)", _settings.broker.oauth.db_path)

    # 5. Create connect token store (in-memory, single-use tokens for browser OAuth)
    _connect_token_store = ConnectTokenStore()

    # 6. Import connector modules — config-driven discovery
    _load_connectors(_settings.broker.connectors)

    registered = ConnectorRegistry.list_all()
    logger.info("[Broker] Registered connectors: %s", [c.meta.name for c in registered])

    # 7. Create persistent httpx clients for proxied connectors (skip native)
    for connector in registered:
        if isinstance(connector, NativeConnector):
            logger.info("[Broker] Native connector (in-process): %s", connector.meta.name)
            continue
        clients[connector.meta.name] = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=True,
        )

    # 8. Create token store
    _store = create_token_store(_settings.store, _settings.broker.encryption_keys)

    # 9. Create OAuth handler
    _oauth_handler = OAuthHandler(state_secret=_settings.broker.state_secret)

    # 10. Create discovery + discover metadata for discovery-enabled connectors
    _discovery = OAuthDiscovery()
    await _run_discovery(_discovery, registered)

    # 11. Start background token refresh loop (if enabled)
    refresh_task = _start_token_refresh(_settings)

    logger.info(
        "[Broker] Ready on %s:%s with %s connectors",
        _settings.broker.host,
        _settings.broker.port,
        len(registered),
    )

    yield

    # Cleanup
    logger.info("[Broker] Shutting down")
    if refresh_task:
        refresh_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await refresh_task
    if _key_store:
        await _key_store.teardown()
    for client in clients.values():
        await client.aclose()
    clients.clear()


# =============================================================================
# APP
# =============================================================================

app = FastAPI(
    title="MCP Broker",
    description="OAuth proxy for remote MCP servers",
    version="0.1.0",
    lifespan=lifespan,
)


# Read OAuth toggle + public_url synchronously at module import so the
# middleware can stash them. ``broker/__main__.py`` already validated settings
# before uvicorn started; this second parse is cheap and lets the middleware
# see the OAuth config (its constructor needs scalars, not callables).
#
# Import-time failure is tolerated: tests import ``broker.main`` without a
# ``settings.yaml`` and stitch state in directly. In that case OAuth stays off
# and the legacy auth path is unaffected.
def _bootstrap_oauth_args() -> tuple[bool, str]:
    """Best-effort read of OAuth toggle + public_url at module import."""
    try:
        bootstrap = load_settings()
    except Exception:  # noqa: BLE001 -- tests import without settings.yaml; default to disabled
        return False, ""
    return bootstrap.broker.oauth.enabled, bootstrap.broker.public_url


_BOOTSTRAP_OAUTH_ENABLED, _BOOTSTRAP_PUBLIC_URL = _bootstrap_oauth_args()

# Auth middleware — registered before lifespan, uses lazy accessors for the
# stores. ``oauth_enabled`` and ``public_url`` are read once at import; flipping
# them requires a process restart (matches the existing connectors-list pattern).
app.add_middleware(
    BrokerAuthMiddleware,
    get_key_store=_get_key_store,
    get_client_registry=_get_client_registry,
    get_connect_token_store=_get_connect_token_store,
    exempt_prefixes=("/health", "/admin"),
    exempt_paths=(),
    oauth_enabled=_BOOTSTRAP_OAUTH_ENABLED,
    public_url=_BOOTSTRAP_PUBLIC_URL,
    get_inbound_auth_store=_get_inbound_auth_store,
    get_connector_names=ConnectorRegistry.list_names,
)


# =============================================================================
# ADMIN ROUTES (module-level to avoid route accumulation in tests)
# =============================================================================


def _get_admin_endpoints() -> AdminEndpoints:
    """Lazy-create AdminEndpoints from module-level state.

    Raises RuntimeError if called before lifespan init — admin routes are
    exempt from middleware so they won't get a 503, but the endpoint handler
    will raise before doing any work.
    """
    settings = _get_settings()
    key_store = _key_store
    client_registry = _client_registry
    connect_token_store = _connect_token_store
    if not key_store or not client_registry or not connect_token_store:
        raise RuntimeError("Admin services not initialized — lifespan not started")

    async def _do_refresh() -> dict[str, int]:
        return await _refresh_expiring_tokens(settings.broker.public_url)

    return AdminEndpoints(
        key_store=key_store,
        admin_key=settings.broker.admin_key,
        client_registry=client_registry,
        connect_token_store=connect_token_store,
        token_store=_store,
        refresh_callback=_do_refresh,
        inbound_auth_store=_inbound_auth_store,
    )


@app.post("/admin/keys")
async def admin_create_key(request: Request):
    return await _get_admin_endpoints().create_key(request)


@app.get("/admin/keys")
async def admin_list_keys(request: Request):
    return await _get_admin_endpoints().list_keys(request)


@app.post("/admin/keys/{app_key:path}/rotate")
async def admin_rotate_key(app_key: str, request: Request):
    return await _get_admin_endpoints().rotate_key(app_key, request)


@app.delete("/admin/keys/{app_key:path}")
async def admin_delete_key(app_key: str, request: Request):
    return await _get_admin_endpoints().delete_key(app_key, request)


@app.post("/admin/connect-token")
async def admin_create_connect_token(request: Request):
    return await _get_admin_endpoints().create_connect_token(request)


@app.post("/admin/refresh")
async def admin_refresh_tokens(request: Request):
    return await _get_admin_endpoints().refresh_tokens(request)


# =============================================================================
# INBOUND OAUTH ROUTES (gated by settings.broker.oauth.enabled)
# =============================================================================


def _get_oauth_endpoints() -> OAuthServerEndpoints | None:
    """Return the lifespan-initialized OAuth endpoints, or None when disabled.

    Returns a singleton so the in-memory ``_DCRRateLimiter._events`` dict
    accumulates state across requests. Constructing a fresh instance per
    request would reset the counter on every call and silently disable the
    10/15min/IP rate limit — and silently nullify the ``WEB_CONCURRENCY=1``
    startup check, which exists precisely because the limiter is in-process.

    Returns ``None`` when ``broker.oauth.enabled=false`` so route handlers
    can short-circuit to a 404 instead of letting a RuntimeError propagate
    into a 500.
    """
    return _oauth_endpoints


@app.post("/oauth/register")
async def oauth_register(request: Request):
    endpoints = _get_oauth_endpoints()
    if endpoints is None:
        return _oauth_disabled_not_found()
    return await endpoints.register(request)


@app.get("/oauth/authorize")
async def oauth_authorize_get(request: Request):
    endpoints = _get_oauth_endpoints()
    if endpoints is None:
        return _oauth_disabled_not_found()
    return await endpoints.authorize_get(request)


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request):
    endpoints = _get_oauth_endpoints()
    if endpoints is None:
        return _oauth_disabled_not_found()
    return await endpoints.authorize_post(request)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    endpoints = _get_oauth_endpoints()
    if endpoints is None:
        return _oauth_disabled_not_found()
    return await endpoints.token(request)


@app.post("/oauth/revoke")
async def oauth_revoke(request: Request):
    endpoints = _get_oauth_endpoints()
    if endpoints is None:
        return _oauth_disabled_not_found()
    return await endpoints.revoke(request)


def _oauth_disabled_not_found() -> JSONResponse:
    """404 for the five /oauth/* routes when broker.oauth.enabled=false.

    Mirrors the in-handler `_not_found()` shape from oauth_server.py so a
    misconfigured client sees the same disabled-mode response regardless of
    whether oauth was disabled at lifespan-init time (this path) or flipped
    off mid-process (the handler-internal check — currently unreachable but
    kept as defense in depth).
    """
    return JSONResponse({"error": "not_found"}, status_code=HTTPStatus.NOT_FOUND)


@app.get("/.well-known/oauth-authorization-server")
async def wellknown_oauth_as():
    """RFC 8414 AS metadata. Always reachable so claude.ai discovery works
    before the operator flips ``broker.oauth.enabled`` — claude.ai stops here
    if it can't read the metadata."""
    settings = _get_settings()
    return handle_authorization_server_metadata(
        settings.broker.public_url, ConnectorRegistry.list_names()
    )


@app.get("/.well-known/oauth-protected-resource")
async def wellknown_oauth_pr_broker():
    """RFC 9728 PRM for the broker as a whole.

    Returned when a bearer challenge fires on a non-connector-scoped path
    (e.g. ``/status``). The path-parameterized handler below requires at least
    one segment, so this bare route covers the no-suffix case; without it the
    ``WWW-Authenticate: Bearer resource_metadata="..."`` URL would 404 and
    break MCP-client discovery bootstrap.
    """
    settings = _get_settings()
    return handle_broker_protected_resource_metadata(
        settings.broker.public_url, ConnectorRegistry.list_names()
    )


@app.get("/.well-known/oauth-protected-resource/{wellknown_path:path}")
async def wellknown_oauth_pr(wellknown_path: str):
    """RFC 9728 PRM. Path-style suffix so ``proxy/notion/mcp`` works alongside
    ``proxy/workspace_mcp/`` (no uniform per-connector path shape)."""
    settings = _get_settings()
    return handle_protected_resource_metadata(
        settings.broker.public_url, wellknown_path, ConnectorRegistry.list_names()
    )


# =============================================================================
# HELPERS
# =============================================================================


def _get_connector_or_404(connector_name: str) -> BaseConnector:
    """Look up connector, raise 404 if not found."""
    connector = ConnectorRegistry.get(connector_name)
    if not connector:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {connector_name}")
    return connector


def _require_scope(request: Request, scope: str) -> None:
    """Check if the authenticated identity has the required scope. Raises 403."""
    identity = getattr(request.state, "identity", None)
    if not identity or not identity.has_scope(scope):
        raise HTTPException(status_code=403, detail="Insufficient scope")


def _check_connector_access(request: Request, connector_name: str) -> None:
    """Check if the authenticated identity can access this connector. Raises 403."""
    identity = getattr(request.state, "identity", None)
    if not identity or not identity.can_access_connector(connector_name):
        raise HTTPException(status_code=403, detail=f"Access denied to connector: {connector_name}")


# =============================================================================
# MCP PROXY
# =============================================================================


@app.api_route("/proxy/{connector_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def mcp_proxy(connector_name: str, path: str, request: Request):
    """Proxy MCP requests to remote server with OAuth token injection.

    Auth: Middleware validates X-Broker-Key + X-App-Id, sets request.state.identity.
    """
    _require_scope(request, "proxy")
    _check_connector_access(request, connector_name)
    return await proxy_mcp_request(
        connector_name,
        request,
        _get_store(),
        _get_oauth_handler(),
        _get_settings(),
        _get_discovery(),
        path=path,
    )


# =============================================================================
# OAUTH FLOW
# =============================================================================


def _reject_sidecar_managed(connector: BaseConnector) -> None:
    """Raise 404 if the connector manages its own auth (no broker OAuth)."""
    if connector.meta.is_sidecar_managed:
        raise HTTPException(
            status_code=404,
            detail=f"{connector.meta.display_name} manages its own authentication",
        )


def _resolve_oauth_success_url(settings: BrokerSettings, connector_name: str) -> str:
    """Resolve the post-OAuth-callback redirect URL.

    Honors ``broker.success_redirect_url`` when set; otherwise falls back to
    the broker's built-in ``/oauth/success`` page so operators don't need to
    configure anything to get a sensible default UX. Previously the default
    was inline HTML rendered by the callback handler itself — a stable URL
    is cleaner because operators can link to it, bookmark it, and (if they
    later want a real dashboard) point ``success_redirect_url`` at it as a
    fallback. ``connector_name`` is URL-encoded as defense-in-depth: in
    practice it's a Pydantic-validated identifier, but encoding ensures any
    future code path that admits weirder values can't fold characters into
    the URL structure (e.g. injecting an extra query param).
    """
    if settings.broker.success_redirect_url:
        return settings.broker.success_redirect_url
    issuer = settings.broker.public_url.rstrip("/")
    return f"{issuer}/oauth/success?connector={quote(connector_name, safe='')}"


@app.get("/oauth/{connector_name}/connect")
async def oauth_connect(
    connector_name: str,
    request: Request,
    app_key: str | None = None,  # accepted but unused — prevents 422 if clients include it in URL
):
    """Start OAuth flow.

    Two auth modes:
    - API client: X-App-Id + X-Broker-Key headers
    - Browser: connect_token query param (from POST /admin/connect-token)
    """
    _require_scope(request, "proxy")
    _check_connector_access(request, connector_name)
    identity = request.state.identity
    connector = _get_connector_or_404(connector_name)
    _reject_sidecar_managed(connector)

    callback_url = str(request.url_for("oauth_callback", connector_name=connector_name))

    try:
        resolved = await resolve_oauth(
            connector,
            identity.app_key,
            callback_url,
            _get_settings(),
            _get_store(),
            _get_discovery(),
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    url = _get_oauth_handler().build_authorize_url(
        connector, identity.app_key, resolved, callback_url
    )
    return RedirectResponse(url)


async def _exchange_and_store_token(  # noqa: PLR0913 — OAuth exchange needs all context
    connector: BaseConnector,
    connector_name: str,
    code: str,
    state: str,
    request: Request,
) -> str:
    """Exchange OAuth code for token and store it. Returns the app_key."""
    store = _get_store()
    oauth = _get_oauth_handler()

    decoded_state = oauth.decode_state(state)
    app_key = decoded_state["app_key"]

    callback_url = str(request.url_for("oauth_callback", connector_name=connector_name))
    resolved = await resolve_oauth(
        connector, app_key, callback_url, _get_settings(), store, _get_discovery()
    )

    connection, returned_app_key = await oauth.exchange_code(
        connector, code, state, resolved, callback_url
    )

    await store.save(returned_app_key, connector_name, connection)
    return returned_app_key


@app.get("/oauth/{connector_name}/callback")
async def oauth_callback(connector_name: str, code: str, state: str, request: Request):
    """OAuth callback — exchange code, store token, show success page.

    No auth needed — callback is from OAuth provider. Signed state protects it.
    """
    connector = _get_connector_or_404(connector_name)
    _reject_sidecar_managed(connector)

    try:
        returned_app_key = await _exchange_and_store_token(
            connector, connector_name, code, state, request
        )
        logger.info("[Broker] OAuth connected: %s/%s", returned_app_key, connector_name)
        return RedirectResponse(_resolve_oauth_success_url(_get_settings(), connector_name))
    except ValueError as value_error:
        logger.warning("[Broker] OAuth callback failed: %s", value_error)
        return HTMLResponse(
            "<h1>Connection failed</h1><p>Authentication failed. Please try again.</p>",
            status_code=400,
        )
    except Exception:  # noqa: BLE001
        logger.exception("[Broker] OAuth callback error")
        return HTMLResponse(
            "<h1>Connection failed</h1><p>Unexpected error — check broker logs.</p>",
            status_code=500,
        )


@app.get("/oauth/success")
async def oauth_success_page(connector: str | None = None):
    """Built-in landing page after a successful outbound OAuth connect.

    Operator-facing. No auth — the success page leaks no protected state and
    the operator's browser just completed an OAuth dance, so locking the page
    behind broker-key auth would only break the UX. Operators with a real
    dashboard override this by setting ``broker.success_redirect_url``.
    """
    name = connector if connector and connector.isidentifier() else "Connection"
    return HTMLResponse(
        f"<h1>{html.escape(name.title())} connected</h1><p>You can close this tab.</p>"
    )


@app.post("/oauth/{connector_name}/disconnect")
async def oauth_disconnect(connector_name: str, request: Request):
    """Delete stored token. Auth: Middleware validates X-Broker-Key + X-App-Id."""
    _require_scope(request, "proxy")
    # Use identity from middleware (not caller-supplied app_key)
    identity = request.state.identity
    _check_connector_access(request, connector_name)
    connector = _get_connector_or_404(connector_name)
    _reject_sidecar_managed(connector)
    await _get_store().delete(identity.app_key, connector_name)
    logger.info("[Broker] Disconnected: %s/%s", identity.app_key, connector_name)
    return {"status": "disconnected"}


# =============================================================================
# ADMIN (token refresh — kept here, key CRUD moved to api/admin.py)
# =============================================================================


async def _refresh_single_connection(  # noqa: PLR0913 — refresh needs all service deps
    app_key: str,
    connector_name: str,
    connector: BaseConnector,
    connection: AppConnection,
    base_url: str,
    settings: BrokerSettings,
    store: TokenStore,
    oauth: OAuthHandler,
    discovery: OAuthDiscovery | None,
) -> str:
    """Attempt to refresh a single connection. Returns 'refreshed', 'skipped', or 'failed'."""
    try:
        callback_url = f"{base_url}oauth/{connector_name}/callback"
        resolved = await resolve_oauth(connector, app_key, callback_url, settings, store, discovery)
        refreshed = await get_valid_token(
            app_key, connector_name, connector, resolved, store, oauth
        )
        if refreshed and refreshed.access_token != connection.access_token:
            return "refreshed"
        return "skipped"
    except Exception:  # noqa: BLE001
        logger.exception("[Refresh] Failed: %s/%s", app_key, connector_name)
        return "failed"


async def _refresh_expiring_tokens(base_url: str) -> dict[str, int]:
    """Find tokens expiring within 10 minutes and refresh them.

    Returns summary counts: {"refreshed": N, "failed": N, "skipped": N}.
    """
    store = _get_store()
    oauth = _get_oauth_handler()
    settings = _get_settings()
    discovery = _get_discovery()

    expiring = await store.list_expiring(buffer_seconds=600)
    results: dict[str, int] = {"refreshed": 0, "failed": 0, "skipped": 0}

    for app_key, connector_name, connection in expiring:
        connector = ConnectorRegistry.get(connector_name)
        if not connector:
            results["skipped"] += 1
            continue

        outcome = await _refresh_single_connection(
            app_key,
            connector_name,
            connector,
            connection,
            base_url,
            settings,
            store,
            oauth,
            discovery,
        )
        results[outcome] += 1

    return results


# --- Background refresh loop ---


async def _token_refresh_loop(base_url: str, interval_seconds: int) -> None:
    """Periodically refresh expiring tokens. Runs as a background asyncio task.

    Also reaps expired rows from the inbound auth store when OAuth is enabled —
    cheaper than a separate timer and runs on the same cadence as everything
    else that touches token state.
    """
    logger.info("[TokenRefresh] Started (interval=%ds)", interval_seconds)
    while True:
        try:
            results = await _refresh_expiring_tokens(base_url)
            if results["refreshed"] or results["failed"]:
                logger.info("[TokenRefresh] %s", results)
            if _inbound_auth_store is not None:
                await _inbound_auth_store.cleanup_expired()
        except Exception:  # noqa: BLE001
            logger.exception("[TokenRefresh] Unexpected error in refresh loop")
        await asyncio.sleep(interval_seconds)


# =============================================================================
# STATUS + HEALTH
# =============================================================================


@app.get("/status")
async def status(request: Request):
    """List connections for an app with token health.

    Auth: Middleware validates X-Broker-Key + X-App-Id.
    Uses identity from middleware (not caller-supplied app_key query param).
    """
    _require_scope(request, "status")
    identity = request.state.identity
    connections = await _get_store().list_for_app(identity.app_key)

    # Filter connections to only allowed connectors
    filtered = []
    for c in connections:
        if identity.can_access_connector(c.connector_name):
            filtered.append(
                {
                    "connector": c.connector_name,
                    "connected": True,
                    "token_expires_at": c.expires_at,
                    "token_valid": c.expires_at is None or c.expires_at > time.time(),
                }
            )

    return {"app": identity.app_key, "connections": filtered}


@app.get("/health")
async def health():
    """Unauthenticated health check — no sensitive data."""
    connectors = [
        {
            "name": c.meta.name,
            "display_name": c.meta.display_name,
            "transport": c.meta.mcp_transport,
            "auth_mode": c.meta.auth_mode,
        }
        for c in ConnectorRegistry.list_all()
    ]
    return {"status": "healthy", "connectors": connectors}
