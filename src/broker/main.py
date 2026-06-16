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
import os
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
from broker.services.auth_store_interfaces import (
    ConnectTokenStoreABC,
    DCRRateLimiter,
    InboundAuthStore,
    OutboundOAuthStateStore,
)
from broker.services.client_registry import BrokerClientRegistry
from broker.services.discovery import OAuthDiscovery, resolve_oauth
from broker.services.firestore_broker_key_store import FirestoreBrokerKeyStore
from broker.services.firestore_client import close_firestore_client
from broker.services.firestore_connect_token_store import FirestoreConnectTokenStore
from broker.services.firestore_dcr_rate_limiter import FirestoreDCRRateLimiter
from broker.services.firestore_inbound_auth_store import FirestoreInboundAuthStore
from broker.services.firestore_outbound_state_store import FirestoreOutboundOAuthStateStore
from broker.services.inbound_auth_store import SQLiteInboundAuthStore
from broker.services.oauth import OAuthHandler
from broker.services.proxy import clients, get_valid_token, proxy_mcp_request
from broker.services.sqlite_api_key_store import SQLiteBrokerKeyStore
from broker.services.store import TokenStore, create_token_store

logger = logging.getLogger(__name__)

# How far ahead of expiry the maintenance loop refreshes outbound tokens.
# Matches the default window of ``TokenStore.list_expiring`` so the loop
# refreshes exactly the connections the store reports as expiring.
TOKEN_REFRESH_BUFFER_SECONDS = 600

# OAuth callback query params stripped before a connector's parse_callback_params
# hook sees them — a connector must never receive (or be able to persist) the
# single-use authorization code or the signed state.
_OAUTH_CALLBACK_PARAMS = frozenset({"code", "state", "error", "error_description"})

# Module-level references (set during lifespan startup)
_store: TokenStore | None = None
_oauth_handler: OAuthHandler | None = None
_settings: BrokerSettings | None = None
_discovery: OAuthDiscovery | None = None
_key_store: BrokerKeyStore | None = None
_client_registry: BrokerClientRegistry | None = None
_connect_token_store: ConnectTokenStoreABC | None = None
_inbound_auth_store: InboundAuthStore | None = None
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


def _get_connect_token_store() -> ConnectTokenStoreABC | None:
    """Return connect token store (None before lifespan init — middleware returns 503)."""
    return _connect_token_store


def _get_inbound_auth_store() -> InboundAuthStore | None:
    """Return inbound OAuth auth store (None when ``broker.oauth.enabled=false``).

    Middleware fails closed on ``None`` only when ``oauth_enabled`` is also true;
    otherwise the legacy auth path continues to work unchanged.
    """
    return _inbound_auth_store


# =============================================================================
# LIFESPAN HELPERS
# =============================================================================


def _abort_if_multiworker_with_oauth(oauth_enabled: bool, store_backend: str = "sqlite") -> None:
    """Refuse to start under multi-worker uvicorn when inbound OAuth is on AND
    the store backend keeps OAuth state process-local.

    With the default (sqlite / in-memory) backend the DCR rate limiter and the
    outbound nonce/PKCE state are per-process: ``WEB_CONCURRENCY > 1`` would make
    the limiter cap (cap × N) and let per-flow state land on a different worker
    than the one that issued it. With ``store.backend == "firestore"`` all of
    that state is shared across instances (inbound auth store, connect tokens,
    outbound nonce/PKCE, and the DCR limiter), so multi-worker is legal.

    This runs inside lifespan startup so the invariant holds for ANY launch
    shape — including the production Dockerfile, which runs
    ``uvicorn broker.main:app`` directly and never calls ``__main__.main()``.
    ``__main__`` performs the same check pre-uvicorn so the ``./start`` dev
    path fails fast with a friendly ``SystemExit`` before a worker spins up;
    both checks exist because neither entrypoint is guaranteed to run.
    """
    if not oauth_enabled or store_backend == "firestore":
        return
    workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
    if workers > 1:
        raise RuntimeError(
            "broker.oauth.enabled=true is incompatible with WEB_CONCURRENCY="
            f"{workers} on the '{store_backend}' store backend. The DCR rate "
            "limiter and outbound OAuth state are per-process. Set "
            "WEB_CONCURRENCY=1, switch store.backend to 'firestore' for "
            "multi-worker, or disable broker.oauth in settings.yaml."
        )


async def _build_connect_token_store(settings: BrokerSettings) -> ConnectTokenStoreABC:
    """Connect token store: Firestore (shared) on the firestore backend, else in-memory."""
    if settings.store.backend == "firestore" and settings.store.firestore is not None:
        fs = settings.store.firestore
        store = FirestoreConnectTokenStore(
            project_id=fs.project_id, database=fs.database, collection_prefix=fs.collection_prefix
        )
        await store.setup()
        return store
    return ConnectTokenStore()


async def _build_outbound_state_store(settings: BrokerSettings) -> OutboundOAuthStateStore | None:
    """Outbound OAuth state store: Firestore (shared) on the firestore backend.

    Returns None for non-Firestore backends so OAuthHandler falls back to its
    in-memory module singleton (preserving the single-instance default).
    """
    if settings.store.backend == "firestore" and settings.store.firestore is not None:
        fs = settings.store.firestore
        store = FirestoreOutboundOAuthStateStore(
            project_id=fs.project_id, database=fs.database, collection_prefix=fs.collection_prefix
        )
        await store.setup()
        return store
    return None


async def _build_dcr_rate_limiter(settings: BrokerSettings) -> DCRRateLimiter | None:
    """DCR rate limiter: Firestore (shared) on the firestore backend.

    Returns None for non-Firestore backends so OAuthServerEndpoints constructs
    its in-memory default (preserving the single-worker invariant).
    """
    if settings.store.backend == "firestore" and settings.store.firestore is not None:
        fs = settings.store.firestore
        limiter = FirestoreDCRRateLimiter(
            max_per_window=settings.broker.oauth.dcr_rate_limit_per_ip,
            window_seconds=settings.broker.oauth.dcr_rate_limit_window_seconds,
            project_id=fs.project_id,
            database=fs.database,
            collection_prefix=fs.collection_prefix,
        )
        await limiter.setup()
        return limiter
    return None


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
    """Start the background maintenance loop.

    The loop covers two independent concerns on the same cadence: outbound
    token refresh and inbound OAuth state cleanup. It starts when either is
    active, and the loop body gates each step on its own flag — so an
    operator who disables token refresh still gets OAuth cleanup, and an
    operator who hasn't enabled OAuth still gets token refresh.
    """
    refresh_active = settings.broker.token_refresh_enabled
    oauth_active = settings.broker.oauth.enabled
    if not refresh_active and not oauth_active:
        logger.info("[Broker] Background maintenance disabled (no refresh + no OAuth)")
        return None
    base_url = settings.broker.public_url
    return asyncio.create_task(
        _maintenance_loop(base_url, settings.broker.token_refresh_interval_seconds)
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
        except Exception:  # noqa: BLE001 -- startup continues if one connector's discovery fails; only its /connect breaks, not the whole broker
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

    # 1b. Enforce the single-worker inbound-OAuth invariant for every launch
    #     shape. __main__ checks this pre-uvicorn, but the production Dockerfile
    #     runs `uvicorn broker.main:app` directly and bypasses __main__ — so the
    #     check must also live here, on the actual startup path.
    _abort_if_multiworker_with_oauth(_settings.broker.oauth.enabled, _settings.store.backend)

    # 2. Configure logging from settings
    logging.basicConfig(
        level=getattr(logging, _settings.broker.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    logger.info("[Broker] Starting MCP Broker")

    # 3. Build client registry from YAML clients config
    _client_registry = BrokerClientRegistry(_settings.clients)

    # 4. Create and initialize API key store (backend-aware).
    if _settings.store.backend == "firestore" and _settings.store.firestore is not None:
        fs = _settings.store.firestore
        key_store: BrokerKeyStore = FirestoreBrokerKeyStore(
            project_id=fs.project_id, database=fs.database, collection_prefix=fs.collection_prefix
        )
    else:
        key_store = SQLiteBrokerKeyStore(db_path=_settings.store.sqlite.key_db_path)
    await key_store.setup()
    _key_store = key_store

    # 4b. Inbound OAuth auth store — only initialize when the operator opted in.
    #     Leaving it None keeps the broker's surface area unchanged for users
    #     who haven't flipped `broker.oauth.enabled`.
    if _settings.broker.oauth.enabled:
        if _settings.store.backend == "firestore" and _settings.store.firestore is not None:
            fs_oauth = _settings.store.firestore
            inbound_store: InboundAuthStore = FirestoreInboundAuthStore(
                project_id=fs_oauth.project_id,
                database=fs_oauth.database,
                collection_prefix=fs_oauth.collection_prefix,
            )
        else:
            inbound_store = SQLiteInboundAuthStore(db_path=_settings.broker.oauth.db_path)
        await inbound_store.setup()
        _inbound_auth_store = inbound_store
        # The DCR rate limiter MUST be a singleton across requests so its counter
        # accumulates. On Firestore it is shared across instances (so multi-worker
        # is legal); otherwise the in-memory default is constructed inside
        # OAuthServerEndpoints and the single-worker invariant applies.
        rate_limiter = await _build_dcr_rate_limiter(_settings)
        _oauth_endpoints = OAuthServerEndpoints(
            inbound_auth_store=inbound_store,
            config=_settings.broker.oauth,
            connector_names_provider=ConnectorRegistry.list_names,
            public_url=_settings.broker.public_url,
            rate_limiter=rate_limiter,
        )
        logger.info("[Broker] Inbound OAuth enabled (db=%s)", _settings.broker.oauth.db_path)

    # 5. Create connect token store: Firestore (shared, single-use across
    #    instances) or the in-memory default (single-process).
    _connect_token_store = await _build_connect_token_store(_settings)

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
    # Initialize the store (Firestore acquires its client; SQLite is a no-op).
    await _store.setup()

    # 9. Create OAuth handler. On Firestore the outbound nonce/PKCE state is
    #    shared across instances; otherwise the in-memory default is used.
    outbound_state_store = await _build_outbound_state_store(_settings)
    _oauth_handler = OAuthHandler(
        state_secret=_settings.broker.state_secret, state_store=outbound_state_store
    )

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
    if _store:
        await _store.teardown()
    await close_firestore_client()
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


# Auth middleware — registered before lifespan, uses lazy accessors for every
# settings-derived value. Reading the module-level ``_settings`` per-request
# keeps a single source of truth (the lifespan-loaded value) and tolerates the
# pre-lifespan / no-settings.yaml case by defaulting to OAuth-off, matching
# the legacy auth path's behaviour during startup and in test imports.
def _oauth_enabled_or_default() -> bool:
    return _settings.broker.oauth.enabled if _settings is not None else False


def _public_url_or_default() -> str:
    return _settings.broker.public_url if _settings is not None else ""


app.add_middleware(
    BrokerAuthMiddleware,
    get_key_store=_get_key_store,
    get_client_registry=_get_client_registry,
    get_connect_token_store=_get_connect_token_store,
    exempt_prefixes=("/health", "/admin"),
    exempt_paths=(),
    get_oauth_enabled=_oauth_enabled_or_default,
    get_public_url=_public_url_or_default,
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
        connector_lookup=ConnectorRegistry.get,
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


@app.post("/admin/oauth/revoke/{app_key:path}")
async def admin_revoke_inbound_oauth(app_key: str, request: Request):
    return await _get_admin_endpoints().revoke_inbound_oauth(app_key, request)


@app.delete("/admin/connections/{app_key:path}/{connector_name}")
async def admin_disconnect_connection(app_key: str, connector_name: str, request: Request):
    return await _get_admin_endpoints().disconnect_connection(app_key, connector_name, request)


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
    """RFC 8414 AS metadata.

    The route is always mounted, but unauthenticated discovery only succeeds
    when ``broker.oauth.enabled=true`` — the middleware exempts the
    ``/.well-known/oauth-`` prefix on the same flag. With OAuth disabled,
    callers must present a broker key to read this document.
    """
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

    url = await _get_oauth_handler().build_authorize_url(
        connector, identity.app_key, resolved, callback_url
    )
    return RedirectResponse(url)


def _capture_provider_metadata(
    connector: BaseConnector, query_params: dict[str, str]
) -> dict[str, str]:
    """Extract a connector's non-secret callback metadata, safely.

    OAuth params (code/state/error*) are stripped first so a connector hook never
    sees — let alone persists — the single-use authorization code. The hook is
    guarded so a faulty connector implementation cannot lose an already-exchanged
    token: on failure we log and return {} so the connection is still saved.
    """
    safe_params = {
        key: value for key, value in query_params.items() if key not in _OAUTH_CALLBACK_PARAMS
    }
    try:
        return connector.parse_callback_params(safe_params)
    except Exception:  # noqa: BLE001 -- a faulty hook must not lose an already-exchanged token
        logger.warning(
            "[Broker] parse_callback_params failed for %s; storing connection without metadata",
            connector.meta.name,
            exc_info=True,
        )
        return {}


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

    # Capture non-secret provider identifiers that arrive on the callback redirect
    # rather than in the token response (e.g. QuickBooks' realmId). OAuth params are
    # stripped and the hook is guarded — see _capture_provider_metadata.
    provider_metadata = _capture_provider_metadata(connector, dict(request.query_params))
    if provider_metadata:
        connection = connection.model_copy(update={"provider_metadata": provider_metadata})

    await store.save(returned_app_key, connector_name, connection)
    return returned_app_key


@app.get("/oauth/{connector_name}/callback")
async def oauth_callback(  # noqa: PLR0913 -- FastAPI binds each callback query param positionally; the OAuth 2 success and error redirects together carry all six
    connector_name: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """OAuth callback — exchange code, store token, show success page.

    No auth needed — callback is from OAuth provider. Signed state protects it.

    Providers signal user denial / errors with ``?error=...&state=...`` and no
    ``code`` (RFC 6749 §4.1.2.1). These params are optional so FastAPI does not
    422 on that legitimate shape; we detect it below and return the same
    400 "Connection failed" page the exchange-failure path uses.
    """
    connector = _get_connector_or_404(connector_name)
    _reject_sidecar_managed(connector)

    # Provider-reported error, or a malformed callback missing code/state.
    # error_description is provider-supplied free text — log it for diagnostics
    # but it carries no secret (the authorization code never reaches this branch).
    if error or not code or not state:
        logger.warning(
            "[Broker] OAuth callback rejected for %s: error=%s description=%s",
            connector_name,
            error,
            error_description,
        )
        return HTMLResponse(
            "<h1>Connection failed</h1><p>Authentication failed. Please try again.</p>",
            status_code=400,
        )

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
    except Exception:  # noqa: BLE001 -- callback returns a 500 page for any unexpected exchange failure rather than surfacing a traceback to the browser
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
    except Exception:  # noqa: BLE001 -- the refresh loop must not die on one connection; mark it failed and continue with the rest
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

    expiring = await store.list_expiring(buffer_seconds=TOKEN_REFRESH_BUFFER_SECONDS)
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


# --- Background maintenance loop ---


async def _maintenance_loop(base_url: str, interval_seconds: int) -> None:
    """Background maintenance loop. Runs as an asyncio task.

    Three flag-gated steps run on the same cadence:
      • outbound token refresh when ``broker.token_refresh_enabled=true``
      • inbound OAuth state cleanup whenever the inbound auth store exists
        (i.e. whenever ``broker.oauth.enabled=true``)
      • inbound DCR rate-limiter cleanup, paired with the inbound store

    Each step can be disabled independently.
    """
    logger.info("[Maintenance] Started (interval=%ds)", interval_seconds)
    while True:
        try:
            if _get_settings().broker.token_refresh_enabled:
                refresh_summary = await _refresh_expiring_tokens(base_url)
                if refresh_summary["refreshed"] or refresh_summary["failed"]:
                    logger.info("[Maintenance] refresh %s", refresh_summary)
            if _inbound_auth_store is not None:
                await _inbound_auth_store.cleanup_expired()
            if _oauth_endpoints is not None:
                await _oauth_endpoints.cleanup_rate_limiter()
        except Exception:  # noqa: BLE001 -- background loop swallows all to keep ticking
            logger.exception("[Maintenance] Unexpected error in loop")
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
