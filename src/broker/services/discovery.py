"""
OAuth Discovery — RFC 8414 metadata discovery + RFC 7591 dynamic client registration.

OAuthDiscovery: HTTP operations (discover endpoints, register client).
resolve_oauth(): Composition function — branches on static vs discovery path.

Neither class imports from store.py or oauth.py — no boundary crossing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from broker.connectors.base import BaseConnector
from broker.models.connector_config import (
    AppConnectorCredentials,
    DynamicRegistration,
    ResolvedOAuth,
)

if TYPE_CHECKING:
    from broker.config import BrokerSettings
    from broker.services.store import TokenStore

logger = logging.getLogger(__name__)

_HTTP_OK = 200
_HTTP_CREATED = 201

# Lock per connector to prevent concurrent duplicate registrations
_registration_locks: dict[str, asyncio.Lock] = {}


def _validate_https_url(url: str, label: str) -> None:
    """Reject non-HTTPS URLs to prevent SSRF via discovery responses.

    Raises:
        ValueError: If scheme is not https or hostname is a private/loopback address.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"{label} must use HTTPS, got: {url}")
    hostname = (parsed.hostname or "").lower()
    if _is_private_host(hostname):
        raise ValueError(f"{label} points to a private address: {url}")


def _is_private_host(hostname: str) -> bool:
    """Check if hostname resolves to a private, loopback, or link-local address."""
    import ipaddress

    _BLOCKED_NAMES = {"localhost"}  # noqa: N806
    if hostname in _BLOCKED_NAMES or hostname.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return False  # Not an IP literal — allow DNS hostnames through


def _registration_lock(connector_name: str) -> asyncio.Lock:
    """Get or create a registration lock for a connector."""
    return _registration_locks.setdefault(connector_name, asyncio.Lock())


def _registration_expired(registration: DynamicRegistration) -> bool:
    """Check if a dynamic registration's client_secret has expired.

    Returns False if client_secret_expires_at is None or 0 (never expires).
    """
    if not registration.client_secret_expires_at:
        return False
    return registration.client_secret_expires_at <= int(time.time())


# =============================================================================
# OAUTH DISCOVERY
# =============================================================================


def _extract_server_metadata(server_metadata: dict, connector_name: str) -> dict[str, str]:
    """Extract and validate required endpoint URLs from authorization server metadata.

    Raises:
        ValueError: If required fields are missing.
    """
    for required_field in ("authorization_endpoint", "token_endpoint"):
        if required_field not in server_metadata:
            raise ValueError(
                f"Missing {required_field} in authorization server metadata for {connector_name}"
            )
        _validate_https_url(
            server_metadata[required_field], f"{required_field} for {connector_name}"
        )

    registration_endpoint = server_metadata.get("registration_endpoint", "")
    if not registration_endpoint:
        raise ValueError(
            f"No registration_endpoint in authorization server metadata for {connector_name}"
        )
    _validate_https_url(registration_endpoint, f"registration_endpoint for {connector_name}")

    return {
        "authorization_endpoint": server_metadata["authorization_endpoint"],
        "token_endpoint": server_metadata["token_endpoint"],
        "registration_endpoint": registration_endpoint,
    }


def _parse_registration(
    registration_response: dict, connector_name: str, redirect_uri: str
) -> DynamicRegistration:
    """Validate and parse a dynamic registration response into a DynamicRegistration."""
    for required_field in ("client_id", "client_secret"):
        if required_field not in registration_response:
            raise ValueError(f"Registration response missing {required_field} for {connector_name}")

    registration = DynamicRegistration(
        connector_name=connector_name,
        client_id=registration_response["client_id"],
        client_secret=registration_response["client_secret"],
        redirect_uri=redirect_uri,
        token_endpoint_auth_method=registration_response.get(
            "token_endpoint_auth_method", "client_secret_basic"
        ),
        client_secret_expires_at=registration_response.get("client_secret_expires_at"),
        registered_at=datetime.now(UTC),
    )

    logger.info(
        "[Discovery] Registered client for %s: client_id=%s, expires_at=%s",
        connector_name,
        registration.client_id,
        registration.client_secret_expires_at,
    )
    return registration


class OAuthDiscovery:
    """RFC 8414 metadata discovery + RFC 7591 dynamic client registration.

    discover_metadata() fetches and caches endpoint URLs from .well-known.
    register_client() performs dynamic client registration at the register endpoint.
    """

    def __init__(self) -> None:
        self._metadata_cache: dict[str, dict[str, str]] = {}

    async def discover_metadata(self, connector_name: str, mcp_oauth_url: str) -> dict[str, str]:
        """Discover OAuth endpoints via RFC 8414 .well-known documents.

        Two-step discovery:
        1. GET {mcp_oauth_url}/.well-known/oauth-protected-resource → authorization_servers[0]
        2. GET {auth_server}/.well-known/oauth-authorization-server → endpoint URLs

        Returns dict with keys: authorization_endpoint, token_endpoint, registration_endpoint.
        Caches result in memory per connector.
        """
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            auth_server = await self._discover_auth_server(client, connector_name, mcp_oauth_url)
            server_metadata = await self._fetch_server_metadata(client, connector_name, auth_server)

        metadata = _extract_server_metadata(server_metadata, connector_name)
        self._metadata_cache[connector_name] = metadata
        logger.info(
            "[Discovery] Cached metadata for %s: authorize=%s, token=%s",
            connector_name,
            metadata["authorization_endpoint"],
            metadata["token_endpoint"],
        )
        return metadata

    async def _discover_auth_server(
        self, client: httpx.AsyncClient, connector_name: str, mcp_oauth_url: str
    ) -> str:
        """Step 1: Fetch protected resource metadata to find the authorization server."""
        resource_url = f"{mcp_oauth_url.rstrip('/')}/.well-known/oauth-protected-resource"
        logger.info("[Discovery] Fetching protected resource metadata: %s", resource_url)
        resource_response = await client.get(resource_url)

        if resource_response.status_code != _HTTP_OK:
            logger.error(
                "[Discovery] Protected resource discovery failed for %s: %s %s",
                connector_name,
                resource_response.status_code,
                resource_response.text[:500].replace("\r", "\\r").replace("\n", "\\n"),
            )
            raise ValueError(
                f"OAuth protected resource discovery failed for {connector_name}: "
                f"HTTP {resource_response.status_code}"
            )

        resource_metadata = resource_response.json()
        auth_servers = resource_metadata.get("authorization_servers", [])
        if not auth_servers:
            raise ValueError(
                f"No authorization_servers in protected resource metadata for {connector_name}"
            )

        auth_server = auth_servers[0].rstrip("/")
        _validate_https_url(auth_server, f"authorization_server for {connector_name}")
        logger.info("[Discovery] Authorization server for %s: %s", connector_name, auth_server)
        return auth_server

    async def _fetch_server_metadata(
        self, client: httpx.AsyncClient, connector_name: str, auth_server: str
    ) -> dict:
        """Step 2: Fetch authorization server metadata from .well-known endpoint."""
        wellknown_url = f"{auth_server}/.well-known/oauth-authorization-server"
        logger.info("[Discovery] Fetching authorization server metadata: %s", wellknown_url)
        server_response = await client.get(wellknown_url)

        if server_response.status_code != _HTTP_OK:
            logger.error(
                "[Discovery] Auth server metadata failed for %s: %s %s",
                connector_name,
                server_response.status_code,
                server_response.text[:500].replace("\r", "\\r").replace("\n", "\\n"),
            )
            raise ValueError(
                f"OAuth authorization server discovery failed for {connector_name}: "
                f"HTTP {server_response.status_code}"
            )

        return server_response.json()

    def get_cached_metadata(self, connector_name: str) -> dict[str, str] | None:
        """Return cached discovery metadata, or None if not yet discovered."""
        return self._metadata_cache.get(connector_name)

    async def register_client(
        self,
        register_endpoint: str,
        connector_name: str,
        redirect_uri: str,
    ) -> DynamicRegistration:
        """Register as an OAuth client via RFC 7591 dynamic client registration.

        POSTs to the registration endpoint with client metadata.
        Returns a DynamicRegistration with the assigned credentials.
        """
        registration_body = {
            "client_name": f"MCP Broker ({connector_name})",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }

        logger.info(
            "[Discovery] Registering client at %s for %s", register_endpoint, connector_name
        )

        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            response = await client.post(
                register_endpoint,
                json=registration_body,
                headers={"Content-Type": "application/json"},
            )

        if response.status_code not in {_HTTP_OK, _HTTP_CREATED}:
            logger.error(
                "[Discovery] Dynamic registration failed for %s: %s %s",
                connector_name,
                response.status_code,
                response.text[:500].replace("\r", "\\r").replace("\n", "\\n"),
            )
            raise ValueError(
                f"Dynamic registration failed for {connector_name}: HTTP {response.status_code}"
            )

        return _parse_registration(response.json(), connector_name, redirect_uri)


# =============================================================================
# RESOLVE OAUTH (composition function)
# =============================================================================


async def _ensure_registration(  # noqa: PLR0913 — registration needs all context + deps
    connector_name: str,
    callback_url: str,
    metadata: dict[str, str],
    store: TokenStore,
    discovery: OAuthDiscovery,
) -> DynamicRegistration:
    """Get or create a dynamic registration, using double-checked locking."""
    registration = await store.get_registration(connector_name)
    if registration and not _registration_expired(registration):
        return registration

    async with _registration_lock(connector_name):
        # Re-check after acquiring lock (another request may have registered)
        registration = await store.get_registration(connector_name)
        if registration and not _registration_expired(registration):
            return registration

        registration = await discovery.register_client(
            metadata["registration_endpoint"], connector_name, callback_url
        )
        await store.save_registration(connector_name, registration)
        return registration


async def resolve_oauth(  # noqa: PLR0913 — composition function needs all dependencies
    connector: BaseConnector,
    app_key: str,
    callback_url: str,
    settings: BrokerSettings,
    store: TokenStore,
    discovery: OAuthDiscovery | None,
) -> ResolvedOAuth:
    """Resolve OAuth credentials — static path or discovery path.

    Static connectors (HubSpot): credentials from settings.yaml.
    Discovery connectors (Notion MCP): credentials from dynamic registration.

    Both paths return the same ResolvedOAuth — callers don't care which ran.
    """
    if not connector.meta.uses_discovery:
        raw = settings.get_app_credentials(app_key, connector.meta.name)
        # Static connectors always have OAuth URLs (validated by ConnectorMeta)
        authorize_url = connector.meta.oauth_authorize_url
        token_url = connector.meta.oauth_token_url
        if not authorize_url or not token_url:
            raise ValueError(f"Static connector {connector.meta.name} missing OAuth URLs")
        return ResolvedOAuth(
            authorize_url=authorize_url,
            token_url=token_url,
            credentials=AppConnectorCredentials(**raw),
        )

    if discovery is None:
        raise RuntimeError(
            f"OAuthDiscovery not initialized for discovery connector: {connector.meta.name}"
        )

    metadata = discovery.get_cached_metadata(connector.meta.name)
    if metadata is None:
        raise RuntimeError(
            f"No cached metadata for {connector.meta.name} — discovery may have failed at startup"
        )

    registration = await _ensure_registration(
        connector.meta.name, callback_url, metadata, store, discovery
    )

    return ResolvedOAuth(
        authorize_url=metadata["authorization_endpoint"],
        token_url=metadata["token_endpoint"],
        credentials=AppConnectorCredentials(
            client_id=registration.client_id,
            client_secret=registration.client_secret,
        ),
    )
