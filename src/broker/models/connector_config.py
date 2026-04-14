"""
Connector configuration models.

ConnectorMeta: Static metadata for a connector (frozen, defined once per connector class).
AppConnectorCredentials: Per-app OAuth credentials from settings.yaml apps section.
DynamicRegistration: Persisted result of RFC 7591 dynamic client registration.
ResolvedOAuth: Unified output of resolve_oauth() — used by routes and proxy.
"""

import re
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

# =============================================================================
# HELPERS
# =============================================================================


_DOCKER_SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$")


def _is_internal_url(url: str) -> bool:
    """Return True for Docker service names and localhost (dev)."""
    hostname = urlparse(url).hostname or ""
    if hostname == "localhost":
        return True
    return bool(_DOCKER_SERVICE_NAME_PATTERN.match(hostname))


# =============================================================================
# CONNECTOR METADATA
# =============================================================================


class ConnectorMeta(BaseModel):
    """Static metadata for a connector — defined once per connector class.

    Frozen Pydantic model — set as class variable on BaseConnector subclasses.
    """

    name: str = Field(..., description="Identifier (e.g. 'notion')")
    display_name: str = Field(..., description="Human-readable name (e.g. 'Notion')")
    mcp_url: str | None = Field(
        default=None,
        description=(
            "Remote MCP server base URL (None for native connectors). Includes the full path "
            "prefix for the MCP endpoint (e.g. 'https://mcp.notion.com/mcp'). The proxy appends "
            "the route's {path} segment after this — connectors with a path in mcp_url should be "
            "called with an empty path."
        ),
    )
    mcp_transport: str = "streamable_http"
    auth_mode: Literal["broker", "sidecar"] = Field(
        default="broker",
        description=(
            "'broker' = broker manages OAuth (default). "
            "'sidecar' = sidecar manages its own credentials, broker proxies without token injection."
        ),
    )
    oauth_authorize_url: str | None = Field(
        default=None, description="OAuth authorization endpoint (required when auth_mode='broker')"
    )
    oauth_token_url: str | None = Field(
        default=None,
        description="OAuth token exchange endpoint (required when auth_mode='broker')",
    )
    scopes: list[str] = Field(default_factory=list, description="OAuth scopes to request")
    supports_pkce: bool = Field(
        default=True,
        description="Whether the OAuth provider supports PKCE (S256). Default True per OAuth 2.1 spec.",
    )

    # MCP OAuth Discovery (RFC 8414 + RFC 7591)
    # Presence means "use discovery + dynamic registration instead of static credentials"
    mcp_oauth_url: str | None = Field(
        default=None,
        description="MCP OAuth server base URL for discovery (e.g. 'https://mcp.notion.com')",
    )

    # JSON-RPC method allowlist — broker rejects any method not in this set.
    # Default covers standard MCP tool usage. Connectors can override.
    allowed_mcp_methods: frozenset[str] = Field(
        default=frozenset(
            {
                "initialize",
                "notifications/initialized",
                "notifications/cancelled",
                "tools/list",
                "tools/call",
                "ping",
            }
        ),
        description="JSON-RPC methods the broker will forward. Others are rejected.",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _validate_url_schemes(self) -> "ConnectorMeta":
        """Enforce HTTPS on OAuth endpoint URLs and external MCP URLs.

        When auth_mode='broker', both OAuth URLs are required.
        When auth_mode='sidecar', OAuth URLs are ignored (sidecar manages credentials).
        """
        if self.auth_mode == "broker":
            for field_name in ("oauth_authorize_url", "oauth_token_url"):
                url = getattr(self, field_name)
                if not url:
                    raise ValueError(f"{field_name} is required when auth_mode='broker'")
                if not url.startswith("https://"):
                    raise ValueError(f"{field_name} must use HTTPS: {url}")

        # Sidecar connectors don't inject tokens — no HTTPS requirement on mcp_url.
        # Broker connectors require HTTPS unless the URL is a Docker-internal hostname.
        if (
            self.auth_mode == "broker"
            and self.mcp_url
            and not self.mcp_url.startswith("https://")
            and not _is_internal_url(self.mcp_url)
        ):
            raise ValueError(f"mcp_url must use HTTPS for external URLs: {self.mcp_url}")

        return self

    @property
    def is_native(self) -> bool:
        """Whether this connector implements tools in-process (no remote MCP server)."""
        return self.mcp_url is None

    @property
    def is_sidecar_managed(self) -> bool:
        """Whether the sidecar manages its own auth (broker proxies without token injection)."""
        return self.auth_mode == "sidecar"

    @property
    def uses_discovery(self) -> bool:
        """Whether this connector uses MCP OAuth discovery."""
        return self.mcp_oauth_url is not None


# =============================================================================
# CREDENTIALS
# =============================================================================


class AppConnectorCredentials(BaseModel):
    """Per-app OAuth credentials from settings.yaml apps section.

    Looked up by app_key + connector_name at request time.
    """

    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)

    model_config = ConfigDict(frozen=True, extra="forbid")


# =============================================================================
# DYNAMIC REGISTRATION (RFC 7591)
# =============================================================================


class DynamicRegistration(BaseModel):
    """Persisted result of RFC 7591 dynamic client registration.

    One registration per connector (shared across all apps).
    The broker is a single OAuth client — tokens remain per-app.
    """

    connector_name: str
    client_id: str
    client_secret: str
    redirect_uri: str
    token_endpoint_auth_method: str = "client_secret_basic"  # noqa: S105 — OAuth enum, not a password
    client_secret_expires_at: int | None = Field(
        default=None, ge=0, description="Unix timestamp when client_secret expires (0 = never)"
    )
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = ConfigDict(frozen=True, extra="forbid")


# =============================================================================
# RESOLVED OAUTH (unified output)
# =============================================================================


class ResolvedOAuth(BaseModel):
    """Unified output of both static and discovery OAuth paths.

    Routes and proxy consume this — they don't care which path produced it.
    """

    authorize_url: str
    token_url: str
    credentials: AppConnectorCredentials

    model_config = ConfigDict(frozen=True, extra="forbid")
