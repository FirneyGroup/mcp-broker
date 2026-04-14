"""
HubSpot MCP Connector

Auto-registers on import via BaseConnector.__init_subclass__.
Uses HubSpot MCP Auth App OAuth endpoints (not the legacy HubSpot API OAuth).
Scopes are auto-determined by the MCP server — empty list lets HubSpot decide.
"""

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta


class HubSpotConnector(BaseConnector):
    """HubSpot MCP connector via MCP Auth App.

    Uses MCP-specific OAuth endpoints at mcp.hubspot.com.
    Token auth: client_secret_post (default BaseConnector behavior).
    PKCE S256 handled by broker's OAuthHandler.
    """

    meta = ConnectorMeta(
        name="hubspot",
        display_name="HubSpot",
        mcp_url="https://mcp.hubspot.com",
        mcp_transport="sse",
        oauth_authorize_url="https://mcp.hubspot.com/oauth/authorize",
        oauth_token_url="https://mcp.hubspot.com/oauth/v3/token",  # noqa: S106 — endpoint URL, not a password
        scopes=[],
    )

    # Standard OAuth2 with client_secret_post — no hook overrides needed
