"""
Notion MCP Connector

Auto-registers on import via BaseConnector.__init_subclass__.
Uses MCP OAuth discovery (mcp_oauth_url) — no manual integration setup needed.
"""

from base64 import b64encode

from broker.connectors.base import BaseConnector
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta

NOTION_API_VERSION = "2022-06-28"


class NotionConnector(BaseConnector):
    """Notion MCP connector.

    Uses MCP OAuth discovery (RFC 8414 + RFC 7591):
    - Endpoints discovered via .well-known at mcp.notion.com
    - Client registered dynamically via /register
    - No manual Notion integration setup required

    Overrides:
    - Token exchange uses HTTP Basic Auth (client_secret_basic)
    - Notion-Version header required for MCP proxy requests
    - Token response parsing extracts standard OAuth2 fields from extended response
    """

    meta = ConnectorMeta(
        name="notion",
        display_name="Notion",
        mcp_url="https://mcp.notion.com/mcp",
        mcp_transport="streamable_http",
        # Static URLs kept for documentation — ignored when mcp_oauth_url is set
        oauth_authorize_url="https://mcp.notion.com/authorize",
        oauth_token_url="https://mcp.notion.com/token",  # noqa: S106 — endpoint URL, not a password
        scopes=[],
        # Discovery — triggers MCP OAuth flow (RFC 8414 + RFC 7591)
        mcp_oauth_url="https://mcp.notion.com",
    )

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """Notion MCP uses HTTP Basic Auth for token exchange (client_secret_basic)."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    def build_auth_header(self, access_token: str) -> dict[str, str]:
        """Notion MCP requires Notion-Version alongside the Bearer token."""
        return {
            "Authorization": f"Bearer {access_token}",
            "Notion-Version": NOTION_API_VERSION,
        }

    def parse_token_response(self, raw_response: dict) -> dict:
        """Extract standard OAuth2 fields from Notion's response.

        Notion may return extra fields (workspace_id, bot_id, owner) —
        extract only what the broker needs for token management.

        Raises:
            ValueError: If access_token is missing from the response.
        """
        if "access_token" not in raw_response:
            raise ValueError("Notion token response missing access_token")
        parsed: dict = {
            "access_token": raw_response["access_token"],
            "token_type": raw_response.get("token_type", "bearer"),
        }
        if "refresh_token" in raw_response:
            parsed["refresh_token"] = raw_response["refresh_token"]
        if "expires_in" in raw_response:
            parsed["expires_in"] = raw_response["expires_in"]
        return parsed
