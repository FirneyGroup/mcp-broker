"""
Google Workspace MCP Connector (Broker-Managed Auth)

Proxies to a community workspace-mcp Docker sidecar running with
EXTERNAL_OAUTH21_PROVIDER=true. The broker manages Google OAuth per-app
and injects Bearer tokens on each proxied request.

Auto-registers on import via BaseConnector.__init_subclass__.
"""

import os

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta

_MCP_URL = os.environ.get("WORKSPACE_MCP_URL", "http://workspace-mcp:8000/mcp")

# Google Workspace scopes — write access is intentional.
# The workspace-mcp sidecar exposes write tools (send_gmail_message,
# create_calendar_event, update_spreadsheet, etc.) alongside read tools.
# A compromised token grants read+write to Gmail, Drive, Calendar, Docs, Sheets.
# For read-only deployments, replace with .readonly variants.
_GOOGLE_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/spreadsheets",
]


class WorkspaceMcpConnector(BaseConnector):
    """Google Workspace via community workspace-mcp sidecar.

    auth_mode='broker': broker handles Google OAuth per-app.
    Sidecar runs with EXTERNAL_OAUTH21_PROVIDER=true and trusts
    the injected Authorization: Bearer token.
    """

    meta = ConnectorMeta(
        name="workspace_mcp",
        display_name="Google Workspace",
        mcp_url=_MCP_URL,
        auth_mode="broker",
        oauth_authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        oauth_token_url="https://oauth2.googleapis.com/token",  # noqa: S106 — endpoint URL, not a password
        scopes=_GOOGLE_SCOPES,
    )

    def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
        """Add Google-specific OAuth params.

        access_type=offline: requests a refresh_token (Google-specific).
        prompt=consent: forces re-consent to ensure a fresh refresh_token
        even if the user previously authorized this app.
        """
        params["access_type"] = "offline"
        params["prompt"] = "consent"
        return params
