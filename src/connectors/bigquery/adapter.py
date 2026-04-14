"""
BigQuery MCP Connector (via MCP Toolbox for Databases)

Proxies to a self-hosted Toolbox sidecar running with useClientOAuth=true.
The broker manages Google OAuth per-app and injects Bearer tokens.
Auto-registers on import via BaseConnector.__init_subclass__.
"""

import os

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta

_MCP_URL = os.environ.get("BIGQUERY_TOOLBOX_URL", "http://bigquery-toolbox:5000/mcp")


class BigQueryConnector(BaseConnector):
    """BigQuery via MCP Toolbox for Databases sidecar.

    auth_mode='broker': broker handles Google OAuth per-app.
    Toolbox runs with useClientOAuth=true and forwards the
    injected Authorization: Bearer token to BigQuery.
    """

    meta = ConnectorMeta(
        name="bigquery",
        display_name="BigQuery",
        mcp_url=_MCP_URL,
        mcp_transport="streamable_http",
        auth_mode="broker",
        oauth_authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        oauth_token_url="https://oauth2.googleapis.com/token",  # noqa: S106 — endpoint URL, not a password
        scopes=["https://www.googleapis.com/auth/bigquery.readonly"],
    )

    def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
        """Add Google-specific OAuth params.

        access_type=offline: requests a refresh_token (Google-specific).
        prompt=consent: forces re-consent to ensure a fresh refresh_token.
        """
        params["access_type"] = "offline"
        params["prompt"] = "consent"
        return params
