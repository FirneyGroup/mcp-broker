"""
Example connector adapter for a sidecar MCP server.

Copy this file to src/connectors/{your_name}/adapter.py, rename the class, and
choose one auth mode by uncommenting the block you want. See README.md in this
directory for the full setup walkthrough.

auth_mode="broker"  — broker runs the OAuth flow, obtains a token, and injects
                      it as Authorization: Bearer into each proxied request.
                      Sidecar trusts the Bearer token.
                      Use when upstream is OAuth 2.1 and the sidecar is
                      configured to accept external tokens
                      (e.g. workspace-mcp's EXTERNAL_OAUTH21_PROVIDER=true).

auth_mode="sidecar" — sidecar manages its own credentials (API key, service
                      account, etc.). Broker proxies without token injection.
                      Use when the sidecar reads its own credentials from
                      its environment or config directory.
"""

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta


class MyServiceConnector(BaseConnector):
    """Template connector — edit before use.

    Uncomment one of the auth_mode blocks below. Leaving both commented or
    uncommenting both will fail at import / startup.
    """

    meta = ConnectorMeta(
        name="my_service",
        display_name="My Service",
        mcp_url="http://my-sidecar:8000/mcp",  # Container name from your sidecar's docker-compose
        # --- Option A: broker-managed OAuth ---
        # auth_mode="broker",
        # oauth_authorize_url="https://auth.myservice.com/oauth/authorize",
        # oauth_token_url="https://auth.myservice.com/oauth/token",  # noqa: S106 — endpoint URL
        # scopes=["read", "write"],
        # --- Option B: sidecar-managed credentials ---
        # auth_mode="sidecar",
    )
