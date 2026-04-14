"""
Example connector adapter for a sidecar MCP server.

Copy this file to src/connectors/{your_name}/adapter.py and edit to match
the service you're integrating. See README.md in this directory for the
full setup walkthrough.

Choose one of the two auth modes below based on who handles authentication:

  auth_mode="broker" — the broker runs the OAuth flow, obtains a token, and
                       injects it as Authorization: Bearer into each proxied
                       request. The sidecar trusts the Bearer token.
                       Use when the upstream service uses OAuth 2.1 and the
                       sidecar is configured to accept external tokens
                       (e.g. workspace-mcp's EXTERNAL_OAUTH21_PROVIDER=true).

  auth_mode="sidecar" — the sidecar manages its own credentials (API key,
                        service account, etc.). The broker proxies without
                        injecting a token.
                        Use when the sidecar reads its own credentials from
                        its environment or config directory.

Delete the mode you are not using before committing.
"""

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta


# --- Option A: broker-managed OAuth ---
class MyServiceConnectorBrokerAuth(BaseConnector):
    """Broker handles OAuth; sidecar receives Bearer tokens."""

    meta = ConnectorMeta(
        name="my_service",
        display_name="My Service",
        mcp_url="http://my-sidecar:8000/mcp",  # Container name from your sidecar's docker-compose
        auth_mode="broker",
        oauth_authorize_url="https://auth.myservice.com/oauth/authorize",
        oauth_token_url="https://auth.myservice.com/oauth/token",  # noqa: S106 — endpoint URL
        scopes=["read", "write"],
    )


# --- Option B: sidecar-managed credentials ---
class MyServiceConnectorSidecarAuth(BaseConnector):
    """Sidecar manages its own credentials; broker is a transparent proxy."""

    meta = ConnectorMeta(
        name="my_service",
        display_name="My Service",
        mcp_url="http://my-sidecar:8000/mcp",
        auth_mode="sidecar",
    )
