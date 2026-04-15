"""
Discovery connector template.

Copy this directory to `src/connectors/{name}/`, rename the class, and replace
every `FILL_ME_IN` value. The template intentionally fails Pydantic validation
on import so it cannot be activated unedited.

Flavour: Discovery — remote MCP server supporting RFC 8414 + RFC 7591.
When to use: a `curl {base}/.well-known/oauth-authorization-server` returns
    200 with a `registration_endpoint` and dynamic registration works.
    Operators run `./start connect` (interactive) and the broker mints per-app
    credentials automatically — no client_id/secret in settings.
Reference example: src/connectors/notion/adapter.py
"""

from __future__ import annotations

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta


class TemplateDiscoveryConnector(BaseConnector):
    """TODO: rename to {Name}Connector. Describe the provider in one sentence."""

    meta = ConnectorMeta(
        # TODO: snake_case identifier used in settings.yaml and the proxy path.
        name="FILL_ME_IN",
        # TODO: human-readable display name.
        display_name="FILL_ME_IN",
        # TODO: full MCP endpoint URL.
        mcp_url="https://FILL_ME_IN/mcp",
        # TODO: "streamable_http" (default) or "sse".
        mcp_transport="streamable_http",
        # Ignored when mcp_oauth_url is set, but required by the model.
        # Kept as documentation of the underlying OAuth server.
        oauth_authorize_url="FILL_ME_IN",
        oauth_token_url="FILL_ME_IN",  # noqa: S106 -- endpoint URL, not a password
        scopes=[],
        # TODO: base URL the broker hits to discover OAuth endpoints.
        # Usually the MCP server's origin (no path). Must respond at
        # /.well-known/oauth-authorization-server.
        mcp_oauth_url="https://FILL_ME_IN",
    )

    # === HOOK OVERRIDES (uncomment if the provider deviates) ===
    #
    # Notion is the canonical example: HTTP Basic Auth for token exchange, plus
    # a Notion-Version header on every MCP request. See src/connectors/notion/adapter.py.
