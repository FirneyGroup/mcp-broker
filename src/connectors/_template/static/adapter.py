"""
Static connector template.

Copy this directory to `src/connectors/{name}/`, rename the class, and replace
every `FILL_ME_IN` value. The template intentionally fails Pydantic validation
on import so it cannot be activated unedited — see settings.example.yaml
comment for activation steps.

Flavour: Static — remote MCP server with fixed OAuth endpoints.
When to use: provider publishes OAuth authorize/token URLs and issues you a
    client_id/client_secret up front. No RFC 8414 discovery.
Reference example: src/connectors/hubspot/adapter.py
"""

from __future__ import annotations

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta


class TemplateStaticConnector(BaseConnector):
    """TODO: rename to {Name}Connector. Describe the provider in one sentence."""

    meta = ConnectorMeta(
        # TODO: snake_case identifier used in settings.yaml and the proxy path.
        name="FILL_ME_IN",
        # TODO: human-readable display name shown in /status and admin UI.
        display_name="FILL_ME_IN",
        # TODO: full MCP endpoint URL from the provider's docs.
        mcp_url="https://FILL_ME_IN/mcp",
        # TODO: "streamable_http" for HTTP POST + SSE, "sse" for Server-Sent Events only.
        mcp_transport="streamable_http",
        # TODO: OAuth authorize endpoint from the provider's docs.
        oauth_authorize_url="FILL_ME_IN",
        # TODO: OAuth token endpoint from the provider's docs.
        oauth_token_url="FILL_ME_IN",  # noqa: S106 -- endpoint URL, not a password
        # TODO: minimum necessary scopes. Empty list means the provider decides.
        scopes=[],
    )

    # === HOOK OVERRIDES (uncomment only if the provider deviates from standard OAuth 2.1) ===
    #
    # def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
    #     """Add provider-specific params to the authorize URL (e.g. access_type)."""
    #     return params
    #
    # def build_auth_header(self, access_token: str) -> dict[str, str]:
    #     """Override to add sibling headers (e.g. API-Version)."""
    #     return {"Authorization": f"Bearer {access_token}"}
    #
    # def build_token_request_auth(self, credentials):
    #     """Override for providers requiring HTTP Basic Auth (client_secret_basic)."""
    #     return {}, {"client_id": credentials.client_id, "client_secret": credentials.client_secret}
