"""
Sidecar connector template.

Copy this directory to `src/connectors/{name}/`, rename the class, and replace
every `FILL_ME_IN` value. Also copy `sidecars/_template/` to `sidecars/{name}/`
and follow its README for the docker-compose side.

Flavour: Sidecar — MCP server runs as a Docker container on the `firney-net`
network, broker proxies to it by service name. Two auth modes:
  - "broker" (this template): broker manages OAuth, injects Bearer tokens.
    Sidecar must run with EXTERNAL_OAUTH21_PROVIDER=true and trust the header.
  - "sidecar": sidecar manages its own credentials; broker proxies without
    touching auth. Flip auth_mode below and remove the OAuth URLs.

Reference example: src/connectors/workspace_mcp/adapter.py
"""

from __future__ import annotations

import os

from broker.connectors.base import BaseConnector
from broker.models.connector_config import ConnectorMeta

# TODO: rename env var to match your sidecar's service name.
_MCP_URL = os.environ.get("FILL_ME_IN_MCP_URL", "http://FILL_ME_IN:8000/mcp")


class TemplateSidecarConnector(BaseConnector):
    """TODO: rename to {Name}Connector. Describe the upstream service in one sentence."""

    meta = ConnectorMeta(
        name="FILL_ME_IN",
        display_name="FILL_ME_IN",
        # Docker service name on firney-net. The broker reaches the sidecar via
        # Docker DNS — never via localhost or a public URL.
        mcp_url=_MCP_URL,
        # "broker" = broker injects Bearer tokens; sidecar trusts them.
        # "sidecar" = sidecar manages its own OAuth; broker proxies without
        # touching auth. Pick deliberately — a wrong choice is silent.
        auth_mode="broker",
        # Required when auth_mode="broker". Remove both if auth_mode="sidecar".
        oauth_authorize_url="FILL_ME_IN",
        oauth_token_url="FILL_ME_IN",  # noqa: S106 -- endpoint URL, not a password
        scopes=[],
    )
