"""OAuth 2.1 well-known discovery endpoints (RFC 8414 + RFC 9728)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# === CONSTANTS ===

# Cache discovery docs for an hour — claude.ai probes on every connection
# and the connector list rarely changes between deploys.
_DISCOVERY_CACHE_HEADER = {"Cache-Control": "public, max-age=3600"}


# === BUILDERS (pure functions, easy to unit-test) ===


def build_authorization_server_metadata(
    public_url: str,
    connector_names: list[str],
) -> dict[str, Any]:
    """RFC 8414 AS metadata. scopes_supported reflects the registered connectors."""
    issuer = public_url.rstrip("/")
    scopes = ["mcp:status"] + [f"mcp:proxy:{name}" for name in connector_names]
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "registration_endpoint": f"{issuer}/oauth/register",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "scopes_supported": scopes,
    }


def build_protected_resource_metadata(
    public_url: str,
    resource_path: str,
    connector_name: str,
) -> dict[str, Any]:
    """RFC 9728 PRM. `resource_path` is the path under public_url that the client pasted."""
    issuer = public_url.rstrip("/")
    return {
        "resource": f"{issuer}/{resource_path.rstrip('/')}",
        "authorization_servers": [issuer],
        "scopes_supported": [f"mcp:proxy:{connector_name}", "mcp:status"],
        "bearer_methods_supported": ["header"],
    }


# === HANDLERS (T04 wires these to FastAPI routes in main.py) ===


def handle_authorization_server_metadata(
    public_url: str,
    connector_names: list[str],
) -> JSONResponse:
    """Return AS metadata with a 1-hour cache header."""
    payload = build_authorization_server_metadata(public_url, connector_names)
    return JSONResponse(payload, headers=dict(_DISCOVERY_CACHE_HEADER))


def handle_protected_resource_metadata(
    public_url: str,
    path: str,
    connector_names: list[str],
) -> JSONResponse:
    """Return PRM for `path` (catch-all suffix after /.well-known/oauth-protected-resource/).

    Only `proxy/{connector}[/...]` shapes are valid. Unknown connectors → 404 so
    discovery probes for nonsense paths don't leak the registered connector list.
    """
    if not path.startswith("proxy/"):
        raise HTTPException(status_code=404, detail="not_found")
    extracted_name = path.removeprefix("proxy/").split("/", 1)[0]
    if extracted_name not in connector_names:
        raise HTTPException(status_code=404, detail="unknown_connector")
    payload = build_protected_resource_metadata(public_url, path, extracted_name)
    return JSONResponse(payload, headers=dict(_DISCOVERY_CACHE_HEADER))
