"""Tests for /.well-known/oauth-* discovery handlers (RFC 8414 + RFC 9728)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import HTTPException

from broker.api.wellknown import (
    build_authorization_server_metadata,
    build_protected_resource_metadata,
    handle_authorization_server_metadata,
    handle_protected_resource_metadata,
)

PUBLIC_URL = "https://broker.example.com/"
CONNECTORS = ["notion", "hubspot", "workspace_mcp"]


# =============================================================================
# AS METADATA
# =============================================================================


class TestAuthorizationServerMetadata:
    @pytest.fixture(scope="class")
    def payload(self) -> dict[str, Any]:
        return build_authorization_server_metadata(PUBLIC_URL, CONNECTORS)

    def test_issuer_strips_trailing_slash(self, payload: dict[str, Any]) -> None:
        assert payload["issuer"] == "https://broker.example.com"

    def test_endpoints_use_issuer(self, payload: dict[str, Any]) -> None:
        issuer = payload["issuer"]
        assert payload["authorization_endpoint"] == f"{issuer}/oauth/authorize"
        assert payload["token_endpoint"] == f"{issuer}/oauth/token"
        assert payload["registration_endpoint"] == f"{issuer}/oauth/register"
        assert payload["revocation_endpoint"] == f"{issuer}/oauth/revoke"

    def test_pkce_s256_only(self, payload: dict[str, Any]) -> None:
        assert payload["code_challenge_methods_supported"] == ["S256"]

    def test_response_and_grant_types(self, payload: dict[str, Any]) -> None:
        assert payload["response_types_supported"] == ["code"]
        assert payload["grant_types_supported"] == ["authorization_code", "refresh_token"]

    def test_token_endpoint_auth_methods(self, payload: dict[str, Any]) -> None:
        assert payload["token_endpoint_auth_methods_supported"] == [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ]

    def test_scopes_include_one_per_connector_plus_status(self, payload: dict[str, Any]) -> None:
        assert payload["scopes_supported"] == [
            "mcp:status",
            "mcp:proxy:notion",
            "mcp:proxy:hubspot",
            "mcp:proxy:workspace_mcp",
        ]

    def test_scopes_with_empty_connector_list(self) -> None:
        empty_payload = build_authorization_server_metadata(PUBLIC_URL, [])
        assert empty_payload["scopes_supported"] == ["mcp:status"]

    def test_handler_sets_cache_control(self) -> None:
        response = handle_authorization_server_metadata(PUBLIC_URL, CONNECTORS)
        assert response.headers["cache-control"] == "public, max-age=3600"
        body = json.loads(response.body.decode())
        assert body["issuer"] == "https://broker.example.com"


# =============================================================================
# PROTECTED RESOURCE METADATA
# =============================================================================


class TestProtectedResourceMetadata:
    def test_builder_echoes_resource_path(self) -> None:
        payload = build_protected_resource_metadata(PUBLIC_URL, "proxy/notion/mcp", "notion")
        assert payload["resource"] == "https://broker.example.com/proxy/notion/mcp"

    def test_builder_scopes(self) -> None:
        payload = build_protected_resource_metadata(PUBLIC_URL, "proxy/notion", "notion")
        assert payload["scopes_supported"] == ["mcp:proxy:notion", "mcp:status"]
        assert payload["bearer_methods_supported"] == ["header"]
        assert payload["authorization_servers"] == ["https://broker.example.com"]

    def test_known_connector_short_path(self) -> None:
        response = handle_protected_resource_metadata(PUBLIC_URL, "proxy/notion", CONNECTORS)
        assert response.status_code == 200
        body = json.loads(response.body.decode())
        assert body["resource"] == "https://broker.example.com/proxy/notion"
        assert response.headers["cache-control"] == "public, max-age=3600"

    def test_known_connector_deep_path_echoes(self) -> None:
        response = handle_protected_resource_metadata(PUBLIC_URL, "proxy/notion/mcp", CONNECTORS)
        body = json.loads(response.body.decode())
        assert body["resource"] == "https://broker.example.com/proxy/notion/mcp"

    @pytest.mark.parametrize(
        "path,connectors,expected_detail",
        [
            ("proxy/unknown_connector", CONNECTORS, "unknown_connector"),
            ("admin/whatever", CONNECTORS, "not_found"),
            # ids[traversal_attempt]: FastAPI normalizes paths so traversal is unreachable,
            # but the unknown-connector guard catches the synthetic form too.
            ("proxy/../etc/passwd", CONNECTORS, "unknown_connector"),
            ("proxy/notion", [], "unknown_connector"),
        ],
        ids=["unknown_connector", "non_proxy_path", "traversal_attempt", "empty_connectors"],
    )
    def test_protected_resource_metadata_returns_404(
        self, path: str, connectors: list, expected_detail: str
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            handle_protected_resource_metadata(PUBLIC_URL, path, connectors)
        assert exc.value.status_code == 404
        assert exc.value.detail == expected_detail
