"""
Notion (hosted MCP) Connector Unit Tests — `notion`.

Tests for: registration & meta (Discovery flavour — mcp_oauth_url set), the
OAuth hooks (Basic-auth token exchange, parse_token_response field handling),
and build_auth_header's delegation to the base class's header-injection guard.

Per AGENTS.md testing rules: the real adapter, real meta validation, and the
real base-class control-character check all run — nothing is mocked here.
"""

from __future__ import annotations

from base64 import b64decode

import pytest

from broker.connectors.registry import ConnectorRegistry

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear connector registry before and after each test."""
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture
def notion_connector():
    """Import the Notion adapter and re-register if the registry was cleared."""
    from connectors.notion.adapter import NotionConnector

    connector = ConnectorRegistry.get("notion")
    if connector is None:
        ConnectorRegistry.auto_register(NotionConnector)
        connector = ConnectorRegistry.get("notion")
    assert connector is not None
    return connector


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Verify the connector auto-registers with valid Discovery-flavour metadata."""

    def test_auto_registers_with_name_notion(self, notion_connector):
        assert notion_connector.meta.name == "notion"

    def test_display_name(self, notion_connector):
        assert notion_connector.meta.display_name == "Notion"

    def test_is_discovery_flavour(self, notion_connector):
        # mcp_oauth_url set => Discovery (RFC 8414 + RFC 7591), per the connector table.
        assert notion_connector.meta.mcp_oauth_url == "https://mcp.notion.com"
        assert notion_connector.meta.uses_discovery is True


# =============================================================================
# OAUTH — build_token_request_auth + parse_token_response
# =============================================================================


class TestTokenRequestAuth:
    """Notion uses HTTP Basic Auth (client_secret_basic) for token exchange."""

    def test_basic_auth_header_shape(self, notion_connector):
        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
        )
        headers, body_credentials = notion_connector.build_token_request_auth(credentials)

        assert headers["Authorization"].startswith("Basic ")
        # Basic auth carries the credentials in the header; the POST body stays empty.
        assert body_credentials == {}

    def test_basic_auth_encodes_credentials(self, notion_connector):
        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(client_id="my_id", client_secret="my_secret")
        headers, _ = notion_connector.build_token_request_auth(credentials)
        encoded_part = headers["Authorization"].removeprefix("Basic ")
        assert b64decode(encoded_part).decode() == "my_id:my_secret"


class TestParseTokenResponse:
    """parse_token_response keeps standard fields and the optional ones when present."""

    def test_raises_when_access_token_missing(self, notion_connector):
        with pytest.raises(ValueError, match="missing access_token"):
            notion_connector.parse_token_response({"token_type": "bearer"})

    def test_keeps_refresh_token_and_workspace_fields_discarded(self, notion_connector):
        parsed = notion_connector.parse_token_response(
            {
                "access_token": "tok",
                "refresh_token": "refresh123",
                "workspace_id": "ws_abc",
                "bot_id": "bot_xyz",
            }
        )
        assert parsed["access_token"] == "tok"
        assert parsed["refresh_token"] == "refresh123"
        # Non-standard workspace fields are extracted out, not forwarded to the store.
        assert "workspace_id" not in parsed
        assert "bot_id" not in parsed

    def test_keeps_expires_in_when_present(self, notion_connector):
        # The hosted mcp.notion.com AS issues expires_in — it must be passed through.
        parsed = notion_connector.parse_token_response({"access_token": "tok", "expires_in": 3600})
        assert parsed["expires_in"] == 3600

    def test_omits_expires_in_when_absent(self, notion_connector):
        parsed = notion_connector.parse_token_response({"access_token": "tok"})
        assert "expires_in" not in parsed


# =============================================================================
# BUILD_AUTH_HEADER — Notion-Version + base-class injection guard (finding 8)
# =============================================================================


class TestBuildAuthHeader:
    """build_auth_header must add Notion-Version AND keep the base injection guard."""

    def test_returns_bearer_and_version(self, notion_connector):
        from connectors.notion.adapter import NOTION_API_VERSION

        headers = notion_connector.build_auth_header("valid_token")
        assert headers["Authorization"] == "Bearer valid_token"
        assert headers["Notion-Version"] == NOTION_API_VERSION

    def test_rejects_control_chars_in_token(self, notion_connector):
        # Delegating to super() preserves the header-injection guard — a CRLF in the
        # token must raise rather than smuggle extra headers into the upstream request.
        with pytest.raises(ValueError, match="control characters"):
            notion_connector.build_auth_header("token\r\nX-Injected: evil")
