"""
Notion (REST) Connector Unit Tests — `notion_api`.

Tests for: registration & meta, OAuth hooks (Basic auth + parse_token_response),
the filter DSL, serialization helpers, ID validation, MCP dispatch, and a
representative slice of tools with outbound HTTP mocked.

Per AGENTS.md testing rules: real helpers run for real (filter builder, simplifiers,
validation, OAuth Basic, parse_token_response). Only outbound HTTP is mocked — we patch
the module's own `_request` / `_send` wrappers (mirroring reddit's `_reddit_get` patching)
and assert on observable behaviour, never on internal call counts.
"""

from __future__ import annotations

import json
from base64 import b64decode
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

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
    from connectors.notion_api.adapter import NotionApiConnector

    connector = ConnectorRegistry.get("notion_api")
    if connector is None:
        ConnectorRegistry.auto_register(NotionApiConnector)
        connector = ConnectorRegistry.get("notion_api")
    assert connector is not None
    return connector


def _mock_response(status_code: int, json_data: dict | None = None) -> MagicMock:
    """Build a mock httpx.Response for `_send` callers that branch on status_code.

    `is_error` is set explicitly because _check_status() branches on it — a bare
    MagicMock returns a truthy Mock for `.is_error` and would spuriously raise.
    """
    response = MagicMock()
    response.status_code = status_code
    response.is_error = status_code >= 400
    response.json.return_value = json_data or {}
    response.headers = {}
    return response


# The 19 tools this connector exposes (asserted exactly so a forgotten @native_tool fails).
_EXPECTED_TOOL_NAMES = {
    "query_data_source",
    "fetch",
    "get_block_children",
    "get_page_property",
    "search",
    "get_users",
    "create_pages",
    "update_page_properties",
    "archive_page",
    "append_blocks",
    "update_page_content",
    "create_database",
    "update_data_source",
    "create_view",
    "update_view",
    "move_pages",
    "create_comment",
    "get_comments",
    "upload_file",
}


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Verify the connector auto-registers with correct metadata (AGENTS.md: a, b)."""

    def test_auto_registers_with_name_notion_api(self, notion_connector):
        assert notion_connector.meta.name == "notion_api"

    def test_display_name(self, notion_connector):
        assert notion_connector.meta.display_name == "Notion (REST)"

    def test_has_nineteen_tools(self, notion_connector):
        assert len(notion_connector._tools) == 19

    def test_tool_names(self, notion_connector):
        assert set(notion_connector._tools.keys()) == _EXPECTED_TOOL_NAMES

    def test_authorize_url(self, notion_connector):
        assert (
            notion_connector.meta.oauth_authorize_url == "https://api.notion.com/v1/oauth/authorize"
        )

    def test_token_url(self, notion_connector):
        assert notion_connector.meta.oauth_token_url == "https://api.notion.com/v1/oauth/token"

    def test_scopes_empty(self, notion_connector):
        # Notion uses integration-level capabilities, not OAuth scopes.
        # ConnectorMeta.scopes is a tuple, so the empty value is ().
        assert notion_connector.meta.scopes == ()

    def test_does_not_support_pkce(self, notion_connector):
        assert notion_connector.meta.supports_pkce is False

    def test_is_native_connector(self, notion_connector):
        assert notion_connector.meta.mcp_url is None
        assert notion_connector.meta.is_native


# =============================================================================
# OAUTH — build_token_request_auth + parse_token_response
# =============================================================================


class TestOAuthAuth:
    """Notion uses HTTP Basic Auth for token exchange and omits expires_in."""

    def test_basic_auth_header_format(self, notion_connector):
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
        decoded = b64decode(encoded_part).decode()
        assert decoded == "my_id:my_secret"

    def test_authorize_params_inject_owner_user(self, notion_connector):
        # Notion requires owner=user on the authorize URL (oauth.py applies this hook); without it
        # the flow mints a bot-owned token instead of a user token. Guard against silent regression.
        params = notion_connector.customize_authorize_params({"client_id": "x", "state": "y"})
        assert params["owner"] == "user"
        assert params["client_id"] == "x"  # existing params are preserved


class TestParseTokenResponse:
    """parse_token_response normalizes Notion's non-standard token payload."""

    def test_missing_access_token_raises(self, notion_connector):
        with pytest.raises(ValueError, match="missing access_token"):
            notion_connector.parse_token_response({"token_type": "bearer"})

    def test_refresh_token_without_expires_in_injects_synthetic_ttl(self, notion_connector):
        from connectors.notion_api.adapter import SYNTHETIC_TOKEN_TTL_SECONDS

        parsed = notion_connector.parse_token_response(
            {"access_token": "tok", "refresh_token": "refresh_abc"}
        )
        assert parsed["expires_in"] == SYNTHETIC_TOKEN_TTL_SECONDS
        assert parsed["refresh_token"] == "refresh_abc"

    def test_null_expires_in_falls_back_to_synthetic_ttl(self, notion_connector):
        # Notion omits expires_in, but guard the explicit-null case: it must not leave the
        # token without an expiry (which would disable proactive refresh).
        from connectors.notion_api.adapter import SYNTHETIC_TOKEN_TTL_SECONDS

        parsed = notion_connector.parse_token_response(
            {"access_token": "tok", "refresh_token": "r", "expires_in": None}
        )
        assert parsed["expires_in"] == SYNTHETIC_TOKEN_TTL_SECONDS

    def test_explicit_expires_in_kept(self, notion_connector):
        parsed = notion_connector.parse_token_response(
            {"access_token": "tok", "refresh_token": "refresh_abc", "expires_in": 1234}
        )
        assert parsed["expires_in"] == 1234

    def test_expires_in_without_refresh_token_kept(self, notion_connector):
        parsed = notion_connector.parse_token_response({"access_token": "tok", "expires_in": 999})
        assert parsed["expires_in"] == 999
        assert "refresh_token" not in parsed

    def test_token_type_defaulted(self, notion_connector):
        parsed = notion_connector.parse_token_response({"access_token": "tok"})
        assert parsed["token_type"] == "bearer"


# =============================================================================
# FILTER DSL — _build_filter / _build_condition (real, with a stub schema)
# =============================================================================


_STUB_SCHEMA = {
    "Due": "date",
    "Status": "status",
    "Name": "title",
    "Priority": "select",
    "Score": "number",
}


class TestFilterDSL:
    """Exercise the real filter builder against a stub schema dict."""

    def test_date_on_or_before_today_resolves_to_iso(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [{"property": "Due", "op": "on_or_before", "value": "today"}], "all", _STUB_SCHEMA
        )
        resolved = datetime.now(UTC).date().isoformat()
        assert notion_filter == {"property": "Due", "date": {"on_or_before": resolved}}

    def test_status_does_not_equal(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [{"property": "Status", "op": "does_not_equal", "value": "Done"}], "all", _STUB_SCHEMA
        )
        assert notion_filter == {"property": "Status", "status": {"does_not_equal": "Done"}}

    def test_single_condition_returns_bare_object(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [{"property": "Name", "op": "contains", "value": "draft"}], "all", _STUB_SCHEMA
        )
        # A single condition is NOT wrapped in and/or.
        assert "and" not in notion_filter
        assert "or" not in notion_filter
        assert notion_filter["property"] == "Name"

    def test_compound_match_all_uses_and(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [
                {"property": "Due", "op": "on_or_before", "value": "today"},
                {"property": "Status", "op": "does_not_equal", "value": "Done"},
            ],
            "all",
            _STUB_SCHEMA,
        )
        assert "and" in notion_filter
        assert len(notion_filter["and"]) == 2

    def test_compound_match_any_uses_or(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [
                {"property": "Priority", "op": "equals", "value": "High"},
                {"property": "Status", "op": "equals", "value": "Blocked"},
            ],
            "any",
            _STUB_SCHEMA,
        )
        assert "or" in notion_filter
        assert len(notion_filter["or"]) == 2

    def test_empty_filters_returns_none(self):
        from connectors.notion_api.adapter import _build_filter

        assert _build_filter([], "all", _STUB_SCHEMA) is None

    def test_unknown_property_raises(self):
        from connectors.notion_api.adapter import _build_filter

        with pytest.raises(ValueError, match="Unknown property"):
            _build_filter(
                [{"property": "Nonexistent", "op": "equals", "value": "x"}], "all", _STUB_SCHEMA
            )

    def test_operator_invalid_for_type_raises(self):
        from connectors.notion_api.adapter import _build_filter

        # `contains` is a text/multi operator — not valid for a number property.
        with pytest.raises(ValueError, match="not valid for"):
            _build_filter(
                [{"property": "Score", "op": "contains", "value": 5}], "all", _STUB_SCHEMA
            )

    def test_is_empty_coerces_value_to_true(self):
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [{"property": "Due", "op": "is_empty", "value": None}], "all", _STUB_SCHEMA
        )
        assert notion_filter == {"property": "Due", "date": {"is_empty": True}}


# =============================================================================
# SERIALIZATION HELPERS
# =============================================================================


class TestSimplifyProperty:
    """_simplify_property reduces each Notion property type to a plain value."""

    def test_title(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "title", "title": [{"plain_text": "Hello "}, {"plain_text": "World"}]}
        assert _simplify_property(prop) == "Hello World"

    def test_rich_text(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "rich_text", "rich_text": [{"plain_text": "body"}]}
        assert _simplify_property(prop) == "body"

    def test_date_returns_full_object(self):
        from connectors.notion_api.serialize import _simplify_property

        # date is returned as the whole {start[, end]} dict, not just the start string.
        prop = {"type": "date", "date": {"start": "2026-01-01", "end": None}}
        assert _simplify_property(prop) == {"start": "2026-01-01", "end": None}

    def test_date_null(self):
        from connectors.notion_api.serialize import _simplify_property

        assert _simplify_property({"type": "date", "date": None}) is None

    def test_status(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "status", "status": {"name": "In Progress"}}
        assert _simplify_property(prop) == "In Progress"

    def test_status_null(self):
        from connectors.notion_api.serialize import _simplify_property

        assert _simplify_property({"type": "status", "status": None}) is None

    def test_select(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "select", "select": {"name": "Option A"}}
        assert _simplify_property(prop) == "Option A"

    def test_multi_select(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "multi_select", "multi_select": [{"name": "red"}, {"name": "blue"}]}
        assert _simplify_property(prop) == ["red", "blue"]

    def test_number(self):
        from connectors.notion_api.serialize import _simplify_property

        assert _simplify_property({"type": "number", "number": 42}) == 42

    def test_checkbox(self):
        from connectors.notion_api.serialize import _simplify_property

        assert _simplify_property({"type": "checkbox", "checkbox": True}) is True

    def test_people(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "people", "people": [{"id": "user-1"}, {"id": "user-2"}]}
        assert _simplify_property(prop) == ["user-1", "user-2"]

    def test_relation(self):
        from connectors.notion_api.serialize import _simplify_property

        prop = {"type": "relation", "relation": [{"id": "page-a"}, {"id": "page-b"}]}
        assert _simplify_property(prop) == ["page-a", "page-b"]


class TestSimplifyPage:
    """_simplify_page reduces a page to page_id/url/title + flat properties."""

    def test_extracts_id_url_title_and_props(self):
        from connectors.notion_api.serialize import _simplify_page

        page = {
            "id": "page-123",
            "url": "https://notion.so/page-123",
            "properties": {
                "Name": {"type": "title", "title": [{"plain_text": "My Task"}]},
                "Done": {"type": "checkbox", "checkbox": False},
            },
        }
        simplified = _simplify_page(page)
        assert simplified["page_id"] == "page-123"
        assert simplified["url"] == "https://notion.so/page-123"
        assert simplified["title"] == "My Task"
        assert simplified["properties"]["Done"] is False

    def test_no_title_property_omits_title_key(self):
        from connectors.notion_api.serialize import _simplify_page

        page = {
            "id": "page-456",
            "url": "https://notion.so/page-456",
            "properties": {"Count": {"type": "number", "number": 3}},
        }
        simplified = _simplify_page(page)
        assert "title" not in simplified
        assert simplified["properties"]["Count"] == 3


class TestSimplifyBlock:
    """_simplify_block reduces a block to id/type/text/has_children."""

    def test_paragraph_block(self):
        from connectors.notion_api.serialize import _simplify_block

        block = {
            "id": "block-1",
            "type": "paragraph",
            "paragraph": {"rich_text": [{"plain_text": "some text"}]},
            "has_children": False,
        }
        simplified = _simplify_block(block)
        assert simplified == {
            "id": "block-1",
            "type": "paragraph",
            "text": "some text",
            "has_children": False,
        }

    def test_block_without_rich_text_body(self):
        from connectors.notion_api.serialize import _simplify_block

        # An image block has no rich_text body — text falls back to empty string.
        block = {"id": "block-2", "type": "image", "image": {"type": "external"}}
        simplified = _simplify_block(block)
        assert simplified["text"] == ""
        assert simplified["type"] == "image"


class TestSimplifyUser:
    """_simplify_user reduces a user object to id/name/type/email."""

    def test_person_with_email(self):
        from connectors.notion_api.serialize import _simplify_user

        user = {
            "id": "user-1",
            "name": "Alice",
            "type": "person",
            "person": {"email": "alice@example.com"},
        }
        assert _simplify_user(user) == {
            "id": "user-1",
            "name": "Alice",
            "type": "person",
            "email": "alice@example.com",
        }

    def test_bot_without_person(self):
        from connectors.notion_api.serialize import _simplify_user

        user = {"id": "bot-1", "name": "Integration", "type": "bot", "bot": {}}
        simplified = _simplify_user(user)
        assert simplified["email"] is None
        assert simplified["type"] == "bot"


class TestMcpTextContent:
    """_mcp_text_content wraps a payload as MCP text blocks (json round-trips)."""

    def test_round_trips_payload(self):
        from connectors.notion_api.client import _mcp_text_content

        blocks = _mcp_text_content({"key": "value", "count": 3})
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert json.loads(blocks[0]["text"]) == {"key": "value", "count": 3}


class TestClampMaxRows:
    """_clamp_max_rows bounds the accumulation cap to [1, MAX_ROWS_CAP]."""

    def test_caps_at_max(self):
        from connectors.notion_api.client import MAX_ROWS_CAP, _clamp_max_rows

        assert _clamp_max_rows(5000) == MAX_ROWS_CAP

    def test_floors_at_one(self):
        from connectors.notion_api.client import _clamp_max_rows

        assert _clamp_max_rows(0) == 1
        assert _clamp_max_rows(-10) == 1

    def test_passes_through_valid(self):
        from connectors.notion_api.client import _clamp_max_rows

        assert _clamp_max_rows(50) == 50


# =============================================================================
# ID VALIDATION — _normalize_id
# =============================================================================


class TestNormalizeId:
    """_normalize_id accepts dashed/undashed UUIDs and notion.so URLs; rejects garbage."""

    def test_accepts_dashed_uuid(self):
        from connectors.notion_api.client import _normalize_id

        assert (
            _normalize_id("12345678-90ab-cdef-1234-567890abcdef")
            == "1234567890abcdef1234567890abcdef"
        )

    def test_accepts_undashed_uuid(self):
        from connectors.notion_api.client import _normalize_id

        assert (
            _normalize_id("1234567890abcdef1234567890abcdef") == "1234567890abcdef1234567890abcdef"
        )

    def test_extracts_from_notion_url(self):
        from connectors.notion_api.client import _normalize_id

        url = "https://www.notion.so/Project-Roadmap-200d7c2bff0f8061a5e2c5d2f9a1b3c4"
        assert _normalize_id(url) == "200d7c2bff0f8061a5e2c5d2f9a1b3c4"

    def test_url_slug_ending_in_hex_does_not_truncate(self):
        # Regression: a slug word ending in hex letters (a-f) must not bleed into the id.
        from connectors.notion_api.client import _normalize_id

        assert (
            _normalize_id("https://www.notion.so/My-Page-200d7c2bff0f8061a5e2c5d2f9a1b3c4")
            == "200d7c2bff0f8061a5e2c5d2f9a1b3c4"
        )

    def test_url_with_query_string_is_stripped(self):
        from connectors.notion_api.client import _normalize_id

        assert (
            _normalize_id("https://notion.so/Title-200d7c2bff0f8061a5e2c5d2f9a1b3c4?v=abc123")
            == "200d7c2bff0f8061a5e2c5d2f9a1b3c4"
        )

    def test_strips_whitespace(self):
        from connectors.notion_api.client import _normalize_id

        assert (
            _normalize_id("  1234567890abcdef1234567890abcdef  ")
            == "1234567890abcdef1234567890abcdef"
        )

    def test_rejects_garbage(self):
        from connectors.notion_api.client import _normalize_id

        with pytest.raises(ValueError, match="Could not extract a Notion ID"):
            _normalize_id("not-a-real-id")

    def test_rejects_empty(self):
        from connectors.notion_api.client import _normalize_id

        with pytest.raises(ValueError, match="Could not extract a Notion ID"):
            _normalize_id("")


# =============================================================================
# MCP DISPATCH
# =============================================================================


class TestMCPDispatch:
    """Verify JSON-RPC dispatch for standard MCP methods (AGENTS.md: c)."""

    async def test_initialize_returns_server_info(self, notion_connector):
        response = await notion_connector.handle_mcp_request(
            method="initialize", params={}, request_id=1, access_token="fake"
        )
        assert response["jsonrpc"] == "2.0"
        assert response["result"]["serverInfo"]["name"] == "notion_api"

    async def test_tools_list_returns_nineteen(self, notion_connector):
        response = await notion_connector.handle_mcp_request(
            method="tools/list", params={}, request_id=2, access_token="fake"
        )
        assert len(response["result"]["tools"]) == 19

    async def test_ping_returns_empty(self, notion_connector):
        response = await notion_connector.handle_mcp_request(
            method="ping", params={}, request_id=3, access_token="fake"
        )
        assert response["result"] == {}

    async def test_unknown_method_returns_error(self, notion_connector):
        response = await notion_connector.handle_mcp_request(
            method="resources/list", params={}, request_id=4, access_token="fake"
        )
        assert response["error"]["code"] == -32601


# =============================================================================
# TOOL: query_data_source (mocked HTTP)
# =============================================================================


class TestQueryDataSource:
    """query_data_source resolves schema (via _send), then queries rows (via _request)."""

    async def test_returns_simplified_rows_and_carries_filter(self, notion_connector):
        # _resolve_ds_and_schema reads schema via _send (it branches on status_code);
        # _query_pages POSTs the query via _request. Patch both.
        schema_response = _mock_response(
            200,
            {
                "id": "200d7c2bff0f8061a5e2c5d2f9a1b3c4",
                "properties": {
                    "Status": {"type": "status"},
                    "Due": {"type": "date"},
                },
            },
        )
        query_page = {
            "results": [
                {
                    "id": "row-1",
                    "url": "https://notion.so/row-1",
                    "properties": {"Status": {"type": "status", "status": {"name": "In Progress"}}},
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }

        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = schema_response
            mock_request.return_value = query_page
            content = await notion_connector.query_data_source(
                access_token="fake",
                data_source="200d7c2bff0f8061a5e2c5d2f9a1b3c4",
                filters=[{"property": "Status", "op": "does_not_equal", "value": "Done"}],
            )

        # Observable: simplified rows come back in the payload.
        payload = json.loads(content[0]["text"])
        assert payload["count"] == 1
        assert payload["rows"][0]["properties"]["Status"] == "In Progress"
        # Observable: the built filter rode along on the query POST body.
        sent_body = mock_request.call_args.kwargs["json_body"]
        assert sent_body["filter"] == {"property": "Status", "status": {"does_not_equal": "Done"}}

    async def test_dispatch_via_mcp(self, notion_connector):
        schema_response = _mock_response(
            200, {"id": "200d7c2bff0f8061a5e2c5d2f9a1b3c4", "properties": {}}
        )
        query_page = {"results": [], "has_more": False, "next_cursor": None}

        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = schema_response
            mock_request.return_value = query_page
            response = await notion_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "query_data_source",
                    "arguments": {"data_source": "200d7c2bff0f8061a5e2c5d2f9a1b3c4"},
                },
                request_id=10,
                access_token="fake",
            )

        assert "result" in response
        assert "isError" not in response["result"]


# =============================================================================
# TOOL: archive_page (mocked HTTP)
# =============================================================================


class TestArchivePage:
    """archive_page PATCHes {"archived": true} on a normalized self-id."""

    async def test_patches_archived_true(self, notion_connector):
        page_id = "1234567890abcdef1234567890abcdef"
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = {"id": page_id, "archived": True}
            content = await notion_connector.archive_page(access_token="fake", page_id=page_id)

        # Observable: the PATCH body sets archived true on the page's own id.
        assert mock_request.call_args.args[2] == "PATCH"
        assert mock_request.call_args.args[3] == f"/pages/{page_id}"
        assert mock_request.call_args.kwargs["json_body"] == {"archived": True}
        # Observable: the response reflects the resulting state.
        payload = json.loads(content[0]["text"])
        assert payload == {"page_id": page_id, "archived": True}

    async def test_restore_patches_archived_false(self, notion_connector):
        page_id = "1234567890abcdef1234567890abcdef"
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = {"id": page_id, "archived": False}
            await notion_connector.archive_page(
                access_token="fake", page_id=page_id, archived=False
            )

        assert mock_request.call_args.kwargs["json_body"] == {"archived": False}


# =============================================================================
# TOOL: search (validation before HTTP)
# =============================================================================


class TestSearch:
    """search validates object_type before any HTTP and simplifies hits."""

    async def test_invalid_object_type_raises_before_http(self, notion_connector):
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            with pytest.raises(ValueError, match="object_type must be"):
                await notion_connector.search(access_token="fake", object_type="database")
            mock_request.assert_not_called()

    async def test_returns_simplified_hits(self, notion_connector):
        search_page = {
            "results": [
                {
                    "object": "page",
                    "id": "page-1",
                    "url": "https://notion.so/page-1",
                    "properties": {"Name": {"type": "title", "title": [{"plain_text": "Found"}]}},
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = search_page
            content = await notion_connector.search(access_token="fake", query="Found")

        payload = json.loads(content[0]["text"])
        assert payload["count"] == 1
        assert payload["results"][0]["title"] == "Found"


# =============================================================================
# TOOL: get_users (403 fallback path, mocked HTTP)
# =============================================================================


class TestGetUsers:
    """get_users falls back to /me when GET /users 403s (PAT restriction)."""

    async def test_403_falls_back_to_me(self, notion_connector):
        forbidden = _mock_response(403)
        me_user = {
            "id": "bot-1",
            "name": "My Integration",
            "type": "bot",
            "bot": {},
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = forbidden
            mock_request.return_value = me_user
            content = await notion_connector.get_users(access_token="fake")

        payload = json.loads(content[0]["text"])
        assert payload["list_available"] is False
        assert payload["me"]["name"] == "My Integration"
        # Observable: the fallback fetched /users/me.
        assert mock_request.call_args.args[3] == "/users/me"


# =============================================================================
# TOOL DISPATCH — error handling
# =============================================================================


class TestToolDispatchErrors:
    """Verify error handling in tool dispatch (AGENTS.md: tools/call isError)."""

    async def test_unknown_tool_returns_error(self, notion_connector):
        response = await notion_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "nonexistent", "arguments": {}},
            request_id=50,
            access_token="fake",
        )
        assert response["error"]["code"] == -32602

    async def test_tool_exception_returns_is_error(self, notion_connector):
        # A non-ValueError exception surfaces as result.isError == True with a
        # generic message — the raw exception text is withheld to avoid leaking
        # SDK response bodies/tokens; only the tool name is exposed.
        with patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = RuntimeError("upstream blew up")
            response = await notion_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "query_data_source",
                    "arguments": {"data_source": "1234567890abcdef1234567890abcdef"},
                },
                request_id=51,
                access_token="fake",
            )

        assert response["result"]["isError"] is True
        text = response["result"]["content"][0]["text"]
        assert "upstream blew up" not in text
        assert "query_data_source" in text


# =============================================================================
# PER-TOOL SMOKE TESTS (mocked HTTP) — one happy-path per remaining tool
# =============================================================================
#
# Patch target rule: patch `_request`/`_send` in the namespace where the CALLER is defined.
# Tool bodies and adapter-resident helpers (_resolve_ds_and_schema, _query_pages, _create_one_page,
# _build_page_schema) resolve them in `adapter`; the paginators (_paginate_get / _paginate_property)
# live in `client` and resolve `_request` there. Any id passed through _normalize_id must be 32-hex.

_HEX_A = "1234567890abcdef1234567890abcdef"
_HEX_B = "200d7c2bff0f8061a5e2c5d2f9a1b3c4"
_HEX_C = "fedcba0987654321fedcba0987654321"


class TestReadToolsSmoke:
    """fetch / get_block_children / get_page_property / get_comments (paginators live in client)."""

    async def test_fetch_page_returns_page_and_blocks(self, notion_connector):
        page_json = {
            "id": "p1",
            "url": "https://notion.so/p1",
            "properties": {"Name": {"type": "title", "title": [{"plain_text": "Doc"}]}},
        }
        blocks_page = {
            "results": [
                {
                    "id": "b1",
                    "type": "paragraph",
                    "paragraph": {"rich_text": [{"plain_text": "hi"}]},
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = _mock_response(
                200, page_json
            )  # GET /pages/{id} (200, not 404)
            mock_request.return_value = blocks_page  # _paginate_get over /blocks/{id}/children
            content = await notion_connector.fetch(access_token="fake", notion_id=_HEX_A)

        payload = json.loads(content[0]["text"])
        assert payload["kind"] == "page"
        assert payload["page"]["title"] == "Doc"
        assert payload["blocks"][0]["text"] == "hi"

    async def test_get_block_children_returns_children(self, notion_connector):
        blocks_page = {
            "results": [
                {"id": "b1", "type": "paragraph", "paragraph": {"rich_text": [{"plain_text": "x"}]}}
            ],
            "has_more": False,
            "next_cursor": None,
        }
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = blocks_page
            content = await notion_connector.get_block_children(
                access_token="fake", block_id=_HEX_A
            )

        payload = json.loads(content[0]["text"])
        assert payload["count"] == 1
        assert payload["blocks"][0]["id"] == "b1"
        assert mock_request.call_args.args[3] == f"/blocks/{_HEX_A}/children"

    async def test_get_page_property_returns_value(self, notion_connector):
        # A non-list property is returned directly by _paginate_property.
        prop = {"object": "property_item", "type": "number", "number": 42}
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = prop
            content = await notion_connector.get_page_property(
                access_token="fake", page_id=_HEX_A, property_id="Due"
            )

        payload = json.loads(content[0]["text"])
        assert payload["property_id"] == "Due"
        assert payload["value"] == prop

    async def test_get_comments_returns_simplified_thread(self, notion_connector):
        comments_page = {
            "results": [
                {
                    "id": "c1",
                    "discussion_id": "d1",
                    "rich_text": [{"plain_text": "hello"}],
                    "parent": {"type": "page_id", "page_id": _HEX_A},
                    "created_time": "2026-01-01T00:00:00Z",
                    "created_by": {"id": "u1"},
                    "display_name": {"resolved_name": "Alice"},
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = comments_page
            content = await notion_connector.get_comments(access_token="fake", page_id=_HEX_A)

        payload = json.loads(content[0]["text"])
        assert payload["count"] == 1
        assert payload["comments"][0]["text"] == "hello"
        assert payload["comments"][0]["discussion_id"] == "d1"
        # GET /comments is keyed by block_id even for pages.
        assert mock_request.call_args.kwargs["params"]["block_id"] == _HEX_A


class TestPageWriteToolsSmoke:
    """create_pages / update_page_properties / append_blocks / update_page_content / move_pages."""

    async def test_create_pages_creates_row_under_data_source(self, notion_connector):
        ds = _mock_response(200, {"id": _HEX_B, "properties": {"Name": {"type": "title"}}})
        created = {
            "id": "newpage",
            "url": "https://notion.so/newpage",
            "properties": {"Name": {"type": "title", "title": [{"plain_text": "Task A"}]}},
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = (
                ds  # _resolve_parent + _resolve_ds_and_schema probe GET /data_sources
            )
            mock_request.return_value = created  # POST /pages
            content = await notion_connector.create_pages(
                access_token="fake", parent=_HEX_A, pages=[{"properties": {"Name": "Task A"}}]
            )

        payload = json.loads(content[0]["text"])
        assert payload["count"] == 1
        assert payload["pages"][0]["title"] == "Task A"
        assert mock_request.call_args.args[2:4] == ("POST", "/pages")

    async def test_update_page_properties_patches_row(self, notion_connector):
        page_with_parent = {"parent": {"type": "data_source_id", "data_source_id": _HEX_B}}
        ds = _mock_response(200, {"id": _HEX_B, "properties": {"Status": {"type": "status"}}})
        updated = {
            "id": _HEX_A,
            "url": "https://notion.so/p",
            "properties": {"Status": {"type": "status", "status": {"name": "Done"}}},
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = ds  # _resolve_ds_and_schema (schema lookup)
            mock_request.side_effect = [
                page_with_parent,
                updated,
            ]  # GET page (for parent), then PATCH
            content = await notion_connector.update_page_properties(
                access_token="fake", page_id=_HEX_A, properties={"Status": "Done"}
            )

        payload = json.loads(content[0]["text"])
        assert payload["properties"]["Status"] == "Done"
        # second _request is the PATCH carrying the built property value.
        patch_call = mock_request.call_args_list[1]
        assert patch_call.args[2:4] == ("PATCH", f"/pages/{_HEX_A}")
        assert patch_call.kwargs["json_body"]["properties"]["Status"] == {
            "status": {"name": "Done"}
        }

    async def test_append_blocks_converts_markdown_and_patches_children(self, notion_connector):
        appended = {
            "results": [
                {
                    "id": "nb1",
                    "type": "paragraph",
                    "paragraph": {"rich_text": [{"plain_text": "line one"}]},
                }
            ]
        }
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = appended
            content = await notion_connector.append_blocks(
                access_token="fake", block_id=_HEX_A, markdown="line one"
            )

        payload = json.loads(content[0]["text"])
        assert payload["created_count"] == 1
        assert mock_request.call_args.args[2:4] == ("PATCH", f"/blocks/{_HEX_A}/children")
        # markdown was converted to a Notion paragraph block.
        assert mock_request.call_args.kwargs["json_body"]["children"][0]["type"] == "paragraph"

    async def test_update_page_content_replaces_single_match(self, notion_connector):
        blocks_page = {
            "results": [
                {
                    "id": _HEX_C,
                    "type": "paragraph",
                    "paragraph": {"rich_text": [{"plain_text": "the old text here"}]},
                    "has_children": False,
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }
        updated_block = {
            "id": _HEX_C,
            "type": "paragraph",
            "paragraph": {"rich_text": [{"plain_text": "the new text here"}]},
        }
        with (
            patch(
                "connectors.notion_api.client._request", new_callable=AsyncMock
            ) as mock_client_request,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_client_request.return_value = blocks_page  # _paginate_get fetches children
            mock_request.return_value = updated_block  # PATCH /blocks/{id}
            content = await notion_connector.update_page_content(
                access_token="fake", page_id=_HEX_A, old_str="old text", new_str="new text"
            )

        payload = json.loads(content[0]["text"])
        assert payload["status"] == "ok"
        assert payload["match_count"] == 1
        assert mock_request.call_args.args[2] == "PATCH"

    async def test_move_pages_reparents_via_move_endpoint(self, notion_connector):
        moved = {
            "id": _HEX_A,
            "url": "https://notion.so/p",
            "parent": {"type": "page_id", "page_id": _HEX_C},
        }
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = moved
            content = await notion_connector.move_pages(
                access_token="fake", page_id=_HEX_A, new_parent={"page_id": _HEX_C}
            )

        payload = json.loads(content[0]["text"])
        assert payload["page_id"] == _HEX_A
        assert mock_request.call_args.args[2:4] == ("POST", f"/pages/{_HEX_A}/move")


class TestDatabaseToolsSmoke:
    """create_database / update_data_source / create_view / update_view."""

    async def test_create_database_returns_ids(self, notion_connector):
        created = {
            "id": "db1",
            "data_sources": [{"id": _HEX_B}],
            "title": [{"plain_text": "My DB"}],
            "url": "https://notion.so/db1",
        }
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = created
            content = await notion_connector.create_database(
                access_token="fake",
                parent_page=_HEX_A,
                title="My DB",
                properties={"Name": {"type": "title"}},
            )

        payload = json.loads(content[0]["text"])
        assert payload["database_id"] == "db1"
        assert payload["data_source_id"] == _HEX_B
        assert mock_request.call_args.args[2:4] == ("POST", "/databases")

    async def test_update_data_source_adds_property(self, notion_connector):
        ds = _mock_response(200, {"id": _HEX_B, "properties": {"Name": {"type": "title"}}})
        updated = {
            "title": [{"plain_text": "DS"}],
            "properties": {"Name": {"type": "title"}, "Priority": {"type": "select"}},
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = ds  # _resolve_ds_and_schema
            mock_request.return_value = updated  # PATCH /data_sources/{id}
            content = await notion_connector.update_data_source(
                access_token="fake",
                data_source=_HEX_B,
                add={"Priority": {"type": "select", "options": ["Low"]}},
            )

        payload = json.loads(content[0]["text"])
        assert payload["data_source_id"] == _HEX_B
        assert payload["properties"]["Priority"] == "select"
        assert mock_request.call_args.args[2:4] == ("PATCH", f"/data_sources/{_HEX_B}")

    async def test_create_view_returns_view(self, notion_connector):
        ds = _mock_response(200, {"id": _HEX_B, "properties": {}})
        view = {
            "id": "v1",
            "name": "Board",
            "type": "board",
            "parent": {},
            "data_source_id": _HEX_B,
            "url": "u",
        }
        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
        ):
            mock_send.return_value = ds
            mock_request.return_value = view  # POST /views
            content = await notion_connector.create_view(
                access_token="fake",
                database_id=_HEX_A,
                data_source=_HEX_B,
                name="Board",
                view_type="board",
            )

        payload = json.loads(content[0]["text"])
        assert payload["view_id"] == "v1"
        assert payload["type"] == "board"
        assert mock_request.call_args.args[2:4] == ("POST", "/views")

    async def test_update_view_renames(self, notion_connector):
        view = {
            "id": "v1",
            "name": "Renamed",
            "type": "board",
            "parent": {},
            "data_source_id": _HEX_B,
            "url": "u",
        }
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = view
            content = await notion_connector.update_view(
                access_token="fake", view_id=_HEX_C, name="Renamed"
            )

        payload = json.loads(content[0]["text"])
        assert payload["name"] == "Renamed"
        assert mock_request.call_args.args[2:4] == ("PATCH", f"/views/{_HEX_C}")


class TestCommentFileToolsSmoke:
    """create_comment / upload_file."""

    async def test_create_comment_posts_page_comment(self, notion_connector):
        comment = {
            "id": "c1",
            "discussion_id": "d1",
            "rich_text": [{"plain_text": "nice"}],
            "parent": {"type": "page_id", "page_id": _HEX_A},
            "created_time": "2026-01-01T00:00:00Z",
            "created_by": {"id": "u1"},
            "display_name": {"resolved_name": "Bob"},
        }
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = comment
            content = await notion_connector.create_comment(
                access_token="fake", text="nice", page_id=_HEX_A
            )

        payload = json.loads(content[0]["text"])
        assert payload["text"] == "nice"
        assert mock_request.call_args.args[2:4] == ("POST", "/comments")
        assert mock_request.call_args.kwargs["json_body"]["parent"] == {"page_id": _HEX_A}

    async def test_upload_file_creates_and_sends(self, notion_connector):
        created = {"id": _HEX_B, "upload_url": "https://api.notion.com/v1/file_uploads/x/send"}
        sent = {
            "filename": "notes.txt",
            "status": "uploaded",
            "content_length": 5,
            "expiry_time": None,
        }
        # _send_file_bytes is the multipart-POST HTTP boundary for this tool — mock it like outbound HTTP.
        with (
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_request,
            patch(
                "connectors.notion_api.adapter._send_file_bytes", new_callable=AsyncMock
            ) as mock_send_bytes,
        ):
            mock_request.return_value = created  # POST /file_uploads (create)
            mock_send_bytes.return_value = sent
            content = await notion_connector.upload_file(
                access_token="fake", filename="notes.txt", text_content="hello"
            )

        payload = json.loads(content[0]["text"])
        assert payload["file_upload_id"] == _HEX_B
        assert payload["status"] == "uploaded"
        assert payload["attached_block_id"] is None  # no attach_page_id given


class TestResolveParentTypeProbe:
    """_resolve_parent must treat Notion's 400 'wrong object type' as 'not this type' (regression).

    Notion returns 400 (not 404) for GET /databases/{page_id} ("is a page, not a database").
    The resolver must keep probing and land on the page branch — not misroute the page as a DB.
    """

    async def test_page_parent_resolves_despite_400_on_databases(self):
        from connectors.notion_api.adapter import _resolve_parent

        page_id = "1234567890abcdef1234567890abcdef"

        async def fake_send(_client, _token, _method, path, **_kw):
            if path.startswith("/data_sources/"):
                return _mock_response(404)
            if path.startswith("/databases/"):  # the bug: 400, NOT 404
                return _mock_response(
                    400, {"message": "Provided database_id is a page, not a database."}
                )
            if path.startswith("/pages/"):
                return _mock_response(200, {"id": page_id})
            return _mock_response(404)

        with patch("connectors.notion_api.adapter._send", new=fake_send):
            parent, schema = await _resolve_parent(None, "fake", page_id)

        assert parent == {"type": "page_id", "page_id": page_id}
        assert schema is None


class TestReviewFixRegressions:
    """Regressions for issues caught in PR review."""

    def test_relative_date_op_emits_empty_object(self):
        # past_week must produce {"date": {"past_week": {}}}, not {"date": {"past_week": null}}.
        from connectors.notion_api.adapter import _build_filter

        notion_filter = _build_filter(
            [{"property": "Due", "op": "past_week", "value": None}], "all", _STUB_SCHEMA
        )
        assert notion_filter == {"property": "Due", "date": {"past_week": {}}}

    async def test_paginator_stops_on_has_more_with_null_cursor(self):
        # Malformed page (has_more=True, next_cursor=None) must NOT loop or duplicate rows.
        from connectors.notion_api.client import _paginate_get

        page = {"results": [{"id": "only"}], "has_more": True, "next_cursor": None}
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = page
            items, _has_more, _cursor = await _paginate_get(None, "fake", "/x", 100)
        assert len(items) == 1  # single fetch, no duplication
        assert mock_request.call_count == 1

    async def test_upload_file_rejects_off_domain_upload_url(self, notion_connector):
        # The bearer token must never be POSTed to a non-api.notion.com URL.
        created = {"id": _HEX_B, "upload_url": "https://evil.example.com/steal"}
        with patch(
            "connectors.notion_api.adapter._request", new_callable=AsyncMock
        ) as mock_request:
            mock_request.return_value = created
            with pytest.raises(ValueError, match="Unexpected upload_url domain"):
                await notion_connector.upload_file(
                    access_token="fake", filename="x.txt", text_content="hi"
                )

    async def test_retry_after_http_date_falls_back_to_default(self):
        # RFC 7231 permits an HTTP-date Retry-After; float() would crash on it. The retry must
        # fall back to the default delay and still retry once, not surface a parse error.
        from connectors.notion_api.client import (
            DEFAULT_RETRY_AFTER_SECONDS,
            _retry_on_rate_limit,
        )

        rate_limited = _mock_response(429)
        rate_limited.headers = {"Retry-After": "Fri, 28 May 2026 00:00:00 GMT"}
        retry_ok = _mock_response(200, {"ok": True})
        request_fn = AsyncMock(return_value=retry_ok)
        with patch(
            "connectors.notion_api.client.asyncio.sleep", new_callable=AsyncMock
        ) as mock_sleep:
            result = await _retry_on_rate_limit(rate_limited, request_fn)

        assert result is retry_ok  # retried instead of raising on the date-form header
        assert mock_sleep.call_args.args[0] == DEFAULT_RETRY_AFTER_SECONDS
        request_fn.assert_awaited_once()

    async def test_update_page_content_signals_truncation_on_no_match(self, notion_connector):
        # >DEFAULT_MAX_CONTENT_BLOCKS blocks: a no-match must flag search_truncated so the caller
        # can tell "absent" from "search window exhausted" instead of trusting a false negative.
        blocks = [
            {
                "id": _HEX_C,
                "type": "paragraph",
                "paragraph": {"rich_text": [{"plain_text": "unrelated"}]},
                "has_children": False,
            }
        ]
        with patch(
            "connectors.notion_api.adapter._paginate_get", new_callable=AsyncMock
        ) as mock_paginate:
            mock_paginate.return_value = (blocks, True, "next-cursor")  # has_more=True -> truncated
            content = await notion_connector.update_page_content(
                access_token="fake", page_id=_HEX_A, old_str="absent text", new_str="x"
            )

        payload = json.loads(content[0]["text"])
        assert payload["status"] == "error"
        assert payload["match_count"] == 0
        assert payload["search_truncated"] is True
        assert payload["blocks_searched"] == 1

    async def test_update_page_content_replaces_only_first_occurrence_in_block(
        self, notion_connector
    ):
        # A block containing old_str twice must change only the FIRST occurrence (count=1), not both.
        blocks_page = {
            "results": [
                {
                    "id": _HEX_C,
                    "type": "paragraph",
                    "paragraph": {"rich_text": [{"plain_text": "meeting at 9 and meeting at 5"}]},
                    "has_children": False,
                }
            ],
            "has_more": False,
            "next_cursor": None,
        }
        with (
            patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_paginate,
            patch("connectors.notion_api.adapter._request", new_callable=AsyncMock) as mock_patch,
        ):
            mock_paginate.return_value = blocks_page
            mock_patch.return_value = {
                "id": _HEX_C,
                "type": "paragraph",
                "paragraph": {"rich_text": [{"plain_text": "x"}]},
            }
            await notion_connector.update_page_content(
                access_token="fake", page_id=_HEX_A, old_str="meeting", new_str="standup"
            )

        sent_text = mock_patch.call_args.kwargs["json_body"]["paragraph"]["rich_text"][0]["text"][
            "content"
        ]
        assert sent_text == "standup at 9 and meeting at 5"  # only the first 'meeting' replaced

    def test_resolve_upload_bytes_rejects_non_alphabet_base64(self):
        # validate=True must reject base64 carrying stray non-alphabet chars instead of silently
        # stripping them and uploading different bytes than the caller encoded.
        from connectors.notion_api.adapter import _resolve_upload_bytes

        assert _resolve_upload_bytes(content_base64="aGVsbG8=", text_content=None) == b"hello"
        with pytest.raises(ValueError):
            _resolve_upload_bytes(content_base64="aGVs!bG8=", text_content=None)


# =============================================================================
# AUDIT-FIX REGRESSIONS — silent truncation, fetch 400 fallback, partial creates,
# match validation, upload-size cap
# =============================================================================


class TestPaginationTruncation:
    """A page that over-returns past the cap must report has_more/truncated, not drop rows silently."""

    async def test_paginate_get_reports_has_more_when_server_overfills_one_page(self):
        # The server holds 50 rows. With the fix the helper asks for page_size=10 (the cap), so the
        # server returns 10 rows + has_more=True. Pre-fix it asked for page_size=100, got all 50 in
        # one page with has_more=False, then sliced to 10 — losing 40 rows under a false has_more.
        from connectors.notion_api.client import _paginate_get

        async def fake_request(_client, _token, _method, _path, *, params=None, **_kw):
            requested = params["page_size"]
            held = 50
            returned = min(requested, held)
            return {
                "results": [{"id": f"u{i}"} for i in range(returned)],
                "has_more": returned < held,
                "next_cursor": "cursor" if returned < held else None,
            }

        with patch("connectors.notion_api.client._request", new=fake_request):
            items, has_more, cursor = await _paginate_get(None, "fake", "/users", 10)

        assert len(items) == 10  # exactly the cap, no over-fetch
        assert has_more is True  # rows remain — must NOT report "nothing left"
        assert cursor == "cursor"

    async def test_query_data_source_truncated_flag_set_when_page_overfills(self, notion_connector):
        # Adapter-level mirror: with the fix the query asks for page_size=10, the server returns 10
        # rows + has_more=True, and the tool's truncated flag is True. Pre-fix the unconditional
        # page_size=100 pulled all 50 rows in one has_more=False page → truncated=False (rows lost).
        schema_response = _mock_response(200, {"id": _HEX_B, "properties": {}})

        async def fake_request(_client, _token, _method, path, *, json_body=None, **_kw):
            requested = json_body["page_size"]
            held = 50
            returned = min(requested, held)
            return {
                "results": [
                    {"id": f"row-{i}", "url": f"https://notion.so/row-{i}", "properties": {}}
                    for i in range(returned)
                ],
                "has_more": returned < held,
                "next_cursor": "cursor" if returned < held else None,
            }

        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new=fake_request),
        ):
            mock_send.return_value = schema_response
            content = await notion_connector.query_data_source(
                access_token="fake", data_source=_HEX_B, max_rows=10
            )

        payload = json.loads(content[0]["text"])
        assert payload["count"] == 10
        assert payload["has_more"] is True
        assert payload["truncated"] is True

    async def test_paginate_get_terminates_on_empty_page_with_has_more(self):
        # A server can return an empty results list while still claiming has_more=True. Without the
        # empty-page break this loops forever; the break makes it terminate after one fetch.
        from connectors.notion_api.client import _paginate_get

        page = {"results": [], "has_more": True, "next_cursor": "always-more"}
        with patch("connectors.notion_api.client._request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = page
            items, has_more, _cursor = await _paginate_get(None, "fake", "/x", 100)

        assert items == []
        assert has_more is True
        assert mock_request.call_count == 1  # did not loop on the empty page


class TestFetchFallbackOnNon200:
    """fetch must fall back to data-source resolution on ANY non-200 page probe, not just 404."""

    async def _run_fetch_with_page_status(self, notion_connector, page_status: int):
        ds_schema = {"id": _HEX_B, "properties": {"Name": {"type": "title"}}}

        async def fake_send(_client, _token, _method, path, **_kw):
            if path.startswith("/pages/"):
                return _mock_response(page_status)
            if path.startswith("/data_sources/"):
                return _mock_response(200, ds_schema)
            return _mock_response(404)

        with patch("connectors.notion_api.adapter._send", new=fake_send):
            content = await notion_connector.fetch(access_token="fake", notion_id=_HEX_B)
        return json.loads(content[0]["text"])

    async def test_page_probe_400_takes_data_source_branch(self, notion_connector):
        # Notion answers 400 (not 404) when a data-source id is sent to GET /pages. Pre-fix the
        # 404-only check fell through to _check_status and raised, so the data-source path was dead.
        payload = await self._run_fetch_with_page_status(notion_connector, 400)
        assert payload["kind"] == "data_source"
        assert payload["data_source_id"] == _HEX_B

    async def test_page_probe_404_takes_data_source_branch(self, notion_connector):
        payload = await self._run_fetch_with_page_status(notion_connector, 404)
        assert payload["kind"] == "data_source"
        assert payload["data_source_id"] == _HEX_B


class TestCreatePagesPartialFailure:
    """create_pages must cap batch size and never lose the record of pages already written."""

    async def test_rejects_batch_over_cap(self, notion_connector):
        from connectors.notion_api.adapter import MAX_PAGES_PER_CALL

        oversized = [{"properties": {"Name": "x"}} for _ in range(MAX_PAGES_PER_CALL + 1)]
        with pytest.raises(ValueError, match="the limit is"):
            await notion_connector.create_pages(access_token="fake", parent=_HEX_A, pages=oversized)

    async def test_mid_loop_failure_returns_created_so_far_and_failed_at(self, notion_connector):
        # Page index 1 fails on POST /pages; page index 0 was already written. The payload must
        # report status=partial with the created page kept and failed_at=1 — never a lost write.
        ds = _mock_response(200, {"id": _HEX_B, "properties": {"Name": {"type": "title"}}})

        first_created = {
            "id": "page-0",
            "url": "https://notion.so/page-0",
            "properties": {"Name": {"type": "title", "title": [{"plain_text": "A"}]}},
        }
        calls = {"n": 0}

        async def fake_request(_client, _token, method, path, *, json_body=None, **_kw):
            if (method, path) == ("POST", "/pages"):
                calls["n"] += 1
                if calls["n"] == 1:
                    return first_created
                raise ValueError("Notion API error (409): conflict")
            return {}

        with (
            patch("connectors.notion_api.adapter._send", new_callable=AsyncMock) as mock_send,
            patch("connectors.notion_api.adapter._request", new=fake_request),
        ):
            mock_send.return_value = ds
            content = await notion_connector.create_pages(
                access_token="fake",
                parent=_HEX_A,
                pages=[{"properties": {"Name": "A"}}, {"properties": {"Name": "B"}}],
            )

        payload = json.loads(content[0]["text"])
        assert payload["status"] == "partial"
        assert payload["count"] == 1
        assert payload["pages"][0]["title"] == "A"  # the written page is preserved
        assert payload["failed_at"] == 1
        assert "409" in payload["error"]


class TestBuildFilterMatchValidation:
    """_build_filter must reject an out-of-enum match instead of silently treating it as AND."""

    def test_invalid_match_raises_with_value(self):
        from connectors.notion_api.adapter import _build_filter

        with pytest.raises(ValueError, match="bogus"):
            _build_filter(
                [{"property": "Status", "op": "equals", "value": "Done"}], "bogus", _STUB_SCHEMA
            )


class TestUploadFileSizeCap:
    """upload_file must reject an oversized payload before any HTTP (OOM guard)."""

    async def test_oversized_content_base64_raises_before_http(self, notion_connector):
        from base64 import b64encode

        from connectors.notion_api.adapter import MAX_UPLOAD_BYTES

        oversized = b64encode(b"\x00" * (MAX_UPLOAD_BYTES + 1)).decode("ascii")
        # No HTTP is patched: the size check must raise before _create_file_upload is reached,
        # so an unpatched outbound call would itself fail the test if the guard were absent.
        with pytest.raises(ValueError, match="upload limit"):
            await notion_connector.upload_file(
                access_token="fake", filename="big.bin", content_base64=oversized
            )
