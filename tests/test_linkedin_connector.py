"""
LinkedIn Connector Unit Tests

Coverage: auto-registration, meta validation, OAuth hook defaults
(client_secret_post), MCP dispatch, plus regression tests for the audited
fixes — org-tool scope gating, ACL org-ID validation, session-error
propagation in batch org fetch, the get_post_comments FINDER header, and the
non-retry of POST creates on 429.

Mock only outbound HTTP (httpx) and the module's own GET/POST helpers, per the
project Testing Rules.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from broker.connectors.registry import ConnectorRegistry

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear connector registry around every test — isolates re-registration."""
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture
def linkedin_connector():
    """Import the LinkedIn adapter and register it fresh for each test."""
    from connectors.linkedin.adapter import LinkedInConnector

    connector = ConnectorRegistry.get("linkedin")
    if connector is None:
        ConnectorRegistry.auto_register(LinkedInConnector)
        connector = ConnectorRegistry.get("linkedin")
    assert connector is not None
    return connector


def _make_httpx_response(
    *,
    status_code: int = 200,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
    content: bytes = b"{}",
) -> MagicMock:
    """Build a MagicMock that quacks like httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.is_error = status_code >= 400  # noqa: PLR2004 -- HTTP error boundary
    response.headers = headers or {}
    response.json.return_value = json_body or {}
    response.text = json.dumps(json_body) if json_body else ""
    response.content = content
    return response


def _patch_httpx(method: str, responses: list[MagicMock]) -> tuple:
    """Return (context manager, method_mock) yielding the given responses in order."""
    method_mock = AsyncMock(side_effect=responses)
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    setattr(client, method, method_mock)
    return patch("connectors.linkedin.adapter.httpx.AsyncClient", return_value=client), method_mock


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Auto-registration, metadata, scope list (AGENTS.md mandated minimum)."""

    def test_registers_as_linkedin(self, linkedin_connector):
        assert linkedin_connector.meta.name == "linkedin"

    def test_display_name(self, linkedin_connector):
        assert linkedin_connector.meta.display_name == "LinkedIn"

    def test_is_native_connector(self, linkedin_connector):
        assert linkedin_connector.meta.mcp_url is None
        assert linkedin_connector.meta.is_native

    def test_authorize_url(self, linkedin_connector):
        assert (
            linkedin_connector.meta.oauth_authorize_url
            == "https://www.linkedin.com/oauth/v2/authorization"
        )

    def test_token_url(self, linkedin_connector):
        assert (
            linkedin_connector.meta.oauth_token_url
            == "https://www.linkedin.com/oauth/v2/accessToken"
        )

    def test_scopes_are_self_serve_only(self, linkedin_connector):
        # Org scopes are intentionally absent until Community Management approval.
        assert set(linkedin_connector.meta.scopes) == {"openid", "profile", "w_member_social"}

    def test_does_not_request_org_scopes(self, linkedin_connector):
        assert "r_organization_social" not in linkedin_connector.meta.scopes

    def test_pkce_disabled(self, linkedin_connector):
        # LinkedIn rejects code_verifier — broker cannot send PKCE.
        assert linkedin_connector.meta.supports_pkce is False

    def test_has_twelve_tools(self, linkedin_connector):
        assert len(linkedin_connector._tools) == 12  # noqa: PLR2004 -- full tool surface

    def test_tool_names(self, linkedin_connector):
        assert set(linkedin_connector._tools.keys()) == {
            "get_me",
            "create_post",
            "create_image_post",
            "create_document_post",
            "delete_post",
            "get_org_posts",
            "get_managed_orgs",
            "create_comment",
            "react_to_post",
            "get_post_comments",
            "get_org_analytics",
            "get_post_analytics",
        }

    def test_tool_prompt_instructions_non_empty(self, linkedin_connector):
        prompt = linkedin_connector.tool_prompt_instructions()
        assert isinstance(prompt, str)
        assert "get_managed_orgs" in prompt


# =============================================================================
# OAUTH HOOKS — LinkedIn overrides nothing, so the broker defaults must hold
# =============================================================================


class TestOAuthHooks:
    """LinkedIn uses client_secret_post (broker default) — verify the shapes."""

    def test_token_request_auth_uses_body_credentials(self, linkedin_connector):
        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="test_client_id",
            client_secret="test_client_secret",  # noqa: S106 -- test fixture, not a real secret
        )
        headers, body_credentials = linkedin_connector.build_token_request_auth(credentials)

        # client_secret_post: no Authorization header, credentials in the POST body.
        assert headers == {}
        assert body_credentials == {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
        }

    def test_auth_header_is_bearer(self, linkedin_connector):
        headers = linkedin_connector.build_auth_header("fake-token")
        assert headers["Authorization"] == "Bearer fake-token"


# =============================================================================
# MCP DISPATCH
# =============================================================================


class TestMCPDispatch:
    """JSON-RPC lifecycle methods."""

    async def test_initialize_returns_server_info(self, linkedin_connector):
        response = await linkedin_connector.handle_mcp_request(
            method="initialize", params={}, request_id=1, access_token="fake"
        )
        assert response["result"]["serverInfo"]["name"] == "linkedin"

    async def test_tools_list_excludes_org_tools_by_default(self, linkedin_connector):
        # With self-serve scopes, only the 5 member tools are advertised; the 7
        # org tools are filtered out of tools/list so the LLM never sees them.
        response = await linkedin_connector.handle_mcp_request(
            method="tools/list", params={}, request_id=2, access_token="fake"
        )
        listed = {tool["name"] for tool in response["result"]["tools"]}
        assert listed == _MEMBER_TOOL_NAMES

    async def test_unknown_method_returns_error(self, linkedin_connector):
        response = await linkedin_connector.handle_mcp_request(
            method="resources/list", params={}, request_id=3, access_token="fake"
        )
        assert response["error"]["code"] == -32601  # noqa: PLR2004 -- JSON-RPC method-not-found

    async def test_unknown_tool_returns_error(self, linkedin_connector):
        response = await linkedin_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "nonexistent", "arguments": {}},
            request_id=4,
            access_token="fake",
        )
        assert response["error"]["code"] == -32602  # noqa: PLR2004 -- JSON-RPC invalid-params


# =============================================================================
# TOOL AVAILABILITY — org tools hidden from tools/list until scopes are granted
# =============================================================================

_ORG_TOOL_NAMES = {
    "get_org_posts",
    "get_managed_orgs",
    "create_comment",
    "react_to_post",
    "get_post_comments",
    "get_org_analytics",
    "get_post_analytics",
}
_MEMBER_TOOL_NAMES = {
    "get_me",
    "create_post",
    "create_image_post",
    "create_document_post",
    "delete_post",
}


class TestToolAvailability:
    """is_tool_available gates the 7 org tools off tools/list and dispatch."""

    async def test_tools_list_omits_all_seven_org_tools(self, linkedin_connector):
        response = await linkedin_connector.handle_mcp_request(
            method="tools/list", params={}, request_id=20, access_token="fake"
        )
        listed = {tool["name"] for tool in response["result"]["tools"]}
        # Exact remaining set: only the member tools survive the filter.
        assert listed == _MEMBER_TOOL_NAMES
        assert listed.isdisjoint(_ORG_TOOL_NAMES)

    async def test_tools_list_includes_org_tools_when_scopes_enabled(self, linkedin_connector):
        # Once the Community Management scopes flip the flag, all 10 tools list.
        with patch("connectors.linkedin.adapter._ORG_TOOLS_ENABLED", True):
            response = await linkedin_connector.handle_mcp_request(
                method="tools/list", params={}, request_id=21, access_token="fake"
            )
        listed = {tool["name"] for tool in response["result"]["tools"]}
        assert listed == _MEMBER_TOOL_NAMES | _ORG_TOOL_NAMES

    async def test_calling_excluded_org_tool_returns_unknown_tool_error(self, linkedin_connector):
        # A direct tools/call on a hidden org tool must be rejected by the
        # dispatch gate with the unknown-tool error -- the same shape as a tool
        # that never existed, and BEFORE the _require_org_tools ValueError path.
        with patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get:
            response = await linkedin_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "get_managed_orgs", "arguments": {}},
                request_id=22,
                access_token="fake",
            )

        # Unknown-tool error shape: a JSON-RPC error, not an isError tool result.
        # If the org-tool ValueError guard had fired instead, this would be an
        # isError result carrying the "Community Management API" message.
        assert response["error"]["code"] == -32602  # noqa: PLR2004 -- JSON-RPC invalid-params
        assert "Unknown tool" in response["error"]["message"]
        assert "result" not in response
        # The handler never ran, so its first outbound call never happened.
        mock_get.assert_not_called()


# =============================================================================
# get_me — works without org scopes
# =============================================================================


class TestGetMe:
    async def test_returns_simplified_profile(self, linkedin_connector):
        raw_profile = {"sub": "abc123", "name": "Alice Example", "picture": "https://x/p.jpg"}
        with patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = raw_profile
            content = await linkedin_connector.get_me(access_token="fake")

        parsed = json.loads(content[0]["text"])
        assert parsed["person_urn"] == "urn:li:person:abc123"
        assert parsed["name"] == "Alice Example"


# =============================================================================
# FINDING 1 — org tools are gated off until Community Management scopes added
# =============================================================================

_ORG_TOOL_CALLS = [
    ("get_org_posts", {"org_id": "12345"}),
    ("get_managed_orgs", {}),
    ("create_comment", {"post_urn": "urn:li:ugcPost:1", "text": "hi"}),
    ("react_to_post", {"post_urn": "urn:li:ugcPost:1", "reaction_type": "LIKE"}),
    ("get_post_comments", {"post_urn": "urn:li:ugcPost:1"}),
    ("get_org_analytics", {"org_id": "12345"}),
    ("get_post_analytics", {"org_id": "12345"}),
]


class TestOrgToolsGated:
    """With self-serve scopes, the 7 org tools raise a clear error before any HTTP."""

    @pytest.mark.parametrize(("tool_name", "arguments"), _ORG_TOOL_CALLS)
    async def test_org_tool_raises_actionable_error(self, linkedin_connector, tool_name, arguments):
        tool = getattr(linkedin_connector, tool_name)
        with pytest.raises(ValueError, match="Community Management API"):
            await tool(access_token="fake", **arguments)

    @pytest.mark.parametrize(("tool_name", "arguments"), _ORG_TOOL_CALLS)
    async def test_org_tool_does_not_call_http(self, linkedin_connector, tool_name, arguments):
        # The guard must fire before any outbound request.
        with (
            patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get,
            patch(
                "connectors.linkedin.adapter._linkedin_post", new_callable=AsyncMock
            ) as mock_post,
        ):
            tool = getattr(linkedin_connector, tool_name)
            with pytest.raises(ValueError, match="Community Management API"):
                await tool(access_token="fake", **arguments)
            mock_get.assert_not_called()
            mock_post.assert_not_called()

    async def test_org_tool_via_mcp_dispatch_is_rejected_as_unknown(self, linkedin_connector):
        # Through dispatch, the availability gate fires first, so an org tool is
        # rejected as unknown rather than reaching the _require_org_tools guard.
        # The call-time guard is still proven by the direct-call tests above.
        response = await linkedin_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "get_managed_orgs", "arguments": {}},
            request_id=10,
            access_token="fake",
        )
        assert response["error"]["code"] == -32602  # noqa: PLR2004 -- JSON-RPC invalid-params
        assert "Unknown tool" in response["error"]["message"]


# =============================================================================
# FINDING 1 — create_post / delete_post branch on the org-tier flag
# =============================================================================


class TestPostingPathSelection:
    """Default (org disabled) posts via /v2/; flag flips to /rest/ when enabled."""

    async def test_create_post_uses_v2_when_org_disabled(self, linkedin_connector):
        with (
            patch(
                "connectors.linkedin.adapter._resolve_author_urn", new_callable=AsyncMock
            ) as mock_resolve,
            patch("connectors.linkedin.adapter._create_post_v2", new_callable=AsyncMock) as mock_v2,
            patch(
                "connectors.linkedin.adapter._create_post_rest", new_callable=AsyncMock
            ) as mock_rest,
        ):
            mock_resolve.return_value = "urn:li:person:abc"
            mock_v2.return_value = {"id": "urn:li:share:1"}
            await linkedin_connector.create_post(access_token="fake", text="hello")

        mock_v2.assert_called_once()
        mock_rest.assert_not_called()

    async def test_create_post_uses_rest_when_org_enabled(self, linkedin_connector):
        with (
            patch("connectors.linkedin.adapter._ORG_TOOLS_ENABLED", True),
            patch(
                "connectors.linkedin.adapter._resolve_author_urn", new_callable=AsyncMock
            ) as mock_resolve,
            patch("connectors.linkedin.adapter._create_post_v2", new_callable=AsyncMock) as mock_v2,
            patch(
                "connectors.linkedin.adapter._create_post_rest", new_callable=AsyncMock
            ) as mock_rest,
        ):
            mock_resolve.return_value = "urn:li:organization:99"
            mock_rest.return_value = {"id": "urn:li:share:2"}
            await linkedin_connector.create_post(access_token="fake", text="hello")

        mock_rest.assert_called_once()
        mock_v2.assert_not_called()

    async def test_delete_post_uses_v2_path_when_org_disabled(self, linkedin_connector):
        with patch(
            "connectors.linkedin.adapter._linkedin_delete", new_callable=AsyncMock
        ) as mock_delete:
            await linkedin_connector.delete_post(access_token="fake", post_urn="urn:li:ugcPost:123")
        path = mock_delete.call_args.args[1]
        assert path.startswith("/v2/ugcPosts/")


# =============================================================================
# MEDIA POSTS — image/document tools upload then post via the versioned flow
# =============================================================================

# base64 of small placeholder bytes -- decodes cleanly, well under the size cap.
_FAKE_MEDIA_B64 = "aW1n"  # b"img"


class TestMediaPosts:
    """create_image_post / create_document_post: validate, upload, then post."""

    async def test_image_post_initializes_uploads_then_posts(self, linkedin_connector):
        with (
            patch(
                "connectors.linkedin.adapter._resolve_author_urn", new_callable=AsyncMock
            ) as mock_resolve,
            patch(
                "connectors.linkedin.adapter._initialize_media_upload", new_callable=AsyncMock
            ) as mock_init,
            patch(
                "connectors.linkedin.adapter._upload_media_binary", new_callable=AsyncMock
            ) as mock_upload,
            patch(
                "connectors.linkedin.adapter._linkedin_post", new_callable=AsyncMock
            ) as mock_post,
        ):
            mock_resolve.return_value = "urn:li:person:abc"
            mock_init.return_value = ("https://upload.example/u", "urn:li:image:1")
            mock_post.return_value = {"id": "urn:li:share:9"}
            content = await linkedin_connector.create_image_post(
                access_token="fake", text="hi", image_base64=_FAKE_MEDIA_B64, alt_text="a cat"
            )

        # Upload targets the /rest/images collection...
        assert mock_init.call_args.args[1] == "images"
        mock_upload.assert_awaited_once()
        # ...and the post references the returned image URN with the alt text.
        body = mock_post.call_args.args[2]
        assert body["content"]["media"] == {"id": "urn:li:image:1", "altText": "a cat"}
        assert json.loads(content[0]["text"]) == {"id": "urn:li:share:9"}

    async def test_document_post_uses_documents_collection_and_title(self, linkedin_connector):
        with (
            patch(
                "connectors.linkedin.adapter._resolve_author_urn", new_callable=AsyncMock
            ) as mock_resolve,
            patch(
                "connectors.linkedin.adapter._initialize_media_upload", new_callable=AsyncMock
            ) as mock_init,
            patch("connectors.linkedin.adapter._upload_media_binary", new_callable=AsyncMock),
            patch(
                "connectors.linkedin.adapter._linkedin_post", new_callable=AsyncMock
            ) as mock_post,
        ):
            mock_resolve.return_value = "urn:li:person:abc"
            mock_init.return_value = ("https://upload.example/u", "urn:li:document:2")
            mock_post.return_value = {"id": "urn:li:share:10"}
            await linkedin_connector.create_document_post(
                access_token="fake", text="deck", document_base64=_FAKE_MEDIA_B64, title="Q3 update"
            )

        assert mock_init.call_args.args[1] == "documents"
        body = mock_post.call_args.args[2]
        assert body["content"]["media"] == {"id": "urn:li:document:2", "title": "Q3 update"}

    async def test_document_post_requires_title(self, linkedin_connector):
        with pytest.raises(ValueError, match="title is required"):
            await linkedin_connector.create_document_post(
                access_token="fake", text="deck", document_base64=_FAKE_MEDIA_B64, title=""
            )

    async def test_image_post_rejects_oversize_text(self, linkedin_connector):
        with pytest.raises(ValueError, match="exceeds"):
            await linkedin_connector.create_image_post(
                access_token="fake", text="x" * 3001, image_base64=_FAKE_MEDIA_B64
            )


class TestDecodeMedia:
    """_decode_media is the real size/format gate (schema maxLength is advisory)."""

    def test_rejects_invalid_base64(self):
        from connectors.linkedin.adapter import _decode_media

        with pytest.raises(ValueError, match="not valid base64"):
            _decode_media("not-base64!!!", 1024, "image")

    def test_rejects_empty(self):
        from connectors.linkedin.adapter import _decode_media

        with pytest.raises(ValueError, match="empty"):
            _decode_media("", 1024, "image")

    def test_rejects_oversize(self):
        from connectors.linkedin.adapter import _decode_media

        # _FAKE_MEDIA_B64 decodes to 3 bytes -- over a 2-byte cap.
        with pytest.raises(ValueError, match="upload limit"):
            _decode_media(_FAKE_MEDIA_B64, 2, "document")

    def test_returns_bytes_within_limit(self):
        from connectors.linkedin.adapter import _decode_media

        assert _decode_media(_FAKE_MEDIA_B64, 1024, "image") == b"img"


# =============================================================================
# FINDING 2 — malformed org URNs in ACLs are validated out
# =============================================================================


class TestAclOrgIdValidation:
    def test_skips_malformed_urn_keeps_valid(self):
        from connectors.linkedin.adapter import _extract_org_ids_from_acls

        elements = [
            {"organizationTarget": "urn:li:organization:123/../evil"},
            {"organizationTarget": "urn:li:organization:456"},
        ]
        org_ids = _extract_org_ids_from_acls(elements)
        assert org_ids == ["456"]

    async def test_batch_fetch_only_requests_valid_org(self, linkedin_connector):
        # get_managed_orgs is gated; exercise the extraction + fetch helpers directly.
        from connectors.linkedin.adapter import _batch_fetch_orgs

        with patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"id": 456, "localizedName": "Acme"}
            await _batch_fetch_orgs("fake", ["456"])

        mock_get.assert_called_once()
        assert mock_get.call_args.args[1] == "/rest/organizations/456"


# =============================================================================
# FINDING 3 — session errors propagate, per-org permission errors degrade
# =============================================================================


class TestBatchFetchErrorHandling:
    async def test_permission_error_degrades_single_org(self):
        from connectors.linkedin.adapter import _batch_fetch_orgs

        with patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [
                {"id": 1, "localizedName": "First"},
                ValueError("Insufficient scope for this operation"),
            ]
            orgs = await _batch_fetch_orgs("fake", ["1", "2"])

        assert orgs[0]["name"] == "First"
        # Second org degrades to URN-only rather than failing the whole batch.
        assert orgs[1] == {
            "org_id": "2",
            "org_urn": "urn:li:organization:2",
            "name": None,
            "vanity_name": None,
        }

    async def test_session_error_propagates_and_stops_batch(self):
        from connectors.linkedin.adapter import _batch_fetch_orgs, _SessionError

        with patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [
                {"id": 1, "localizedName": "First"},
                _SessionError("LinkedIn token expired or revoked"),
            ]
            with pytest.raises(_SessionError, match="token expired"):
                await _batch_fetch_orgs("fake", ["1", "2", "3"])

        # Stopped at org 2 — never reached org 3.
        assert mock_get.call_count == 2  # noqa: PLR2004 -- two orgs attempted before raise

    async def test_check_status_raises_session_error_on_401(self):
        from connectors.linkedin.adapter import _check_status, _SessionError

        response = _make_httpx_response(status_code=401)
        with pytest.raises(_SessionError, match="token expired"):
            _check_status(response)


# =============================================================================
# FINDING 4 — get_post_comments sends X-RestLi-Method: FINDER
# =============================================================================


class TestGetPostCommentsFinder:
    async def test_sends_finder_method(self, linkedin_connector):
        with (
            patch("connectors.linkedin.adapter._ORG_TOOLS_ENABLED", True),
            patch("connectors.linkedin.adapter._linkedin_get", new_callable=AsyncMock) as mock_get,
        ):
            mock_get.return_value = {"elements": []}
            await linkedin_connector.get_post_comments(
                access_token="fake", post_urn="urn:li:ugcPost:123"
            )

        assert mock_get.call_args.kwargs["restli_method"] == "FINDER"


# =============================================================================
# FINDING 5 — POST creates are NOT retried on 429 (non-idempotent)
# =============================================================================


class TestPostNotRetriedOn429:
    async def test_post_raises_on_429_without_second_call(self):
        from connectors.linkedin.adapter import _linkedin_post

        rate_limited = _make_httpx_response(status_code=429, headers={"Retry-After": "1"})
        ctx, post_mock = _patch_httpx("post", [rate_limited])
        with ctx, pytest.raises(ValueError, match="Rate limited"):
            await _linkedin_post("fake", "/rest/posts", {"commentary": "hi"})

        # Exactly one POST — no retry that could double-post.
        assert post_mock.call_count == 1

    async def test_get_still_retries_on_429(self):
        from connectors.linkedin.adapter import _linkedin_get

        rate_limited = _make_httpx_response(status_code=429, headers={"Retry-After": "0"})
        ok = _make_httpx_response(status_code=200, json_body={"elements": []})
        ctx, get_mock = _patch_httpx("get", [rate_limited, ok])
        with ctx, patch("connectors.linkedin.adapter.asyncio.sleep", new=AsyncMock()):
            body = await _linkedin_get("fake", "/rest/posts")

        assert body == {"elements": []}
        assert get_mock.call_count == 2  # noqa: PLR2004 -- first 429, then retry succeeds
