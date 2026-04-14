"""
Reddit Connector Unit Tests

Tests for: serialization helpers, OAuth config, auto-registration,
MCP dispatch, tool execution, input validation, and edge cases.
"""

from __future__ import annotations

import json
from typing import Any
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


# =============================================================================
# SERIALIZATION HELPERS
# =============================================================================


class TestSerializationHelpers:
    """Test module-level serialization helpers."""

    def test_extract_listing_children_normal(self):
        from connectors.reddit.adapter import _extract_listing_children

        listing = {
            "kind": "Listing",
            "data": {
                "children": [
                    {"kind": "t3", "data": {"id": "abc", "title": "Hello"}},
                    {"kind": "t3", "data": {"id": "def", "title": "World"}},
                ],
            },
        }
        children = _extract_listing_children(listing)
        assert len(children) == 2
        assert children[0]["data"]["id"] == "abc"

    def test_extract_listing_children_empty(self):
        from connectors.reddit.adapter import _extract_listing_children

        listing = {"kind": "Listing", "data": {"children": []}}
        assert _extract_listing_children(listing) == []

    def test_extract_listing_children_error_response(self):
        from connectors.reddit.adapter import _extract_listing_children

        assert _extract_listing_children({"error": 404}) == []

    def test_extract_listing_children_missing_data(self):
        from connectors.reddit.adapter import _extract_listing_children

        assert _extract_listing_children({}) == []

    def test_simplify_post(self):
        from connectors.reddit.adapter import _simplify_post

        raw = {
            "id": "abc123",
            "name": "t3_abc123",
            "title": "Test Post",
            "selftext": "Body text",
            "author": "testuser",
            "subreddit": "python",
            "score": 42,
            "num_comments": 5,
            "url": "https://reddit.com/r/python/...",
            "created_utc": 1700000000.0,
            "permalink": "/r/python/comments/abc123/test_post/",
            "is_self": True,
            "extra_field": "ignored",
        }
        simplified = _simplify_post(raw)
        assert simplified["id"] == "abc123"
        assert simplified["title"] == "Test Post"
        assert simplified["author"] == "testuser"
        assert "extra_field" not in simplified

    def test_simplify_comment(self):
        from connectors.reddit.adapter import _simplify_comment

        raw = {
            "id": "xyz789",
            "name": "t1_xyz789",
            "body": "Great post!",
            "author": "commenter",
            "score": 10,
            "created_utc": 1700000000.0,
            "parent_id": "t3_abc123",
            "permalink": "/r/python/comments/abc123/.../xyz789/",
            "extra": "ignored",
        }
        simplified = _simplify_comment(raw)
        assert simplified["id"] == "xyz789"
        assert simplified["body"] == "Great post!"
        assert "extra" not in simplified

    def test_simplify_post_deleted_author(self):
        from connectors.reddit.adapter import _simplify_post

        raw = {"id": "abc", "title": "Test", "author": None}
        assert _simplify_post(raw)["author"] == "[deleted]"

    def test_simplify_comment_deleted_author(self):
        from connectors.reddit.adapter import _simplify_comment

        raw = {"id": "xyz", "body": "text", "author": None}
        assert _simplify_comment(raw)["author"] == "[deleted]"

    def test_clamp_limit_caps_at_max(self):
        from connectors.reddit.adapter import _clamp_limit

        assert _clamp_limit(200) == 100

    def test_clamp_limit_floors_at_1(self):
        from connectors.reddit.adapter import _clamp_limit

        assert _clamp_limit(0) == 1
        assert _clamp_limit(-5) == 1

    def test_clamp_limit_passes_through_valid(self):
        from connectors.reddit.adapter import _clamp_limit

        assert _clamp_limit(50) == 50

    def test_mcp_text_content_format(self):
        from connectors.reddit.adapter import _mcp_text_content

        blocks = _mcp_text_content({"key": "value"})
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert json.loads(blocks[0]["text"]) == {"key": "value"}


# =============================================================================
# INPUT VALIDATION
# =============================================================================


class TestInputValidation:
    """Test path traversal prevention in URL-interpolated parameters."""

    def test_valid_subreddit(self):
        from connectors.reddit.adapter import _validate_subreddit

        _validate_subreddit("python")
        _validate_subreddit("Ask_Reddit")
        _validate_subreddit("A" * 50)

    def test_subreddit_rejects_path_traversal(self):
        from connectors.reddit.adapter import _validate_subreddit

        with pytest.raises(ValueError, match="Invalid subreddit"):
            _validate_subreddit("../../api/v1/me")

    def test_subreddit_rejects_slashes(self):
        from connectors.reddit.adapter import _validate_subreddit

        with pytest.raises(ValueError, match="Invalid subreddit"):
            _validate_subreddit("r/python")

    def test_subreddit_rejects_empty(self):
        from connectors.reddit.adapter import _validate_subreddit

        with pytest.raises(ValueError, match="Invalid subreddit"):
            _validate_subreddit("")

    def test_valid_post_id(self):
        from connectors.reddit.adapter import _validate_post_id

        _validate_post_id("abc123")
        _validate_post_id("z9")

    def test_post_id_rejects_path_traversal(self):
        from connectors.reddit.adapter import _validate_post_id

        with pytest.raises(ValueError, match="Invalid post ID"):
            _validate_post_id("../api/v1/me")

    def test_post_id_rejects_uppercase(self):
        from connectors.reddit.adapter import _validate_post_id

        with pytest.raises(ValueError, match="Invalid post ID"):
            _validate_post_id("ABC123")

    def test_valid_fullname(self):
        from connectors.reddit.adapter import _validate_fullname

        _validate_fullname("t3_abc123")
        _validate_fullname("t1_xyz")

    def test_fullname_rejects_invalid_prefix(self):
        from connectors.reddit.adapter import _validate_fullname

        with pytest.raises(ValueError, match="Invalid fullname"):
            _validate_fullname("t9_abc")

    def test_fullname_rejects_no_prefix(self):
        from connectors.reddit.adapter import _validate_fullname

        with pytest.raises(ValueError, match="Invalid fullname"):
            _validate_fullname("abc123")

    async def test_search_validates_subreddit(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid subreddit"):
            await reddit_connector.search(
                access_token="fake", query="test", subreddit="../../api/v1/me"
            )

    async def test_get_subreddit_posts_validates_subreddit(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid subreddit"):
            await reddit_connector.get_subreddit_posts(
                access_token="fake", subreddit="../../api/v1/me"
            )

    async def test_get_post_comments_validates_post_id(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid post ID"):
            await reddit_connector.get_post_comments(access_token="fake", post_id="../api/v1/me")

    async def test_submit_post_validates_subreddit(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid subreddit"):
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="../../evil",
                title="Test",
                kind="self",
                text="body",
            )

    async def test_add_comment_validates_parent(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid fullname"):
            await reddit_connector.add_comment(access_token="fake", parent="not_valid", text="hi")

    async def test_delete_validates_fullname(self, reddit_connector):
        with pytest.raises(ValueError, match="Invalid fullname"):
            await reddit_connector.delete(access_token="fake", fullname="../../evil")


# =============================================================================
# ASYNC API HELPERS
# =============================================================================


def _mock_httpx_response(
    status_code: int = 200, json_data: Any = None, headers: dict | None = None
) -> MagicMock:
    """Create a mock httpx response (sync methods like .json() and .raise_for_status())."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.headers = headers or {}
    return response


class TestAsyncApiHelpers:
    """Test _reddit_get and _reddit_post wrappers."""

    async def test_reddit_get_adds_auth_and_user_agent(self):
        from connectors.reddit.adapter import REDDIT_USER_AGENT, _reddit_get

        mock_response = _mock_httpx_response(200, {"data": "test"})

        with patch("connectors.reddit.adapter.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            await _reddit_get("fake_token", "/api/v1/me")

        call_kwargs = mock_client.get.call_args
        assert call_kwargs.kwargs["headers"]["Authorization"] == "bearer fake_token"
        assert call_kwargs.kwargs["headers"]["User-Agent"] == REDDIT_USER_AGENT

    async def test_reddit_get_raises_on_401(self):
        from connectors.reddit.adapter import _reddit_get

        mock_response = _mock_httpx_response(401)

        with patch("connectors.reddit.adapter.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            with pytest.raises(ValueError, match="token expired or revoked"):
                await _reddit_get("bad_token", "/api/v1/me")

    async def test_reddit_get_retries_on_429(self):
        from connectors.reddit.adapter import _reddit_get

        mock_429 = _mock_httpx_response(429, headers={"Retry-After": "1"})
        mock_200 = _mock_httpx_response(200, {"success": True})

        with patch("connectors.reddit.adapter.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=[mock_429, mock_200])
            mock_client_cls.return_value = mock_client

            with patch(
                "connectors.reddit.adapter.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                result = await _reddit_get("token", "/test")

            mock_sleep.assert_called_once_with(1.0)
            assert result == {"success": True}

    async def test_reddit_get_raises_on_double_429(self):
        from connectors.reddit.adapter import _reddit_get

        mock_429 = _mock_httpx_response(429, headers={"Retry-After": "1"})

        with patch("connectors.reddit.adapter.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_429)
            mock_client_cls.return_value = mock_client

            with patch("connectors.reddit.adapter.asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(ValueError, match="Rate limited"):
                    await _reddit_get("token", "/test")

    async def test_reddit_post_sends_form_fields(self):
        from connectors.reddit.adapter import _reddit_post

        mock_response = _mock_httpx_response(200, {"success": True})

        with patch("connectors.reddit.adapter.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            await _reddit_post("token", "/api/submit", {"sr": "python", "title": "Test"})

        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs["data"] == {"sr": "python", "title": "Test"}


# =============================================================================
# FIXTURES (Reddit connector)
# =============================================================================


@pytest.fixture
def reddit_connector():
    """Import the Reddit adapter and re-register if the registry was cleared."""
    from connectors.reddit.adapter import RedditConnector

    connector = ConnectorRegistry.get("reddit")
    if connector is None:
        ConnectorRegistry.auto_register(RedditConnector)
        connector = ConnectorRegistry.get("reddit")
    assert connector is not None
    return connector


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Verify the connector auto-registers with correct metadata."""

    def test_auto_registers_with_name_reddit(self, reddit_connector):
        assert reddit_connector.meta.name == "reddit"

    def test_display_name(self, reddit_connector):
        assert reddit_connector.meta.display_name == "Reddit"

    def test_has_seven_tools(self, reddit_connector):
        assert len(reddit_connector._tools) == 7

    def test_tool_names(self, reddit_connector):
        expected = {
            "get_me",
            "submit_post",
            "add_comment",
            "search",
            "get_subreddit_posts",
            "get_post_comments",
            "delete",
        }
        assert set(reddit_connector._tools.keys()) == expected

    def test_authorize_url(self, reddit_connector):
        assert (
            reddit_connector.meta.oauth_authorize_url == "https://www.reddit.com/api/v1/authorize"
        )

    def test_token_url(self, reddit_connector):
        assert "api/v1/access_token" in reddit_connector.meta.oauth_token_url

    def test_scopes_include_identity(self, reddit_connector):
        assert "identity" in reddit_connector.meta.scopes

    def test_scopes_include_read(self, reddit_connector):
        assert "read" in reddit_connector.meta.scopes

    def test_is_native_connector(self, reddit_connector):
        assert reddit_connector.meta.mcp_url is None
        assert reddit_connector.meta.is_native


# =============================================================================
# OAUTH — build_token_request_auth + customize_authorize_params
# =============================================================================


class TestOAuthAuth:
    """Reddit requires HTTP Basic Auth and duration=permanent."""

    def test_basic_auth_header_format(self, reddit_connector):
        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
        )
        headers, body_credentials = reddit_connector.build_token_request_auth(credentials)

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        assert body_credentials == {}

    def test_basic_auth_encodes_credentials(self, reddit_connector):
        from base64 import b64decode

        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="my_id",
            client_secret="my_secret",
        )
        headers, _ = reddit_connector.build_token_request_auth(credentials)
        encoded_part = headers["Authorization"].removeprefix("Basic ")
        decoded = b64decode(encoded_part).decode()
        assert decoded == "my_id:my_secret"

    def test_customize_authorize_params_adds_duration(self, reddit_connector):
        params = {"client_id": "abc", "scope": "identity read"}
        result = reddit_connector.customize_authorize_params(params)
        assert result["duration"] == "permanent"
        assert result["client_id"] == "abc"


# =============================================================================
# MCP DISPATCH
# =============================================================================


class TestMCPDispatch:
    """Verify JSON-RPC dispatch for standard MCP methods."""

    async def test_initialize_returns_server_info(self, reddit_connector):
        response = await reddit_connector.handle_mcp_request(
            method="initialize",
            params={},
            request_id=1,
            access_token="fake",
        )
        assert response["jsonrpc"] == "2.0"
        assert response["result"]["serverInfo"]["name"] == "reddit"

    async def test_tools_list_returns_seven(self, reddit_connector):
        response = await reddit_connector.handle_mcp_request(
            method="tools/list",
            params={},
            request_id=2,
            access_token="fake",
        )
        assert len(response["result"]["tools"]) == 7

    async def test_unknown_method_returns_error(self, reddit_connector):
        response = await reddit_connector.handle_mcp_request(
            method="resources/list",
            params={},
            request_id=3,
            access_token="fake",
        )
        assert response["error"]["code"] == -32601

    async def test_ping_returns_ok(self, reddit_connector):
        response = await reddit_connector.handle_mcp_request(
            method="ping",
            params={},
            request_id=4,
            access_token="fake",
        )
        assert response["result"] == {}


# =============================================================================
# TOOL: get_me
# =============================================================================


class TestGetMe:
    """Tests for the get_me tool."""

    async def test_returns_user_profile(self, reddit_connector):
        mock_profile = {
            "name": "testuser",
            "link_karma": 100,
            "comment_karma": 200,
        }
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_profile
            content = await reddit_connector.get_me(access_token="fake_token")

        mock_get.assert_called_once_with("fake_token", "/api/v1/me")
        parsed = json.loads(content[0]["text"])
        assert parsed["name"] == "testuser"

    async def test_dispatch_via_mcp(self, reddit_connector):
        mock_profile = {"name": "testuser"}
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_profile
            response = await reddit_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "get_me", "arguments": {}},
                request_id=10,
                access_token="fake_token",
            )

        assert "result" in response
        assert len(response["result"]["content"]) == 1


# =============================================================================
# TOOL: search
# =============================================================================


class TestSearch:
    """Tests for the search tool."""

    async def test_searches_all_reddit(self, reddit_connector):
        mock_listing = {
            "kind": "Listing",
            "data": {"children": [{"kind": "t3", "data": {"id": "s1", "title": "Python tips"}}]},
        }
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_listing
            await reddit_connector.search(
                access_token="fake",
                query="python",
                limit=5,
            )

        call_kwargs = mock_get.call_args
        assert call_kwargs.args[1] == "/search"
        assert call_kwargs.kwargs["q"] == "python"

    async def test_searches_within_subreddit(self, reddit_connector):
        mock_listing = {"kind": "Listing", "data": {"children": []}}
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_listing
            await reddit_connector.search(
                access_token="fake",
                query="tips",
                subreddit="python",
            )

        call_kwargs = mock_get.call_args
        assert call_kwargs.args[1] == "/r/python/search"
        assert call_kwargs.kwargs["restrict_sr"] == "true"

    async def test_clamps_limit(self, reddit_connector):
        mock_listing = {"kind": "Listing", "data": {"children": []}}
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_listing
            await reddit_connector.search(access_token="fake", query="test", limit=500)

        assert mock_get.call_args.kwargs["limit"] == 100


# =============================================================================
# TOOL: get_subreddit_posts
# =============================================================================


class TestGetSubredditPosts:
    """Tests for the get_subreddit_posts tool."""

    async def test_gets_hot_posts(self, reddit_connector):
        mock_listing = {
            "kind": "Listing",
            "data": {"children": [{"kind": "t3", "data": {"id": "p1", "title": "Hot post"}}]},
        }
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_listing
            content = await reddit_connector.get_subreddit_posts(
                access_token="fake",
                subreddit="python",
            )

        mock_get.assert_called_once()
        assert mock_get.call_args.args[1] == "/r/python"
        assert mock_get.call_args.kwargs["sort"] == "hot"
        parsed = json.loads(content[0]["text"])
        assert len(parsed) == 1

    async def test_uses_specified_sort(self, reddit_connector):
        mock_listing = {"kind": "Listing", "data": {"children": []}}
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_listing
            await reddit_connector.get_subreddit_posts(
                access_token="fake",
                subreddit="python",
                sort="new",
            )

        assert mock_get.call_args.args[1] == "/r/python"
        assert mock_get.call_args.kwargs["sort"] == "new"


# =============================================================================
# TOOL: get_post_comments
# =============================================================================


class TestGetPostComments:
    """Tests for the get_post_comments tool."""

    async def test_gets_comments(self, reddit_connector):
        # Reddit returns [post_listing, comments_listing] for comment endpoints
        mock_response = [
            {"kind": "Listing", "data": {"children": []}},
            {
                "kind": "Listing",
                "data": {
                    "children": [
                        {
                            "kind": "t1",
                            "data": {
                                "id": "c1",
                                "body": "Nice!",
                                "author": "user1",
                            },
                        },
                    ],
                },
            },
        ]
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            content = await reddit_connector.get_post_comments(
                access_token="fake",
                post_id="abc123",
            )

        assert mock_get.call_args.args[1] == "/comments/abc123"
        parsed = json.loads(content[0]["text"])
        assert len(parsed) == 1
        assert parsed[0]["body"] == "Nice!"

    async def test_nested_replies(self, reddit_connector):
        mock_response = [
            {"kind": "Listing", "data": {"children": []}},
            {
                "kind": "Listing",
                "data": {
                    "children": [
                        {
                            "kind": "t1",
                            "data": {
                                "id": "c1",
                                "body": "Top",
                                "author": "user1",
                                "replies": {
                                    "kind": "Listing",
                                    "data": {
                                        "children": [
                                            {
                                                "kind": "t1",
                                                "data": {
                                                    "id": "c2",
                                                    "body": "Reply",
                                                    "author": "user2",
                                                },
                                            },
                                        ],
                                    },
                                },
                            },
                        },
                    ],
                },
            },
        ]
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            content = await reddit_connector.get_post_comments(
                access_token="fake",
                post_id="abc123",
                depth=3,
            )

        parsed = json.loads(content[0]["text"])
        assert parsed[0]["replies"][0]["body"] == "Reply"

    async def test_depth_1_skips_replies(self, reddit_connector):
        mock_response = [
            {"kind": "Listing", "data": {"children": []}},
            {
                "kind": "Listing",
                "data": {
                    "children": [
                        {
                            "kind": "t1",
                            "data": {
                                "id": "c1",
                                "body": "Top",
                                "author": "user1",
                                "replies": {
                                    "kind": "Listing",
                                    "data": {"children": []},
                                },
                            },
                        },
                    ],
                },
            },
        ]
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            content = await reddit_connector.get_post_comments(
                access_token="fake",
                post_id="abc123",
                depth=1,
            )

        parsed = json.loads(content[0]["text"])
        assert "replies" not in parsed[0]


# =============================================================================
# TOOL: submit_post
# =============================================================================


class TestSubmitPost:
    """Tests for the submit_post tool."""

    async def test_submits_text_post(self, reddit_connector):
        mock_response = {"json": {"data": {"name": "t3_new123", "url": "https://reddit.com/..."}}}
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="python",
                title="Test Post",
                kind="self",
                text="Hello world",
            )

        call_kwargs = mock_post.call_args
        assert call_kwargs.args[2]["sr"] == "python"
        assert call_kwargs.args[2]["kind"] == "self"
        assert call_kwargs.args[2]["text"] == "Hello world"

    async def test_submits_link_post(self, reddit_connector):
        mock_response = {"json": {"data": {"name": "t3_link1"}}}
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="python",
                title="Cool Link",
                kind="link",
                url="https://example.com",
            )

        assert mock_post.call_args.args[2]["url"] == "https://example.com"

    async def test_rejects_title_over_300_chars(self, reddit_connector):
        with pytest.raises(ValueError, match="exceeds 300 characters"):
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="test",
                title="x" * 301,
                kind="self",
                text="body",
            )

    async def test_rejects_link_without_url(self, reddit_connector):
        with pytest.raises(ValueError, match="url is required"):
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="test",
                title="Link Post",
                kind="link",
            )

    async def test_rejects_self_without_text(self, reddit_connector):
        with pytest.raises(ValueError, match="text is required"):
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="test",
                title="Text Post",
                kind="self",
            )

    async def test_rejects_text_over_40000_chars(self, reddit_connector):
        with pytest.raises(ValueError, match="exceeds 40000 characters"):
            await reddit_connector.submit_post(
                access_token="fake",
                subreddit="test",
                title="Long Post",
                kind="self",
                text="x" * 40_001,
            )

    async def test_does_not_call_api_on_validation_error(self, reddit_connector):
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            with pytest.raises(ValueError):
                await reddit_connector.submit_post(
                    access_token="fake",
                    subreddit="test",
                    title="x" * 301,
                    kind="self",
                    text="body",
                )
            mock_post.assert_not_called()

    async def test_dispatch_via_mcp(self, reddit_connector):
        mock_response = {"json": {"data": {"name": "t3_new"}}}
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            response = await reddit_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "submit_post",
                    "arguments": {
                        "subreddit": "test",
                        "title": "Test",
                        "kind": "self",
                        "text": "body",
                    },
                },
                request_id=20,
                access_token="fake",
            )

        assert "result" in response
        assert "isError" not in response["result"]


# =============================================================================
# TOOL: add_comment
# =============================================================================


class TestAddComment:
    """Tests for the add_comment tool."""

    async def test_adds_comment(self, reddit_connector):
        mock_response = {
            "json": {"data": {"things": [{"data": {"id": "new_comment", "name": "t1_new"}}]}},
        }
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            await reddit_connector.add_comment(
                access_token="fake",
                parent="t3_abc123",
                text="Great post!",
            )

        call_kwargs = mock_post.call_args
        assert call_kwargs.args[2]["parent"] == "t3_abc123"
        assert call_kwargs.args[2]["text"] == "Great post!"

    async def test_rejects_comment_over_10000_chars(self, reddit_connector):
        with pytest.raises(ValueError, match="exceeds 10000 characters"):
            await reddit_connector.add_comment(
                access_token="fake",
                parent="t3_abc",
                text="x" * 10_001,
            )

    async def test_does_not_call_api_on_validation_error(self, reddit_connector):
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            with pytest.raises(ValueError):
                await reddit_connector.add_comment(
                    access_token="fake",
                    parent="t3_abc",
                    text="x" * 10_001,
                )
            mock_post.assert_not_called()

    async def test_dispatch_via_mcp(self, reddit_connector):
        mock_response = {"json": {"data": {"things": [{"data": {"id": "c1"}}]}}}
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            response = await reddit_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "add_comment",
                    "arguments": {"parent": "t3_abc", "text": "Nice!"},
                },
                request_id=25,
                access_token="fake",
            )

        assert "result" in response
        assert "isError" not in response["result"]


# =============================================================================
# TOOL: delete
# =============================================================================


class TestDelete:
    """Tests for the delete tool."""

    async def test_deletes_post(self, reddit_connector):
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {}
            content = await reddit_connector.delete(
                access_token="fake",
                fullname="t3_abc123",
            )

        assert mock_post.call_args.args[2]["id"] == "t3_abc123"
        parsed = json.loads(content[0]["text"])
        assert parsed["fullname"] == "t3_abc123"
        assert parsed["deleted"] is True

    async def test_dispatch_via_mcp(self, reddit_connector):
        with patch("connectors.reddit.adapter._reddit_post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {}
            response = await reddit_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "delete",
                    "arguments": {"fullname": "t1_xyz"},
                },
                request_id=30,
                access_token="fake",
            )

        assert "result" in response
        assert "isError" not in response["result"]


# =============================================================================
# TOOL DISPATCH — unknown tool + exception handling
# =============================================================================


class TestToolDispatchErrors:
    """Verify error handling in tool dispatch."""

    async def test_unknown_tool_returns_error(self, reddit_connector):
        response = await reddit_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "nonexistent", "arguments": {}},
            request_id=50,
            access_token="fake",
        )
        assert response["error"]["code"] == -32602

    async def test_tool_exception_returns_is_error(self, reddit_connector):
        with patch("connectors.reddit.adapter._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = RuntimeError("API error")
            response = await reddit_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "get_me", "arguments": {}},
                request_id=51,
                access_token="fake",
            )

        assert response["result"]["isError"] is True
        assert "API error" in response["result"]["content"][0]["text"]
