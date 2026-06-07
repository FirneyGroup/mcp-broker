"""
Twitter/X Connector Unit Tests

Tests for: auto-registration, OAuth config, MCP dispatch, tool execution,
input validation, and edge cases.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

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
def twitter_connector():
    """Import the Twitter adapter and re-register if the registry was cleared."""
    from connectors.twitter.adapter import TwitterConnector

    connector = ConnectorRegistry.get("twitter")
    if connector is None:
        ConnectorRegistry.auto_register(TwitterConnector)
        connector = ConnectorRegistry.get("twitter")
    assert connector is not None
    return connector


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Verify the connector auto-registers with correct metadata."""

    def test_auto_registers_with_name_twitter(self, twitter_connector):
        assert twitter_connector.meta.name == "twitter"

    def test_display_name(self, twitter_connector):
        assert twitter_connector.meta.display_name == "Twitter/X"

    def test_has_seven_tools(self, twitter_connector):
        assert len(twitter_connector._tools) == 7

    def test_tool_names(self, twitter_connector):
        expected_names = {
            "post_tweet",
            "get_me",
            "delete_tweet",
            "get_my_tweets",
            "search_tweets",
            "post_thread",
            "reply_to_tweet",
        }
        actual_names = set(twitter_connector._tools.keys())
        assert actual_names == expected_names

    def test_authorize_url_contains_x_dot_com(self, twitter_connector):
        assert "x.com" in twitter_connector.meta.oauth_authorize_url

    def test_token_url_contains_api_x_dot_com(self, twitter_connector):
        assert "api.x.com" in twitter_connector.meta.oauth_token_url

    def test_scopes_include_offline_access(self, twitter_connector):
        assert "offline.access" in twitter_connector.meta.scopes

    def test_scopes_include_tweet_write(self, twitter_connector):
        assert "tweet.write" in twitter_connector.meta.scopes

    def test_scopes_include_tweet_read(self, twitter_connector):
        assert "tweet.read" in twitter_connector.meta.scopes

    def test_scopes_include_users_read(self, twitter_connector):
        assert "users.read" in twitter_connector.meta.scopes

    def test_is_native_connector(self, twitter_connector):
        assert twitter_connector.meta.mcp_url is None
        assert twitter_connector.meta.is_native


# =============================================================================
# OAUTH — build_token_request_auth
# =============================================================================


class TestOAuthAuth:
    """X requires HTTP Basic Auth for token exchange."""

    def test_basic_auth_header_format(self, twitter_connector):
        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
        )
        headers, body_credentials = twitter_connector.build_token_request_auth(credentials)

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        assert body_credentials == {}

    def test_basic_auth_encodes_credentials(self, twitter_connector):
        from base64 import b64decode

        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(
            client_id="my_id",
            client_secret="my_secret",
        )
        headers, _ = twitter_connector.build_token_request_auth(credentials)
        encoded_part = headers["Authorization"].removeprefix("Basic ")
        decoded = b64decode(encoded_part).decode()
        assert decoded == "my_id:my_secret"


# =============================================================================
# MCP DISPATCH — initialize, tools/list, unknown method
# =============================================================================


class TestMCPDispatch:
    """Verify JSON-RPC dispatch for standard MCP methods."""

    async def test_initialize_returns_server_info(self, twitter_connector):
        response = await twitter_connector.handle_mcp_request(
            method="initialize",
            params={},
            request_id=1,
            access_token="fake_token",
        )
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        server_info = response["result"]["serverInfo"]
        assert server_info["name"] == "twitter"

    async def test_tools_list_returns_all_seven(self, twitter_connector):
        response = await twitter_connector.handle_mcp_request(
            method="tools/list",
            params={},
            request_id=2,
            access_token="fake_token",
        )
        tool_names = [t["name"] for t in response["result"]["tools"]]
        assert len(tool_names) == 7
        assert "post_tweet" in tool_names
        assert "post_thread" in tool_names
        assert "reply_to_tweet" in tool_names

    async def test_unknown_method_returns_error(self, twitter_connector):
        response = await twitter_connector.handle_mcp_request(
            method="resources/list",
            params={},
            request_id=3,
            access_token="fake_token",
        )
        assert "error" in response
        assert response["error"]["code"] == -32601

    async def test_ping_returns_ok(self, twitter_connector):
        response = await twitter_connector.handle_mcp_request(
            method="ping",
            params={},
            request_id=4,
            access_token="fake_token",
        )
        assert response["result"] == {}


# =============================================================================
# TOOL: post_tweet
# =============================================================================


class TestPostTweet:
    """Tests for the post_tweet tool."""

    async def test_posts_tweet_successfully(self, twitter_connector):
        mock_response = {"data": {"id": "123456", "text": "Hello world"}}
        with patch("connectors.twitter.adapter._post_tweet_sync") as mock_post:
            mock_post.return_value = mock_response
            content_blocks = await twitter_connector.post_tweet(
                access_token="fake_token", text="Hello world"
            )

        mock_post.assert_called_once_with("fake_token", "Hello world")
        assert len(content_blocks) == 1
        assert content_blocks[0]["type"] == "text"
        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["data"]["id"] == "123456"

    async def test_rejects_text_over_280_chars(self, twitter_connector):
        long_text = "x" * 281
        with pytest.raises(ValueError, match="exceeds 280 characters"):
            await twitter_connector.post_tweet(access_token="fake_token", text=long_text)

    async def test_allows_exactly_280_chars(self, twitter_connector):
        text_280 = "x" * 280
        mock_response = {"data": {"id": "999", "text": text_280}}
        with patch("connectors.twitter.adapter._post_tweet_sync") as mock_post:
            mock_post.return_value = mock_response
            content_blocks = await twitter_connector.post_tweet(
                access_token="fake_token", text=text_280
            )

        assert len(content_blocks) == 1

    async def test_does_not_call_xdk_on_validation_error(self, twitter_connector):
        with patch("connectors.twitter.adapter._post_tweet_sync") as mock_post:
            with pytest.raises(ValueError):
                await twitter_connector.post_tweet(access_token="fake_token", text="x" * 281)
            mock_post.assert_not_called()

    async def test_dispatch_via_mcp(self, twitter_connector):
        """Verify post_tweet works through handle_mcp_request dispatch."""
        mock_response = {"data": {"id": "789", "text": "dispatched"}}
        with patch("connectors.twitter.adapter._post_tweet_sync") as mock_post:
            mock_post.return_value = mock_response
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "post_tweet", "arguments": {"text": "dispatched"}},
                request_id=10,
                access_token="fake_token",
            )

        assert "result" in response
        assert len(response["result"]["content"]) == 1


# =============================================================================
# TOOL: get_me
# =============================================================================


class TestGetMe:
    """Tests for the get_me tool."""

    async def test_returns_user_profile(self, twitter_connector):
        mock_profile = {"id": "111", "username": "testuser", "name": "Test User"}
        with patch("connectors.twitter.adapter._get_me_sync") as mock_get:
            mock_get.return_value = mock_profile
            content_blocks = await twitter_connector.get_me(access_token="fake_token")

        mock_get.assert_called_once_with("fake_token")
        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["username"] == "testuser"

    async def test_dispatch_via_mcp(self, twitter_connector):
        mock_profile = {"id": "111", "username": "testuser", "name": "Test User"}
        with patch("connectors.twitter.adapter._get_me_sync") as mock_get:
            mock_get.return_value = mock_profile
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "get_me", "arguments": {}},
                request_id=20,
                access_token="fake_token",
            )

        assert "result" in response
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed["id"] == "111"


# =============================================================================
# TOOL: delete_tweet
# =============================================================================


class TestDeleteTweet:
    """Tests for the delete_tweet tool."""

    async def test_deletes_tweet_successfully(self, twitter_connector):
        mock_deletion = {"tweet_id": "456", "deleted": True}
        with patch("connectors.twitter.adapter._delete_tweet_sync") as mock_delete:
            mock_delete.return_value = mock_deletion
            content_blocks = await twitter_connector.delete_tweet(
                access_token="fake_token", tweet_id="456"
            )

        mock_delete.assert_called_once_with("fake_token", "456")
        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["deleted"] is True
        assert parsed["tweet_id"] == "456"

    async def test_dispatch_via_mcp(self, twitter_connector):
        mock_deletion = {"tweet_id": "456", "deleted": True}
        with patch("connectors.twitter.adapter._delete_tweet_sync") as mock_delete:
            mock_delete.return_value = mock_deletion
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "delete_tweet", "arguments": {"tweet_id": "456"}},
                request_id=30,
                access_token="fake_token",
            )

        assert "result" in response
        assert "isError" not in response["result"]


# =============================================================================
# TOOL: get_my_tweets
# =============================================================================


class TestGetMyTweets:
    """Tests for the get_my_tweets tool."""

    async def test_returns_tweets(self, twitter_connector):
        mock_tweets = [
            {"id": "t1", "text": "First tweet"},
            {"id": "t2", "text": "Second tweet"},
        ]
        with patch("connectors.twitter.adapter._get_my_tweets_sync") as mock_get:
            mock_get.return_value = mock_tweets
            content_blocks = await twitter_connector.get_my_tweets(
                access_token="fake_token", max_results=5
            )

        mock_get.assert_called_once_with("fake_token", 5)
        parsed = json.loads(content_blocks[0]["text"])
        assert len(parsed) == 2

    async def test_caps_max_results_at_100(self, twitter_connector):
        with patch("connectors.twitter.adapter._get_my_tweets_sync") as mock_get:
            mock_get.return_value = []
            await twitter_connector.get_my_tweets(access_token="fake_token", max_results=500)

        mock_get.assert_called_once_with("fake_token", 100)

    async def test_clamps_negative_to_one(self, twitter_connector):
        with patch("connectors.twitter.adapter._get_my_tweets_sync") as mock_get:
            mock_get.return_value = []
            await twitter_connector.get_my_tweets(access_token="fake_token", max_results=-5)

        mock_get.assert_called_once_with("fake_token", 1)

    async def test_default_max_results(self, twitter_connector):
        with patch("connectors.twitter.adapter._get_my_tweets_sync") as mock_get:
            mock_get.return_value = []
            await twitter_connector.get_my_tweets(access_token="fake_token")

        mock_get.assert_called_once_with("fake_token", 10)


# =============================================================================
# TOOL: search_tweets
# =============================================================================


class TestSearchTweets:
    """Tests for the search_tweets tool."""

    async def test_searches_tweets(self, twitter_connector):
        mock_tweets = [{"id": "s1", "text": "Python is great"}]
        with patch("connectors.twitter.adapter._search_tweets_sync") as mock_search:
            mock_search.return_value = mock_tweets
            content_blocks = await twitter_connector.search_tweets(
                access_token="fake_token", query="python", max_results=10
            )

        mock_search.assert_called_once_with("fake_token", "python", 10)
        parsed = json.loads(content_blocks[0]["text"])
        assert len(parsed) == 1
        assert parsed[0]["text"] == "Python is great"

    async def test_caps_max_results_at_100(self, twitter_connector):
        with patch("connectors.twitter.adapter._search_tweets_sync") as mock_search:
            mock_search.return_value = []
            await twitter_connector.search_tweets(
                access_token="fake_token", query="test", max_results=200
            )

        mock_search.assert_called_once_with("fake_token", "test", 100)

    async def test_default_max_results(self, twitter_connector):
        with patch("connectors.twitter.adapter._search_tweets_sync") as mock_search:
            mock_search.return_value = []
            await twitter_connector.search_tweets(access_token="fake_token", query="test")

        mock_search.assert_called_once_with("fake_token", "test", 10)

    async def test_dispatch_via_mcp(self, twitter_connector):
        mock_tweets = [{"id": "s1", "text": "MCP tweet"}]
        with patch("connectors.twitter.adapter._search_tweets_sync") as mock_search:
            mock_search.return_value = mock_tweets
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "search_tweets",
                    "arguments": {"query": "mcp", "max_results": 5},
                },
                request_id=40,
                access_token="fake_token",
            )

        assert "result" in response
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed[0]["id"] == "s1"


# =============================================================================
# TOOL: post_thread
# =============================================================================


class TestPostThread:
    """Tests for the post_thread tool (handler validation + result wrapping)."""

    def test_schema_advertises_max_thread_tweets(self, twitter_connector):
        """The LLM-facing tools/list schema must publish the same ceiling the validator enforces."""
        from connectors.twitter.adapter import MAX_THREAD_TWEETS

        tweets_schema = twitter_connector._tools["post_thread"].meta.input_schema["properties"][
            "tweets"
        ]
        assert tweets_schema["maxItems"] == MAX_THREAD_TWEETS

    async def test_posts_thread_successfully(self, twitter_connector):
        mock_outcome = {
            "status": "complete",
            "count": 2,
            "thread": [{"id": "1", "text": "a"}, {"id": "2", "text": "b"}],
        }
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            mock_thread.return_value = mock_outcome
            content_blocks = await twitter_connector.post_thread(
                access_token="fake_token", tweets=["a", "b"]
            )

        mock_thread.assert_called_once_with("fake_token", ["a", "b"])
        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["status"] == "complete"
        assert parsed["count"] == 2

    async def test_rejects_empty_list(self, twitter_connector):
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            with pytest.raises(ValueError, match="non-empty list"):
                await twitter_connector.post_thread(access_token="fake_token", tweets=[])
            mock_thread.assert_not_called()

    async def test_rejects_over_length_tweet(self, twitter_connector):
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            with pytest.raises(ValueError, match="exceeds 280 characters"):
                await twitter_connector.post_thread(
                    access_token="fake_token", tweets=["ok", "x" * 281]
                )
            mock_thread.assert_not_called()

    async def test_rejects_too_many_tweets(self, twitter_connector):
        from connectors.twitter.adapter import MAX_THREAD_TWEETS

        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            with pytest.raises(ValueError, match="exceeds"):
                await twitter_connector.post_thread(
                    access_token="fake_token", tweets=["x"] * (MAX_THREAD_TWEETS + 1)
                )
            mock_thread.assert_not_called()

    async def test_rejects_empty_tweet_text(self, twitter_connector):
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            with pytest.raises(ValueError, match="is empty"):
                await twitter_connector.post_thread(access_token="fake_token", tweets=["ok", "   "])
            mock_thread.assert_not_called()

    async def test_surfaces_partial_status(self, twitter_connector):
        mock_outcome = {
            "status": "partial",
            "posted": [{"id": "1", "text": "a"}],
            "failed_at_index": 1,
            "error": "rate limited",
        }
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            mock_thread.return_value = mock_outcome
            content_blocks = await twitter_connector.post_thread(
                access_token="fake_token", tweets=["a", "b"]
            )

        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["status"] == "partial"
        assert parsed["posted"][0]["id"] == "1"

    async def test_dispatch_via_mcp(self, twitter_connector):
        mock_outcome = {"status": "complete", "count": 1, "thread": [{"id": "9", "text": "x"}]}
        with patch("connectors.twitter.adapter._post_thread_sync") as mock_thread:
            mock_thread.return_value = mock_outcome
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "post_thread", "arguments": {"tweets": ["x"]}},
                request_id=60,
                access_token="fake_token",
            )

        assert "result" in response
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed["thread"][0]["id"] == "9"


# =============================================================================
# TOOL: reply_to_tweet
# =============================================================================


class TestReplyToTweet:
    """Tests for the reply_to_tweet tool."""

    async def test_rejects_empty_text(self, twitter_connector):
        with patch("connectors.twitter.adapter._reply_to_tweet_sync") as mock_reply_sync:
            with pytest.raises(ValueError, match="empty"):
                await twitter_connector.reply_to_tweet(
                    access_token="fake_token", text="   ", tweet_id="123"
                )
            mock_reply_sync.assert_not_called()

    async def test_replies_successfully(self, twitter_connector):
        mock_reply = {"data": {"id": "555", "text": "nice"}}
        with patch("connectors.twitter.adapter._reply_to_tweet_sync") as mock_reply_sync:
            mock_reply_sync.return_value = mock_reply
            content_blocks = await twitter_connector.reply_to_tweet(
                access_token="fake_token", text="nice", tweet_id="123"
            )

        mock_reply_sync.assert_called_once_with("fake_token", "nice", "123")
        parsed = json.loads(content_blocks[0]["text"])
        assert parsed["data"]["id"] == "555"

    async def test_rejects_over_length(self, twitter_connector):
        with patch("connectors.twitter.adapter._reply_to_tweet_sync") as mock_reply_sync:
            with pytest.raises(ValueError, match="exceeds 280 characters"):
                await twitter_connector.reply_to_tweet(
                    access_token="fake_token", text="x" * 281, tweet_id="123"
                )
            mock_reply_sync.assert_not_called()

    async def test_rejects_invalid_tweet_id(self, twitter_connector):
        with patch("connectors.twitter.adapter._reply_to_tweet_sync") as mock_reply_sync:
            with pytest.raises(ValueError, match="Invalid tweet ID"):
                await twitter_connector.reply_to_tweet(
                    access_token="fake_token", text="hi", tweet_id="not-an-id"
                )
            mock_reply_sync.assert_not_called()

    async def test_dispatch_via_mcp(self, twitter_connector):
        mock_reply = {"data": {"id": "777", "text": "dispatched reply"}}
        with patch("connectors.twitter.adapter._reply_to_tweet_sync") as mock_reply_sync:
            mock_reply_sync.return_value = mock_reply
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={
                    "name": "reply_to_tweet",
                    "arguments": {"text": "dispatched reply", "tweet_id": "123"},
                },
                request_id=61,
                access_token="fake_token",
            )

        assert "result" in response
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed["data"]["id"] == "777"


# =============================================================================
# TOOL DISPATCH — unknown tool
# =============================================================================


class TestToolDispatchErrors:
    """Verify error handling in tool dispatch."""

    async def test_unknown_tool_returns_error(self, twitter_connector):
        response = await twitter_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "nonexistent_tool", "arguments": {}},
            request_id=50,
            access_token="fake_token",
        )
        assert "error" in response
        assert response["error"]["code"] == -32602

    async def test_tool_exception_returns_is_error(self, twitter_connector):
        """When a tool raises, MCP returns isError=True with the message."""
        with patch("connectors.twitter.adapter._get_me_sync") as mock_get:
            mock_get.side_effect = RuntimeError("API rate limited")
            response = await twitter_connector.handle_mcp_request(
                method="tools/call",
                params={"name": "get_me", "arguments": {}},
                request_id=51,
                access_token="fake_token",
            )

        assert response["result"]["isError"] is True
        assert "API rate limited" in response["result"]["content"][0]["text"]


# =============================================================================
# SYNC HELPER UNIT TESTS
# =============================================================================


class TestSyncHelpers:
    """Test module-level sync helpers with mocked xdk Client."""

    def test_model_to_dict_with_dict(self):
        from connectors.twitter.adapter import _model_to_dict

        original = {"id": "123", "text": "hello"}
        assert _model_to_dict(original) is original

    def test_model_to_dict_with_pydantic_model(self):
        from pydantic import BaseModel

        from connectors.twitter.adapter import _model_to_dict

        class FakeModel(BaseModel):
            id: str
            text: str

        model = FakeModel(id="123", text="hello")
        converted = _model_to_dict(model)
        assert isinstance(converted, dict)
        assert converted["id"] == "123"

    def test_extract_user_id_from_dict(self):
        from connectors.twitter.adapter import _extract_user_id

        assert _extract_user_id({"id": "999"}) == "999"

    def test_extract_user_id_from_object(self):
        from connectors.twitter.adapter import _extract_user_id

        class FakeUser:
            id = "888"

        assert _extract_user_id(FakeUser()) == "888"

    def test_extract_user_id_raises_on_bad_input(self):
        from connectors.twitter.adapter import _extract_user_id

        with pytest.raises(ValueError, match="Cannot extract user ID"):
            _extract_user_id("not_a_user")

    def test_clamp_max_results_caps_at_100(self):
        from connectors.twitter.adapter import _clamp_max_results

        assert _clamp_max_results(200) == 100

    def test_clamp_max_results_floors_at_1(self):
        from connectors.twitter.adapter import _clamp_max_results

        assert _clamp_max_results(0) == 1
        assert _clamp_max_results(-10) == 1

    def test_clamp_max_results_passes_through_valid(self):
        from connectors.twitter.adapter import _clamp_max_results

        assert _clamp_max_results(50) == 50

    def test_mcp_text_content_format(self):
        from connectors.twitter.adapter import _mcp_text_content

        blocks = _mcp_text_content({"key": "value"})
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert json.loads(blocks[0]["text"]) == {"key": "value"}

    def test_extract_tweet_id_from_data(self):
        from connectors.twitter.adapter import _extract_tweet_id

        assert _extract_tweet_id({"data": {"id": "777", "text": "x"}}) == "777"

    def test_extract_tweet_id_raises_on_bad_shape(self):
        from connectors.twitter.adapter import _extract_tweet_id

        with pytest.raises(ValueError, match="Unexpected create response"):
            _extract_tweet_id({"errors": [{"message": "no data"}]})

    def test_validate_thread_tweets_accepts_valid(self):
        from connectors.twitter.adapter import _validate_thread_tweets

        _validate_thread_tweets(["first", "second"])  # must not raise

    def test_validate_thread_tweets_rejects_empty_list(self):
        from connectors.twitter.adapter import _validate_thread_tweets

        with pytest.raises(ValueError, match="non-empty list"):
            _validate_thread_tweets([])

    def test_validate_thread_tweets_rejects_too_many(self):
        from connectors.twitter.adapter import MAX_THREAD_TWEETS, _validate_thread_tweets

        with pytest.raises(ValueError, match="exceeds"):
            _validate_thread_tweets(["x"] * (MAX_THREAD_TWEETS + 1))

    def test_validate_thread_tweets_rejects_overlength(self):
        from connectors.twitter.adapter import _validate_thread_tweets

        with pytest.raises(ValueError, match="exceeds 280"):
            _validate_thread_tweets(["ok", "x" * 281])

    def test_post_thread_sync_chains_each_reply_to_the_previous(self):
        """Root has no reply; each subsequent tweet replies to the prior tweet's ID."""
        from connectors.twitter.adapter import _post_thread_sync

        created_bodies = []

        def fake_create(body):
            created_bodies.append(body)
            sequence = len(created_bodies)
            return {"data": {"id": f"id{sequence}", "text": body.text}}

        fake_client = MagicMock()
        fake_client.posts.create.side_effect = fake_create
        with patch("connectors.twitter.adapter.XClient", return_value=fake_client):
            outcome = _post_thread_sync("fake_token", ["first", "second", "third"])

        assert outcome["status"] == "complete"
        assert outcome["count"] == 3
        assert created_bodies[0].reply is None
        assert created_bodies[1].reply.in_reply_to_tweet_id == "id1"
        assert created_bodies[2].reply.in_reply_to_tweet_id == "id2"

    def test_post_thread_sync_returns_partial_on_midthread_failure(self):
        from connectors.twitter.adapter import _post_thread_sync

        attempts = {"count": 0}

        def fake_create(body):
            attempts["count"] += 1
            if attempts["count"] == 2:
                raise RuntimeError("rate limited")
            return {"data": {"id": f"id{attempts['count']}", "text": body.text}}

        fake_client = MagicMock()
        fake_client.posts.create.side_effect = fake_create
        with patch("connectors.twitter.adapter.XClient", return_value=fake_client):
            outcome = _post_thread_sync("fake_token", ["a", "b", "c"])

        assert outcome["status"] == "partial"
        assert outcome["failed_at_index"] == 1
        assert [tweet["id"] for tweet in outcome["posted"]] == ["id1"]
        assert "rate limited" in outcome["error"]

    def test_post_thread_sync_raises_when_first_post_fails(self):
        from connectors.twitter.adapter import _post_thread_sync

        fake_client = MagicMock()
        fake_client.posts.create.side_effect = RuntimeError("boom")
        with patch("connectors.twitter.adapter.XClient", return_value=fake_client):
            with pytest.raises(RuntimeError, match="boom"):
                _post_thread_sync("fake_token", ["only"])

    def test_post_thread_sync_unreadable_id_midthread_raises_not_partial(self):
        """A mid-thread tweet that posts but returns an unreadable ID must raise, not be
        reported as failed_at_index — the tweet is live, so labeling it failed would
        double-post on retry. ID extraction lives outside the post try for this reason."""
        from connectors.twitter.adapter import _post_thread_sync

        attempts = {"count": 0}

        def fake_create(body):
            attempts["count"] += 1
            if attempts["count"] == 2:
                return {"unexpected": "shape"}  # posted successfully, but ID is unreadable
            return {"data": {"id": f"id{attempts['count']}", "text": body.text}}

        fake_client = MagicMock()
        fake_client.posts.create.side_effect = fake_create
        with patch("connectors.twitter.adapter.XClient", return_value=fake_client):
            with pytest.raises(ValueError, match="Unexpected create response"):
                _post_thread_sync("fake_token", ["a", "b", "c"])
