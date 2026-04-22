"""
Slack Connector Unit Tests

Coverage: auto-registration, OAuth config, MCP dispatch, _slack_api_call
(ok:false, 429 retry, HTTP errors), _slack_paginate (cursor loop, cap),
recipient/channel resolution, in-process cache, and each tool end-to-end.
"""

from __future__ import annotations

import asyncio
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
def slack_connector():
    """Import the Slack adapter and register it fresh for each test."""
    from connectors.slack.adapter import SlackConnector

    connector = ConnectorRegistry.get("slack")
    if connector is None:
        ConnectorRegistry.auto_register(SlackConnector)
        connector = ConnectorRegistry.get("slack")
    assert connector is not None
    return connector


def _make_httpx_response(
    *,
    status_code: int = 200,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Build a MagicMock that quacks like httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.is_error = status_code >= 400
    response.headers = headers or {}
    response.json.return_value = json_body or {"ok": True}
    response.text = json.dumps(json_body) if json_body else ""
    return response


def _patch_httpx_post(responses: list[MagicMock]) -> tuple:
    """Return (context manager, post_mock) that yields the given responses in order."""
    post_mock = AsyncMock(side_effect=responses)
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = post_mock
    return patch("connectors.slack.adapter.httpx.AsyncClient", return_value=client), post_mock


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    """Auto-registration, metadata, scope list."""

    def test_registers_as_slack(self, slack_connector):
        assert slack_connector.meta.name == "slack"

    def test_display_name(self, slack_connector):
        assert slack_connector.meta.display_name == "Slack"

    def test_is_native_connector(self, slack_connector):
        assert slack_connector.meta.mcp_url is None

    def test_authorize_url(self, slack_connector):
        assert slack_connector.meta.oauth_authorize_url == "https://slack.com/oauth/v2/authorize"

    def test_token_url(self, slack_connector):
        assert slack_connector.meta.oauth_token_url == "https://slack.com/api/oauth.v2.access"

    def test_scopes_exact(self, slack_connector):
        assert set(slack_connector.meta.scopes) == {
            "chat:write",
            "chat:write.public",
            "im:write",
            "users:read",
            "channels:read",
            "groups:read",
        }

    def test_does_not_request_email_scope(self, slack_connector):
        assert "users:read.email" not in slack_connector.meta.scopes

    def test_has_six_tools(self, slack_connector):
        assert len(slack_connector._tools) == 6

    def test_tool_names(self, slack_connector):
        assert set(slack_connector._tools.keys()) == {
            "send_dm",
            "send_message",
            "update_message",
            "delete_message",
            "find_user",
            "find_channel",
        }

    def test_tool_prompt_instructions_returns_non_empty_string(self, slack_connector):
        prompt = slack_connector.tool_prompt_instructions()
        assert isinstance(prompt, str)
        assert len(prompt.strip()) > 0
        # Key operator-facing guidance an LLM should receive about Slack semantics.
        assert "mrkdwn" in prompt
        assert "find_user" in prompt
        assert str(4000) in prompt


# =============================================================================
# MCP DISPATCH
# =============================================================================


class TestMCPDispatch:
    """JSON-RPC lifecycle methods."""

    async def test_initialize(self, slack_connector):
        response = await slack_connector.handle_mcp_request(
            method="initialize", params={}, request_id=1, access_token="xoxb-fake"
        )
        assert response["result"]["serverInfo"]["name"] == "slack"

    async def test_tools_list_returns_six(self, slack_connector):
        response = await slack_connector.handle_mcp_request(
            method="tools/list", params={}, request_id=2, access_token="xoxb-fake"
        )
        assert len(response["result"]["tools"]) == 6

    async def test_unknown_method(self, slack_connector):
        response = await slack_connector.handle_mcp_request(
            method="resources/list", params={}, request_id=3, access_token="xoxb-fake"
        )
        assert response["error"]["code"] == -32601


# =============================================================================
# _slack_api_call
# =============================================================================


class TestSlackApiCall:
    """Raw Slack API helper: ok-check, 429 retry, HTTP error propagation."""

    async def test_returns_body_on_ok_true(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(json_body={"ok": True, "channel": "C1", "ts": "1.0"})
        ctx, post_mock = _patch_httpx_post([response])
        with ctx:
            body = await _slack_api_call("chat.postMessage", "xoxb-x", channel="C1", text="hi")
        assert body["channel"] == "C1"
        # Verify the URL, Authorization header, and form-encoded data.
        call_args = post_mock.call_args
        assert call_args.args[0] == "https://slack.com/api/chat.postMessage"
        assert call_args.kwargs["headers"]["Authorization"] == "Bearer xoxb-x"
        assert call_args.kwargs["data"]["channel"] == "C1"
        assert call_args.kwargs["data"]["text"] == "hi"

    async def test_raises_on_ok_false(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(json_body={"ok": False, "error": "channel_not_found"})
        ctx, _ = _patch_httpx_post([response])
        with ctx, pytest.raises(ValueError, match="channel_not_found"):
            await _slack_api_call("chat.postMessage", "xoxb-x", channel="BAD")

    async def test_raises_on_http_5xx(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(status_code=503, json_body={})
        ctx, _ = _patch_httpx_post([response])
        with ctx, pytest.raises(ValueError, match=r"Slack API error \(503\)"):
            await _slack_api_call("chat.postMessage", "xoxb-x")

    async def test_retries_once_on_429_then_succeeds(self):
        from connectors.slack.adapter import _slack_api_call

        first = _make_httpx_response(status_code=429, headers={"Retry-After": "0"})
        second = _make_httpx_response(json_body={"ok": True})
        ctx, post_mock = _patch_httpx_post([first, second])
        with ctx, patch("connectors.slack.adapter.asyncio.sleep", new=AsyncMock()):
            body = await _slack_api_call("users.list", "xoxb-x")
        assert body == {"ok": True}
        assert post_mock.call_count == 2

    async def test_raises_on_second_429_with_retry_in_message(self):
        from connectors.slack.adapter import _slack_api_call

        first = _make_httpx_response(status_code=429, headers={"Retry-After": "0"})
        second = _make_httpx_response(status_code=429, headers={"Retry-After": "12"})
        ctx, _ = _patch_httpx_post([first, second])
        with ctx, patch("connectors.slack.adapter.asyncio.sleep", new=AsyncMock()):
            with pytest.raises(ValueError, match="retry in 12s"):
                await _slack_api_call("users.list", "xoxb-x")

    async def test_raises_on_oversized_retry_after(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(status_code=429, headers={"Retry-After": "3600"})
        ctx, _ = _patch_httpx_post([response])
        with ctx:
            with pytest.raises(ValueError, match="retry in 3600s"):
                await _slack_api_call("users.list", "xoxb-x")

    async def test_serializes_bool_and_list_params(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(json_body={"ok": True, "channel": "C1", "ts": "1.0"})
        ctx, post_mock = _patch_httpx_post([response])
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "hi"}}]
        with ctx:
            await _slack_api_call(
                "chat.postMessage",
                "xoxb-x",
                channel="C1",
                text="hi",
                blocks=blocks,
                unfurl_links=False,
                unfurl_media=False,
            )
        data = post_mock.call_args.kwargs["data"]
        assert data["unfurl_links"] == "false"
        assert data["unfurl_media"] == "false"
        assert json.loads(data["blocks"]) == blocks

    async def test_omits_none_params(self):
        from connectors.slack.adapter import _slack_api_call

        response = _make_httpx_response(json_body={"ok": True})
        ctx, post_mock = _patch_httpx_post([response])
        with ctx:
            await _slack_api_call("chat.postMessage", "xoxb-x", channel="C1", blocks=None)
        assert "blocks" not in post_mock.call_args.kwargs["data"]


# =============================================================================
# _slack_paginate
# =============================================================================


class TestSlackPaginate:
    """Cursor pagination: follows next_cursor, stops on empty, caps at MAX_PAGINATION_PAGES."""

    async def test_single_page_stops_on_empty_cursor(self):
        from connectors.slack.adapter import _slack_paginate

        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {
                "ok": True,
                "members": [{"id": "U1"}, {"id": "U2"}],
                "response_metadata": {"next_cursor": ""},
            }
            items = await _slack_paginate("users.list", "xoxb-x", "members")
        assert items == [{"id": "U1"}, {"id": "U2"}]
        assert api.call_count == 1

    async def test_multi_page_concatenates(self):
        from connectors.slack.adapter import _slack_paginate

        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.side_effect = [
                {"members": [{"id": "U1"}], "response_metadata": {"next_cursor": "cursor1"}},
                {"members": [{"id": "U2"}], "response_metadata": {"next_cursor": ""}},
            ]
            items = await _slack_paginate("users.list", "xoxb-x", "members")
        assert [u["id"] for u in items] == ["U1", "U2"]
        assert api.call_count == 2

    async def test_caps_at_max_pages(self):
        from connectors.slack.adapter import MAX_PAGINATION_PAGES, _slack_paginate

        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {
                "members": [{"id": "U"}],
                "response_metadata": {"next_cursor": "never_ending"},
            }
            items = await _slack_paginate("users.list", "xoxb-x", "members")
        assert api.call_count == MAX_PAGINATION_PAGES
        assert len(items) == MAX_PAGINATION_PAGES


# =============================================================================
# Resolvers + cache
# =============================================================================


class TestResolveRecipient:
    """User ID / @handle / real name lookup + ambiguity + email rejection."""

    async def test_passes_through_user_id(self, slack_connector):
        uid = await slack_connector._resolve_recipient("U12345ABC", "xoxb-x")
        assert uid == "U12345ABC"

    async def test_rejects_email_without_scope(self, slack_connector):
        with pytest.raises(ValueError, match="users:read.email"):
            await slack_connector._resolve_recipient("alex@example.com", "xoxb-x")

    async def test_resolves_handle(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U111", "name": "alex", "real_name": "Alex Example"},
                {"id": "U222", "name": "other", "real_name": "Other Person"},
            ]
            uid = await slack_connector._resolve_recipient("@alex", "xoxb-x")
        assert uid == "U111"

    async def test_resolves_real_name(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U111", "name": "a", "real_name": "Alex Example", "profile": {}},
            ]
            uid = await slack_connector._resolve_recipient("Alex Example", "xoxb-x")
        assert uid == "U111"

    async def test_ambiguous_name_raises_with_json_candidates(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U1", "name": "a1", "real_name": "Alex", "profile": {"display_name": ""}},
                {"id": "U2", "name": "a2", "real_name": "Alex", "profile": {"display_name": ""}},
            ]
            with pytest.raises(ValueError) as exc_info:
                await slack_connector._resolve_recipient("Alex", "xoxb-x")
        payload = json.loads(str(exc_info.value))
        assert payload["error"] == "ambiguous_name"
        assert len(payload["candidates"]) == 2

    async def test_no_match_raises(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = []
            with pytest.raises(ValueError, match="No Slack user matches"):
                await slack_connector._resolve_recipient("@nobody", "xoxb-x")

    async def test_skips_deleted_and_bot_users(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U1", "name": "ash", "deleted": True},
                {"id": "U2", "name": "ash", "is_bot": True},
            ]
            with pytest.raises(ValueError, match="No Slack user matches"):
                await slack_connector._resolve_recipient("@ash", "xoxb-x")


class TestResolveChannel:
    """Channel ID / #name / name lookup."""

    async def test_passes_through_channel_id(self, slack_connector):
        cid = await slack_connector._resolve_channel("C12345ABC", "xoxb-x")
        assert cid == "C12345ABC"

    async def test_resolves_hash_name(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [{"id": "C111", "name": "random"}]
            cid = await slack_connector._resolve_channel("#random", "xoxb-x")
        assert cid == "C111"

    async def test_resolves_bare_name(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [{"id": "C111", "name": "random"}]
            cid = await slack_connector._resolve_channel("random", "xoxb-x")
        assert cid == "C111"

    async def test_no_match_raises(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = []
            with pytest.raises(ValueError, match="No Slack channel matches"):
                await slack_connector._resolve_channel("#nope", "xoxb-x")


class TestCache:
    """In-process cache: hit avoids network, TTL expiry, per-token lock serialises misses."""

    async def test_second_call_within_ttl_skips_network(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [{"id": "U1", "name": "alex"}]
            await slack_connector._cached_list("xoxb-x", "users.list", "members")
            await slack_connector._cached_list("xoxb-x", "users.list", "members")
        assert api.call_count == 1

    async def test_different_tokens_get_separate_caches(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.side_effect = [[{"id": "U1"}], [{"id": "U2"}]]
            a = await slack_connector._cached_list("xoxb-a", "users.list", "members")
            b = await slack_connector._cached_list("xoxb-b", "users.list", "members")
        assert a != b
        assert api.call_count == 2

    async def test_expired_entry_refetches(self, slack_connector):
        import time as real_time

        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [{"id": "U1"}]
            await slack_connector._cached_list("xoxb-x", "users.list", "members")
            # Force expiry by rewriting the stored expires_at to the past.
            key = next(iter(slack_connector._cache))
            _, items = slack_connector._cache[key]
            slack_connector._cache[key] = (real_time.monotonic() - 1.0, items)
            await slack_connector._cached_list("xoxb-x", "users.list", "members")
        assert api.call_count == 2

    async def test_concurrent_misses_share_one_fetch(self, slack_connector):
        """Per-token lock prevents thundering herd on cache-miss."""
        fetch_started = asyncio.Event()
        fetch_may_complete = asyncio.Event()
        call_count = 0

        async def slow_paginate(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            fetch_started.set()
            await fetch_may_complete.wait()
            return [{"id": "U1"}]

        with patch("connectors.slack.adapter._slack_paginate", new=slow_paginate):
            task_a = asyncio.create_task(
                slack_connector._cached_list("xoxb-x", "users.list", "members")
            )
            await fetch_started.wait()
            task_b = asyncio.create_task(
                slack_connector._cached_list("xoxb-x", "users.list", "members")
            )
            # Give task_b a chance to reach the lock.
            await asyncio.sleep(0)
            fetch_may_complete.set()
            await asyncio.gather(task_a, task_b)
        assert call_count == 1


# =============================================================================
# Tools (end-to-end with mocked API helpers)
# =============================================================================


class TestSendDm:
    async def test_opens_dm_then_posts(self, slack_connector):
        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.side_effect = [
                {"ok": True, "channel": {"id": "D1"}},
                {"ok": True, "channel": "D1", "ts": "1234.5"},
            ]
            content = await slack_connector.send_dm(
                access_token="xoxb-x", recipient="U12345", text="hi"
            )
        assert api.call_args_list[0].args[0] == "conversations.open"
        assert api.call_args_list[1].args[0] == "chat.postMessage"
        post_kwargs = api.call_args_list[1].kwargs
        assert post_kwargs["channel"] == "D1"
        assert post_kwargs["unfurl_links"] is False
        assert post_kwargs["unfurl_media"] is False
        parsed = json.loads(content[0]["text"])
        assert parsed == {"channel": "D1", "ts": "1234.5"}

    async def test_rejects_long_text(self, slack_connector):
        with pytest.raises(ValueError, match="exceeds 4000 characters"):
            await slack_connector.send_dm(access_token="xoxb-x", recipient="U1", text="x" * 4001)


class TestSendMessage:
    async def test_sets_unfurl_defaults(self, slack_connector):
        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {"ok": True, "channel": "C1", "ts": "2.0"}
            await slack_connector.send_message(access_token="xoxb-x", channel="C12345", text="hi")
        kwargs = api.call_args.kwargs
        assert kwargs["unfurl_links"] is False
        assert kwargs["unfurl_media"] is False

    async def test_passes_thread_ts(self, slack_connector):
        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {"ok": True, "channel": "C1", "ts": "3.0"}
            await slack_connector.send_message(
                access_token="xoxb-x",
                channel="C12345",
                text="reply",
                thread_ts="1.0",
            )
        assert api.call_args.kwargs["thread_ts"] == "1.0"


class TestUpdateMessage:
    async def test_does_not_pass_unfurl_params(self, slack_connector):
        """chat.update rejects unfurl_links / unfurl_media — the adapter must omit them."""
        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {"ok": True, "channel": "C1", "ts": "1.0"}
            await slack_connector.update_message(
                access_token="xoxb-x", channel="C1", ts="1.0", text="edited"
            )
        kwargs = api.call_args.kwargs
        assert "unfurl_links" not in kwargs
        assert "unfurl_media" not in kwargs


class TestDeleteMessage:
    async def test_returns_deleted_true(self, slack_connector):
        with patch("connectors.slack.adapter._slack_api_call", new=AsyncMock()) as api:
            api.return_value = {"ok": True}
            content = await slack_connector.delete_message(
                access_token="xoxb-x", channel="C1", ts="1.0"
            )
        parsed = json.loads(content[0]["text"])
        assert parsed == {"channel": "C1", "ts": "1.0", "deleted": True}


class TestFindUser:
    async def test_returns_summaries(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U1", "name": "alex", "real_name": "Alex Example", "profile": {}},
                {"id": "U2", "name": "other", "real_name": "Someone Else", "profile": {}},
            ]
            content = await slack_connector.find_user(access_token="xoxb-x", query="alex")
        parsed = json.loads(content[0]["text"])
        assert len(parsed) == 1
        assert parsed[0]["id"] == "U1"

    async def test_excludes_deleted_and_bots(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "U1", "name": "bot1", "deleted": True, "profile": {}},
                {"id": "U2", "name": "bot2", "is_bot": True, "profile": {}},
            ]
            content = await slack_connector.find_user(access_token="xoxb-x", query="bot")
        assert json.loads(content[0]["text"]) == []

    @pytest.mark.parametrize("query", ["", " ", "   ", "@", "@ "])
    async def test_rejects_empty_or_sigil_only_query(self, slack_connector, query):
        with pytest.raises(ValueError, match="query must not be empty"):
            await slack_connector.find_user(access_token="xoxb-x", query=query)


class TestFindChannel:
    async def test_substring_match(self, slack_connector):
        with patch("connectors.slack.adapter._slack_paginate", new=AsyncMock()) as api:
            api.return_value = [
                {"id": "C1", "name": "ops-alerts"},
                {"id": "C2", "name": "random"},
            ]
            content = await slack_connector.find_channel(access_token="xoxb-x", query="ops")
        parsed = json.loads(content[0]["text"])
        assert len(parsed) == 1
        assert parsed[0]["id"] == "C1"

    @pytest.mark.parametrize("query", ["", " ", "   ", "#", "# "])
    async def test_rejects_empty_or_sigil_only_query(self, slack_connector, query):
        with pytest.raises(ValueError, match="query must not be empty"):
            await slack_connector.find_channel(access_token="xoxb-x", query=query)


# =============================================================================
# End-to-end problem-shaped tests
# =============================================================================


class TestTokenRevoked:
    """When the bot is uninstalled from Slack, the next call must surface it clearly."""

    async def test_post_message_surfaces_token_revoked(self, slack_connector):
        response = _make_httpx_response(json_body={"ok": False, "error": "token_revoked"})
        ctx, _ = _patch_httpx_post([response])
        with ctx, pytest.raises(ValueError, match="token_revoked"):
            # Bypass resolver — use a raw channel ID so only the API call fails.
            await slack_connector.send_message(
                access_token="xoxb-revoked", channel="C12345", text="hi"
            )

    async def test_invalid_auth_surfaces_cleanly(self, slack_connector):
        response = _make_httpx_response(json_body={"ok": False, "error": "invalid_auth"})
        ctx, _ = _patch_httpx_post([response])
        with ctx, pytest.raises(ValueError, match="invalid_auth"):
            await slack_connector.send_message(access_token="xoxb-bad", channel="C12345", text="hi")


class TestSendThenUpdateFlow:
    """The bot-token choice was sold on 'edit via ts'. Verify the full round-trip."""

    async def test_post_returns_ts_usable_for_update(self, slack_connector):
        post_response = _make_httpx_response(
            json_body={"ok": True, "channel": "C12345", "ts": "1700000000.000100"}
        )
        update_response = _make_httpx_response(
            json_body={"ok": True, "channel": "C12345", "ts": "1700000000.000100"}
        )
        ctx, post_mock = _patch_httpx_post([post_response, update_response])
        with ctx:
            posted = await slack_connector.send_message(
                access_token="xoxb-x", channel="C12345", text="working..."
            )
            posted_payload = json.loads(posted[0]["text"])
            # Feed the returned ts back into update_message — the promised workflow.
            await slack_connector.update_message(
                access_token="xoxb-x",
                channel=posted_payload["channel"],
                ts=posted_payload["ts"],
                text="done.",
            )
        # Both calls went to Slack; update used the ts from post.
        assert post_mock.call_count == 2
        update_call = post_mock.call_args_list[1]
        assert update_call.args[0] == "https://slack.com/api/chat.update"
        assert update_call.kwargs["data"]["ts"] == "1700000000.000100"
        assert update_call.kwargs["data"]["text"] == "done."


class TestMrkdwnPassthrough:
    """The prompt warns the LLM that <@U123> becomes a real mention; verify it reaches Slack."""

    async def test_mention_markup_reaches_slack_unescaped(self, slack_connector):
        response = _make_httpx_response(json_body={"ok": True, "channel": "C12345", "ts": "1.0"})
        ctx, post_mock = _patch_httpx_post([response])
        with ctx:
            await slack_connector.send_message(
                access_token="xoxb-x",
                channel="C12345",
                text="cc <@U99999> please review",
            )
        sent_text = post_mock.call_args.kwargs["data"]["text"]
        assert sent_text == "cc <@U99999> please review"
