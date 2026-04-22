"""
Slack MCP Connector

Native connector that wraps the Slack Web API as MCP tools for bot-identity
messaging. OAuth v2 install yields a bot token (xoxb-...), used for posting
messages, opening DMs, and resolving users/channels by friendly identifiers.

Follows the LinkedIn precedent: raw httpx, manual rate-limit retry, explicit
ok:false handling. All outbound message calls default to unfurl_links=false,
unfurl_media=false to mitigate URL-unfurling as a data-exfiltration side
channel (see the archived Anthropic Slack MCP CVE).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any

import httpx

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import ConnectorMeta

logger = logging.getLogger(__name__)

# === CONSTANTS ===

SLACK_API_BASE = "https://slack.com/api"
SLACK_TIMEOUT_SECONDS = 10.0

# Slack caps message text at 4,000 chars (chat.postMessage / chat.update msg_too_long).
MAX_TEXT_LENGTH = 4000

# Recipient resolver returns up to this many candidates on ambiguous name.
MAX_CANDIDATES = 10

# users.list / conversations.list cache TTL. Slack tier-2 rate limits per method
# are ~20/min; caching keeps chatty agents well inside that window.
CACHE_TTL_SECONDS = 300

# Pagination: Slack's cursor pagination recommends limit=200 per page. 10 pages
# is a safety cap for pathological workspaces — logs a warning if hit.
PAGE_SIZE = 200
MAX_PAGINATION_PAGES = 10

# Rate-limit retry: respect Retry-After up to this many seconds, then fail.
RATE_LIMIT_MAX_WAIT_SECONDS = 30
RATE_LIMITED_STATUS = 429

# Slack ID regexes — prevent needless API calls when the caller already passed an ID.
# Users: U = regular, W = enterprise org user.
_USER_ID_RE = re.compile(r"^[UW][A-Z0-9]{2,}$")
# Channels: C = public, D = direct message, G = private (legacy).
_CHANNEL_ID_RE = re.compile(r"^[CDG][A-Z0-9]{2,}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# === CACHE + API HELPERS ===


def _token_hash(access_token: str) -> str:
    """SHA-256 prefix of a token — safe to use as dict key without leaking secrets to logs."""
    return hashlib.sha256(access_token.encode()).hexdigest()[:16]


def _serialize_params(params: dict[str, Any]) -> dict[str, str]:
    """Slack form encoding: bool -> 'true'/'false', dict/list -> JSON, drop None."""
    form_data: dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            form_data[key] = "true" if value else "false"
        elif isinstance(value, (dict, list)):
            form_data[key] = json.dumps(value)
        else:
            form_data[key] = str(value)
    return form_data


def _parse_retry_after(response: httpx.Response) -> float:
    """Read Retry-After header as seconds. Defaults to 5s if missing or malformed."""
    try:
        return float(response.headers.get("Retry-After", "5"))
    except (ValueError, TypeError):
        return 5.0


async def _slack_api_call(method: str, access_token: str, **params: Any) -> dict[str, Any]:
    """Single point of Slack Web API contact. Handles auth, 429 retry, ok:false.

    - 429 with Retry-After <= RATE_LIMIT_MAX_WAIT_SECONDS: sleep once and retry.
    - 429 beyond the cap, or second 429: raise with retry-in-Ns message.
    - ok:false: raise ValueError(f"Slack {method} failed: {error_code}").
    """
    url = f"{SLACK_API_BASE}/{method}"
    headers = {"Authorization": f"Bearer {access_token}"}
    form_data = _serialize_params(params)
    async with httpx.AsyncClient(timeout=SLACK_TIMEOUT_SECONDS) as client:
        response = await client.post(url, headers=headers, data=form_data)
        if response.status_code == RATE_LIMITED_STATUS:
            response = await _retry_on_rate_limit(response, client, url, headers, form_data)
        return _parse_slack_response(response, method)


def _parse_slack_response(response: httpx.Response, method: str) -> dict[str, Any]:
    """Raise for transport errors (5xx / non-429 4xx) or Slack ok:false, else return the body."""
    # Transport-level failure. Slack's application errors come back as
    # 200 + ok:false, which is handled below.
    if response.is_error:
        logger.debug("[Slack] HTTP %d on %s", response.status_code, method)
        raise ValueError(f"Slack API error ({response.status_code})")
    # Application-level failure (invalid scope, channel_not_found, etc.):
    # Slack returns 200 with {"ok": false, "error": "<code>"}.
    body = response.json()
    if not body.get("ok"):
        error_code = body.get("error", "unknown_error")
        raise ValueError(f"Slack {method} failed: {error_code}")
    return body


async def _retry_on_rate_limit(  # noqa: PLR0913 -- request is a URL + headers + form_data triple
    first_response: httpx.Response,
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    form_data: dict[str, str],
) -> httpx.Response:
    """Sleep Retry-After (capped) and retry once. Raises on oversized wait or second 429."""
    retry_after = _parse_retry_after(first_response)
    if retry_after > RATE_LIMIT_MAX_WAIT_SECONDS:
        raise ValueError(f"Slack rate limited — retry in {retry_after:.0f}s")
    logger.warning("[Slack] Rate limited, retrying after %.1fs", retry_after)
    await asyncio.sleep(retry_after)
    retry_response = await client.post(url, headers=headers, data=form_data)
    if retry_response.status_code == RATE_LIMITED_STATUS:
        new_wait = _parse_retry_after(retry_response)
        raise ValueError(f"Slack rate limited — retry in {new_wait:.0f}s")
    return retry_response


async def _slack_paginate(
    method: str, access_token: str, key: str, **params: Any
) -> list[dict[str, Any]]:
    """Cursor-paginate a Slack list method. `key` is the response field holding the list.

    Caps at MAX_PAGINATION_PAGES (safety for pathological workspaces).
    """
    all_items: list[dict[str, Any]] = []
    # Slack's cursor-paginated endpoints accept an empty cursor as "first page".
    cursor = ""
    for _ in range(MAX_PAGINATION_PAGES):
        response = await _slack_api_call(
            method, access_token, limit=PAGE_SIZE, cursor=cursor, **params
        )
        all_items.extend(response.get(key, []))
        # `response_metadata` is omitted on the last page; treat missing as empty
        # so the fallback `""` triggers the end-of-pagination break below.
        cursor = response.get("response_metadata", {}).get("next_cursor", "")
        if not cursor:
            return all_items
    _warn_pagination_cap_hit(method, len(all_items))
    return all_items


def _warn_pagination_cap_hit(method: str, items_seen: int) -> None:
    """Log when a list method exhausts MAX_PAGINATION_PAGES — callers see a truncated result."""
    logger.warning(
        "[Slack] %s hit pagination cap (%d pages, %d items) — workspace may have more",
        method,
        MAX_PAGINATION_PAGES,
        items_seen,
    )


def _mcp_text(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as an MCP text content block (JSON-serialised)."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


# === TOOL METADATA ===

_SEND_DM_META = NativeToolMeta(
    name="send_dm",
    description=(
        "Send a direct message to a Slack user as the bot app (not as the installing user). "
        "`recipient` can be a Slack user ID (U...), @handle, or real/display name. "
        "Returns {channel, ts}. Use the ts with update_message to edit later."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "recipient": {
                "type": "string",
                "description": "User ID (U...), @handle, or real/display name.",
            },
            "text": {
                "type": "string",
                "description": f"Message text. Max {MAX_TEXT_LENGTH} chars. Slack mrkdwn.",
            },
            "blocks": {
                "type": "array",
                "description": "Optional Block Kit blocks (JSON array).",
                "items": {"type": "object"},
            },
        },
        "required": ["recipient", "text"],
    },
)

_SEND_MESSAGE_META = NativeToolMeta(
    name="send_message",
    description=(
        "Post a message to a Slack channel as the bot app. `channel` can be a channel ID, "
        "#name, or bare name. Works for public channels the bot has not joined. "
        "Returns {channel, ts}."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "description": "Channel ID (C...), #name, or bare name.",
            },
            "text": {
                "type": "string",
                "description": f"Message text. Max {MAX_TEXT_LENGTH} chars. Slack mrkdwn.",
            },
            "blocks": {
                "type": "array",
                "description": "Optional Block Kit blocks.",
                "items": {"type": "object"},
            },
            "thread_ts": {
                "type": "string",
                "description": "Reply in a thread by supplying the parent message's ts.",
            },
        },
        "required": ["channel", "text"],
    },
)

_UPDATE_MESSAGE_META = NativeToolMeta(
    name="update_message",
    description=(
        "Edit a previously-posted message. Use the {channel, ts} returned by send_dm or "
        "send_message. Unfurl behaviour is inherited from the original message and cannot "
        "be changed on update."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "channel": {"type": "string", "description": "Channel ID (C... or D...)."},
            "ts": {"type": "string", "description": "Timestamp of the message to edit."},
            "text": {
                "type": "string",
                "description": f"New text. Max {MAX_TEXT_LENGTH} chars.",
            },
            "blocks": {
                "type": "array",
                "description": "New blocks (replaces existing). Empty array removes blocks.",
                "items": {"type": "object"},
            },
        },
        "required": ["channel", "ts", "text"],
    },
)

_DELETE_MESSAGE_META = NativeToolMeta(
    name="delete_message",
    description="Delete a previously-posted message by {channel, ts}. Bot can only delete its own messages.",
    input_schema={
        "type": "object",
        "properties": {
            "channel": {"type": "string", "description": "Channel ID (C... or D...)."},
            "ts": {"type": "string", "description": "Timestamp of the message to delete."},
        },
        "required": ["channel", "ts"],
    },
)

_FIND_USER_META = NativeToolMeta(
    name="find_user",
    description=(
        f"Look up Slack users matching a name or @handle. Returns up to {MAX_CANDIDATES} "
        "candidates with id / name / real_name / display_name. Use this when unsure before "
        "calling send_dm."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Handle (with or without @) or name fragment.",
            },
        },
        "required": ["query"],
    },
)

_FIND_CHANNEL_META = NativeToolMeta(
    name="find_channel",
    description=(
        f"Look up Slack channels matching a name. Returns up to {MAX_CANDIDATES} candidates "
        "with id / name / is_private / is_archived. Use before calling send_message."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Channel name (with or without #)."},
        },
        "required": ["query"],
    },
)


# === CONNECTOR ===


class SlackConnector(NativeConnector):
    """Slack native connector — bot-identity messaging via Slack Web API.

    Scopes:
    - chat:write            — post messages; delete bot's own messages
    - chat:write.public     — post to public channels without being a member
    - im:write              — open DMs with workspace members
    - users:read            — resolve @handles / names (workspace-unique)
    - channels:read         — resolve public channel names
    - groups:read           — resolve private channel names (bot must be a member)

    users:read.email is intentionally excluded — @handle is workspace-unique and
    sufficient for the single-workspace use case. Add later if email-based lookup
    becomes necessary.
    """

    meta = ConnectorMeta(
        name="slack",
        display_name="Slack",
        oauth_authorize_url="https://slack.com/oauth/v2/authorize",
        oauth_token_url="https://slack.com/api/oauth.v2.access",  # noqa: S106 — endpoint URL, not a password
        scopes=[
            "chat:write",
            "chat:write.public",
            "im:write",
            "users:read",
            "channels:read",
            "groups:read",
        ],
    )

    def __init__(self) -> None:
        # Cache: key = f"{token_hash}:{method}", value = (expires_at, results).
        # Per-workspace isolation via token_hash; one broker-wide cache dict.
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        # Per-token-hash lock protects cache population from the thundering-herd
        # problem — concurrent send_dm calls with a cache miss all wait on the
        # same lock instead of all hitting users.list simultaneously.
        self._cache_locks: dict[str, asyncio.Lock] = {}

    # --- Cache ---

    def _get_lock(self, token_hash: str) -> asyncio.Lock:
        """Return the per-token cache-population lock, creating it lazily."""
        lock = self._cache_locks.get(token_hash)
        if lock is None:
            lock = asyncio.Lock()
            self._cache_locks[token_hash] = lock
        return lock

    async def _cached_list(
        self, access_token: str, method: str, key: str, **params: Any
    ) -> list[dict[str, Any]]:
        """Return cached users.list / conversations.list results, populating under lock on miss."""
        token_hash = _token_hash(access_token)
        cache_key = f"{token_hash}:{method}"
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        async with self._get_lock(token_hash):
            # Re-check inside the lock — another coroutine may have populated it.
            cached = self._cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                return cached[1]
            items = await _slack_paginate(method, access_token, key, **params)
            self._cache[cache_key] = (time.monotonic() + CACHE_TTL_SECONDS, items)
            return items

    # --- Resolvers ---

    async def _resolve_recipient(self, recipient: str, access_token: str) -> str:
        """Return a Slack user ID for a name / @handle / ID. Raises on ambiguity or miss."""
        stripped = recipient.strip()
        if _USER_ID_RE.match(stripped):
            return stripped
        if _EMAIL_RE.match(stripped):
            raise ValueError(
                "Email lookup requires users:read.email scope (not enabled). "
                "Pass a @handle or user ID instead."
            )
        users = await self._cached_list(access_token, "users.list", "members")
        matches = _match_users(users, stripped)
        if len(matches) == 1:
            return matches[0]["id"]
        if len(matches) == 0:
            raise ValueError(f"No Slack user matches {recipient!r}")
        raise ValueError(
            json.dumps(
                {
                    "error": "ambiguous_name",
                    "query": recipient,
                    "candidates": [_user_summary(user) for user in matches[:MAX_CANDIDATES]],
                }
            )
        )

    async def _resolve_channel(self, channel: str, access_token: str) -> str:
        """Return a Slack channel ID for a name / #name / ID. Raises on miss."""
        stripped = channel.strip()
        if _CHANNEL_ID_RE.match(stripped):
            return stripped
        query = stripped[1:] if stripped.startswith("#") else stripped
        channels = await self._cached_list(
            access_token,
            "conversations.list",
            "channels",
            types="public_channel,private_channel",
            exclude_archived="true",
        )
        matches = [candidate for candidate in channels if candidate.get("name") == query]
        if len(matches) == 1:
            return matches[0]["id"]
        if len(matches) == 0:
            raise ValueError(f"No Slack channel matches {channel!r}")
        raise ValueError(_ambiguous_channel_error(channel, matches))

    # --- MCP tools ---

    @native_tool(_SEND_DM_META)
    async def send_dm(
        self,
        *,
        access_token: str,
        recipient: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Open a DM with `recipient` and post `text`. Returns {channel, ts}."""
        _validate_text_length(text)
        user_id = await self._resolve_recipient(recipient, access_token)
        open_response = await _slack_api_call("conversations.open", access_token, users=user_id)
        dm_channel_id = open_response.get("channel", {}).get("id")
        if not dm_channel_id:
            raise ValueError("Slack conversations.open returned no channel id")
        post_response = await _slack_api_call(
            "chat.postMessage",
            access_token,
            channel=dm_channel_id,
            text=text,
            blocks=blocks,
            unfurl_links=False,
            unfurl_media=False,
        )
        return _mcp_text({"channel": post_response["channel"], "ts": post_response["ts"]})

    @native_tool(_SEND_MESSAGE_META)
    async def send_message(  # noqa: PLR0913 -- MCP tool signature
        self,
        *,
        access_token: str,
        channel: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
        thread_ts: str | None = None,
    ) -> list[dict[str, Any]]:
        """Post `text` to `channel`. Returns {channel, ts}."""
        _validate_text_length(text)
        channel_id = await self._resolve_channel(channel, access_token)
        response = await _slack_api_call(
            "chat.postMessage",
            access_token,
            channel=channel_id,
            text=text,
            blocks=blocks,
            thread_ts=thread_ts,
            unfurl_links=False,
            unfurl_media=False,
        )
        return _mcp_text({"channel": response["channel"], "ts": response["ts"]})

    @native_tool(_UPDATE_MESSAGE_META)
    async def update_message(  # noqa: PLR0913 -- MCP tool signature
        self,
        *,
        access_token: str,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Edit a previously-posted message. chat.update does NOT accept unfurl params."""
        _validate_text_length(text)
        response = await _slack_api_call(
            "chat.update",
            access_token,
            channel=channel,
            ts=ts,
            text=text,
            blocks=blocks,
        )
        return _mcp_text({"channel": response["channel"], "ts": response["ts"]})

    @native_tool(_DELETE_MESSAGE_META)
    async def delete_message(
        self, *, access_token: str, channel: str, ts: str
    ) -> list[dict[str, Any]]:
        """Delete a previously-posted message. Bot can only delete its own messages."""
        await _slack_api_call("chat.delete", access_token, channel=channel, ts=ts)
        return _mcp_text({"channel": channel, "ts": ts, "deleted": True})

    @native_tool(_FIND_USER_META)
    async def find_user(self, *, access_token: str, query: str) -> list[dict[str, Any]]:
        """Look up users matching `query`. Returns up to MAX_CANDIDATES non-ambiguous matches."""
        stripped = query.strip()
        needle = stripped[1:].lower() if stripped.startswith("@") else stripped.lower()
        # Reject empty/sigil-only queries — otherwise `in ""` is True and the
        # call dumps MAX_CANDIDATES arbitrary workspace members.
        if not needle:
            raise ValueError("query must not be empty")
        users = await self._cached_list(access_token, "users.list", "members")
        matches = [
            user
            for user in users
            if not user.get("deleted")
            and not user.get("is_bot")
            and (
                needle in user.get("name", "").lower()
                or needle in user.get("real_name", "").lower()
                or needle in user.get("profile", {}).get("display_name", "").lower()
            )
        ]
        return _mcp_text([_user_summary(user) for user in matches[:MAX_CANDIDATES]])

    @native_tool(_FIND_CHANNEL_META)
    async def find_channel(self, *, access_token: str, query: str) -> list[dict[str, Any]]:
        """Look up channels matching `query`. Returns up to MAX_CANDIDATES matches."""
        stripped = query.strip()
        needle = stripped[1:].lower() if stripped.startswith("#") else stripped.lower()
        # Reject empty/sigil-only queries — otherwise `in ""` matches every channel.
        if not needle:
            raise ValueError("query must not be empty")
        channels = await self._cached_list(
            access_token,
            "conversations.list",
            "channels",
            types="public_channel,private_channel",
            exclude_archived="true",
        )
        matches = [channel for channel in channels if needle in channel.get("name", "").lower()]
        return _mcp_text([_channel_summary(channel) for channel in matches[:MAX_CANDIDATES]])

    @classmethod
    def tool_prompt_instructions(cls) -> str:
        """LLM guidance for Slack tool usage."""
        return (
            "Slack tool notes:\n"
            "1. Messages are posted as the bot app (not as the installing user). "
            "You cannot impersonate another user.\n"
            "2. `text` is interpreted as Slack mrkdwn. `<@U123>` becomes a real user mention; "
            "`<#C456>` becomes a real channel link. Only emit these when intended.\n"
            "3. For send_dm, prefer passing an @handle (workspace-unique) or a Slack user ID. "
            "Real-name lookup can be ambiguous — use find_user first if unsure.\n"
            "4. Preserve the returned {channel, ts} so you can call update_message to edit "
            "the same message instead of posting a new one for status updates.\n"
            f"5. Message text is capped at {MAX_TEXT_LENGTH} characters. Split longer content."
        )


# === PRIVATE HELPERS ===


def _match_users(users: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Exact-match users by @handle (if query starts with @) or real/display name.

    Filters out deleted + bot users. Caller decides what to do with 0 / 1 / N matches.
    """
    active = [user for user in users if not user.get("deleted") and not user.get("is_bot")]
    if query.startswith("@"):
        handle = query[1:].lower()
        return [user for user in active if user.get("name", "").lower() == handle]
    query_lower = query.lower()
    return [
        user
        for user in active
        if user.get("real_name", "").lower() == query_lower
        or user.get("profile", {}).get("display_name", "").lower() == query_lower
    ]


def _validate_text_length(text: str) -> None:
    """Raise if `text` exceeds Slack's 4,000-char msg_too_long threshold."""
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"Slack text exceeds {MAX_TEXT_LENGTH} characters ({len(text)} given)")


def _user_summary(user: dict[str, Any]) -> dict[str, Any]:
    """Extract id / name / real_name / display_name from a Slack user object."""
    return {
        "id": user.get("id"),
        "name": user.get("name"),
        "real_name": user.get("real_name"),
        "display_name": user.get("profile", {}).get("display_name"),
    }


def _ambiguous_channel_error(query: str, matches: list[dict[str, Any]]) -> str:
    """JSON error body for a channel name that matched multiple cached entries.

    Channel names are workspace-unique per Slack — multi-match means the cache
    is stale or types overlap. Surface as ambiguous rather than guess.
    """
    return json.dumps(
        {
            "error": "ambiguous_channel",
            "query": query,
            "candidates": [_channel_summary(channel) for channel in matches[:MAX_CANDIDATES]],
        }
    )


def _channel_summary(channel: dict[str, Any]) -> dict[str, Any]:
    """Extract id / name / is_private / is_archived from a Slack channel object."""
    return {
        "id": channel.get("id"),
        "name": channel.get("name"),
        "is_private": channel.get("is_private", False),
        "is_archived": channel.get("is_archived", False),
    }
