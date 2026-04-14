"""
Twitter/X MCP Connector

Native connector that wraps the xdk Python SDK as MCP tools.
Auto-registers on import via NativeConnector.__init_subclass__.

xdk uses synchronous HTTP (requests), so all calls are wrapped in
asyncio.run_in_executor() to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from base64 import b64encode
from typing import Any

from xdk import Client as XClient
from xdk.posts.models import CreateRequest

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta

logger = logging.getLogger(__name__)

# === CONSTANTS ===

MAX_TWEET_LENGTH = 280
MAX_RESULTS_CAP = 100
DEFAULT_MAX_RESULTS = 10

_TWEET_ID_RE = re.compile(r"^\d{1,20}$")

# === TOOL METADATA ===

_POST_TWEET_META = NativeToolMeta(
    name="post_tweet",
    description="Post a tweet to X/Twitter. Text must be 280 characters or fewer.",
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Tweet text (max 280 chars)"},
        },
        "required": ["text"],
    },
)

_GET_ME_META = NativeToolMeta(
    name="get_me",
    description="Get the authenticated user's X/Twitter profile information.",
    input_schema={
        "type": "object",
        "properties": {},
    },
)

_DELETE_TWEET_META = NativeToolMeta(
    name="delete_tweet",
    description="Delete a tweet by its ID.",
    input_schema={
        "type": "object",
        "properties": {
            "tweet_id": {"type": "string", "description": "ID of the tweet to delete"},
        },
        "required": ["tweet_id"],
    },
)

_GET_MY_TWEETS_META = NativeToolMeta(
    name="get_my_tweets",
    description="Get recent tweets from the authenticated user. Returns up to max_results tweets.",
    input_schema={
        "type": "object",
        "properties": {
            "max_results": {
                "type": "integer",
                "description": "Number of tweets to return (1-100, default 10)",
                "default": 10,
            },
        },
    },
)

_SEARCH_TWEETS_META = NativeToolMeta(
    name="search_tweets",
    description="Search recent tweets on X/Twitter matching a query string.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "max_results": {
                "type": "integer",
                "description": "Number of tweets to return (1-100, default 10)",
                "default": 10,
            },
        },
        "required": ["query"],
    },
)


# === SYNC HELPERS (run in executor) ===


def _post_tweet_sync(access_token: str, text: str) -> dict[str, Any]:
    """Post a tweet via xdk. Returns tweet data as a dict."""
    client = XClient(access_token=access_token)
    response = client.posts.create(body=CreateRequest(text=text))
    return _model_to_dict(response)


def _get_me_sync(access_token: str) -> dict[str, Any]:
    """Get authenticated user profile via xdk."""
    client = XClient(access_token=access_token)
    response = client.users.get_me()
    return _model_to_dict(response.data)


def _delete_tweet_sync(access_token: str, tweet_id: str) -> dict[str, Any]:
    """Delete a tweet via xdk."""
    client = XClient(access_token=access_token)
    response = client.posts.delete(id=tweet_id)
    deleted = response.data.deleted if response.data else False
    return {"tweet_id": tweet_id, "deleted": deleted}


def _get_my_tweets_sync(access_token: str, max_results: int) -> list[dict[str, Any]]:
    """Get authenticated user's recent tweets via xdk."""
    client = XClient(access_token=access_token)
    user_response = client.users.get_me()
    user_id = _extract_user_id(user_response.data)

    tweets: list[dict[str, Any]] = []
    for page in client.users.get_posts(id=user_id, max_results=max_results):
        if page.data:
            tweets.extend(_model_to_dict(tweet) for tweet in page.data)
        break  # first page only
    return tweets


def _search_tweets_sync(access_token: str, query: str, max_results: int) -> list[dict[str, Any]]:
    """Search recent tweets via xdk."""
    client = XClient(access_token=access_token)
    tweets: list[dict[str, Any]] = []
    for page in client.posts.search_recent(query=query, max_results=max_results):
        if page.data:
            tweets.extend(_model_to_dict(tweet) for tweet in page.data)
        break  # first page only
    return tweets


# === SERIALIZATION HELPERS ===


def _model_to_dict(model: Any) -> Any:
    """Convert a Pydantic model or dict-like object to a plain dict."""
    if isinstance(model, dict):
        return model
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return dict(model)


def _extract_user_id(user_data: Any) -> str:
    """Extract user ID from get_me response data."""
    if isinstance(user_data, dict):
        return str(user_data["id"])
    if hasattr(user_data, "id"):
        return str(user_data.id)
    raise ValueError("Cannot extract user ID from response")


def _clamp_max_results(max_results: int) -> int:
    """Clamp max_results to the valid range [1, MAX_RESULTS_CAP]."""
    return max(1, min(max_results, MAX_RESULTS_CAP))


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as MCP text content blocks."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


# === CONNECTOR ===


class TwitterConnector(NativeConnector):
    """Twitter/X native connector — wraps xdk SDK as MCP tools.

    Uses OAuth 2.0 with PKCE. X requires HTTP Basic Auth for token exchange
    (base64-encoded client_id:client_secret in Authorization header).
    """

    meta = ConnectorMeta(
        name="twitter",
        display_name="Twitter/X",
        oauth_authorize_url="https://x.com/i/oauth2/authorize",
        oauth_token_url="https://api.x.com/2/oauth2/token",  # noqa: S106 — endpoint URL, not a password
        scopes=["tweet.read", "tweet.write", "users.read", "offline.access"],
    )

    # --- OAuth override ---

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """X requires HTTP Basic Auth for token exchange (client_secret_basic)."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    # --- MCP tools ---

    @native_tool(_POST_TWEET_META)
    async def post_tweet(self, *, access_token: str, text: str) -> list[dict[str, Any]]:
        """Post a tweet. Validates length before calling X API."""
        if len(text) > MAX_TWEET_LENGTH:
            raise ValueError(f"Tweet exceeds {MAX_TWEET_LENGTH} characters ({len(text)} given)")
        loop = asyncio.get_running_loop()
        tweet_response = await loop.run_in_executor(None, _post_tweet_sync, access_token, text)
        return _mcp_text_content(tweet_response)

    @native_tool(_GET_ME_META)
    async def get_me(self, *, access_token: str) -> list[dict[str, Any]]:
        """Get authenticated user's profile."""
        loop = asyncio.get_running_loop()
        profile = await loop.run_in_executor(None, _get_me_sync, access_token)
        return _mcp_text_content(profile)

    @native_tool(_DELETE_TWEET_META)
    async def delete_tweet(self, *, access_token: str, tweet_id: str) -> list[dict[str, Any]]:
        """Delete a tweet by ID."""
        if not _TWEET_ID_RE.match(tweet_id):
            raise ValueError(f"Invalid tweet ID: {tweet_id!r}")
        loop = asyncio.get_running_loop()
        deletion = await loop.run_in_executor(None, _delete_tweet_sync, access_token, tweet_id)
        return _mcp_text_content(deletion)

    @native_tool(_GET_MY_TWEETS_META)
    async def get_my_tweets(
        self, *, access_token: str, max_results: int = DEFAULT_MAX_RESULTS
    ) -> list[dict[str, Any]]:
        """Get the authenticated user's recent tweets."""
        clamped = _clamp_max_results(max_results)
        loop = asyncio.get_running_loop()
        tweets = await loop.run_in_executor(None, _get_my_tweets_sync, access_token, clamped)
        return _mcp_text_content(tweets)

    @native_tool(_SEARCH_TWEETS_META)
    async def search_tweets(
        self, *, access_token: str, query: str, max_results: int = DEFAULT_MAX_RESULTS
    ) -> list[dict[str, Any]]:
        """Search recent tweets matching a query."""
        clamped = _clamp_max_results(max_results)
        loop = asyncio.get_running_loop()
        tweets = await loop.run_in_executor(None, _search_tweets_sync, access_token, query, clamped)
        return _mcp_text_content(tweets)
