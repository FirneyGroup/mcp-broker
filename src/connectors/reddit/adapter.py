"""
Reddit MCP Connector

Native connector that wraps the Reddit API via httpx as MCP tools.
Auto-registers on import via NativeConnector.__init_subclass__.

Uses httpx (async) directly — asyncpraw's built-in token management
conflicts with the broker's OAuth lifecycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from base64 import b64encode
from typing import Any

import httpx

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta

logger = logging.getLogger(__name__)

# === CONSTANTS ===

REDDIT_API_BASE = "https://oauth.reddit.com"
REDDIT_USER_AGENT = "server:com.mcp-broker.reddit:v1.0.0 (by /u/your_reddit_username)"
MAX_TITLE_LENGTH = 300
MAX_SELFTEXT_LENGTH = 40_000
MAX_COMMENT_LENGTH = 10_000
DEFAULT_LIMIT = 10
MAX_LIMIT = 100
MAX_COMMENT_DEPTH = 10
RATE_LIMIT_RETRY_CAP_SECONDS = 30

# Input validation patterns (prevent path traversal in URL construction)
_SUBREDDIT_RE = re.compile(r"^[A-Za-z0-9_]{1,50}$")
_POST_ID_RE = re.compile(r"^[a-z0-9]{1,10}$")
_FULLNAME_RE = re.compile(r"^t[136]_[a-z0-9]+$")


# === INPUT VALIDATION ===


def _validate_subreddit(subreddit: str) -> None:
    """Validate subreddit name. Prevents path traversal in URL construction."""
    if not _SUBREDDIT_RE.match(subreddit):
        raise ValueError(f"Invalid subreddit name: {subreddit!r}")


def _validate_post_id(post_id: str) -> None:
    """Validate post ID (base-36 string). Prevents path traversal in URL construction."""
    if not _POST_ID_RE.match(post_id):
        raise ValueError(f"Invalid post ID: {post_id!r}")


def _validate_fullname(fullname: str) -> None:
    """Validate Reddit fullname (e.g. t3_abc123). Prevents injection via form fields."""
    if not _FULLNAME_RE.match(fullname):
        raise ValueError(f"Invalid fullname: {fullname!r}")


# === SERIALIZATION HELPERS ===


def _extract_listing_children(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract children from Reddit's listing format.

    Reddit wraps results in {"kind": "Listing", "data": {"children": [...]}}.
    Returns empty list for error responses or missing data — never raises.
    """
    return response.get("data", {}).get("children", [])


_POST_FIELDS = (
    "id",
    "name",
    "title",
    "selftext",
    "author",
    "subreddit",
    "score",
    "num_comments",
    "url",
    "created_utc",
    "permalink",
    "is_self",
)

_COMMENT_FIELDS = (
    "id",
    "name",
    "body",
    "author",
    "score",
    "created_utc",
    "parent_id",
    "permalink",
)


def _simplify_post(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract useful fields from a Reddit post object."""
    post = {k: raw[k] for k in _POST_FIELDS if k in raw}
    post["author"] = post.get("author") or "[deleted]"
    return post


def _simplify_comment(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract useful fields from a Reddit comment object."""
    comment = {k: raw[k] for k in _COMMENT_FIELDS if k in raw}
    comment["author"] = comment.get("author") or "[deleted]"
    return comment


def _clamp_limit(limit: int) -> int:
    """Clamp limit to the valid range [1, MAX_LIMIT]."""
    return max(1, min(limit, MAX_LIMIT))


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as MCP text content blocks."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


def _build_comment_tree(children: list[dict[str, Any]], depth: int) -> list[dict[str, Any]]:
    """Recursively build comment tree with depth limit.

    Each comment gets a "replies" field containing nested child comments.
    Depth 1 = top-level only (no replies). Depth 3 = 2 levels of nesting.
    """
    comments: list[dict[str, Any]] = []
    for child in children:
        if child.get("kind") != "t1":
            continue
        comment = _simplify_comment(child.get("data", {}))
        if depth > 1:
            reply_listing = child.get("data", {}).get("replies")
            if isinstance(reply_listing, dict):
                reply_children = _extract_listing_children(reply_listing)
                comment["replies"] = _build_comment_tree(reply_children, depth - 1)
            else:
                comment["replies"] = []
        comments.append(comment)
    return comments


# === ASYNC API HELPERS ===


def _build_headers(access_token: str) -> dict[str, str]:
    """Build headers for Reddit API requests."""
    return {
        "Authorization": f"bearer {access_token}",
        "User-Agent": REDDIT_USER_AGENT,
    }


def _check_status(response: httpx.Response) -> None:
    """Check response for auth errors. Raises on 401, passes through otherwise."""
    if response.status_code == 401:  # noqa: PLR2004 — HTTP status code
        raise ValueError("Reddit token expired or revoked — reconnect via /oauth/reddit/connect")


async def _retry_on_rate_limit(response: httpx.Response, request_fn: Any) -> httpx.Response:
    """If 429, sleep Retry-After (capped) and retry once. Raises on second 429."""
    if response.status_code != 429:  # noqa: PLR2004 — HTTP status code
        response.raise_for_status()
        return response
    retry_after = min(
        float(response.headers.get("Retry-After", "5")),
        RATE_LIMIT_RETRY_CAP_SECONDS,
    )
    logger.warning("[Reddit] Rate limited, retrying after %.1fs", retry_after)
    await asyncio.sleep(retry_after)
    retry_response = await request_fn()
    _check_status(retry_response)
    if retry_response.status_code == 429:  # noqa: PLR2004 — HTTP status code
        raise ValueError("Rate limited by Reddit after retry — try again later")
    retry_response.raise_for_status()
    return retry_response


async def _reddit_get(access_token: str, path: str, **params: Any) -> dict[str, Any]:
    """GET request to Reddit API with auth, rate limiting, and retry."""
    url = f"{REDDIT_API_BASE}{path}"
    headers = _build_headers(access_token)
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)
        _check_status(response)
        response = await _retry_on_rate_limit(
            response, lambda: client.get(url, headers=headers, params=params)
        )
        return response.json()


async def _reddit_post(access_token: str, path: str, form_fields: dict[str, Any]) -> dict[str, Any]:
    """POST request to Reddit API (form-encoded) with auth and rate limiting."""
    url = f"{REDDIT_API_BASE}{path}"
    headers = _build_headers(access_token)
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, data=form_fields)
        _check_status(response)
        response = await _retry_on_rate_limit(
            response, lambda: client.post(url, headers=headers, data=form_fields)
        )
        return response.json()


# === TOOL METADATA ===

_GET_ME_META = NativeToolMeta(
    name="get_me",
    description="Get the authenticated Reddit user's profile (username, karma, account age).",
    input_schema={"type": "object", "properties": {}},
)

_SUBMIT_POST_META = NativeToolMeta(
    name="submit_post",
    description=(
        "Submit a post to a subreddit. Set kind='self' for text posts (requires text), "
        "kind='link' for link posts (requires url). Title max 300 chars."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "subreddit": {
                "type": "string",
                "description": "Subreddit name (without /r/)",
            },
            "title": {
                "type": "string",
                "description": "Post title (max 300 chars)",
            },
            "kind": {
                "type": "string",
                "enum": ["self", "link"],
                "description": "Post type: 'self' for text, 'link' for URL",
            },
            "text": {
                "type": "string",
                "description": "Post body for text posts (max 40000 chars)",
            },
            "url": {"type": "string", "description": "URL for link posts"},
        },
        "required": ["subreddit", "title", "kind"],
    },
)

_ADD_COMMENT_META = NativeToolMeta(
    name="add_comment",
    description=(
        "Reply to a Reddit post or comment. "
        "Parent must be a fullname (t3_ for posts, t1_ for comments)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "parent": {
                "type": "string",
                "description": "Fullname of parent (e.g. t3_abc123 for post, t1_xyz789 for comment)",
            },
            "text": {
                "type": "string",
                "description": "Comment text in Markdown (max 10000 chars)",
            },
        },
        "required": ["parent", "text"],
    },
)

_SEARCH_META = NativeToolMeta(
    name="search",
    description="Search Reddit for posts matching a query. Optionally restrict to a subreddit.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "subreddit": {
                "type": "string",
                "description": "Restrict search to this subreddit (optional)",
            },
            "sort": {
                "type": "string",
                "enum": ["relevance", "hot", "top", "new", "comments"],
                "description": "Sort order (default: relevance)",
                "default": "relevance",
            },
            "limit": {
                "type": "integer",
                "description": "Number of results (1-100, default 10)",
                "default": 10,
            },
        },
        "required": ["query"],
    },
)

_GET_SUBREDDIT_POSTS_META = NativeToolMeta(
    name="get_subreddit_posts",
    description="Get posts from a subreddit sorted by hot, new, top, or rising.",
    input_schema={
        "type": "object",
        "properties": {
            "subreddit": {
                "type": "string",
                "description": "Subreddit name (without /r/)",
            },
            "sort": {
                "type": "string",
                "enum": ["hot", "new", "top", "rising"],
                "description": "Sort order (default: hot)",
                "default": "hot",
            },
            "limit": {
                "type": "integer",
                "description": "Number of posts (1-100, default 10)",
                "default": 10,
            },
        },
        "required": ["subreddit"],
    },
)

_GET_POST_COMMENTS_META = NativeToolMeta(
    name="get_post_comments",
    description=(
        "Get comments on a Reddit post by its ID (without t3_ prefix). "
        "Supports nested replies via depth param."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "post_id": {
                "type": "string",
                "description": "Post ID (e.g. 'abc123', without t3_ prefix)",
            },
            "sort": {
                "type": "string",
                "enum": ["confidence", "top", "new", "controversial", "old"],
                "description": "Comment sort order (default: confidence)",
                "default": "confidence",
            },
            "limit": {
                "type": "integer",
                "description": "Number of top-level comments (1-100, default 10)",
                "default": 10,
            },
            "depth": {
                "type": "integer",
                "description": "Max reply nesting depth (1-10, default 3). 1 = top-level only.",
                "default": 3,
            },
        },
        "required": ["post_id"],
    },
)

_DELETE_META = NativeToolMeta(
    name="delete",
    description="Delete a Reddit post or comment by its fullname (t3_ for posts, t1_ for comments).",
    input_schema={
        "type": "object",
        "properties": {
            "fullname": {
                "type": "string",
                "description": "Fullname of the item to delete (e.g. t3_abc123 or t1_xyz789)",
            },
        },
        "required": ["fullname"],
    },
)


# === CONNECTOR ===


class RedditConnector(NativeConnector):
    """Reddit native connector — wraps Reddit API via httpx as MCP tools.

    Uses OAuth 2.0 with HTTP Basic Auth for token exchange.
    Requires duration=permanent in authorize params for refresh tokens.
    """

    meta = ConnectorMeta(
        name="reddit",
        display_name="Reddit",
        oauth_authorize_url="https://www.reddit.com/api/v1/authorize",
        oauth_token_url="https://www.reddit.com/api/v1/access_token",  # noqa: S106 — endpoint URL, not a password
        scopes=["identity", "read", "submit", "edit"],
    )

    # --- OAuth overrides ---

    def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
        """Add duration=permanent to get refresh tokens from Reddit."""
        params["duration"] = "permanent"
        return params

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """Reddit requires HTTP Basic Auth for token exchange."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    # --- MCP tools ---

    @native_tool(_GET_ME_META)
    async def get_me(self, *, access_token: str) -> list[dict[str, Any]]:
        """Get authenticated user's Reddit profile."""
        profile = await _reddit_get(access_token, "/api/v1/me")
        return _mcp_text_content(profile)

    @native_tool(_SEARCH_META)
    async def search(  # noqa: PLR0913 — MCP tool signature
        self,
        *,
        access_token: str,
        query: str,
        subreddit: str = "",
        sort: str = "relevance",
        limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """Search Reddit for posts matching a query."""
        clamped = _clamp_limit(limit)
        if subreddit:
            _validate_subreddit(subreddit)
            listing = await _reddit_get(
                access_token,
                f"/r/{subreddit}/search",
                q=query,
                sort=sort,
                limit=clamped,
                restrict_sr="true",
            )
        else:
            listing = await _reddit_get(access_token, "/search", q=query, sort=sort, limit=clamped)
        children = _extract_listing_children(listing)
        posts = [_simplify_post(child["data"]) for child in children]
        return _mcp_text_content(posts)

    @native_tool(_GET_SUBREDDIT_POSTS_META)
    async def get_subreddit_posts(
        self,
        *,
        access_token: str,
        subreddit: str,
        sort: str = "hot",
        limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """Get posts from a subreddit."""
        _validate_subreddit(subreddit)
        clamped = _clamp_limit(limit)
        listing = await _reddit_get(access_token, f"/r/{subreddit}", sort=sort, limit=clamped)
        children = _extract_listing_children(listing)
        posts = [_simplify_post(child["data"]) for child in children]
        return _mcp_text_content(posts)

    @native_tool(_GET_POST_COMMENTS_META)
    async def get_post_comments(  # noqa: PLR0913 — MCP tool signature
        self,
        *,
        access_token: str,
        post_id: str,
        sort: str = "confidence",
        limit: int = DEFAULT_LIMIT,
        depth: int = 3,
    ) -> list[dict[str, Any]]:
        """Get comments on a Reddit post with nested replies."""
        _validate_post_id(post_id)
        clamped = _clamp_limit(limit)
        clamped_depth = max(1, min(depth, MAX_COMMENT_DEPTH))
        # Reddit returns [post_listing, comments_listing]
        response = await _reddit_get(
            access_token,
            f"/comments/{post_id}",
            sort=sort,
            limit=clamped,
            depth=clamped_depth,
        )
        if isinstance(response, list) and len(response) >= 2:  # noqa: PLR2004 — Reddit returns exactly 2 listings
            comments_listing = response[1]  # type: ignore[index]  # Reddit returns [post, comments] list
        else:
            comments_listing = response
        children = _extract_listing_children(comments_listing)
        comments = _build_comment_tree(children, clamped_depth)
        return _mcp_text_content(comments)

    @native_tool(_SUBMIT_POST_META)
    async def submit_post(  # noqa: PLR0913 — MCP tool signature
        self,
        *,
        access_token: str,
        subreddit: str,
        title: str,
        kind: str,
        text: str = "",
        url: str = "",
    ) -> list[dict[str, Any]]:
        """Submit a post to a subreddit."""
        _validate_subreddit(subreddit)
        if len(title) > MAX_TITLE_LENGTH:
            raise ValueError(f"Title exceeds {MAX_TITLE_LENGTH} characters ({len(title)} given)")
        if kind == "link" and not url:
            raise ValueError("url is required for link posts")
        if kind == "self" and not text:
            raise ValueError("text is required for text posts")
        if kind == "self" and len(text) > MAX_SELFTEXT_LENGTH:
            raise ValueError(f"Text exceeds {MAX_SELFTEXT_LENGTH} characters ({len(text)} given)")
        form_fields: dict[str, Any] = {
            "sr": subreddit,
            "title": title,
            "kind": kind,
            "resubmit": "true",
            "sendreplies": "true",
        }
        if kind == "self":
            form_fields["text"] = text
        else:
            form_fields["url"] = url
        response = await _reddit_post(access_token, "/api/submit", form_fields)
        return _mcp_text_content(response)

    @native_tool(_ADD_COMMENT_META)
    async def add_comment(
        self, *, access_token: str, parent: str, text: str
    ) -> list[dict[str, Any]]:
        """Reply to a post or comment."""
        _validate_fullname(parent)
        if len(text) > MAX_COMMENT_LENGTH:
            raise ValueError(f"Comment exceeds {MAX_COMMENT_LENGTH} characters ({len(text)} given)")
        response = await _reddit_post(
            access_token, "/api/comment", {"parent": parent, "text": text}
        )
        return _mcp_text_content(response)

    @native_tool(_DELETE_META)
    async def delete(self, *, access_token: str, fullname: str) -> list[dict[str, Any]]:
        """Delete a post or comment by fullname."""
        _validate_fullname(fullname)
        await _reddit_post(access_token, "/api/del", {"id": fullname})
        return _mcp_text_content({"fullname": fullname, "deleted": True})
