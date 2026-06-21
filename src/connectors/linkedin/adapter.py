"""
LinkedIn MCP Connector

Native connector that wraps the LinkedIn API via httpx as MCP tools.
Auto-registers on import via NativeConnector.__init_subclass__.

Uses httpx (async) directly with standard OAuth 2.0 client_secret_post
(broker default -- no auth override needed).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from base64 import b64decode
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import ConnectorMeta

logger = logging.getLogger(__name__)

# === CONSTANTS ===

LINKEDIN_API_BASE = "https://api.linkedin.com"
# Versioned API (Community Management) — versions sunset after 12 months.
# Check active versions: https://learn.microsoft.com/en-us/linkedin/marketing/integrations/migrations
LINKEDIN_API_VERSION = "202601"
MAX_POST_LENGTH = 3000
MAX_COMMENT_LENGTH = 1250
DEFAULT_LIMIT = 10
MAX_LIMIT = 50
RATE_LIMIT_RETRY_CAP_SECONDS = 30
# LinkedIn daily quotas have long retry windows -- don't wait, just fail fast
DAILY_QUOTA_THRESHOLD_SECONDS = 300

# Media uploads are larger than the JSON calls; the 5s httpx default is too tight.
MEDIA_UPLOAD_TIMEOUT_SECONDS = 60.0
# Byte ceilings enforced before the upload PUT. LinkedIn's documented maxima:
# images have no published MB cap (only a pixel ceiling) -- 10 MB is a safe practical
# bound; documents (which render as a swipeable carousel) allow up to 100 MB / 300 pages.
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_DOCUMENT_BYTES = 100 * 1024 * 1024
# Base64 inflates bytes by ~4/3. _decode_media rejects an over-long encoded string before
# decoding it (OOM defence -- mirrors the notion_api upload_file tool); the same ceiling is
# surfaced as the schema maxLength, which is advisory only -- the broker does not validate
# inputs against it. Ceil-divide the byte cap by 3, then multiply by 4.
_MAX_IMAGE_BASE64_CHARS = -(-MAX_IMAGE_BYTES // 3) * 4
_MAX_DOCUMENT_BASE64_CHARS = -(-MAX_DOCUMENT_BYTES // 3) * 4

# initializeUpload returns the URL the media bytes are PUT to with the access token
# attached, so that URL is restricted to LinkedIn's own domains (see _validate_upload_url).
_UPLOAD_HOST_SUFFIXES = (".linkedin.com", ".licdn.com")
_EXACT_UPLOAD_HOSTS = frozenset({"linkedin.com", "licdn.com"})

# === SCOPES ===

# OAuth scopes requested for every LinkedIn connection. Self-serve products only
# (Share on LinkedIn + Sign In with OpenID Connect), which is what an app gets
# without LinkedIn review.
#
# To enable the organization tools (get_org_posts, get_managed_orgs,
# create_comment, react_to_post, get_post_comments, get_org_analytics,
# get_post_analytics) apply for the Community Management API at
# developer.linkedin.com, then add the org scopes here:
#   "r_organization_social", "w_organization_social",
#   "r_organization_social_feed", "w_organization_social_feed",
#   "rw_organization_admin"
_SCOPES = (
    "openid",
    "profile",
    "w_member_social",
)

# Org tools call /rest/ Community Management endpoints. Without the org scopes
# above those calls are guaranteed 403s, so we guard the tools on this flag and
# raise an actionable error instead. Derived from _SCOPES so the gate flips
# automatically once the org scopes are added.
_ORG_TOOLS_ENABLED = "r_organization_social" in _SCOPES

# The 7 org-tier tools, gated behind the Community Management scopes. Used by
# is_tool_available to hide them from tools/list (and reject direct calls) until
# _ORG_TOOLS_ENABLED flips. Kept in sync with the org tools listed in _SCOPES.
_ORG_TOOL_NAMES = frozenset(
    {
        "get_org_posts",
        "get_managed_orgs",
        "create_comment",
        "react_to_post",
        "get_post_comments",
        "get_org_analytics",
        "get_post_analytics",
    }
)

# Raised by org tools when the Community Management scopes are not configured.
_ORG_TOOLS_DISABLED_ERROR = (
    "LinkedIn organization tools require the Community Management API "
    "(r_organization_social scope) -- see src/connectors/linkedin/SETUP.md"
)


def _require_org_tools() -> None:
    """Guard org-only tools. Raises a clear error before any HTTP call when the
    Community Management scopes are not configured (the calls would 403 anyway).
    """
    if not _ORG_TOOLS_ENABLED:
        raise ValueError(_ORG_TOOLS_DISABLED_ERROR)


# === INPUT VALIDATION ===

# URN regexes prevent path traversal in URL construction
_PERSON_URN_RE = re.compile(r"^urn:li:person:[A-Za-z0-9_-]{1,50}$")
_ORG_URN_RE = re.compile(r"^urn:li:organization:\d{1,20}$")
_POST_URN_RE = re.compile(r"^urn:li:(share|ugcPost|activity):\d{1,20}$")
_ORG_ID_RE = re.compile(r"^\d{1,20}$")


def _validate_post_urn(urn: str) -> None:
    """Validate post URN (share, ugcPost, or activity). Prevents injection via path/query."""
    if not _POST_URN_RE.match(urn):
        raise ValueError(f"Invalid post URN: {urn!r}")


def _validate_org_id(org_id: str) -> None:
    """Validate numeric organization ID. Prevents path traversal in URL construction."""
    if not _ORG_ID_RE.match(org_id):
        raise ValueError(f"Invalid organization ID: {org_id!r}")


def _decode_media(media_base64: str, max_bytes: int, label: str) -> bytes:
    """Decode base64 media and enforce the size ceiling BEFORE any HTTP call.

    The schema's maxLength is advisory -- the broker does not validate inputs against it
    (native.py passes raw arguments straight to the handler) -- so the real gate is here:
    reject an over-long encoded string before decoding (so an oversized payload is never
    expanded ~4/3 in memory), then re-check the decoded byte length.
    """
    # base64 inflates ~4/3, so bound the encoded length first (ceil(max_bytes / 3) * 4).
    if len(media_base64) > -(-max_bytes // 3) * 4:
        raise ValueError(f"The {label} exceeds the upload limit of {max_bytes} bytes")
    try:
        raw_bytes = b64decode(media_base64, validate=True)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise ValueError(f"The {label} is not valid base64") from exc
    if not raw_bytes:
        raise ValueError(f"The {label} is empty")
    if len(raw_bytes) > max_bytes:
        raise ValueError(
            f"The {label} is {len(raw_bytes)} bytes; the upload limit is {max_bytes} bytes"
        )
    return raw_bytes


def _validate_upload_url(url: str) -> None:
    """Guard the media-upload PUT, which carries the live access token.

    initializeUpload returns the URL the bytes are PUT to with the token in the
    Authorization header. Restrict it to HTTPS on a LinkedIn-owned host so a
    malformed or compromised initializeUpload response can't redirect the token to
    an attacker-controlled or internal address (SSRF + token leak). Allowlisting
    LinkedIn's domains is stricter than rejecting only private IPs -- nothing
    outside them is accepted, raw-IP hosts included.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https":
        raise ValueError("LinkedIn upload URL must use HTTPS")
    if host not in _EXACT_UPLOAD_HOSTS and not host.endswith(_UPLOAD_HOST_SUFFIXES):
        raise ValueError(f"Unexpected LinkedIn upload host: {host!r}")


# === SERIALIZATION HELPERS ===


def _simplify_profile(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract name, person URN, and picture from /userinfo response."""
    sub = raw.get("sub", "")
    return {
        "person_urn": f"urn:li:person:{sub}" if sub else None,
        "name": raw.get("name"),
        "given_name": raw.get("given_name"),
        "family_name": raw.get("family_name"),
        "picture": raw.get("picture"),
    }


def _simplify_post(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract author, commentary text, created time, URN, and engagement from a post."""
    return {
        "urn": raw.get("id"),
        "author": raw.get("author"),
        "text": raw.get("commentary"),
        "created_at": raw.get("createdAt"),
        "visibility": raw.get("visibility"),
        "likes": raw.get("likesSummary", {}).get("totalLikes"),
        "comments": raw.get("commentsSummary", {}).get("totalFirstLevelComments"),
        "reposts": raw.get("resharesSummary", {}).get("totalShareStatistics"),
    }


def _simplify_comment(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract actor, message text, and created time from a comment."""
    return {
        "urn": raw.get("$URN"),
        "actor": raw.get("actor"),
        "text": raw.get("message", {}).get("text"),
        "created_at": raw.get("created", {}).get("time"),
    }


def _simplify_org(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract org ID, name, and vanity name from an organization object."""
    return {
        "org_id": str(raw.get("id", "")),
        "org_urn": raw.get("$URN"),
        "name": raw.get("localizedName") or raw.get("name", {}).get("localized", {}).get("en_US"),
        "vanity_name": raw.get("vanityName"),
    }


def _simplify_analytics(raw: dict[str, Any], period: str) -> dict[str, Any]:
    """Flatten nested analytics stats to key-value pairs."""
    elements = raw.get("elements", [])
    if not elements:
        return {"period": period, "stats": {}}
    # Use the first element -- period is metadata-only (not sent to API)
    stats = elements[0].get("totalPageStatistics", elements[0])
    flat: dict[str, Any] = {"period": period}
    for section_key, section_val in stats.items():
        if isinstance(section_val, dict):
            for metric_key, metric_val in section_val.items():
                flat[f"{section_key}_{metric_key}"] = metric_val
        else:
            flat[section_key] = section_val
    return flat


def _simplify_share_stats(element: dict[str, Any]) -> dict[str, Any]:
    """Extract key metrics from a share statistics element."""
    totals = element.get("totalShareStatistics", {})
    return {
        "share_urn": element.get("share") or element.get("ugcPost"),
        "impressions": totals.get("impressionCount"),
        "clicks": totals.get("clickCount"),
        "likes": totals.get("likeCount"),
        "comments": totals.get("commentCount"),
        "shares": totals.get("shareCount"),
        "engagement_rate": totals.get("engagement"),
    }


def _clamp_limit(limit: int) -> int:
    """Clamp limit to the valid range [1, MAX_LIMIT]."""
    return max(1, min(limit, MAX_LIMIT))


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as MCP text content blocks."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


def _extract_org_id_from_urn(org_urn: str) -> str:
    """Extract numeric org ID from urn:li:organization:{id} format."""
    return org_urn.rsplit(":", 1)[-1]


# === ASYNC API HELPERS ===


class _SessionError(ValueError):
    """A failure that invalidates the whole session, not just one resource.

    Raised for token expiry (401) and exhausted rate limits. Subclasses
    ValueError so existing `except ValueError` handlers keep working, but lets
    per-resource degradation loops (e.g. _batch_fetch_orgs) re-raise it instead
    of masking token expiry as a missing name.
    """


def _build_headers(access_token: str, *, versioned: bool = True) -> dict[str, str]:
    """Build headers for LinkedIn API requests.

    versioned=True: /rest/ endpoints (Community Management API) — requires Linkedin-Version.
    versioned=False: /v2/ endpoints (Share on LinkedIn) — no version header needed.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": "2.0.0",
    }
    if versioned:
        headers["Linkedin-Version"] = LINKEDIN_API_VERSION
    return headers


def _check_status(response: httpx.Response) -> None:
    """Check response for auth and permission errors. Raises with sanitized messages."""
    if response.status_code == 401:  # noqa: PLR2004 -- HTTP status code
        raise _SessionError(
            "LinkedIn token expired or revoked -- reconnect via /oauth/linkedin/connect"
        )
    if response.status_code == 403:  # noqa: PLR2004 -- HTTP status code
        # LinkedIn 403s cover two distinct failure modes -- distinguish for actionability
        error_body = ""
        with contextlib.suppress(ValueError):  # response.json() raises on non-JSON bodies
            error_body = response.json().get("message", "")
        if "not approved" in error_body.lower() or "application" in error_body.lower():
            raise ValueError("LinkedIn API product not approved -- apply at developer.linkedin.com")
        raise ValueError("Insufficient scope for this operation")
    # Catch-all for other errors -- sanitize so raw URLs don't leak via str(exc)
    if response.is_error:
        logger.debug(
            "[LinkedIn] API error %d: %s",
            response.status_code,
            response.text[:500],
        )
        raise ValueError(f"LinkedIn API error ({response.status_code})")


async def _handle_response(
    response: httpx.Response,
    retry_fn: Callable[[], Awaitable[httpx.Response]],
    *,
    idempotent: bool = True,
) -> httpx.Response:
    """Handle rate limiting and status checking in correct order.

    _check_status must NOT run before retry logic, because it raises on 429
    and would prevent the retry from ever executing.

    idempotent=False (POST creates): never retry. Re-issuing a create after a
    429 risks a double-post / double-comment, so we surface the rate limit
    immediately instead.
    """
    if response.status_code == 429:  # noqa: PLR2004 -- HTTP status code
        if not idempotent:
            raise _SessionError("Rate limited by LinkedIn -- try again later")
        return await _retry_on_rate_limit(response, retry_fn)
    _check_status(response)
    return response


async def _retry_on_rate_limit(
    response: httpx.Response,
    request_fn: Callable[[], Awaitable[httpx.Response]],
) -> httpx.Response:
    """Sleep Retry-After (capped) and retry once. Raises on daily quota or second 429.

    LinkedIn daily quotas use very long Retry-After values. If Retry-After
    exceeds DAILY_QUOTA_THRESHOLD_SECONDS, raise immediately rather than sleep.
    """
    try:
        retry_after = float(response.headers.get("Retry-After", "5"))
    except (ValueError, TypeError):
        retry_after = 5.0  # HTTP spec allows date format — fall back to safe default
    if retry_after > DAILY_QUOTA_THRESHOLD_SECONDS:
        raise _SessionError("LinkedIn daily quota exceeded -- try again tomorrow")
    capped = min(retry_after, RATE_LIMIT_RETRY_CAP_SECONDS)
    logger.warning("[LinkedIn] Rate limited, retrying after %.1fs", capped)
    await asyncio.sleep(capped)
    retry_response = await request_fn()
    if retry_response.status_code == 429:  # noqa: PLR2004 -- HTTP status code
        raise _SessionError("Rate limited by LinkedIn after retry -- try again later")
    _check_status(retry_response)
    return retry_response


async def _linkedin_get(
    access_token: str,
    path: str,
    *,
    restli_method: str | None = None,
    versioned: bool = True,
    **params: Any,
) -> dict[str, Any]:
    """GET request to LinkedIn API with auth, rate limiting, and retry."""
    url = f"{LINKEDIN_API_BASE}{path}"
    headers = _build_headers(access_token, versioned=versioned)
    if restli_method:
        headers["X-RestLi-Method"] = restli_method
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)
        response = await _handle_response(
            response, lambda: client.get(url, headers=headers, params=params)
        )
        return response.json()


async def _linkedin_post(  # noqa: PLR0913 -- all params required
    access_token: str,
    path: str,
    json_body: dict[str, Any],
    *,
    extra_params: dict[str, str] | None = None,
    versioned: bool = True,
) -> dict[str, Any]:
    """POST request to LinkedIn API (JSON body) with auth and rate limiting."""
    url = f"{LINKEDIN_API_BASE}{path}"
    headers = _build_headers(access_token, versioned=versioned)
    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            headers=headers,
            json=json_body,
            params=extra_params,
        )
        # idempotent=False -- POST creates are not retried; the retry_fn is never
        # invoked but the signature still requires a callable.
        response = await _handle_response(
            response,
            lambda: client.post(url, headers=headers, json=json_body, params=extra_params),
            idempotent=False,
        )
        if response.content:
            return response.json()
        # LinkedIn returns URN in x-restli-id header for create operations
        restli_id = response.headers.get("x-restli-id", "")
        return {"id": restli_id} if restli_id else {}


async def _linkedin_delete(access_token: str, path: str, *, versioned: bool = True) -> None:
    """DELETE request to LinkedIn API with auth and rate limiting."""
    url = f"{LINKEDIN_API_BASE}{path}"
    headers = _build_headers(access_token, versioned=versioned)
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
        await _handle_response(response, lambda: client.delete(url, headers=headers))


async def _get_person_urn(access_token: str) -> str:
    """Fetch the authenticated user's person URN via /userinfo."""
    profile = await _linkedin_get(access_token, "/v2/userinfo", versioned=False)
    sub = profile.get("sub", "")
    if not sub:
        raise ValueError("Could not resolve person URN -- /userinfo returned no sub field")
    return f"urn:li:person:{sub}"


# === TOOL METADATA ===

_GET_ME_META = NativeToolMeta(
    name="get_me",
    description="Get the authenticated LinkedIn member's profile (name, URN, picture).",
    input_schema={"type": "object", "properties": {}},
)

_CREATE_POST_META = NativeToolMeta(
    name="create_post",
    description=(
        "Create a LinkedIn post as the authenticated member or a managed organization. "
        "If author_urn is omitted, posts as the authenticated member. "
        "Text max 3000 chars."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Post text content (max 3000 chars)",
            },
            "author_urn": {
                "type": "string",
                "description": (
                    "URN of the author -- urn:li:person:{id} or urn:li:organization:{id}. "
                    "Defaults to the authenticated member if omitted."
                ),
            },
            "visibility": {
                "type": "string",
                "enum": ["PUBLIC", "CONNECTIONS"],
                "description": "Post visibility (default: PUBLIC)",
                "default": "PUBLIC",
            },
        },
        "required": ["text"],
    },
)

_CREATE_IMAGE_POST_META = NativeToolMeta(
    name="create_image_post",
    description=(
        "Create a LinkedIn post with an attached image, as the authenticated member "
        "or a managed organization. The image is supplied as base64-encoded bytes "
        "(PNG/JPG/GIF). If author_urn is omitted, posts as the authenticated member. "
        "Text max 3000 chars."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Post text content (max 3000 chars)",
            },
            "image_base64": {
                "type": "string",
                "description": "Base64-encoded image bytes (PNG/JPG/GIF, up to 10 MB).",
                "maxLength": _MAX_IMAGE_BASE64_CHARS,
            },
            "alt_text": {
                "type": "string",
                "description": "Alternative text describing the image, for accessibility (optional).",
            },
            "author_urn": {
                "type": "string",
                "description": (
                    "URN of the author -- urn:li:person:{id} or urn:li:organization:{id}. "
                    "Defaults to the authenticated member if omitted."
                ),
            },
            "visibility": {
                "type": "string",
                "enum": ["PUBLIC", "CONNECTIONS"],
                "description": "Post visibility (default: PUBLIC)",
                "default": "PUBLIC",
            },
        },
        "required": ["text", "image_base64"],
    },
)

_CREATE_DOCUMENT_POST_META = NativeToolMeta(
    name="create_document_post",
    description=(
        "Create a LinkedIn post with an attached document (PDF/PPTX/DOCX), as the "
        "authenticated member or a managed organization. A multi-page document renders "
        "as a swipeable carousel in the feed. The document is supplied as base64-encoded "
        "bytes. If author_urn is omitted, posts as the authenticated member. Text max 3000 chars."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Post text content (max 3000 chars)",
            },
            "document_base64": {
                "type": "string",
                "description": "Base64-encoded document bytes (PDF/PPT/PPTX/DOC/DOCX, up to 100 MB).",
                "maxLength": _MAX_DOCUMENT_BASE64_CHARS,
            },
            "title": {
                "type": "string",
                "description": "Document title shown on the carousel (required).",
            },
            "author_urn": {
                "type": "string",
                "description": (
                    "URN of the author -- urn:li:person:{id} or urn:li:organization:{id}. "
                    "Defaults to the authenticated member if omitted."
                ),
            },
            "visibility": {
                "type": "string",
                "enum": ["PUBLIC", "CONNECTIONS"],
                "description": "Post visibility (default: PUBLIC)",
                "default": "PUBLIC",
            },
        },
        "required": ["text", "document_base64", "title"],
    },
)

_DELETE_POST_META = NativeToolMeta(
    name="delete_post",
    description="Delete a LinkedIn post by its URN (urn:li:share:*, urn:li:ugcPost:*, or urn:li:activity:*).",
    input_schema={
        "type": "object",
        "properties": {
            "post_urn": {
                "type": "string",
                "description": "Post URN to delete (e.g. urn:li:ugcPost:1234567890)",
            },
        },
        "required": ["post_urn"],
    },
)

_GET_ORG_POSTS_META = NativeToolMeta(
    name="get_org_posts",
    description=(
        "Get recent posts for a LinkedIn organization page. "
        "Use get_managed_orgs first to find the org ID."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "org_id": {
                "type": "string",
                "description": "Numeric LinkedIn organization ID (e.g. '12345678')",
            },
            "count": {
                "type": "integer",
                "description": "Number of posts to return (1-50, default 10)",
                "default": 10,
            },
        },
        "required": ["org_id"],
    },
)

_GET_MANAGED_ORGS_META = NativeToolMeta(
    name="get_managed_orgs",
    description=(
        "List LinkedIn organization pages the authenticated member has admin access to. "
        "Returns org IDs and names needed for org-scoped tools."
    ),
    input_schema={"type": "object", "properties": {}},
)

_CREATE_COMMENT_META = NativeToolMeta(
    name="create_comment",
    description="Add a comment to a LinkedIn post. Text max 1250 chars.",
    input_schema={
        "type": "object",
        "properties": {
            "post_urn": {
                "type": "string",
                "description": "URN of the post to comment on (e.g. urn:li:ugcPost:1234567890)",
            },
            "text": {
                "type": "string",
                "description": "Comment text (max 1250 chars)",
            },
        },
        "required": ["post_urn", "text"],
    },
)

_REACT_TO_POST_META = NativeToolMeta(
    name="react_to_post",
    description="React to a LinkedIn post with a specific reaction type.",
    input_schema={
        "type": "object",
        "properties": {
            "post_urn": {
                "type": "string",
                "description": "URN of the post to react to",
            },
            "reaction_type": {
                "type": "string",
                "enum": ["LIKE", "PRAISE", "APPRECIATION", "EMPATHY", "INTEREST", "ENTERTAINMENT"],
                "description": (
                    "Reaction type: LIKE, PRAISE (celebrate), APPRECIATION (support), "
                    "EMPATHY (love), INTEREST (insightful), ENTERTAINMENT (funny)"
                ),
            },
        },
        "required": ["post_urn", "reaction_type"],
    },
)

_GET_POST_COMMENTS_META = NativeToolMeta(
    name="get_post_comments",
    description="Get comments on a LinkedIn post.",
    input_schema={
        "type": "object",
        "properties": {
            "post_urn": {
                "type": "string",
                "description": "URN of the post (e.g. urn:li:ugcPost:1234567890)",
            },
            "count": {
                "type": "integer",
                "description": "Number of comments to return (1-50, default 10)",
                "default": 10,
            },
        },
        "required": ["post_urn"],
    },
)

_GET_ORG_ANALYTICS_META = NativeToolMeta(
    name="get_org_analytics",
    description=(
        "Get follower and page engagement analytics for a LinkedIn organization page. "
        "Use get_managed_orgs first to find the org ID."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "org_id": {
                "type": "string",
                "description": "Numeric LinkedIn organization ID",
            },
            "period": {
                "type": "string",
                "enum": ["7d", "30d", "90d"],
                "description": "Reporting period label (default: 30d). Note: LinkedIn returns lifetime stats; period is metadata-only.",
                "default": "30d",
            },
        },
        "required": ["org_id"],
    },
)

_GET_POST_ANALYTICS_META = NativeToolMeta(
    name="get_post_analytics",
    description=(
        "Get impression and engagement stats for posts on a LinkedIn organization page. "
        "Optionally filter to specific post URNs."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "org_id": {
                "type": "string",
                "description": "Numeric LinkedIn organization ID",
            },
            "post_urns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of post URNs to filter analytics",
            },
        },
        "required": ["org_id"],
    },
)


# === CONNECTOR ===


class LinkedInConnector(NativeConnector):
    """LinkedIn native connector -- wraps LinkedIn API via httpx as MCP tools.

    Uses standard OAuth 2.0 client_secret_post (broker default).
    No token exchange auth override needed.

    Note: r_member_social scope is closed for most apps -- member posts cannot
    be read back after creation. Use org tools (get_org_posts) for content retrieval.

    Scope notes (verified Feb 2025):
    - w_member_social: create posts/comments as member (Posts API)
    - w_member_social_feed: react on behalf of member (Reactions API, deprecated old name)
    - w_organization_social: create org posts/comments (Posts API)
    - w_organization_social_feed: react on behalf of org (Reactions API)
    - r_organization_social: read org posts (Posts API)
    - rw_organization_admin: org ACLs, analytics, org lookup
    The _feed suffix scopes replaced the non-feed versions for reactions/comments
    via socialActions in June 2023. Posts API still uses the non-feed names.
    We request both to cover all tool functionality.
    """

    meta = ConnectorMeta(
        name="linkedin",
        display_name="LinkedIn",
        oauth_authorize_url="https://www.linkedin.com/oauth/v2/authorization",
        oauth_token_url="https://www.linkedin.com/oauth/v2/accessToken",  # noqa: S106 -- endpoint URL, not a password
        scopes=_SCOPES,
        supports_pkce=False,  # LinkedIn's standard OAuth flow rejects code_verifier
    )

    # No build_token_request_auth override — LinkedIn uses client_secret_post
    # (client_id + client_secret in POST body), which is the broker default.

    # --- MCP tools ---

    @native_tool(_GET_ME_META)
    async def get_me(self, *, access_token: str) -> list[dict[str, Any]]:
        """Get the authenticated member's LinkedIn profile."""
        profile = await _linkedin_get(access_token, "/v2/userinfo", versioned=False)
        return _mcp_text_content(_simplify_profile(profile))

    @native_tool(_CREATE_POST_META)
    async def create_post(  # noqa: PLR0913 -- MCP tool signature
        self,
        *,
        access_token: str,
        text: str,
        author_urn: str = "",
        visibility: str = "PUBLIC",
    ) -> list[dict[str, Any]]:
        """Create a post as the authenticated member or a managed org."""
        if len(text) > MAX_POST_LENGTH:
            raise ValueError(f"Post text exceeds {MAX_POST_LENGTH} characters ({len(text)} given)")
        resolved_urn = await _resolve_author_urn(access_token, author_urn)
        # /rest/ posting (org tier) is only reachable with the Community Management
        # scopes; without them the v2 Share-on-LinkedIn path is the only one that works.
        if _ORG_TOOLS_ENABLED:
            created = await _create_post_rest(access_token, resolved_urn, text, visibility)
        else:
            created = await _create_post_v2(access_token, resolved_urn, text, visibility)
        return _mcp_text_content(created)

    @native_tool(_CREATE_IMAGE_POST_META)
    async def create_image_post(  # noqa: PLR0913 -- MCP tool signature
        self,
        *,
        access_token: str,
        text: str,
        image_base64: str,
        alt_text: str = "",
        author_urn: str = "",
        visibility: str = "PUBLIC",
    ) -> list[dict[str, Any]]:
        """Create a post with an attached image (member or managed org author).

        Image/document posts always use the versioned /rest/ media flow -- it is the
        only path that supports documents, and the docs confirm member-owned uploads
        work with the self-serve w_member_social scope.
        """
        if len(text) > MAX_POST_LENGTH:
            raise ValueError(f"Post text exceeds {MAX_POST_LENGTH} characters ({len(text)} given)")
        raw_bytes = _decode_media(image_base64, MAX_IMAGE_BYTES, "image")
        author = await _resolve_author_urn(access_token, author_urn)
        media_attrs = {"altText": alt_text} if alt_text else {}
        created = await _create_media_post(
            access_token, author, text, visibility, "images", raw_bytes, media_attrs=media_attrs
        )
        return _mcp_text_content(created)

    @native_tool(_CREATE_DOCUMENT_POST_META)
    async def create_document_post(  # noqa: PLR0913 -- MCP tool signature
        self,
        *,
        access_token: str,
        text: str,
        document_base64: str,
        title: str = "",
        author_urn: str = "",
        visibility: str = "PUBLIC",
    ) -> list[dict[str, Any]]:
        """Create a post with an attached document; a multi-page doc renders as a carousel."""
        if len(text) > MAX_POST_LENGTH:
            raise ValueError(f"Post text exceeds {MAX_POST_LENGTH} characters ({len(text)} given)")
        if not title:
            raise ValueError("A document title is required")
        raw_bytes = _decode_media(document_base64, MAX_DOCUMENT_BYTES, "document")
        author = await _resolve_author_urn(access_token, author_urn)
        created = await _create_media_post(
            access_token,
            author,
            text,
            visibility,
            "documents",
            raw_bytes,
            media_attrs={"title": title},
        )
        return _mcp_text_content(created)

    @native_tool(_DELETE_POST_META)
    async def delete_post(self, *, access_token: str, post_urn: str) -> list[dict[str, Any]]:
        """Delete a LinkedIn post by URN."""
        _validate_post_urn(post_urn)
        encoded_urn = quote(post_urn, safe="")
        # /rest/ deletion (org tier) requires the Community Management scopes;
        # otherwise delete via the v2 Share-on-LinkedIn path.
        if _ORG_TOOLS_ENABLED:
            await _linkedin_delete(access_token, f"/rest/posts/{encoded_urn}")
        else:
            await _linkedin_delete(access_token, f"/v2/ugcPosts/{encoded_urn}", versioned=False)
        return _mcp_text_content({"post_urn": post_urn, "deleted": True})

    @native_tool(_GET_ORG_POSTS_META)
    async def get_org_posts(
        self,
        *,
        access_token: str,
        org_id: str,
        count: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """Get recent posts for a LinkedIn organization page."""
        _require_org_tools()
        _validate_org_id(org_id)
        clamped = _clamp_limit(count)
        org_urn = f"urn:li:organization:{org_id}"
        # X-RestLi-Method: FINDER required for q= finder requests on /rest/ endpoints
        response = await _linkedin_get(
            access_token,
            "/rest/posts",
            restli_method="FINDER",
            q="author",
            author=org_urn,
            count=clamped,
        )
        elements = response.get("elements", [])
        posts = [_simplify_post(post) for post in elements]
        return _mcp_text_content(posts)

    @native_tool(_GET_MANAGED_ORGS_META)
    async def get_managed_orgs(self, *, access_token: str) -> list[dict[str, Any]]:
        """List organization pages the authenticated member administers.

        Two-step: (1) fetch ACLs to get org URNs, (2) batch-fetch org details.
        The /rest/ API doesn't support Rest.li v1 projections (~dereference),
        so we make a follow-up call to /rest/organizations for names.
        """
        _require_org_tools()
        acl_response = await _linkedin_get(
            access_token,
            "/rest/organizationAcls",
            restli_method="FINDER",
            q="roleAssignee",
            role="ADMINISTRATOR",
            state="APPROVED",
        )
        elements = acl_response.get("elements", [])
        org_ids = _extract_org_ids_from_acls(elements)
        if not org_ids:
            return _mcp_text_content([])
        orgs = await _batch_fetch_orgs(access_token, org_ids)
        return _mcp_text_content(orgs)

    @native_tool(_CREATE_COMMENT_META)
    async def create_comment(
        self,
        *,
        access_token: str,
        post_urn: str,
        text: str,
    ) -> list[dict[str, Any]]:
        """Add a comment to a LinkedIn post.

        Note: the socialActions endpoint is on a deprecation path -- monitor
        Linkedin-Version updates.
        """
        _require_org_tools()
        _validate_post_urn(post_urn)
        if len(text) > MAX_COMMENT_LENGTH:
            raise ValueError(f"Comment exceeds {MAX_COMMENT_LENGTH} characters ({len(text)} given)")
        person_urn = await _get_person_urn(access_token)
        encoded_urn = quote(post_urn, safe="")
        body = {
            "actor": person_urn,
            "message": {"text": text},
        }
        created = await _linkedin_post(
            access_token, f"/rest/socialActions/{encoded_urn}/comments", body
        )
        return _mcp_text_content(created)

    @native_tool(_REACT_TO_POST_META)
    async def react_to_post(
        self,
        *,
        access_token: str,
        post_urn: str,
        reaction_type: str,
    ) -> list[dict[str, Any]]:
        """React to a LinkedIn post."""
        _require_org_tools()
        _validate_post_urn(post_urn)
        person_urn = await _get_person_urn(access_token)
        body = {
            "root": post_urn,
            "reactionType": reaction_type,
        }
        # actor is a query param — httpx handles URL-encoding, don't pre-encode
        created = await _linkedin_post(
            access_token,
            "/rest/reactions",
            body,
            extra_params={"actor": person_urn},
        )
        return _mcp_text_content({"post_urn": post_urn, "reaction_type": reaction_type, **created})

    @native_tool(_GET_POST_COMMENTS_META)
    async def get_post_comments(
        self,
        *,
        access_token: str,
        post_urn: str,
        count: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """Get comments on a LinkedIn post.

        Note: the socialActions endpoint is on a deprecation path -- monitor
        Linkedin-Version updates.
        """
        _require_org_tools()
        _validate_post_urn(post_urn)
        clamped = _clamp_limit(count)
        encoded_urn = quote(post_urn, safe="")
        # X-RestLi-Method: FINDER required for finder requests on /rest/ endpoints
        response = await _linkedin_get(
            access_token,
            f"/rest/socialActions/{encoded_urn}/comments",
            restli_method="FINDER",
            count=clamped,
        )
        elements = response.get("elements", [])
        comments = [_simplify_comment(comment) for comment in elements]
        return _mcp_text_content(comments)

    @native_tool(_GET_ORG_ANALYTICS_META)
    async def get_org_analytics(
        self,
        *,
        access_token: str,
        org_id: str,
        period: str = "30d",
    ) -> list[dict[str, Any]]:
        """Get follower and page analytics for an org page.

        The period param is metadata-only -- LinkedIn returns lifetime stats.
        """
        _require_org_tools()
        _validate_org_id(org_id)
        org_urn = f"urn:li:organization:{org_id}"
        follower_stats, page_stats = await _fetch_org_analytics(access_token, org_urn, period)
        merged = {
            "org_id": org_id,
            "period": period,
            "followers": follower_stats,
            "page_views": page_stats,
        }
        return _mcp_text_content(merged)

    @native_tool(_GET_POST_ANALYTICS_META)
    async def get_post_analytics(
        self,
        *,
        access_token: str,
        org_id: str,
        post_urns: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Get impression and engagement stats for org posts."""
        _require_org_tools()
        _validate_org_id(org_id)
        org_urn = f"urn:li:organization:{org_id}"
        params: dict[str, Any] = {"q": "organizationalEntity", "organizationalEntity": org_urn}
        if post_urns:
            params["shares"] = _build_restli_list(post_urns, _validate_post_urn)
        response = await _linkedin_get(
            access_token,
            "/rest/organizationalEntityShareStatistics",
            restli_method="FINDER",
            **params,
        )
        stats = [_simplify_share_stats(el) for el in response.get("elements", [])]
        return _mcp_text_content({"org_id": org_id, "post_stats": stats})

    def is_tool_available(self, tool_name: str) -> bool:
        """Hide the 7 org-tier tools from tools/list until the Community
        Management scopes are configured.

        Without the org scopes those tools are guaranteed 403s, so advertising
        them to the LLM only invites doomed calls. Returning False here filters
        them out of tools/list and makes the dispatcher reject direct calls with
        the unknown-tool error. The per-tool _require_org_tools() call-time guard
        stays in place as defense in depth -- if a tool's availability and its
        guard ever drift, the guard still blocks the actual HTTP request.
        """
        if not _ORG_TOOLS_ENABLED and tool_name in _ORG_TOOL_NAMES:
            return False
        return super().is_tool_available(tool_name)

    @classmethod
    def tool_prompt_instructions(cls) -> str:
        """LLM guidance for LinkedIn tool usage."""
        return (
            "LinkedIn tool notes:\n"
            "1. Member post retrieval is not available -- r_member_social scope is closed for "
            "most apps. You cannot read back posts made as a member. For content retrieval, "
            "use get_org_posts with a managed organization.\n"
            "2. For any organization operation (get_org_posts, get_org_analytics, "
            "get_post_analytics, create_post as org), first call get_managed_orgs to find "
            "the numeric org ID. Never assume an org ID -- always look it up first.\n"
            "3. Post URNs take the form urn:li:ugcPost:DIGITS or urn:li:share:DIGITS. "
            "Activity URNs (urn:li:activity:DIGITS) are also accepted.\n"
            "4. Reaction types use API values, not UI labels: LIKE, PRAISE (celebrate), "
            "APPRECIATION (support), EMPATHY (love), INTEREST (insightful), ENTERTAINMENT (funny)."
        )


# --- Private helpers (module-level to keep connector body short) ---


def _rest_post_body(
    author_urn: str, text: str, visibility: str, *, media: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a /rest/posts request body, optionally carrying an attached media reference."""
    body: dict[str, Any] = {
        "author": author_urn,
        "commentary": text,
        "visibility": visibility,
        "distribution": {
            "feedDistribution": "MAIN_FEED",
            "targetEntities": [],
            "thirdPartyDistributionChannels": [],
        },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": False,
    }
    if media is not None:
        body["content"] = {"media": media}
    return body


async def _create_post_rest(
    access_token: str, author_urn: str, text: str, visibility: str
) -> dict[str, Any]:
    """Create post via /rest/posts (Community Management API, versioned)."""
    return await _linkedin_post(
        access_token, "/rest/posts", _rest_post_body(author_urn, text, visibility)
    )


async def _initialize_media_upload(
    access_token: str, collection: str, owner_urn: str
) -> tuple[str, str]:
    """Initialize a versioned media upload. Returns (upload_url, media_urn).

    collection is the /rest/ resource ('images' or 'documents'); the returned URN
    keys off its singular form ('image' / 'document') and is referenced in the post.
    """
    response = await _linkedin_post(
        access_token,
        f"/rest/{collection}",
        {"initializeUploadRequest": {"owner": owner_urn}},
        extra_params={"action": "initializeUpload"},
    )
    value = response.get("value", {})
    upload_url = value.get("uploadUrl")
    media_urn = value.get(collection[:-1])  # 'images' -> 'image', 'documents' -> 'document'
    if not upload_url or not media_urn:
        raise ValueError("LinkedIn did not return a media upload URL")
    return upload_url, media_urn


async def _upload_media_binary(access_token: str, upload_url: str, raw_bytes: bytes) -> None:
    """PUT raw media bytes to the pre-signed LinkedIn upload URL from initializeUpload.

    The upload URL is a LinkedIn media host, not a /rest/ resource, so it takes the
    Bearer token but no Linkedin-Version header.
    """
    _validate_upload_url(upload_url)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/octet-stream",
    }
    async with httpx.AsyncClient(timeout=MEDIA_UPLOAD_TIMEOUT_SECONDS) as client:
        response = await client.put(upload_url, headers=headers, content=raw_bytes)
        _check_status(response)


async def _create_media_post(  # noqa: PLR0913 -- carries the full post + media payload
    access_token: str,
    author_urn: str,
    text: str,
    visibility: str,
    collection: str,
    raw_bytes: bytes,
    *,
    media_attrs: dict[str, Any],
) -> dict[str, Any]:
    """Upload media then create a /rest/posts post referencing it (versioned flow)."""
    upload_url, media_urn = await _initialize_media_upload(access_token, collection, author_urn)
    await _upload_media_binary(access_token, upload_url, raw_bytes)
    media = {"id": media_urn, **media_attrs}
    return await _linkedin_post(
        access_token, "/rest/posts", _rest_post_body(author_urn, text, visibility, media=media)
    )


async def _create_post_v2(
    access_token: str, author_urn: str, text: str, visibility: str
) -> dict[str, Any]:
    """Create post via /v2/ugcPosts (Share on LinkedIn, legacy unversioned).

    Body format verified from official examples and live testing.
    """
    return await _linkedin_post(
        access_token,
        "/v2/ugcPosts",
        {
            "author": author_urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": text},
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": visibility,
            },
        },
        versioned=False,
    )


async def _fetch_org_analytics(
    access_token: str, org_urn: str, period: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch follower stats and page stats from separate LinkedIn endpoints."""
    follower_response = await _linkedin_get(
        access_token,
        "/rest/organizationalEntityFollowerStatistics",
        restli_method="FINDER",
        q="organizationalEntity",
        organizationalEntity=org_urn,
    )
    page_response = await _linkedin_get(
        access_token,
        "/rest/organizationPageStatistics",
        restli_method="FINDER",
        q="organization",
        organization=org_urn,
    )
    return _simplify_analytics(follower_response, period), _simplify_analytics(
        page_response, period
    )


def _build_restli_list(urns: list[str], validate_fn: Callable[[str], None]) -> str:
    """Build Rest.li List format: List(encoded_urn1,encoded_urn2)."""
    for urn in urns:
        validate_fn(urn)
    encoded = ",".join(quote(u, safe="") for u in urns)
    return f"List({encoded})"


async def _resolve_author_urn(access_token: str, author_urn: str) -> str:
    """Resolve author URN, defaulting to authenticated member if empty."""
    if not author_urn:
        return await _get_person_urn(access_token)
    if not (_PERSON_URN_RE.match(author_urn) or _ORG_URN_RE.match(author_urn)):
        raise ValueError(f"Invalid author URN: {author_urn!r}")
    return author_urn


def _extract_org_ids_from_acls(elements: list[dict[str, Any]]) -> list[str]:
    """Extract unique org IDs from organizationAcls response elements.

    ACL elements use 'organization' or 'organizationTarget' depending on
    the response format -- handle both.

    Each extracted ID is validated against _ORG_ID_RE before use. The ID comes
    from LinkedIn's response but is interpolated into a URL path downstream
    (/rest/organizations/{id}); a malformed URN like
    urn:li:organization:123/../evil would otherwise inject path segments.
    """
    org_ids: list[str] = []
    seen: set[str] = set()
    for acl in elements:
        org_urn = acl.get("organizationTarget") or acl.get("organization", "")
        org_id = _extract_org_id_from_urn(org_urn)
        if not _ORG_ID_RE.match(org_id):
            logger.debug("[LinkedIn] Skipping malformed org URN in ACLs: %r", org_urn)
            continue
        if org_id not in seen:
            seen.add(org_id)
            org_ids.append(org_id)
    return org_ids


async def _batch_fetch_orgs(
    access_token: str,
    org_ids: list[str],
) -> list[dict[str, Any]]:
    """Fetch org details for a list of org IDs via /rest/organizations/{id}.

    Falls back to just org_id + urn if the lookup fails (e.g. insufficient permissions).
    """
    orgs: list[dict[str, Any]] = []
    for org_id in org_ids:
        try:
            raw = await _linkedin_get(access_token, f"/rest/organizations/{org_id}")
        except _SessionError:
            # Token expiry / exhausted rate limit affects every org -- surface it
            # instead of silently degrading each row to a missing name.
            raise
        except ValueError:
            # Graceful degradation -- return URN even if name lookup fails
            orgs.append(
                {
                    "org_id": org_id,
                    "org_urn": f"urn:li:organization:{org_id}",
                    "name": None,
                    "vanity_name": None,
                }
            )
            continue
        orgs.append(_simplify_org(raw))
    return orgs
