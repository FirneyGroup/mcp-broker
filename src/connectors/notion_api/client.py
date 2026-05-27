"""
Notion REST HTTP layer for the `notion_api` connector.

The low-level "how we talk to Notion" plumbing shared by every tool: request
sending with 429-retry, status checking, pagination, ID normalization, and the
MCP text-content wrapper. Pure transport — no Notion-object simplification or
tool logic lives here. API behaviour validated against `Notion-Version: 2025-09-03`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# === CONSTANTS ===

NOTION_API_BASE = "https://api.notion.com/v1"
# Pinned to the data-sources-split API version; 2026-03-11 introduces deltas (noted at call sites).
NOTION_VERSION = "2025-09-03"
HTTP_TIMEOUT_SECONDS = 30.0

# Pagination: Notion caps page_size at 100 and silently clamps oversized values — clamp client-side.
MAX_PAGE_SIZE = 100
DEFAULT_MAX_ROWS = 100
MAX_ROWS_CAP = 1000
RATE_LIMIT_RETRY_CAP_SECONDS = 30
# Fallback when Retry-After is absent or non-numeric (RFC 7231 §7.1.3 also permits an HTTP-date).
DEFAULT_RETRY_AFTER_SECONDS = 5.0

# Comment listing uses the same page-size cap as other paginated GETs (Notion caps at 100).
DEFAULT_MAX_COMMENTS = 100

_HTTP_OK = 200
_HTTP_UNAUTHORIZED = 401
_HTTP_NOT_FOUND = 404
_HTTP_RATE_LIMITED = 429
# HTTP 403 Forbidden. Used by get_users to detect the PAT-vs-OAuth restriction without hardcoding.
_HTTP_FORBIDDEN = 403

# Property pagination page_size cap: the Retrieve-a-page endpoint truncates properties
# at 25 references. Clamp to 25 so we don't over-fetch on a single request.
_MAX_PROPERTY_PAGE_SIZE = 25

# Notion IDs are 32 hex chars, dashed or undashed. Guards path traversal in URL building.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX32_RE = re.compile(r"[0-9a-fA-F]{32}$")  # trailing 32-hex: Notion appends the id at the END


# === ID NORMALIZATION ===


def _normalize_id(ref: str) -> str:
    """Extract and normalize a Notion UUID from an id or notion.so URL. Guards path traversal."""
    candidate = ref.strip()
    if _UUID_RE.match(candidate):
        return candidate.replace("-", "")
    # URL/slug: isolate the last path segment, drop query/fragment, de-dash, take the TRAILING
    # 32 hex. Notion appends the id at the END of the slug, and slug words can themselves contain
    # hex letters (a-f) — so anchoring at the end avoids matching inside the slug (e.g. ".../My-Page-<id>").
    segment = candidate.split("?")[0].split("#")[0].rstrip("/").rsplit("/", 1)[-1]
    match = _HEX32_RE.search(segment.replace("-", ""))
    if not match:
        raise ValueError(f"Could not extract a Notion ID from: {ref!r}")
    return match.group(0)


# === TRANSPORT ===


def _headers(access_token: str) -> dict[str, str]:
    """Auth + version headers required on every Notion REST request."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
    }


def _check_status(response: httpx.Response) -> None:
    """Raise a clean ValueError on auth/other errors. 401 -> reconnect hint; never leaks the token."""
    if response.status_code == _HTTP_UNAUTHORIZED:
        raise ValueError(
            "Notion token expired or revoked — reconnect via /oauth/notion_api/connect"
        )
    if response.is_error:
        message = ""
        try:
            message = response.json().get("message", "")
        except (ValueError, KeyError, AttributeError):
            message = ""
        logger.debug("[Notion API] API error %d: %s", response.status_code, message[:300])
        raise ValueError(f"Notion API error ({response.status_code}): {message[:300]}")


async def _retry_on_rate_limit(response: httpx.Response, request_fn: Any) -> httpx.Response:
    """If 429, sleep Retry-After (capped) and retry once. Raises on a second 429."""
    if response.status_code != _HTTP_RATE_LIMITED:
        return response
    raw_retry_after = response.headers.get("Retry-After", "")
    try:
        retry_seconds = float(raw_retry_after)
    except ValueError:
        # Missing or non-numeric (RFC 7231 permits an HTTP-date form) — use a safe default.
        retry_seconds = DEFAULT_RETRY_AFTER_SECONDS
    retry_after = min(retry_seconds, RATE_LIMIT_RETRY_CAP_SECONDS)
    logger.warning("[Notion API] Rate limited, retrying after %.1fs", retry_after)
    await asyncio.sleep(retry_after)
    retry_response = await request_fn()
    if retry_response.status_code == _HTTP_RATE_LIMITED:
        raise ValueError("Rate limited by Notion after retry — try again later")
    return retry_response


async def _send(  # noqa: PLR0913 -- HTTP helper: client + auth + method/path + params/body
    client: httpx.AsyncClient,
    access_token: str,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Send one request (with 429 retry) and return the raw response — caller checks status."""
    url = f"{NOTION_API_BASE}{path}"
    headers = _headers(access_token)

    def _do() -> Any:
        return client.request(method, url, headers=headers, params=params, json=json_body)

    response = await _do()
    return await _retry_on_rate_limit(response, _do)


async def _request(  # noqa: PLR0913 -- HTTP helper: client + auth + method/path + params/body
    client: httpx.AsyncClient,
    access_token: str,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a request, raise on error, return parsed JSON."""
    response = await _send(client, access_token, method, path, params=params, json_body=json_body)
    _check_status(response)
    return response.json()


# === MCP / CAP UTILITIES ===


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as MCP text content blocks."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


def _clamp_max_rows(max_rows: int) -> int:
    """Clamp the accumulation cap to [1, MAX_ROWS_CAP]."""
    return max(1, min(max_rows, MAX_ROWS_CAP))


# === PAGINATION ===


async def _paginate_get(  # noqa: PLR0913 -- pagination needs client + auth + path + cap + params
    client: httpx.AsyncClient,
    access_token: str,
    path: str,
    max_items: int,
    extra_params: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Accumulate results from a paginated GET endpoint up to max_items. Returns (results, has_more, cursor)."""
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    has_more = False
    while True:
        params = dict(extra_params or {})
        params["page_size"] = MAX_PAGE_SIZE
        if cursor:
            params["start_cursor"] = cursor
        page = await _request(client, access_token, "GET", path, params=params)
        items.extend(page.get("results", []))
        has_more = bool(page.get("has_more"))
        cursor = page.get("next_cursor")
        if not has_more or len(items) >= max_items or not cursor:
            break
    return items[:max_items], has_more, cursor


async def _paginate_property(
    client: httpx.AsyncClient,
    access_token: str,
    path: str,
    max_items: int,
) -> dict[str, Any]:
    """Paginate a list-type property response and return accumulated results.

    The first GET determines whether the property is list-type (object=="list") or flat
    (object=="property_item"). Flat responses are returned immediately. List responses are
    accumulated across pages up to max_items.
    """
    params: dict[str, Any] = {"page_size": min(_MAX_PROPERTY_PAGE_SIZE, max_items)}
    first_page = await _request(client, access_token, "GET", path, params=params)

    if first_page.get("object") != "list":
        # Non-paginated property type (date, status, select, number, checkbox, etc.)
        return first_page

    # Paginated property type (title, rich_text, relation, people, rollup)
    accumulated = list(first_page.get("results", []))
    has_more = bool(first_page.get("has_more"))
    cursor: str | None = first_page.get("next_cursor")
    prop_meta = first_page.get("property_item", {})

    while has_more and cursor and len(accumulated) < max_items:
        next_params: dict[str, Any] = {
            "page_size": min(_MAX_PROPERTY_PAGE_SIZE, max_items - len(accumulated)),
        }
        if cursor:
            next_params["start_cursor"] = cursor
        next_page = await _request(client, access_token, "GET", path, params=next_params)
        accumulated.extend(next_page.get("results", []))
        has_more = bool(next_page.get("has_more"))
        cursor = next_page.get("next_cursor")

    return {
        "object": "list",
        "type": "property_item",
        "property_item": prop_meta,
        "results": accumulated[:max_items],
        "has_more": has_more,
        "next_cursor": cursor,
    }


async def _search_pages(  # noqa: PLR0913 -- search needs client + auth + query params + cap
    client: httpx.AsyncClient,
    access_token: str,
    query: str | None,
    object_type: str | None,
    max_results: int,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """POST /v1/search with pagination, accumulating up to max_results.

    filter.value must be "page" or "data_source" — "database" is a hard 400 on 2025-09-03.
    Omit filter when object_type is None to return both pages and data sources.
    """
    hits: list[dict[str, Any]] = []
    cursor: str | None = None
    has_more = False
    while True:
        body: dict[str, Any] = {"page_size": min(MAX_PAGE_SIZE, max_results - len(hits))}
        if query:
            body["query"] = query
        if object_type:
            body["filter"] = {"property": "object", "value": object_type}
        if cursor:
            body["start_cursor"] = cursor
        page = await _request(client, access_token, "POST", "/search", json_body=body)
        hits.extend(page.get("results", []))
        has_more = bool(page.get("has_more"))
        cursor = page.get("next_cursor")
        if not has_more or len(hits) >= max_results or not cursor:
            break
    return hits[:max_results], has_more, cursor
