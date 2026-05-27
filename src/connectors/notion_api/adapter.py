"""
Notion (REST) MCP Connector — `notion_api`.

Native connector that wraps the Notion REST API (https://api.notion.com) via httpx
as MCP tools. Distinct from the hosted-MCP passthrough connector `notion`
(mcp.notion.com), which withholds row-query tools; this connector exposes the REST
surface directly. Auto-registers on import via NativeConnector.__init_subclass__.

Uses httpx (async) directly — same idiom as `reddit`/`linkedin`. API behaviour was
validated live against `Notion-Version: 2025-09-03`.

Auth: public-integration OAuth (HTTP Basic token exchange). Notion does NOT support
PKCE on api.notion.com (→ supports_pkce=False) and omits `expires_in`; parse_token_response
injects a conservative synthetic TTL so the broker refreshes proactively, and the rotated
refresh_token is persisted on every token response.
"""

from __future__ import annotations

import mimetypes
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from broker.connectors.native import NativeConnector, native_tool
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta
from connectors.notion_api.client import (
    _HTTP_FORBIDDEN,
    _HTTP_NOT_FOUND,
    _HTTP_OK,
    DEFAULT_MAX_COMMENTS,
    DEFAULT_MAX_ROWS,
    HTTP_TIMEOUT_SECONDS,
    MAX_PAGE_SIZE,
    NOTION_VERSION,
    _check_status,
    _clamp_max_rows,
    _mcp_text_content,
    _normalize_id,
    _paginate_get,
    _paginate_property,
    _request,
    _retry_on_rate_limit,
    _search_pages,
    _send,
)
from connectors.notion_api.schemas import (
    _APPEND_BLOCKS_META,
    _ARCHIVE_PAGE_META,
    _CREATE_COMMENT_META,
    _CREATE_DATABASE_META,
    _CREATE_PAGES_META,
    _CREATE_VIEW_META,
    _FETCH_META,
    _GET_BLOCK_CHILDREN_META,
    _GET_COMMENTS_META,
    _GET_PAGE_PROPERTY_META,
    _GET_USERS_META,
    _MOVE_PAGES_META,
    _QUERY_DATA_SOURCE_META,
    _SEARCH_META,
    _UPDATE_DATA_SOURCE_META,
    _UPDATE_PAGE_CONTENT_META,
    _UPDATE_PAGE_PROPERTIES_META,
    _UPDATE_VIEW_META,
    _UPLOAD_FILE_META,
)
from connectors.notion_api.serialize import (
    _plain_text,
    _simplify_block,
    _simplify_comment,
    _simplify_page,
    _simplify_search_hit,
    _simplify_user,
    _simplify_view,
)

# === CONSTANTS ===

# Notion omits expires_in; treat tokens as refreshable on this cadence so the broker's
# expiry-based refresh fires before the (unpublished) real lifetime elapses.
SYNTHETIC_TOKEN_TTL_SECONDS = 3000  # 50 minutes


# === FILTER DSL (simple filters -> Notion filter object) ===

_TEXT_OPS = {
    "equals",
    "does_not_equal",
    "contains",
    "does_not_contain",
    "starts_with",
    "ends_with",
    "is_empty",
    "is_not_empty",
}
_DATE_OPS = {
    "equals",
    "before",
    "after",
    "on_or_before",
    "on_or_after",
    "is_empty",
    "is_not_empty",
    "past_week",
    "past_month",
    "past_year",
    "next_week",
    "next_month",
    "next_year",
    "this_week",
}
_NUMBER_OPS = {
    "equals",
    "does_not_equal",
    "greater_than",
    "less_than",
    "greater_than_or_equal_to",
    "less_than_or_equal_to",
    "is_empty",
    "is_not_empty",
}
_SELECT_OPS = {"equals", "does_not_equal", "is_empty", "is_not_empty"}
_MULTI_OPS = {"contains", "does_not_contain", "is_empty", "is_not_empty"}
_CHECKBOX_OPS = {"equals", "does_not_equal"}
_CONTAINS_OPS = {"contains", "does_not_contain", "is_empty", "is_not_empty"}

_TYPE_OPS: dict[str, set[str]] = {
    "title": _TEXT_OPS,
    "rich_text": _TEXT_OPS,
    "url": _TEXT_OPS,
    "email": _TEXT_OPS,
    "phone_number": _TEXT_OPS,
    "date": _DATE_OPS,
    "created_time": _DATE_OPS,
    "last_edited_time": _DATE_OPS,
    "number": _NUMBER_OPS,
    "select": _SELECT_OPS,
    "status": _SELECT_OPS,
    "multi_select": _MULTI_OPS,
    "checkbox": _CHECKBOX_OPS,
    "people": _CONTAINS_OPS,
    "created_by": _CONTAINS_OPS,
    "last_edited_by": _CONTAINS_OPS,
    "relation": _CONTAINS_OPS,
    "files": {"is_empty", "is_not_empty"},
}
_BOOL_OPS = {"is_empty", "is_not_empty"}  # value must be a bool (true) for these
# Relative-date operators take an empty object as their value, e.g. {"date": {"past_week": {}}}.
_RELATIVE_DATE_OPS = {
    "past_week",
    "past_month",
    "past_year",
    "next_week",
    "next_month",
    "next_year",
    "this_week",
}


def _resolve_date_value(value: Any) -> Any:
    """Resolve relative date keywords to ISO dates; pass other values through."""
    if value == "today":
        return datetime.now(UTC).date().isoformat()
    return value


def _build_condition(simple: dict[str, Any], schema: dict[str, str]) -> dict[str, Any]:
    """Build one Notion filter condition from a simple {property, op, value}."""
    prop = simple.get("property")
    if prop not in schema:
        raise ValueError(f"Unknown property {prop!r}; available: {sorted(schema)}")
    prop_type = schema[prop]
    allowed = _TYPE_OPS.get(prop_type)
    if allowed is None:
        raise ValueError(f"Property {prop!r} has unsupported type {prop_type!r} for filtering")
    op = simple.get("op", "")
    if op not in allowed:
        raise ValueError(
            f"Operator {op!r} not valid for {prop_type} property {prop!r}; allowed: {sorted(allowed)}"
        )
    return {"property": prop, prop_type: {op: _condition_value(prop_type, op, simple.get("value"))}}


def _condition_value(prop_type: str, op: str, value: Any) -> Any:
    """Coerce the DSL value for the operator (is_empty/is_not_empty take bool true; dates resolve)."""
    if op in _BOOL_OPS:
        return True
    if op in _RELATIVE_DATE_OPS:
        return {}  # Notion expects an empty object for relative-date operators
    if prop_type in ("date", "created_time", "last_edited_time"):
        return _resolve_date_value(value)
    return value


def _build_filter(
    filters: list[dict[str, Any]], match: str, schema: dict[str, str]
) -> dict[str, Any] | None:
    """Combine simple filters into a Notion `filter` object (None when empty)."""
    if not filters:
        return None
    conditions = [_build_condition(f, schema) for f in filters]
    if len(conditions) == 1:
        return conditions[0]
    return {"or" if match == "any" else "and": conditions}


def _build_sorts(sorts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map simple {property, direction} sorts to Notion sort objects."""
    return [
        {"property": s["property"], "direction": s.get("direction", "ascending")} for s in sorts
    ]


# === DATA SOURCE RESOLUTION ===


async def _resolve_ds_and_schema(
    client: httpx.AsyncClient, access_token: str, ref: str
) -> tuple[str, dict[str, str]]:
    """Resolve a data_source_id (+ its property-name -> type schema) from an id/URL.

    Accepts a data_source_id, a database_id, or a notion.so URL. database_id and
    data_source_id are distinct UUIDs, so try data source first, then database.
    """
    notion_id = _normalize_id(ref)
    ds_response = await _send(client, access_token, "GET", f"/data_sources/{notion_id}")
    # Not a data source → try database. Notion answers 404 OR 400 ("is a page/database, not a
    # data source") depending on the id's real type, so treat any non-200 as "not a data source".
    if ds_response.status_code != _HTTP_OK:
        db = await _request(client, access_token, "GET", f"/databases/{notion_id}")
        sources = db.get("data_sources") or []
        if not sources:
            raise ValueError(f"Database {notion_id} has no data sources")
        ds_id = _normalize_id(sources[0]["id"])
        ds_response = await _send(client, access_token, "GET", f"/data_sources/{ds_id}")
    _check_status(ds_response)
    data_source = ds_response.json()
    return _normalize_id(data_source["id"]), _extract_schema(data_source)


def _extract_schema(data_source: dict[str, Any]) -> dict[str, str]:
    """Map property name -> Notion type from a data source object."""
    return {
        name: prop.get("type", "") for name, prop in (data_source.get("properties") or {}).items()
    }


# === QUERY PAGINATION ===


async def _query_pages(  # noqa: PLR0913 -- pagination needs client + auth + target + body + cap
    client: httpx.AsyncClient,
    access_token: str,
    ds_id: str,
    body_base: dict[str, Any],
    max_rows: int,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Page through a data-source query, accumulating up to max_rows. Returns (rows, has_more, cursor)."""
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    has_more = False
    while True:
        body = dict(body_base)
        body["page_size"] = MAX_PAGE_SIZE
        if cursor:
            body["start_cursor"] = cursor
        page = await _request(
            client, access_token, "POST", f"/data_sources/{ds_id}/query", json_body=body
        )
        rows.extend(_simplify_page(p) for p in page.get("results", []))
        has_more = bool(page.get("has_more"))
        cursor = page.get("next_cursor")
        if not has_more or len(rows) >= max_rows or not cursor:
            break
    return rows[:max_rows], has_more, cursor


# === PAGE-WRITE HELPERS ===

# Notion title/rich_text accept up to 100 rich-text items per array; a single-element
# array is the common case for plain-string writes.
_TITLE_TEXT_TYPES = ("title", "rich_text")
# Property types whose simple value is a list of names ({"name": s} entries).
_NAME_LIST_TYPES = ("multi_select",)
# Property types whose simple value is a list of UUIDs ({"id": s} entries).
_ID_LIST_TYPES = ("people", "relation")
# Property types that take a single {"name": ...} object.
_NAME_OBJECT_TYPES = ("select", "status")


def _build_property_value(prop_type: str, value: Any) -> dict[str, Any]:  # noqa: C901 — one branch per Notion property type (write-side mirror of _simplify_property)
    """Build a Notion property-value object from a simple Python value (shared by create + update).

    Shapes verified on the wire. `value=None` clears nullable properties on PATCH
    (date/status/select/url/email/number/phone_number/multi_select/people/relation send the typed
    key as null; title/rich_text clear via an empty array). checkbox has no null form. Multi-value
    types accept a list of plain strings and are wrapped here so callers never build inner dicts.
    """
    if prop_type in _TITLE_TEXT_TYPES:
        if value is None:
            return {prop_type: []}
        return {prop_type: [{"text": {"content": str(value)}}]}
    if prop_type == "date":
        # value: ISO date/datetime string, a {start[, end, time_zone]} dict, or None to clear.
        if value is None:
            return {"date": None}
        if isinstance(value, dict):
            return {"date": value}
        return {"date": {"start": value}}
    if prop_type in _NAME_OBJECT_TYPES:
        return {prop_type: None if value is None else {"name": value}}
    if prop_type == "number":
        return {"number": None if value is None else value}
    if prop_type == "checkbox":
        return {"checkbox": bool(value)}
    if prop_type in ("url", "email", "phone_number"):
        return {prop_type: value}  # None clears; a string sets it
    if prop_type in _NAME_LIST_TYPES:
        return {prop_type: [] if value is None else [{"name": name} for name in value]}
    if prop_type in _ID_LIST_TYPES:
        return {prop_type: [] if value is None else [{"id": item_id} for item_id in value]}
    raise ValueError(f"Unsupported property type {prop_type!r} for writing")


def _build_properties(
    properties: dict[str, Any], schema: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Map {name: simple value} to Notion property-value objects using the data-source schema.

    Raises on unknown property names so a typo fails loudly instead of silently dropping the write.
    """
    built: dict[str, dict[str, Any]] = {}
    for name, value in properties.items():
        prop_type = schema.get(name)
        if prop_type is None:
            raise ValueError(f"Unknown property {name!r}; available: {sorted(schema)}")
        built[name] = _build_property_value(prop_type, value)
    return built


def _paragraph_blocks(paragraphs: list[str]) -> list[dict[str, Any]]:
    """Build simple paragraph blocks from plain strings (children for create_pages content)."""
    return [
        {"type": "paragraph", "paragraph": {"rich_text": [{"text": {"content": text}}]}}
        for text in paragraphs
    ]


async def _resolve_parent(
    client: httpx.AsyncClient, access_token: str, ref: str
) -> tuple[dict[str, Any], dict[str, str] | None]:
    """Resolve a create-page parent from an id/URL to a Notion parent payload + optional schema.

    data_source_id and page_id are both 32-hex UUIDs — indistinguishable by shape — so probe the
    API (via _send, inspecting status_code; no try/except). Order: data_source, then database
    (→ its first data_source), then page. Returns ({parent payload}, schema) where schema is the
    data-source property types for a DB-row parent, or None for a plain page parent.
    """
    notion_id = _normalize_id(ref)
    # Probe data_source → database → page. Notion returns 400 (not 404) when an id is the WRONG
    # object type (e.g. GET /databases/{page_id} → 400 "is a page, not a database"), so ONLY a 200
    # counts as a match; any non-200 means "not this type, try the next endpoint".
    ds_response = await _send(client, access_token, "GET", f"/data_sources/{notion_id}")
    if ds_response.status_code == _HTTP_OK:
        # Reuse the probe body — no need to re-fetch the same data source.
        data_source = ds_response.json()
        ds_id = _normalize_id(data_source["id"])
        return {"type": "data_source_id", "data_source_id": ds_id}, _extract_schema(data_source)
    db_response = await _send(client, access_token, "GET", f"/databases/{notion_id}")
    if db_response.status_code == _HTTP_OK:
        # Database parent: resolve its first data source directly from the probe body.
        sources = db_response.json().get("data_sources") or []
        if not sources:
            raise ValueError(f"Database {notion_id} has no data sources")
        ds_id, schema = await _resolve_ds_and_schema(client, access_token, sources[0]["id"])
        return {"type": "data_source_id", "data_source_id": ds_id}, schema
    page_response = await _send(client, access_token, "GET", f"/pages/{notion_id}")
    if page_response.status_code == _HTTP_OK:
        return {"type": "page_id", "page_id": notion_id}, None
    raise ValueError(f"Parent {ref!r} is not a reachable data source, database, or page")


# A plain page parent has no data-source schema; create_pages still needs a type to build the
# page title. Hard-wire the only property a page child supports: its title, keyed "title".
_PAGE_PARENT_SCHEMA: dict[str, str] = {"title": "title"}


async def _create_one_page(  # noqa: PLR0913 -- builder needs client + auth + parent + schema + page spec
    client: httpx.AsyncClient,
    access_token: str,
    parent: dict[str, Any],
    schema: dict[str, str],
    page: dict[str, Any],
) -> dict[str, Any]:
    """POST one page under a resolved parent; return its simplified id/url/title + properties."""
    raw_properties = page.get("properties") or {}
    body: dict[str, Any] = {
        "parent": parent,
        "properties": _build_properties(raw_properties, schema),
    }
    content = page.get("content")
    if content:
        body["children"] = _paragraph_blocks(content)
    created = await _request(client, access_token, "POST", "/pages", json_body=body)
    return _simplify_page(created)


async def _build_page_schema(
    client: httpx.AsyncClient, access_token: str, page_id: str
) -> dict[str, str]:
    """Resolve the data-source schema for an existing DB-row page (for typed property writes).

    Fetches the page, reads its parent.data_source_id, and resolves that data source's schema
    (the task's prescribed two-call path). The page-GET response embeds a `type` on every property,
    so a one-call type map is possible; the canonical data-source schema is used here instead so
    validation matches create_pages exactly.
    """
    page = await _request(client, access_token, "GET", f"/pages/{page_id}")
    parent = page.get("parent") or {}
    ds_ref = parent.get("data_source_id")
    if not ds_ref:
        raise ValueError(
            f"Page {page_id} is not a database row (parent.type={parent.get('type')!r}); "
            "update_page_properties only supports database-row pages"
        )
    _, schema = await _resolve_ds_and_schema(client, access_token, ds_ref)
    return schema


# === BLOCK / MARKDOWN HELPERS ===

# Notion caps block children at 100 per PATCH /v1/blocks/{id}/children request.
MAX_BLOCKS_PER_REQUEST = 100

# Cap on first-level blocks scanned when searching for a find-and-replace target. A find-one
# edit over a page with thousands of blocks is a sign of misuse; bound the read to stay cheap.
DEFAULT_MAX_CONTENT_BLOCKS = 500

# Markdown line prefixes → Notion block type. Order matters: longer/more-specific prefixes
# ("- [ ] ", "### ") MUST be tested before their shorter substrings ("- ", "# "), so the
# converter checks these as an ordered list, not a dict.
_TODO_UNCHECKED_PREFIX = "- [ ] "
_TODO_CHECKED_PREFIX = "- [x] "
_HEADING_PREFIXES = (("### ", "heading_3"), ("## ", "heading_2"), ("# ", "heading_1"))
_BULLET_PREFIXES = ("- ", "* ")

# Block types whose body is `{ "rich_text": [...] }` — the only types update_page_content can
# rewrite in place. Other types (images, tables, embeds, child_page, etc.) have no editable
# rich_text body, so they are skipped during matching and can never be selected.
_TEXT_BLOCK_TYPES = frozenset(
    {
        "paragraph",
        "heading_1",
        "heading_2",
        "heading_3",
        "to_do",
        "bulleted_list_item",
        "numbered_list_item",
        "quote",
        "callout",
        "toggle",
    }
)


def _rich_text(content: str) -> dict[str, Any]:
    """Minimal Notion rich_text item — `{ "text": { "content": "..." } }`."""
    return {"text": {"content": content}}


def _text_block(block_type: str, content: str) -> dict[str, Any]:
    """Build one Notion block: `{ "type": t, t: { "rich_text": [...] } }` (type key mirrors type)."""
    return {"type": block_type, block_type: {"rich_text": [_rich_text(content)]}}


def _todo_block(content: str, *, is_checked: bool) -> dict[str, Any]:
    """Build a to_do block — rich_text plus the required `checked` flag."""
    return {"type": "to_do", "to_do": {"rich_text": [_rich_text(content)], "checked": is_checked}}


def _numbered_prefix_len(line: str) -> int:
    """Return the length of a leading `N. ` ordered-list marker, or 0 if the line isn't one."""
    digits = 0
    while digits < len(line) and line[digits].isdigit():
        digits += 1
    if digits and line[digits : digits + 2] == ". ":
        return digits + 2
    return 0


def _line_to_block(line: str) -> dict[str, Any] | None:
    """Convert one Markdown line to a Notion block, or None for a blank line (skipped).

    Supported (hand-rolled — md2notion/martian are dead): `#`/`##`/`###` headings,
    `-`/`*` bullets, `N.` numbered list, `- [ ]`/`- [x]` to-do, everything else → paragraph.
    Inline Markdown (bold/links) is NOT parsed — content is taken literally.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith(_TODO_UNCHECKED_PREFIX):
        return _todo_block(stripped[len(_TODO_UNCHECKED_PREFIX) :], is_checked=False)
    if stripped.startswith(_TODO_CHECKED_PREFIX):
        return _todo_block(stripped[len(_TODO_CHECKED_PREFIX) :], is_checked=True)
    for prefix, block_type in _HEADING_PREFIXES:
        if stripped.startswith(prefix):
            return _text_block(block_type, stripped[len(prefix) :])
    for prefix in _BULLET_PREFIXES:
        if stripped.startswith(prefix):
            return _text_block("bulleted_list_item", stripped[len(prefix) :])
    numbered_len = _numbered_prefix_len(stripped)
    if numbered_len:
        return _text_block("numbered_list_item", stripped[numbered_len:])
    return _text_block("paragraph", stripped)


def _markdown_to_blocks(markdown: str) -> list[dict[str, Any]]:
    """Convert a Markdown string to a list of Notion block children (blank lines dropped)."""
    blocks = [_line_to_block(line) for line in markdown.splitlines()]
    return [block for block in blocks if block is not None]


def _block_text_key(block: dict[str, Any]) -> str | None:
    """Return the block's type if it carries an editable rich_text body, else None."""
    block_type = block.get("type", "")
    if block_type not in _TEXT_BLOCK_TYPES:
        return None
    body = block.get(block_type)
    if isinstance(body, dict) and "rich_text" in body:
        return block_type
    return None


def _find_blocks_containing(blocks: list[dict[str, Any]], needle: str) -> list[dict[str, Any]]:
    """Return the editable text blocks whose plain text contains `needle` (substring match)."""
    matches: list[dict[str, Any]] = []
    for block in blocks:
        text_key = _block_text_key(block)
        if text_key is None:
            continue
        if needle in _plain_text(block[text_key].get("rich_text")):
            matches.append(block)
    return matches


# === DATABASE / VIEW / MOVE HELPERS ===

# Notion property colors accepted on select/status/multi_select options.
# Used only to default the color when an option is given as a bare string.
_DEFAULT_OPTION_COLOR = "default"

# Property types whose schema body carries an `options` list (verified).
_OPTION_PROPERTY_TYPES = {"select", "status", "multi_select"}


def _normalize_options(options: list[Any]) -> list[dict[str, Any]]:
    """Normalize select/status/multi_select options to Notion option objects.

    Accepts bare strings (color defaults to "default") or full {"name", "color"?} objects,
    so callers can pass either ["Low", "High"] or [{"name": "Low", "color": "gray"}].
    """
    normalized: list[dict[str, Any]] = []
    for option in options:
        if isinstance(option, str):
            normalized.append({"name": option, "color": _DEFAULT_OPTION_COLOR})
            continue
        if not isinstance(option, dict) or "name" not in option:
            raise ValueError(f"Option must be a name string or an object with 'name': {option!r}")
        built = {"name": option["name"], "color": option.get("color", _DEFAULT_OPTION_COLOR)}
        if option.get("description") is not None:
            built["description"] = option["description"]
        normalized.append(built)
    return normalized


def _build_property_schema(spec: dict[str, Any]) -> dict[str, Any]:
    """Build a Notion property-schema object from a simple {"type", "options"?} spec.

    Shared by create_database (under initial_data_source.properties) and update_data_source
    (add case). Plain types -> {"<type>": {}}; option types -> {"<type>": {"options": [...]}}.
    The verified create/update bodies use exactly this shape.
    """
    prop_type = spec.get("type")
    if not prop_type:
        raise ValueError(f"Property spec missing 'type': {spec!r}")
    if prop_type in _OPTION_PROPERTY_TYPES:
        options = spec.get("options") or []
        return {prop_type: {"options": _normalize_options(options)}}
    # Plain types (title, date, number, checkbox, rich_text, url, email, people, ...)
    # take an empty config object on create/add (verified for title/date).
    return {prop_type: {}}


def _build_properties_schema(properties: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Map a {name: spec} dict to {name: <Notion property schema>} for create/add."""
    return {name: _build_property_schema(spec) for name, spec in properties.items()}


def _title_rich_text(title: str) -> list[dict[str, Any]]:
    """Wrap a plain title string in Notion's single-element rich-text array."""
    return [{"type": "text", "text": {"content": title}}]


def _build_move_parent(new_parent: dict[str, Any]) -> dict[str, Any]:
    """Build the /move `parent` object from {"page_id"|"data_source_id": <id>}.

    Exactly one key is required; the matching `type` is injected (verified — the
    wire body is {"type": "page_id"|"data_source_id", "<key>": "<id>"}). UUIDs are normalized.
    Reject database_id parents: resolve a database to its data_source_id before moving.
    """
    has_page = "page_id" in new_parent
    has_ds = "data_source_id" in new_parent
    if has_page == has_ds:  # both present or neither present
        raise ValueError("new_parent must have exactly one of 'page_id' or 'data_source_id'")
    if has_page:
        return {"type": "page_id", "page_id": _normalize_id(new_parent["page_id"])}
    return {"type": "data_source_id", "data_source_id": _normalize_id(new_parent["data_source_id"])}


# === COMMENT / FILE-UPLOAD HELPERS ===

# Notion file upload: single_part covers files up to 20 MiB. multi_part (>20 MiB, needs
# per-part sends + a /complete call) and external_url mode are out of scope for this tool.
# Notion rejects unknown extensions AND generic types (e.g. application/octet-stream) at create
# (live-verified) — content_type is inferred from the filename via mimetypes, never a generic default.
TEXT_UPLOAD_CONTENT_TYPE = "text/plain"


def _multipart_headers(access_token: str) -> dict[str, str]:
    """Auth + version headers for the multipart file-send step — NO Content-Type.

    The Notion file-upload `upload_url` is on api.notion.com (not a presigned third-party
    URL), so Authorization + Notion-Version are still required. Content-Type is deliberately
    omitted so httpx sets `multipart/form-data` with the correct boundary itself.
    """
    return {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": NOTION_VERSION,
    }


def _comment_rich_text(text: str) -> list[dict[str, Any]]:
    """Build the rich_text array for a comment from a plain string."""
    return [{"text": {"content": text}}]


def _resolve_upload_bytes(content_base64: str | None, text_content: str | None) -> bytes:
    """Decode the bytes to upload from exactly one of text_content / content_base64.

    Raises ValueError if neither or both are given (they are mutually exclusive inputs).
    """
    if (content_base64 is None) == (text_content is None):
        raise ValueError("Provide exactly one of content_base64 or text_content")
    if text_content is not None:
        return text_content.encode("utf-8")
    # content_base64 is non-None here (the XOR guard rejected both/neither); the explicit
    # check lets the type checker narrow str | None -> str.
    if content_base64 is not None:
        return b64decode(content_base64)
    raise ValueError("Provide exactly one of content_base64 or text_content")


def _resolve_content_type(filename: str, content_type: str | None, is_text: bool) -> str:
    """Resolve a Notion-accepted MIME type: explicit > text/plain (text input) > extension guess.

    Notion's File Upload API rejects unknown extensions and generic types like
    application/octet-stream at create time (live-verified). We never fall back to a generic
    type — an unrecognized extension raises so the caller can pass an explicit content_type.
    """
    if content_type:
        return content_type
    if is_text:
        return TEXT_UPLOAD_CONTENT_TYPE
    guessed, _ = mimetypes.guess_type(filename)
    if not guessed:
        raise ValueError(
            f"Could not infer a content type from filename {filename!r}; pass content_type"
        )
    return guessed


async def _create_file_upload(
    client: httpx.AsyncClient, access_token: str, filename: str, content_type: str
) -> dict[str, Any]:
    """Step 1 — create a single_part file upload; returns the file_upload object (status pending)."""
    body = {"mode": "single_part", "filename": filename, "content_type": content_type}
    return await _request(client, access_token, "POST", "/file_uploads", json_body=body)


async def _send_file_bytes(  # noqa: PLR0913 -- multipart send needs client + auth + url + filename + bytes + type
    client: httpx.AsyncClient,
    access_token: str,
    upload_url: str,
    filename: str,
    raw_bytes: bytes,
    content_type: str,
) -> dict[str, Any]:
    """Step 2 — POST the bytes to the upload_url as multipart/form-data field `file`.

    The upload_url is the absolute `…/file_uploads/{id}/send` URL from the create response.
    Field name is `file` (verified). httpx sets the multipart boundary; we keep
    Auth + Notion-Version but omit Content-Type so it is not pinned to JSON.
    """
    files = {"file": (filename, raw_bytes, content_type)}

    def _do() -> Any:
        return client.post(upload_url, headers=_multipart_headers(access_token), files=files)

    response = await _do()
    response = await _retry_on_rate_limit(response, _do)
    _check_status(response)
    return response.json()


def _file_block(file_upload_id: str) -> dict[str, Any]:
    """Build a `file` block referencing an uploaded file (outer block wraps the file_upload value).

    Block shape: {"type":"file","file":{"type":"file_upload","file_upload":{"id":...}}} — the
    inner {"type":"file_upload",...} is the VALUE of `file`, not the block itself.
    """
    return {
        "type": "file",
        "file": {"type": "file_upload", "file_upload": {"id": file_upload_id}},
    }


async def _attach_file_block(
    client: httpx.AsyncClient, access_token: str, page_id: str, file_upload_id: str
) -> str | None:
    """Append a file block referencing the upload to a page; return the created block id.

    Must run within the upload's ~1 h expiry window; on success the upload's expiry_time
    clears to null. page_id is the raw ref (normalized here).
    """
    normalized = _normalize_id(page_id)
    body = {"children": [_file_block(file_upload_id)]}
    created = await _request(
        client, access_token, "PATCH", f"/blocks/{normalized}/children", json_body=body
    )
    blocks = created.get("results") or []
    return blocks[0].get("id") if blocks else None


# === CONNECTOR ===


class NotionApiConnector(NativeConnector):
    """Notion REST native connector — wraps api.notion.com as MCP tools.

    Public-integration OAuth: HTTP Basic token exchange; PKCE unsupported upstream; tokens omit
    `expires_in` and rotate the refresh_token on every response (see parse_token_response).
    """

    meta = ConnectorMeta(
        name="notion_api",
        display_name="Notion (REST)",
        oauth_authorize_url="https://api.notion.com/v1/oauth/authorize",
        oauth_token_url="https://api.notion.com/v1/oauth/token",  # noqa: S106 — endpoint URL, not a password
        scopes=[],  # Notion uses integration-level capabilities (set in the dashboard), not OAuth scopes.
        supports_pkce=False,  # api.notion.com OAuth does not support PKCE S256; waives broker PKCE invariant.
    )

    # --- OAuth overrides ---

    def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
        """Add owner=user — Notion requires it on the authorize URL to issue a user-owned token."""
        params["owner"] = "user"
        return params

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """Notion uses HTTP Basic Auth for token exchange (client_secret_basic)."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    def parse_token_response(self, raw_response: dict) -> dict:
        """Extract standard OAuth fields; inject a synthetic expires_in so the broker refreshes.

        Notion omits `expires_in` but issues a rotating `refresh_token`. Without an expiry the
        broker would never refresh; we set a conservative TTL so refresh fires before the
        (unpublished) real lifetime elapses. The rotated refresh_token is kept on every response.

        Raises:
            ValueError: If access_token is missing.
        """
        if "access_token" not in raw_response:
            raise ValueError("Notion token response missing access_token")
        parsed: dict = {
            "access_token": raw_response["access_token"],
            "token_type": raw_response.get("token_type", "bearer"),
        }
        if "refresh_token" in raw_response:
            parsed["refresh_token"] = raw_response["refresh_token"]
            # `or` (not a get() default) so an explicit null/0 also falls back to the synthetic TTL.
            parsed["expires_in"] = raw_response.get("expires_in") or SYNTHETIC_TOKEN_TTL_SECONDS
        elif "expires_in" in raw_response:
            parsed["expires_in"] = raw_response["expires_in"]
        return parsed

    # --- MCP tools ---

    @native_tool(_QUERY_DATA_SOURCE_META)
    async def query_data_source(  # noqa: PLR0913 -- MCP tool signature (keyword-only args)
        self,
        *,
        access_token: str,
        data_source: str,
        filters: list[dict[str, Any]] | None = None,
        match: str = "all",
        sorts: list[dict[str, Any]] | None = None,
        max_rows: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """Query database rows with filters/sorts, returning typed rows (paginated, capped)."""
        capped = _clamp_max_rows(max_rows)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            ds_id, schema = await _resolve_ds_and_schema(client, access_token, data_source)
            body_base: dict[str, Any] = {}
            notion_filter = _build_filter(filters or [], match, schema)
            if notion_filter:
                body_base["filter"] = notion_filter
            if sorts:
                body_base["sorts"] = _build_sorts(sorts)
            rows, has_more, cursor = await _query_pages(
                client, access_token, ds_id, body_base, capped
            )
        return _mcp_text_content(
            {
                "data_source_id": ds_id,
                "count": len(rows),
                "has_more": has_more,
                "next_cursor": cursor,
                "truncated": has_more and len(rows) >= capped,
                "rows": rows,
            }
        )

    @native_tool(_FETCH_META)
    async def fetch(
        self,
        *,
        access_token: str,
        notion_id: str,
        max_blocks: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """Retrieve a page with blocks, or resolve a data source schema.

        Tries GET /v1/pages/{id} first. On 404 falls back to _resolve_ds_and_schema (which
        also handles database IDs). This matches the adapter's own 404-branch pattern in
        _resolve_ds_and_schema (lines 231-238) — use _send + manual status check, not _request.
        """
        capped = _clamp_max_rows(max_blocks)
        raw_id = _normalize_id(notion_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            page_response = await _send(client, access_token, "GET", f"/pages/{raw_id}")
            if page_response.status_code == _HTTP_NOT_FOUND:
                # Not a page — attempt to resolve as a database / data source
                ds_id, schema = await _resolve_ds_and_schema(client, access_token, notion_id)
                return _mcp_text_content(
                    {"kind": "data_source", "data_source_id": ds_id, "schema": schema}
                )
            _check_status(page_response)
            page = page_response.json()
            blocks_raw, has_more, _cursor = await _paginate_get(
                client, access_token, f"/blocks/{raw_id}/children", capped
            )
        blocks = [_simplify_block(block) for block in blocks_raw]
        return _mcp_text_content(
            {
                "kind": "page",
                "page": _simplify_page(page),
                "blocks": blocks,
                "blocks_truncated": has_more,
            }
        )

    @native_tool(_GET_BLOCK_CHILDREN_META)
    async def get_block_children(
        self,
        *,
        access_token: str,
        block_id: str,
        max_blocks: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """Return direct child blocks of a page or block, paginated up to max_blocks."""
        capped = _clamp_max_rows(max_blocks)
        raw_id = _normalize_id(block_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            blocks_raw, has_more, cursor = await _paginate_get(
                client, access_token, f"/blocks/{raw_id}/children", capped
            )
        blocks = [_simplify_block(block) for block in blocks_raw]
        return _mcp_text_content(
            {
                "block_id": raw_id,
                "count": len(blocks),
                "has_more": has_more,
                "next_cursor": cursor,
                "blocks": blocks,
            }
        )

    @native_tool(_GET_PAGE_PROPERTY_META)
    async def get_page_property(  # noqa: PLR0913 -- tool has page_id + property_id + max_items + self + access_token = 5
        self,
        *,
        access_token: str,
        page_id: str,
        property_id: str,
        max_items: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """Retrieve the full value of a single page property, paginating if needed.

        property_id is URL-encoded with quote(safe="") to handle names that contain slashes
        or other special characters. The API accepts both opaque short ids (e.g. "BEaP") and
        human-readable names (e.g. "Due") — short ids are preferred for stability.
        """
        capped = _clamp_max_rows(max_items)
        raw_page_id = _normalize_id(page_id)
        # quote(safe="") encodes every special character, including "/" in property names.
        encoded_prop = quote(property_id, safe="")
        path = f"/pages/{raw_page_id}/properties/{encoded_prop}"
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            prop_value = await _paginate_property(client, access_token, path, capped)
        return _mcp_text_content(
            {"page_id": raw_page_id, "property_id": property_id, "value": prop_value}
        )

    @native_tool(_SEARCH_META)
    async def search(  # noqa: PLR0913 -- tool has query + object_type + max_results + self + access_token = 5
        self,
        *,
        access_token: str,
        query: str | None = None,
        object_type: str | None = None,
        max_results: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """Search workspace pages/databases by title and return simplified hit objects.

        filter.value must be "page" or "data_source" — "database" is a hard 400 on 2025-09-03.
        Validates object_type before sending to give a clear error rather than a Notion 400.
        """
        if object_type is not None and object_type not in {"page", "data_source"}:
            raise ValueError(
                f"object_type must be 'page' or 'data_source', got {object_type!r}. "
                "Note: 'database' was removed in Notion API 2025-09-03."
            )
        capped = _clamp_max_rows(max_results)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            hits_raw, has_more, cursor = await _search_pages(
                client, access_token, query, object_type, capped
            )
        hits = [_simplify_search_hit(hit) for hit in hits_raw]
        return _mcp_text_content(
            {
                "count": len(hits),
                "has_more": has_more,
                "next_cursor": cursor,
                "results": hits,
            }
        )

    @native_tool(_GET_USERS_META)
    async def get_users(
        self,
        *,
        access_token: str,
        max_users: int = DEFAULT_MAX_ROWS,
    ) -> list[dict[str, Any]]:
        """List workspace users (OAuth token) or return bot identity (PAT/internal token).

        Internal integration tokens (PAT-style) get HTTP 403 from GET /v1/users — Notion
        blocks list for this token type. Unlike other read tools that let _check_status raise,
        this tool branches on _HTTP_FORBIDDEN rather than raising: the PAT-vs-OAuth distinction
        is a known-stable restriction worth surfacing as structured data so the LLM can explain
        it to the user. When the list 403s, the tool falls back to GET /v1/users/me (which
        always works) and includes list_available=False in the response. All other errors
        (401, 5xx, etc.) propagate normally via _check_status.
        """
        capped = _clamp_max_rows(max_users)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            list_response = await _send(client, access_token, "GET", "/users")
            if list_response.status_code == _HTTP_FORBIDDEN:
                # PAT restriction: "Personal access tokens cannot list users."
                # Fall back to /me which always works for any token type.
                me = await _request(client, access_token, "GET", "/users/me")
                return _mcp_text_content(
                    {
                        "list_available": False,
                        "list_error": "GET /v1/users requires a public OAuth token (PAT cannot list users)",
                        "me": _simplify_user(me),
                    }
                )
            _check_status(list_response)
            first_page = list_response.json()
            users = list(first_page.get("results", []))
            has_more = bool(first_page.get("has_more"))
            cursor: str | None = first_page.get("next_cursor")
            while has_more and len(users) < capped:
                params: dict[str, Any] = {"page_size": MAX_PAGE_SIZE, "start_cursor": cursor}
                page = await _request(client, access_token, "GET", "/users", params=params)
                users.extend(page.get("results", []))
                has_more = bool(page.get("has_more"))
                cursor = page.get("next_cursor")
            users = users[:capped]
            me = await _request(client, access_token, "GET", "/users/me")
        return _mcp_text_content(
            {
                "list_available": True,
                "count": len(users),
                "has_more": has_more,
                "next_cursor": cursor,
                "me": _simplify_user(me),
                "users": [_simplify_user(user) for user in users],
            }
        )

    @native_tool(_CREATE_PAGES_META)
    async def create_pages(
        self,
        *,
        access_token: str,
        parent: str,
        pages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Create one page per entry under a resolved parent; return created ids/urls."""
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            parent_payload, schema = await _resolve_parent(client, access_token, parent)
            effective_schema = schema if schema is not None else _PAGE_PARENT_SCHEMA
            created = [
                await _create_one_page(client, access_token, parent_payload, effective_schema, page)
                for page in pages
            ]
        return _mcp_text_content({"count": len(created), "pages": created})

    @native_tool(_UPDATE_PAGE_PROPERTIES_META)
    async def update_page_properties(
        self,
        *,
        access_token: str,
        page_id: str,
        properties: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Patch properties on an existing database-row page (partial; null clears)."""
        notion_id = _normalize_id(page_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            schema = await _build_page_schema(client, access_token, notion_id)
            body = {"properties": _build_properties(properties, schema)}
            updated = await _request(
                client, access_token, "PATCH", f"/pages/{notion_id}", json_body=body
            )
        return _mcp_text_content(_simplify_page(updated))

    @native_tool(_ARCHIVE_PAGE_META)
    async def archive_page(
        self,
        *,
        access_token: str,
        page_id: str,
        archived: bool = True,
    ) -> list[dict[str, Any]]:
        """Archive (move to trash) or restore a page; confirm via the response `archived` flag."""
        notion_id = _normalize_id(page_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            page = await _request(
                client,
                access_token,
                "PATCH",
                f"/pages/{notion_id}",
                json_body={"archived": archived},
            )
        # On 2025-09-03, `archived` reflects the trash state (is_archived is unrelated, always
        # false). On 2026-03-11 this field is renamed `in_trash`.
        return _mcp_text_content({"page_id": page.get("id"), "archived": page.get("archived")})

    @native_tool(_APPEND_BLOCKS_META)
    async def append_blocks(  # noqa: PLR0913 -- MCP tool signature (keyword-only args)
        self,
        *,
        access_token: str,
        block_id: str,
        markdown: str,
        after: str | None = None,
    ) -> list[dict[str, Any]]:
        """Convert Markdown to blocks and append them to a page/block; return created summaries.

        On Notion-Version 2025-09-03 the connector uses the top-level `after` parameter (a block
        id string). The 2026-03-11 delta replaces it with a `position` object — switch when the
        connector retargets that version.

        LIVE-VERIFIED QUIRK: when `after` is set, Notion's response `results` returns the inserted
        block(s) PLUS the pre-existing blocks that now follow them (the shifted-down tail) — so
        `created_count` over-reports for mid-list inserts. The inserted content is still correct on
        the page. Without `after` (append at end), `results` lists exactly the created blocks.
        """
        notion_id = _normalize_id(block_id)
        children = _markdown_to_blocks(markdown)
        if not children:
            raise ValueError("markdown produced no blocks — provide at least one non-blank line")
        if len(children) > MAX_BLOCKS_PER_REQUEST:
            raise ValueError(
                f"markdown produced {len(children)} blocks; Notion accepts at most "
                f"{MAX_BLOCKS_PER_REQUEST} per request — split the content into smaller chunks"
            )
        body: dict[str, Any] = {"children": children}
        if after:
            body["after"] = _normalize_id(after)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            appended = await _request(
                client, access_token, "PATCH", f"/blocks/{notion_id}/children", json_body=body
            )
        created = [_simplify_block(block) for block in appended.get("results", [])]
        return _mcp_text_content(
            {"block_id": notion_id, "created_count": len(created), "blocks": created}
        )

    @native_tool(_UPDATE_PAGE_CONTENT_META)
    async def update_page_content(  # noqa: PLR0913 -- MCP tool signature (keyword-only args)
        self,
        *,
        access_token: str,
        page_id: str,
        old_str: str,
        new_str: str,
    ) -> list[dict[str, Any]]:
        """Replace `old_str` with `new_str` in the single page block that contains it.

        No Notion REST primitive does find-and-replace, so this fetches the page's first-level
        block children, locates the one editable text block containing `old_str`, and PATCHes
        only that block's rich_text. Matching is exact-substring and case-sensitive.

        Behaviour (enforced for safety — destructive edits must be unambiguous):
          - 0 matches  → returns {"status": "error", ...} and performs no write (no-op).
          - >1 matches → returns {"status": "error", ...} listing the matches; performs no write.
          - exactly 1  → PATCH /v1/blocks/{block_id} with old_str→new_str applied to its text.

        Limitation: only first-level blocks of types in _TEXT_BLOCK_TYPES (paragraph, headings,
        to_do, bullet/numbered list, quote, callout, toggle) are searched and editable. Nested
        child blocks and non-text blocks (images, tables, code, etc.) are never matched. Any inline
        formatting on the matched block (bold, italics, links, per-span colour) is collapsed to a
        single plain-text span — sibling block fields (to_do.checked, callout.icon) ARE preserved.
        """
        notion_id = _normalize_id(page_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            blocks, has_more, _cursor = await _paginate_get(
                client, access_token, f"/blocks/{notion_id}/children", DEFAULT_MAX_CONTENT_BLOCKS
            )
            matches = _find_blocks_containing(blocks, old_str)
            if not matches:
                # has_more means the page exceeds DEFAULT_MAX_CONTENT_BLOCKS first-level blocks, so
                # old_str may sit in the unsearched tail. Surface that so the caller can distinguish
                # "genuinely absent" from "search window exhausted" instead of trusting a no-op.
                return _mcp_text_content(
                    {
                        "status": "error",
                        "error": f"No block on this page contains {old_str!r} — nothing changed.",
                        "match_count": 0,
                        "blocks_searched": len(blocks),
                        "search_truncated": has_more,
                    }
                )
            if len(matches) > 1:
                return _mcp_text_content(
                    {
                        "status": "error",
                        "error": (
                            f"{len(matches)} blocks contain {old_str!r}; refusing to edit ambiguously. "
                            "Make old_str more specific so it matches exactly one block."
                        ),
                        "match_count": len(matches),
                        "matches": [_simplify_block(block) for block in matches],
                    }
                )
            target = matches[0]
            text_key = target["type"]
            new_text = _plain_text(target[text_key].get("rich_text")).replace(old_str, new_str)
            # Send ONLY rich_text. Notion deep-merges block PATCHes, so sibling fields survive —
            # to_do.checked stays set, heading/callout colour is kept (both verified live). Do NOT
            # echo the block's full GET body back: it carries read-only/contextual fields (e.g.
            # paragraph.color plus a null `icon`) that the PATCH endpoint rejects with HTTP 400.
            patch_body = {text_key: {"rich_text": [_rich_text(new_text)]}}
            updated = await _request(
                client,
                access_token,
                "PATCH",
                f"/blocks/{_normalize_id(target['id'])}",
                json_body=patch_body,
            )
        return _mcp_text_content(
            {"status": "ok", "match_count": 1, "block": _simplify_block(updated)}
        )

    @native_tool(_CREATE_DATABASE_META)
    async def create_database(  # noqa: PLR0913 -- MCP tool: token + parent + title + properties schema
        self,
        *,
        access_token: str,
        parent_page: str,
        title: str,
        properties: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Create a database under a page; return its database_id and data_source_id."""
        parent_id = _normalize_id(parent_page)
        body: dict[str, Any] = {
            "parent": {"type": "page_id", "page_id": parent_id},
            "title": _title_rich_text(title),
            # On 2025-09-03 the schema goes under initial_data_source.properties.
            "initial_data_source": {"properties": _build_properties_schema(properties)},
        }
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            created = await _request(client, access_token, "POST", "/databases", json_body=body)
        # The data_source_id is in data_sources[0].id, NOT an initial_data_source echo.
        data_sources = created.get("data_sources") or []
        data_source_id = data_sources[0]["id"] if data_sources else None
        return _mcp_text_content(
            {
                "database_id": created.get("id"),
                "data_source_id": data_source_id,
                "title": _plain_text(created.get("title")),
                "url": created.get("url"),
            }
        )

    @native_tool(_UPDATE_DATA_SOURCE_META)
    async def update_data_source(  # noqa: PLR0913 -- MCP tool: token + target + add/rename/remove/title ops
        self,
        *,
        access_token: str,
        data_source: str,
        add: dict[str, dict[str, Any]] | None = None,
        rename: dict[str, str] | None = None,
        remove: list[str] | None = None,
        title: str | None = None,
    ) -> list[dict[str, Any]]:
        """Add/rename/remove schema properties and/or rename a data source; return updated schema."""
        if not any((add, rename, remove, title)):
            raise ValueError("Provide at least one of: add, rename, remove, title")
        # Merge all property mutations into one `properties` patch (add/rename/remove share the key).
        properties: dict[str, Any] = {}
        if add:
            properties.update(_build_properties_schema(add))
        if rename:
            for current_name, new_name in rename.items():
                properties[current_name] = {"name": new_name}
        if remove:
            for name in remove:
                properties[name] = None  # null removes the column
        body: dict[str, Any] = {}
        if properties:
            body["properties"] = properties
        if title:
            body["title"] = _title_rich_text(title)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            ds_id, _ = await _resolve_ds_and_schema(client, access_token, data_source)
            updated = await _request(
                client, access_token, "PATCH", f"/data_sources/{ds_id}", json_body=body
            )
        return _mcp_text_content(
            {
                "data_source_id": ds_id,
                "title": _plain_text(updated.get("title")),
                "properties": _extract_schema(updated),
            }
        )

    @native_tool(_CREATE_VIEW_META)
    async def create_view(  # noqa: PLR0913 -- MCP tool: token + database_id + data_source + name + view_type
        self,
        *,
        access_token: str,
        database_id: str,
        data_source: str,
        name: str,
        view_type: str,
    ) -> list[dict[str, Any]]:
        """Create a view on a database; return the new view object."""
        db_id = _normalize_id(database_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            ds_id, _ = await _resolve_ds_and_schema(client, access_token, data_source)
            body = {
                "database_id": db_id,
                "data_source_id": ds_id,
                "name": name,
                "type": view_type,
            }
            view = await _request(client, access_token, "POST", "/views", json_body=body)
        return _mcp_text_content(_simplify_view(view))

    @native_tool(_UPDATE_VIEW_META)
    async def update_view(
        self,
        *,
        access_token: str,
        view_id: str,
        name: str,
    ) -> list[dict[str, Any]]:
        """Rename an existing view; return the updated view object."""
        normalized_view_id = _normalize_id(view_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            view = await _request(
                client,
                access_token,
                "PATCH",
                f"/views/{normalized_view_id}",
                json_body={"name": name},
            )
        return _mcp_text_content(_simplify_view(view))

    @native_tool(_MOVE_PAGES_META)
    async def move_pages(
        self,
        *,
        access_token: str,
        page_id: str,
        new_parent: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Reparent a page via POST /pages/{id}/move; return its new parent."""
        normalized_page_id = _normalize_id(page_id)
        parent = _build_move_parent(new_parent)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            moved = await _request(
                client,
                access_token,
                "POST",
                f"/pages/{normalized_page_id}/move",
                json_body={"parent": parent},
            )
        return _mcp_text_content(
            {
                "page_id": moved.get("id"),
                "url": moved.get("url"),
                "parent": moved.get("parent"),
            }
        )

    @native_tool(_CREATE_COMMENT_META)
    async def create_comment(
        self,
        *,
        access_token: str,
        text: str,
        page_id: str | None = None,
        discussion_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Create a page-level comment, or reply to a discussion (discussion_id takes precedence)."""
        body: dict[str, Any] = {"rich_text": _comment_rich_text(text)}
        # discussion_id wins (reply); else page_id (new comment). The elif lets the type
        # checker narrow page_id from str | None to str before _normalize_id.
        if discussion_id:
            body["discussion_id"] = _normalize_id(discussion_id)
        elif page_id:
            body["parent"] = {"page_id": _normalize_id(page_id)}
        else:
            raise ValueError("Provide page_id (new comment) or discussion_id (reply)")
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            comment = await _request(client, access_token, "POST", "/comments", json_body=body)
        return _mcp_text_content(_simplify_comment(comment))

    @native_tool(_GET_COMMENTS_META)
    async def get_comments(
        self, *, access_token: str, page_id: str, max_comments: int = DEFAULT_MAX_COMMENTS
    ) -> list[dict[str, Any]]:
        """List comments on a page/block (flat; each carries discussion_id), paginated and capped."""
        capped = _clamp_max_rows(max_comments)
        # GET /v1/comments uses the `block_id` query param even for pages.
        block_id = _normalize_id(page_id)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            raw_comments, has_more, cursor = await _paginate_get(
                client, access_token, "/comments", capped, extra_params={"block_id": block_id}
            )
        comments = [_simplify_comment(c) for c in raw_comments]
        return _mcp_text_content(
            {
                "page_id": block_id,
                "count": len(comments),
                "has_more": has_more,
                "next_cursor": cursor,
                "truncated": has_more and len(comments) >= capped,
                "comments": comments,
            }
        )

    @native_tool(_UPLOAD_FILE_META)
    async def upload_file(  # noqa: PLR0913 -- MCP tool signature (keyword-only args)
        self,
        *,
        access_token: str,
        filename: str,
        text_content: str | None = None,
        content_base64: str | None = None,
        content_type: str | None = None,
        attach_page_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Single-part upload: create the upload, send the bytes, optionally attach to a page."""
        raw_bytes = _resolve_upload_bytes(content_base64, text_content)
        resolved_type = _resolve_content_type(filename, content_type, text_content is not None)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            created = await _create_file_upload(client, access_token, filename, resolved_type)
            file_upload_id = _normalize_id(created["id"])
            upload_url = created.get("upload_url")
            if not upload_url:
                raise ValueError("File-upload create response had no upload_url")
            # Never forward the bearer token off-domain: Notion's single-part upload_url is on
            # api.notion.com; reject anything else (e.g. a future presigned third-party host).
            if not upload_url.startswith("https://api.notion.com/"):
                raise ValueError(
                    f"Unexpected upload_url domain (expected api.notion.com): {upload_url!r}"
                )
            # send the bytes to the absolute upload_url from the create response (multipart `file`).
            sent = await _send_file_bytes(
                client, access_token, upload_url, filename, raw_bytes, resolved_type
            )
            attached_block_id: str | None = None
            if attach_page_id:
                attached_block_id = await _attach_file_block(
                    client, access_token, attach_page_id, file_upload_id
                )
        return _mcp_text_content(
            {
                "file_upload_id": file_upload_id,
                "filename": sent.get("filename", filename),
                "status": sent.get("status"),
                "content_length": sent.get("content_length"),
                "expiry_time": sent.get("expiry_time"),
                "attached_block_id": attached_block_id,
            }
        )
