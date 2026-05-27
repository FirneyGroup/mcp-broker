"""
Tool JSON-Schema definitions for the `notion_api` connector.

The `NativeToolMeta` for each of the 19 MCP tools — the LLM-facing contract
(name, description, input_schema) served verbatim by `tools/list`. Separated
from adapter.py so tool *behaviour* reads without 700 lines of schema noise.
Edit here to change what a tool advertises to the model.
"""

from __future__ import annotations

from broker.connectors.native import NativeToolMeta
from connectors.notion_api.client import (
    DEFAULT_MAX_COMMENTS,
    DEFAULT_MAX_ROWS,
    MAX_ROWS_CAP,
)

_QUERY_DATA_SOURCE_META = NativeToolMeta(
    name="query_data_source",
    description=(
        "Query rows of a Notion database/data source with filters and sorting — use this for "
        "'what's overdue', 'list tasks where…', and any report over database rows. "
        "Pass `data_source` as a database ID, data source ID, or notion.so URL (it is resolved "
        'automatically). Filters are simple objects: {"property": "<exact property name>", '
        '"op": "<operator>", "value": <value>}. Operators by property type — date: '
        "on_or_before/on_or_after/before/after/equals/is_empty/is_not_empty; status & select: "
        "equals/does_not_equal; checkbox: equals (value true/false); number: greater_than/less_than/"
        'equals; text(title/rich_text): contains/equals. For dates, the value "today" is resolved '
        "server-side. `match`='all' (AND) or 'any' (OR). Example overdue filter: "
        '[{"property":"Due","op":"on_or_before","value":"today"},'
        '{"property":"Status","op":"does_not_equal","value":"Done"}].'
    ),
    input_schema={
        "type": "object",
        "properties": {
            "data_source": {
                "type": "string",
                "description": "Database ID, data source ID, or notion.so URL of the database to query.",
            },
            "filters": {
                "type": "array",
                "description": "Simple filter conditions (combined per `match`).",
                "items": {
                    "type": "object",
                    "properties": {
                        "property": {
                            "type": "string",
                            "description": "Exact property name from the database schema.",
                        },
                        "op": {
                            "type": "string",
                            "description": "Operator valid for the property's type.",
                        },
                        "value": {
                            "description": 'Comparison value; for dates use an ISO date or "today".'
                        },
                    },
                    "required": ["property", "op"],
                },
            },
            "match": {
                "type": "string",
                "enum": ["all", "any"],
                "description": "Combine filters with AND ('all', default) or OR ('any').",
                "default": "all",
            },
            "sorts": {
                "type": "array",
                "description": "Sort order, applied in sequence.",
                "items": {
                    "type": "object",
                    "properties": {
                        "property": {"type": "string"},
                        "direction": {"type": "string", "enum": ["ascending", "descending"]},
                    },
                    "required": ["property"],
                },
            },
            "max_rows": {
                "type": "integer",
                "description": f"Max rows to return across pages (1-{MAX_ROWS_CAP}, default {DEFAULT_MAX_ROWS}).",
                "default": DEFAULT_MAX_ROWS,
            },
        },
        "required": ["data_source"],
    },
)

_FETCH_META = NativeToolMeta(
    name="fetch",
    description=(
        "Retrieve a Notion page (title, properties, and body blocks) or resolve a database / "
        "data source schema. Pass any page ID, database ID, data source ID, or notion.so URL as "
        "`notion_id`. If it resolves as a page you get `{kind:'page', page:{...}, blocks:[...], "
        "blocks_truncated}` — blocks are the first-level body blocks (up to `max_blocks`). "
        "If it resolves as a database/data source you get "
        "`{kind:'data_source', data_source_id, schema}` which is the property schema for "
        "query_data_source. For pages with many blocks, use get_block_children to paginate "
        "further. For relation/rollup/people properties truncated at 25 items, use "
        "get_page_property to retrieve the full value."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "notion_id": {
                "type": "string",
                "description": "Page ID, database ID, data source ID, or notion.so URL to fetch.",
            },
            "max_blocks": {
                "type": "integer",
                "description": (
                    f"Max body blocks to return for a page (1-{MAX_ROWS_CAP}, "
                    f"default {DEFAULT_MAX_ROWS}). Ignored for data sources."
                ),
                "default": DEFAULT_MAX_ROWS,
            },
        },
        "required": ["notion_id"],
    },
)

_GET_BLOCK_CHILDREN_META = NativeToolMeta(
    name="get_block_children",
    description=(
        "List the direct child blocks of a Notion page or block. Returns one level of children "
        "only — blocks with `has_children: true` require a follow-up call with that block's id. "
        "Use this to paginate a page's body content beyond what `fetch` returns, or to drill into "
        "a nested block (toggle, callout, column, etc.). Results are in document order."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "block_id": {
                "type": "string",
                "description": "Page ID, block ID, or notion.so URL whose children to list.",
            },
            "max_blocks": {
                "type": "integer",
                "description": (
                    f"Max blocks to return (1-{MAX_ROWS_CAP}, default {DEFAULT_MAX_ROWS}). "
                    "Fetches multiple pages if needed."
                ),
                "default": DEFAULT_MAX_ROWS,
            },
        },
        "required": ["block_id"],
    },
)

_GET_PAGE_PROPERTY_META = NativeToolMeta(
    name="get_page_property",
    description=(
        "Retrieve the full value of a single property on a Notion page. Use this when `fetch` "
        "returns a property with in-property `has_more: true` (relation/rollup/people with >25 "
        "items) — this endpoint returns the complete paginated value. `property_id` accepts the "
        "short opaque id (e.g. `BEaP`, `title`) OR the human-readable name (e.g. `Due`, `Name`). "
        "Short ids are more stable (names are user-editable). For non-paginated types (date, "
        "status, select, number, checkbox, etc.) returns the value directly. For paginated types "
        "(title, rich_text, relation, people, rollup) returns the accumulated results up to "
        "`max_items`."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "Page ID or notion.so URL.",
            },
            "property_id": {
                "type": "string",
                "description": "Property id (e.g. `BEaP`) or property name (e.g. `Due`).",
            },
            "max_items": {
                "type": "integer",
                "description": (
                    f"Max items to accumulate for paginated property types (1-{MAX_ROWS_CAP}, "
                    f"default {DEFAULT_MAX_ROWS}). Ignored for non-paginated types."
                ),
                "default": DEFAULT_MAX_ROWS,
            },
        },
        "required": ["page_id", "property_id"],
    },
)

_SEARCH_META = NativeToolMeta(
    name="search",
    description=(
        "Search across Notion pages and databases by title. Returns matches from pages or "
        "databases/data-sources that the integration can access. NOTE: this is title-only "
        "search — it does NOT search page body text or database property values. For row-level "
        "filtering over a database, use query_data_source instead. Scope is connection-based: "
        "only objects explicitly shared with this integration via 'Add connections' in the "
        "Notion UI appear in results. `object_type` filters to 'page' or 'data_source' "
        "(omit to return both). `query` is a title substring (omit to list all accessible)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Title substring to match (omit to return all accessible objects).",
            },
            "object_type": {
                "type": "string",
                "enum": ["page", "data_source"],
                "description": "Restrict results to 'page' or 'data_source' (omit for both).",
            },
            "max_results": {
                "type": "integer",
                "description": (
                    f"Max results to return across pages (1-{MAX_ROWS_CAP}, default {DEFAULT_MAX_ROWS})."
                ),
                "default": DEFAULT_MAX_ROWS,
            },
        },
    },
)

_GET_USERS_META = NativeToolMeta(
    name="get_users",
    description=(
        "List workspace members or retrieve the integration's own identity. For internal "
        "integration tokens (PAT-style), `GET /v1/users` returns HTTP 403 — list is restricted "
        "to public OAuth tokens. In that case the tool returns only the bot identity from "
        "`GET /v1/users/me`. For a public OAuth token the tool returns the full workspace "
        "member list. Use this to identify the integration bot's workspace name, owner, and "
        "email, or to resolve user IDs encountered in page properties."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "max_users": {
                "type": "integer",
                "description": (
                    f"Max users to return for list (1-{MAX_ROWS_CAP}, default {DEFAULT_MAX_ROWS}). "
                    "Ignored when the token type prohibits list."
                ),
                "default": DEFAULT_MAX_ROWS,
            },
        },
    },
)

_CREATE_PAGES_META = NativeToolMeta(
    name="create_pages",
    description=(
        "Create one or more Notion pages — use this to add rows to a database ('add a task', "
        "'log an entry') or to create child pages under a page. Pass `parent` as a database ID, "
        "data source ID, or page id/URL (resolved automatically): a database/data-source parent "
        "creates database rows; a page parent creates child pages. Each item in `pages` has "
        "`properties` (a map of property name -> simple value) and optional `content` (a list of "
        "paragraph strings for the page body). Property values are simple: title/rich_text take a "
        'string; date takes an ISO date string (e.g. "2026-06-15"); status & select take the '
        "option name (must already exist on the database); number takes a number; checkbox a bool; "
        "multi_select a list of names; people/relation a list of UUIDs. For a page parent, the only "
        'property is the title, keyed "title". Returns the created pages\' ids and urls.'
    ),
    input_schema={
        "type": "object",
        "properties": {
            "parent": {
                "type": "string",
                "description": (
                    "Database ID, data source ID, or page id/URL to create the page(s) under. "
                    "A database/data-source parent creates rows; a page parent creates child pages."
                ),
            },
            "pages": {
                "type": "array",
                "description": "Pages to create (one POST each).",
                "items": {
                    "type": "object",
                    "properties": {
                        "properties": {
                            "type": "object",
                            "description": (
                                "Map of property name -> simple value. For a database parent, names "
                                'must match the schema. For a page parent, use {"title": "..."}.'
                            ),
                        },
                        "content": {
                            "type": "array",
                            "description": "Optional page body as paragraph strings.",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["properties"],
                },
            },
        },
        "required": ["parent", "pages"],
    },
)

_UPDATE_PAGE_PROPERTIES_META = NativeToolMeta(
    name="update_page_properties",
    description=(
        "Update properties on an existing Notion database-row page — use this to change a row's "
        "fields ('mark as Done', 'set the due date', 'rename'). Pass the `page_id` (id or URL) and "
        "`properties` as a map of property name -> new simple value. Only the properties you include "
        "are changed; others are untouched. Values are simple: title/rich_text a string; date an "
        "ISO date string; status & select the option name (must exist); number a number; checkbox a "
        "bool; multi_select a list of names; people/relation a list of UUIDs. Send `null` as the "
        "value to clear a property (e.g. clear a date or status). Does NOT archive — use archive_page "
        "for that. Returns the updated page (id, url, title, and all properties)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "Page id or notion.so URL of the database row to update.",
            },
            "properties": {
                "type": "object",
                "description": (
                    "Map of property name -> new simple value (only included keys change). "
                    "Use null to clear a nullable property."
                ),
            },
        },
        "required": ["page_id", "properties"],
    },
)

_ARCHIVE_PAGE_META = NativeToolMeta(
    name="archive_page",
    description=(
        "Archive (move to trash) or restore a Notion page — use this to delete/remove a page or "
        "database row ('archive this task', 'delete this row') or to restore one. Pass the `page_id` "
        "(id or URL); set `archived` to true to archive (default) or false to restore. Archiving "
        "hides the page from the workspace; it can be restored with archived=false. Returns "
        "{page_id, archived} reflecting the resulting state."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "Page id or notion.so URL to archive or restore.",
            },
            "archived": {
                "type": "boolean",
                "description": "true to archive (move to trash, default); false to restore.",
                "default": True,
            },
        },
        "required": ["page_id"],
    },
)

_APPEND_BLOCKS_META = NativeToolMeta(
    name="append_blocks",
    description=(
        "Append content to a Notion page or block by writing Markdown — use this to add notes, "
        "sections, checklists, or paragraphs to an existing page. `block_id` is a page ID, block "
        "ID, or notion.so URL (pages are blocks). `markdown` is converted to Notion blocks: "
        "`# `/`## `/`### ` → headings; `- `/`* ` → bullets; `1. ` → numbered list; `- [ ] ` / "
        "`- [x] ` → to-do (unchecked/checked); every other non-blank line → a paragraph. Blank "
        "lines are skipped. Inline styling (bold, links) is NOT parsed — text is literal. "
        "Optionally set `after` to a block ID to insert the new blocks immediately after that "
        "block instead of at the end. Limit: 100 blocks per call — split larger content."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "block_id": {
                "type": "string",
                "description": "Page ID, block ID, or notion.so URL to append children to.",
            },
            "markdown": {
                "type": "string",
                "description": "Markdown content; converted to Notion blocks (≤100 blocks per call).",
            },
            "after": {
                "type": "string",
                "description": "Optional block ID — insert the new blocks right after this one.",
            },
        },
        "required": ["block_id", "markdown"],
    },
)

_UPDATE_PAGE_CONTENT_META = NativeToolMeta(
    name="update_page_content",
    description=(
        "Find-and-replace text inside ONE block on a Notion page. Use this to fix a typo or "
        "reword a single line — NOT for bulk edits. `page_id` is a page ID, block ID, or "
        "notion.so URL. The tool scans the page's top-level text blocks (paragraph, headings, "
        "to-do, bullet/numbered list, quote, callout, toggle) for blocks whose text contains "
        "`old_str`, then replaces `old_str` with `new_str` in the single matching block. "
        "SAFETY: if zero blocks match it returns an error and changes nothing; if MORE THAN ONE "
        "block matches it returns an error asking you to make `old_str` more specific and changes "
        "nothing. Only the matching block's text is rewritten — no blocks are added or deleted, "
        "and nested child blocks are not searched. Non-text blocks (images, tables, etc.) are "
        "ignored."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "Page ID, block ID, or notion.so URL whose blocks to search.",
            },
            "old_str": {
                "type": "string",
                "description": "Exact substring to find; must match exactly one block's text.",
            },
            "new_str": {
                "type": "string",
                "description": "Replacement substring written in place of `old_str`.",
            },
        },
        "required": ["page_id", "old_str", "new_str"],
    },
)

_PROPERTY_SPEC_SCHEMA = {
    "type": "object",
    "description": (
        "Property definition. `type` is a Notion property type (title, rich_text, date, "
        "number, checkbox, select, status, multi_select, url, email, phone_number, people). "
        "For select/status/multi_select, `options` lists the choices."
    ),
    "properties": {
        "type": {
            "type": "string",
            "description": "Notion property type, e.g. 'title', 'date', 'status', 'select', 'number'.",
        },
        "options": {
            "type": "array",
            "description": (
                "Choices for select/status/multi_select. Each item is a name string or an "
                '{"name": "...", "color": "..."} object. Colors: default, gray, brown, orange, '
                "yellow, green, blue, purple, pink, red."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "color": {"type": "string"},
                },
                "required": ["name"],
            },
        },
    },
    "required": ["type"],
}

_CREATE_DATABASE_META = NativeToolMeta(
    name="create_database",
    description=(
        "Create a new Notion database under a parent page. Pass `parent_page` as a page ID or "
        "notion.so URL, a `title` string, and a `properties` map defining the schema — e.g. "
        '{"Name": {"type": "title"}, "Due": {"type": "date"}, '
        '"Status": {"type": "status", "options": ["Not Started", "Done"]}}. '
        "Exactly one property should be of type 'title'. Returns the new database_id and "
        "data_source_id (use data_source_id for create_pages/query_data_source)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "parent_page": {
                "type": "string",
                "description": "Parent page ID or notion.so URL under which to create the database.",
            },
            "title": {
                "type": "string",
                "description": "Database title (plain text).",
            },
            "properties": {
                "type": "object",
                "description": (
                    "Schema as a map of property name -> {type, options?}. "
                    "Include exactly one property of type 'title'."
                ),
                "additionalProperties": _PROPERTY_SPEC_SCHEMA,
            },
        },
        "required": ["parent_page", "title", "properties"],
    },
)

_UPDATE_DATA_SOURCE_META = NativeToolMeta(
    name="update_data_source",
    description=(
        "Edit a Notion database's schema (its data source): add, rename, or remove properties, "
        "or rename the data source. Pass `data_source` as a database ID, data source ID, or "
        "notion.so URL (resolved automatically). `add` is a map of new property name -> "
        '{type, options?} (e.g. {"Priority": {"type": "select", "options": ["Low","High"]}}). '
        '`rename` maps current name -> new name (e.g. {"Priority": "Importance"}). `remove` is a '
        "list of property names to delete (this deletes the column and its data — use with care). "
        "`title` renames the data source. Returns the full updated schema."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "data_source": {
                "type": "string",
                "description": "Database ID, data source ID, or notion.so URL to edit.",
            },
            "add": {
                "type": "object",
                "description": "New properties to add: name -> {type, options?}.",
                "additionalProperties": _PROPERTY_SPEC_SCHEMA,
            },
            "rename": {
                "type": "object",
                "description": "Rename properties: current name -> new name.",
                "additionalProperties": {"type": "string"},
            },
            "remove": {
                "type": "array",
                "description": "Property names to remove (deletes the column and its data).",
                "items": {"type": "string"},
            },
            "title": {
                "type": "string",
                "description": "New title for the data source.",
            },
        },
        "required": ["data_source"],
    },
)

_CREATE_VIEW_META = NativeToolMeta(
    name="create_view",
    description=(
        "Create a new view on a Notion database. Pass `database_id` and its `data_source` "
        "(database ID, data source ID, or notion.so URL — resolved automatically), a `name`, "
        "and a `view_type` (one of: table, board, calendar, timeline, gallery, list). "
        "Returns the new view object including its id."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "database_id": {
                "type": "string",
                "description": "Database ID (or notion.so URL) the view belongs to.",
            },
            "data_source": {
                "type": "string",
                "description": "Data source ID, database ID, or notion.so URL scoping the view.",
            },
            "name": {
                "type": "string",
                "description": "Display name for the view.",
            },
            "view_type": {
                "type": "string",
                "enum": ["table", "board", "calendar", "timeline", "gallery", "list"],
                "description": "View layout type.",
            },
        },
        "required": ["database_id", "data_source", "name", "view_type"],
    },
)

_UPDATE_VIEW_META = NativeToolMeta(
    name="update_view",
    description=(
        "Rename an existing Notion view. Pass the `view_id` and the new `name`. "
        "Returns the updated view object."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "view_id": {
                "type": "string",
                "description": "ID of the view to update.",
            },
            "name": {
                "type": "string",
                "description": "New display name for the view.",
            },
        },
        "required": ["view_id", "name"],
    },
)

_MOVE_PAGES_META = NativeToolMeta(
    name="move_pages",
    description=(
        "Move (reparent) a Notion page under a new parent. Pass `page_id` and `new_parent` with "
        'exactly one of {"page_id": "<page>"} (move under another page) or '
        '{"data_source_id": "<ds>"} (move into a database). To move into a database, use its '
        "data_source_id (resolve a database ID first). This is the ONLY way to reparent a page — "
        "updating a page's properties does not change its parent. Returns the page's new parent."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "ID (or notion.so URL) of the page to move.",
            },
            "new_parent": {
                "type": "object",
                "description": 'New parent: {"page_id": "..."} or {"data_source_id": "..."}.',
                "properties": {
                    "page_id": {"type": "string"},
                    "data_source_id": {"type": "string"},
                },
            },
        },
        "required": ["page_id", "new_parent"],
    },
)

_CREATE_COMMENT_META = NativeToolMeta(
    name="create_comment",
    description=(
        "Add a comment to a Notion page, or reply to an existing comment thread. "
        "To start a new page-level comment, pass `page_id` (a page ID or notion.so URL) "
        "and `text`. To reply within an existing thread, pass `discussion_id` (obtained "
        "from get_comments) and `text` — do NOT pass page_id when replying. Returns the "
        "created comment's id and its discussion_id (the thread it belongs to). Requires "
        "the integration's Insert-comment capability (enabled). Note: the API cannot start "
        "an inline comment anchored to a specific block — only page-level comments or "
        "replies to an existing discussion."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": (
                    "Page ID or notion.so URL to comment on. Use for a new page-level "
                    "comment; omit when replying via discussion_id."
                ),
            },
            "text": {
                "type": "string",
                "description": "The comment body (plain text).",
            },
            "discussion_id": {
                "type": "string",
                "description": (
                    "Existing discussion/thread ID to reply to (from get_comments). "
                    "When set, page_id is ignored."
                ),
            },
        },
        "required": ["text"],
    },
)

_GET_COMMENTS_META = NativeToolMeta(
    name="get_comments",
    description=(
        "List unresolved comments on a Notion page (or block). Returns a flat list of "
        "comments; each carries a `discussion_id` so you can group them into threads "
        "(Notion returns no nested threading — a reply and its originating comment share a "
        "discussion_id). Pass `page_id` as a page ID, block ID, or notion.so URL. Requires "
        "the integration's Read-comment capability (enabled)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "page_id": {
                "type": "string",
                "description": "Page ID, block ID, or notion.so URL to list comments for.",
            },
            "max_comments": {
                "type": "integer",
                "description": (
                    f"Max comments to return across pages "
                    f"(1-{MAX_ROWS_CAP}, default {DEFAULT_MAX_COMMENTS})."
                ),
                "default": DEFAULT_MAX_COMMENTS,
            },
        },
        "required": ["page_id"],
    },
)

_UPLOAD_FILE_META = NativeToolMeta(
    name="upload_file",
    description=(
        "Upload a small file to Notion and optionally attach it to a page. Provide a "
        "`filename` plus EXACTLY ONE of: `text_content` (a plain-text string) or "
        "`content_base64` (base64-encoded bytes for binary files). The MIME `content_type` is "
        "inferred from the filename extension (e.g. .pdf, .png, .csv) when omitted; pass it "
        "explicitly for unusual extensions. If `attach_page_id` is given, a file "
        "block referencing the upload is appended to that page. Returns the file_upload id, "
        "its status (flips to 'uploaded' after the bytes are sent), and the attached block "
        "id when applicable. Single-part uploads only (files up to 20 MiB); multi-part and "
        "external-URL uploads are not supported. An unattached upload expires in ~1 hour."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "File name including extension (e.g. 'notes.txt').",
            },
            "text_content": {
                "type": "string",
                "description": "Plain-text file contents. Mutually exclusive with content_base64.",
            },
            "content_base64": {
                "type": "string",
                "description": (
                    "Base64-encoded file bytes for binary files. Mutually exclusive with "
                    "text_content."
                ),
            },
            "content_type": {
                "type": "string",
                "description": (
                    "MIME type of the file (e.g. 'text/plain', 'application/pdf'). Optional — "
                    "inferred from the filename extension when omitted. Notion rejects unknown "
                    "extensions and generic types, so pass this for unusual file types."
                ),
            },
            "attach_page_id": {
                "type": "string",
                "description": (
                    "Optional page ID or notion.so URL to attach the uploaded file to (as a "
                    "file block). Must be done within the upload's ~1 h expiry window."
                ),
            },
        },
        "required": ["filename"],
    },
)
