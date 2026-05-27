"""
Notion JSON -> plain typed values for the `notion_api` connector.

Reduces Notion's verbose API objects (pages, properties, blocks, users, views,
comments, search hits) to the flat, LLM-friendly shapes the tools return. Pure
functions, no I/O — the read-side mirror of the write-side builders in adapter.py.
"""

from __future__ import annotations

from typing import Any


def _plain_text(rich: list[dict[str, Any]] | None) -> str:
    """Join a Notion rich_text array to plain text."""
    return "".join(part.get("plain_text", "") for part in rich or [])


def _simplify_property(prop: dict[str, Any]) -> Any:  # noqa: PLR0911 — one return per Notion property type
    """Reduce a Notion property value to a plain typed value."""
    ptype = prop.get("type", "")
    value = prop.get(ptype)
    if ptype in ("title", "rich_text"):
        return _plain_text(value)
    if ptype in ("select", "status"):
        return value.get("name") if value else None
    if ptype == "multi_select":
        return [opt.get("name") for opt in value or []]
    if ptype == "date":
        return value if value else None
    if ptype in ("number", "checkbox", "url", "email", "phone_number"):
        return value
    if ptype == "people":
        return [person.get("id") for person in value or []]
    if ptype == "relation":
        return [rel.get("id") for rel in value or []]
    if ptype in ("created_time", "last_edited_time"):
        return value
    return value


def _simplify_page(page: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Notion page object to id/url/title + flat typed properties."""
    props = page.get("properties") or {}
    simplified: dict[str, Any] = {
        "page_id": page.get("id"),
        "url": page.get("url"),
        "properties": {name: _simplify_property(prop) for name, prop in props.items()},
    }
    title = next((name for name, p in props.items() if p.get("type") == "title"), None)
    if title:
        simplified["title"] = simplified["properties"].get(title)
    return simplified


def _simplify_block(block: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Notion block to id/type/text/has_children (text = plain text of its rich_text)."""
    btype = block.get("type", "")
    body = block.get(btype)
    rich = body.get("rich_text") if isinstance(body, dict) else None
    return {
        "id": block.get("id"),
        "type": btype,
        "text": _plain_text(rich),
        "has_children": block.get("has_children", False),
    }


def _simplify_user(user: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Notion user object to id/name/type/email."""
    person = user.get("person")
    email = person.get("email") if isinstance(person, dict) else None
    return {
        "id": user.get("id"),
        "name": user.get("name"),
        "type": user.get("type"),
        "email": email,
    }


def _simplify_search_hit(hit: dict[str, Any]) -> dict[str, Any]:
    """Reduce a /search result (page or data source) to id/object/title/url."""
    if hit.get("object") == "page":
        page = _simplify_page(hit)
        return {
            "object": "page",
            "id": page["page_id"],
            "url": page.get("url"),
            "title": page.get("title"),
        }
    return {
        "object": hit.get("object"),
        "id": hit.get("id"),
        "title": _plain_text(hit.get("title")),
    }


def _simplify_view(view: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Notion view object to id/name/type/parent/data_source_id/url."""
    return {
        "view_id": view.get("id"),
        "name": view.get("name"),
        "type": view.get("type"),
        "parent": view.get("parent"),
        "data_source_id": view.get("data_source_id"),
        "url": view.get("url"),
    }


def _simplify_comment(comment: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Notion comment object to id/discussion_id/text/parent/created_time.

    Surfaces discussion_id per comment so the caller can group a flat list into threads
    (Notion returns comments flat, grouped only by discussion_id).
    """
    parent = comment.get("parent") or {}
    display_name = comment.get("display_name") or {}
    return {
        "id": comment.get("id"),
        "discussion_id": comment.get("discussion_id"),
        "text": _plain_text(comment.get("rich_text")),
        "parent_type": parent.get("type"),
        "parent_id": parent.get("page_id") or parent.get("block_id"),
        "created_time": comment.get("created_time"),
        "created_by": (comment.get("created_by") or {}).get("id"),
        "author_name": display_name.get("resolved_name"),
    }
