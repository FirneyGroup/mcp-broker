"""
NativeConnector -- base class for connectors that implement MCP tools in-process.

Extends BaseConnector (keeps OAuth + auto-registration via __init_subclass__).
Tools registered via @native_tool decorator, collected at class creation.
The proxy calls handle_mcp_request() instead of forwarding upstream.

Follows a decorator-based registration pattern: auto-collection
in __init_subclass__, dispatch via handler lookup.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from broker.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


# === MODELS ===


class NativeToolMeta(BaseModel):
    """Static metadata for a native MCP tool.

    Defines the tool's JSON Schema for LLM discovery via tools/list.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    model_config = ConfigDict(frozen=True)


class _RegisteredTool(BaseModel):
    """Internal: pairs tool metadata with the handler method name on the connector."""

    meta: NativeToolMeta
    handler_name: str
    model_config = ConfigDict(frozen=True)


# === JSON-RPC HELPERS ===


def _jsonrpc_ok(request_id: Any, result: dict) -> dict:
    """Build a successful JSON-RPC 2.0 response."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


# === DECORATOR ===


def native_tool(meta: NativeToolMeta) -> Callable:
    """Mark a method as a native MCP tool. Collected by __init_subclass__."""

    def decorator(fn: Any) -> Any:
        fn._tool_meta = meta
        return fn

    return decorator


# === BASE CLASS ===

# MCP protocol version this implementation supports
_MCP_PROTOCOL_VERSION = "2025-03-26"


class NativeConnector(BaseConnector):
    """Base for connectors that implement MCP tools directly.

    Extends BaseConnector -- keeps OAuth and auto-registration via
    __init_subclass__. Adds tool registration via @native_tool decorator
    and JSON-RPC dispatch via handle_mcp_request().

    The proxy route checks isinstance(NativeConnector) and calls
    handle_mcp_request() instead of forwarding upstream.
    """

    _tools: ClassVar[dict[str, _RegisteredTool]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        # Collect @native_tool methods BEFORE super().__init_subclass__
        # triggers ConnectorRegistry.auto_register
        cls._tools = {}
        for attr_name in cls.__dict__:
            method = cls.__dict__[attr_name]
            if hasattr(method, "_tool_meta"):
                tool_meta: NativeToolMeta = method._tool_meta
                cls._tools[tool_meta.name] = _RegisteredTool(
                    meta=tool_meta,
                    handler_name=attr_name,
                )
        super().__init_subclass__(**kwargs)

    # --- MCP JSON-RPC dispatch ---

    async def handle_mcp_request(
        self,
        *,
        method: str,
        params: dict,
        request_id: Any,
        access_token: str,
    ) -> dict:
        """Handle an MCP JSON-RPC request. Token passed directly as argument."""
        match method:
            case "initialize":
                return _jsonrpc_ok(
                    request_id,
                    {
                        "protocolVersion": _MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": self.meta.name, "version": "1.0.0"},
                    },
                )
            case "notifications/initialized":
                return {}  # Empty dict signals "no response" — caller returns 204
            case "tools/list":
                return _jsonrpc_ok(
                    request_id,
                    {
                        "tools": [
                            {
                                "name": tool.meta.name,
                                "description": tool.meta.description,
                                "inputSchema": tool.meta.input_schema,
                            }
                            for tool in self._tools.values()
                        ],
                    },
                )
            case "tools/call":
                return await _dispatch_tool(self, params, request_id, access_token)
            case "ping":
                return _jsonrpc_ok(request_id, {})
            case _:
                return _jsonrpc_error(request_id, -32601, f"Method not found: {method}")


# --- Tool dispatch (module-level to keep NativeConnector body short) ---


async def _dispatch_tool(
    connector: NativeConnector,
    params: dict,
    request_id: Any,
    access_token: str,
) -> dict:
    """Look up and execute a registered tool by name."""
    if not isinstance(params, dict):
        return _jsonrpc_error(request_id, -32602, "params must be an object")

    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if not isinstance(arguments, dict):
        return _jsonrpc_error(request_id, -32602, "Tool arguments must be an object")
    arguments.pop("access_token", None)

    registered = connector._tools.get(tool_name)
    if not registered:
        return _jsonrpc_error(request_id, -32602, f"Unknown tool: {tool_name}")
    try:
        handler = getattr(connector, registered.handler_name)
        content = await handler(access_token=access_token, **arguments)
    except Exception as exc:
        logger.exception("[%s] Tool %s failed", connector.meta.name, tool_name)
        return _jsonrpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            },
        )
    return _jsonrpc_ok(request_id, {"content": content})
