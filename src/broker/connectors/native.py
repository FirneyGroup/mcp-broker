"""
NativeConnector -- base class for connectors that implement MCP tools in-process.

Extends BaseConnector (keeps OAuth + auto-registration via __init_subclass__).
Tools registered via @native_tool decorator, collected at class creation.
The proxy calls handle_mcp_request() instead of forwarding upstream.

Follows a decorator-based registration pattern: auto-collection
in __init_subclass__, dispatch via handler lookup.
"""

from __future__ import annotations

import inspect
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
    # Whether the handler declares a `provider_metadata` parameter. Detected once at
    # registration so dispatch only forwards metadata to handlers that opted in —
    # handlers without it (e.g. every Twitter tool) keep their original signature.
    accepts_metadata: bool = False
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
    """Mark a method as a native MCP tool. Collected by __init_subclass__.

    MUST return the handler unwrapped (or, if ever wrapped, set ``__wrapped__``):
    __init_subclass__ uses ``inspect.signature`` on the handler to detect whether
    it opts into ``provider_metadata``. A wrapper without ``__wrapped__`` would hide
    the real signature and silently stop metadata (e.g. QuickBooks' realmId) from
    being forwarded.
    """

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
                    accepts_metadata="provider_metadata" in inspect.signature(method).parameters,
                )
        super().__init_subclass__(**kwargs)

    # --- Tool availability ---

    def is_tool_available(self, tool_name: str) -> bool:
        """Whether a registered tool should be exposed on this request.

        Defaults to True -- every registered tool is available. Connectors whose
        tool tiers depend on granted OAuth scopes override this to return False
        for tools the current connection cannot use, so those tools never reach
        the LLM's tool menu via tools/list (and calling them is rejected exactly
        like an unknown tool). The default keeps existing connectors unchanged.
        """
        return True

    # --- MCP JSON-RPC dispatch ---

    async def handle_mcp_request(  # noqa: PLR0913 -- MCP dispatch needs method/params/request_id/token/metadata
        self,
        *,
        method: str,
        params: dict,
        request_id: Any,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
    ) -> dict | None:
        """Handle an MCP JSON-RPC request. Token passed directly as argument.

        ``provider_metadata`` carries non-secret per-connection identifiers (e.g.
        QuickBooks' realmId) captured at OAuth-callback time; it is forwarded only
        to tool handlers that declare a ``provider_metadata`` parameter.

        Returns None when the payload is a JSON-RPC notification (no ``id``):
        the spec mandates that notifications receive NO response, so the caller
        replies 204 with an empty body rather than emitting an error.
        """
        # JSON-RPC notifications carry no id. They MUST NOT get a response body —
        # not even an error — so allowlisted notifications (initialized/cancelled
        # are no-ops) are acknowledged with None and the caller returns 204.
        if request_id is None:
            return None

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
                            if self.is_tool_available(tool.meta.name)
                        ],
                    },
                )
            case "tools/call":
                return await _dispatch_tool(
                    self, params, request_id, access_token, provider_metadata
                )
            case "ping":
                return _jsonrpc_ok(request_id, {})
            case _:
                return _jsonrpc_error(request_id, -32601, f"Method not found: {method}")


# --- Tool dispatch (module-level to keep NativeConnector body short) ---


async def _dispatch_tool(  # noqa: PLR0913 -- dispatch needs connector/params/request_id/token/metadata
    connector: NativeConnector,
    params: dict,
    request_id: Any,
    access_token: str,
    provider_metadata: dict[str, str] | None = None,
) -> dict:
    """Look up and execute a registered tool by name."""
    if not isinstance(params, dict):
        return _jsonrpc_error(request_id, -32602, "params must be an object")

    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if not isinstance(arguments, dict):
        return _jsonrpc_error(request_id, -32602, "Tool arguments must be an object")
    # Strip broker-injected kwargs (access_token, provider_metadata) from untrusted
    # client args without mutating the caller's dict — the broker supplies the real
    # values below, so a spoofed value in arguments must never override them.
    tool_arguments = {
        key: value
        for key, value in arguments.items()
        if key not in ("access_token", "provider_metadata")
    }

    registered = connector._tools.get(tool_name)
    # An unavailable tool was filtered out of tools/list, so to the client it
    # never existed. Return the SAME unknown-tool error to keep availability
    # indistinguishable from nonexistence -- a client that guesses the name
    # learns nothing about which scope tier is enabled.
    if not registered or not connector.is_tool_available(tool_name):
        return _jsonrpc_error(request_id, -32602, f"Unknown tool: {tool_name}")
    try:
        handler = getattr(connector, registered.handler_name)
        # Forward provider_metadata only to handlers that declared the parameter,
        # so handlers without it keep their original (access_token-only) signature.
        metadata_kwarg = (
            {"provider_metadata": provider_metadata or {}} if registered.accepts_metadata else {}
        )
        content = await handler(access_token=access_token, **metadata_kwarg, **tool_arguments)
    except ValueError as validation_error:
        # ValueError is the connector-authored, pre-sanitized error channel —
        # its message is intended for the remote client. Any other exception type
        # may embed SDK response bodies/URLs/tokens, so only ValueError passes through.
        logger.exception("[%s] Tool %s failed", connector.meta.name, tool_name)
        return _tool_error(request_id, str(validation_error))
    except Exception as exc:
        logger.exception("[%s] Tool %s failed", connector.meta.name, tool_name)
        return _tool_error(request_id, f"{tool_name} tool failed: {type(exc).__name__}")
    return _jsonrpc_ok(request_id, {"content": content})


def _tool_error(request_id: Any, message: str) -> dict:
    """Build a tools/call result marked isError with a single text content block."""
    return _jsonrpc_ok(
        request_id,
        {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        },
    )
