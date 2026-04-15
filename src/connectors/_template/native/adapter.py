"""
Native connector template.

Copy this directory to `src/connectors/{name}/`, rename the class, and replace
every `FILL_ME_IN` value. The template intentionally fails Pydantic validation
on import so it cannot be activated unedited.

Flavour: Native — tools implemented in-process, no external MCP server.
When to use: the provider has no MCP server you can proxy; you wrap their
    REST API or Python SDK directly. The broker handles OAuth and dispatches
    to your tool handlers.
Reference example: src/connectors/twitter/adapter.py
"""

from __future__ import annotations

import asyncio
from typing import Any

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connector_config import ConnectorMeta

# === TOOL METADATA ===
#
# Each tool needs a NativeToolMeta describing its JSON Schema. The schema is
# delivered verbatim to LLMs via tools/list — keep descriptions actionable and
# include a "required" list for mandatory parameters.

_EXAMPLE_TOOL_META = NativeToolMeta(
    name="FILL_ME_IN_tool_name",
    description="FILL_ME_IN — a short verb-phrase the LLM will read to decide when to call this tool.",
    input_schema={
        "type": "object",
        "properties": {
            "example_arg": {
                "type": "string",
                "description": "FILL_ME_IN",
            },
        },
        "required": ["example_arg"],
    },
)


# === SYNC HELPERS (run in executor) ===
#
# Most provider SDKs are synchronous. Wrap them in module-level functions so
# the tool handlers can submit them to an executor — a blocking call in the
# handler itself would stall the event loop for every concurrent request.


def _call_example_api_sync(access_token: str, example_arg: str) -> dict[str, Any]:
    """TODO: call the upstream SDK with access_token and return a plain dict."""
    raise NotImplementedError("Replace with the real SDK call")


# === CONNECTOR ===


class TemplateNativeConnector(NativeConnector):
    """TODO: rename to {Name}Connector. Describe the provider in one sentence."""

    meta = ConnectorMeta(
        # TODO: snake_case identifier.
        name="FILL_ME_IN",
        # TODO: human-readable display name.
        display_name="FILL_ME_IN",
        # Leave mcp_url unset — that is what routes requests in-process.
        # TODO: OAuth endpoints for the provider.
        oauth_authorize_url="FILL_ME_IN",
        oauth_token_url="FILL_ME_IN",  # noqa: S106 -- endpoint URL, not a password
        scopes=[],
    )

    @native_tool(_EXAMPLE_TOOL_META)
    async def FILL_ME_IN_tool_name(
        self,
        *,
        access_token: str,
        example_arg: str,
    ) -> list[dict[str, Any]]:
        """TODO: describe what this tool does for future maintainers.

        Handler contract:
        - `async def` + keyword-only `access_token: str` — the dispatcher
          passes the access token as a kwarg.
        - Return a list of MCP content blocks (typically one text block).
        - Do NOT log, persist, or return `access_token`.
        """
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _call_example_api_sync, access_token, example_arg)
        return [{"type": "text", "text": str(result)}]
