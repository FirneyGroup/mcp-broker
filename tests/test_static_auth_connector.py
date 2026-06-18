"""auth_mode='none' connectors — open / static-token APIs that skip the OAuth gate.

A connector whose upstream is an open API (or one it authenticates to with its own
static credential) sets auth_mode='none'. The broker then dispatches it WITHOUT
resolving or injecting an OAuth token: native handlers receive an empty access_token
and self-source any credential from their own config.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.connectors.registry import ConnectorRegistry
from broker.models.connector_config import ConnectorMeta
from broker.services.proxy import _dispatch_native_request, proxy_mcp_request


def _make_request(method: str, body: bytes, app_key: str = "acme:app1") -> MagicMock:
    request = MagicMock()
    request.method = method
    request.body = AsyncMock(return_value=body)
    request.client = MagicMock(host="127.0.0.1")
    request.state.identity = MagicMock(app_key=app_key)
    return request


@pytest.fixture
def open_connector():
    class OpenApiConnector(NativeConnector):
        meta = ConnectorMeta(
            name="open_api_test",
            display_name="Open API Test",
            auth_mode="none",  # open/static-token API — no OAuth URLs, no broker token
        )

        @native_tool(
            NativeToolMeta(name="ping", description="ping", input_schema={"type": "object"})
        )
        async def ping(self, *, access_token: str = "", **_: Any) -> list[dict[str, Any]]:
            # Echo the token so the test can prove no broker credential was injected.
            return [{"type": "text", "text": f"token={access_token!r}"}]

    connector = ConnectorRegistry.get("open_api_test")
    assert connector is not None
    return connector


def test_auth_mode_none_meta_validates_without_oauth_urls() -> None:
    meta = ConnectorMeta(name="z", display_name="Z", auth_mode="none")
    assert meta.is_native is True
    assert meta.is_sidecar_managed is False
    assert meta.requires_oauth is False


async def test_native_dispatch_with_no_connection(open_connector) -> None:
    body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
    response = await _dispatch_native_request(_make_request("POST", body), open_connector, None)
    assert response.status_code == 200
    names = {t["name"] for t in json.loads(response.body)["result"]["tools"]}
    assert "ping" in names


async def test_tool_call_receives_empty_token_without_connection(open_connector) -> None:
    body = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ping","arguments":{}},"id":2}'
    response = await _dispatch_native_request(_make_request("POST", body), open_connector, None)
    assert response.status_code == 200
    text = json.loads(response.body)["result"]["content"][0]["text"]
    assert text == "token=''"  # empty access_token injected — no broker credential


async def test_proxy_skips_oauth_gate_for_auth_mode_none(open_connector) -> None:
    # store/oauth_handler/settings are unused on the no-OAuth branch — that is the point.
    body = b'{"jsonrpc":"2.0","method":"tools/list","id":3}'
    response = await proxy_mcp_request(
        "open_api_test", _make_request("POST", body), MagicMock(), MagicMock(), MagicMock()
    )
    assert response.status_code == 200  # NOT 503 upstream_not_connected
    names = {t["name"] for t in json.loads(response.body)["result"]["tools"]}
    assert "ping" in names
