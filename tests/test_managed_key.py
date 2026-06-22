"""Tests for auth_mode='managed_key' — per-app static key injection.

managed_key resolves a per-app key from apps.{client}.{app}.{connector}.api_key and hands
it to the native handler as access_token (no OAuth, no token store). These tests cover the
resolution helper, end-to-end injection through proxy_mcp_request, the not-configured error,
and the invariant that the key never reaches logs.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.responses import JSONResponse

from broker.config import BrokerConfig, BrokerSettings
from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.connectors.registry import ConnectorRegistry
from broker.models.connector_config import ConnectorMeta
from broker.services.proxy import _resolve_managed_key, proxy_mcp_request

_CONNECTOR = "managed_key_test"
_APP_KEY = "acme:chat"
# Fake key — never a real credential. The per-file ruff ignore covers S106 in tests/.
_KEY = "sk-test-managed-key-SENTINEL-do-not-leak"

# Test-only capture of the access_token each handler call received. Asserting on this
# (not the MCP response or logs) verifies injection without violating the no-leak rule.
_RECEIVED: list[str] = []

_CAPTURE_META = NativeToolMeta(
    name="capture",
    description="Test tool — records the injected access_token for assertion.",
    input_schema={"type": "object", "properties": {}},
)


class _ManagedKeyEchoConnector(NativeConnector):
    """Minimal managed_key native connector used only by these tests."""

    meta = ConnectorMeta(
        name=_CONNECTOR,
        display_name="Managed Key Test",
        auth_mode="managed_key",
    )

    @native_tool(_CAPTURE_META)
    async def capture(self, *, access_token: str) -> list[dict[str, Any]]:
        """Record the injected key (test-only capture) and return a benign block."""
        _RECEIVED.append(access_token)
        return [{"type": "text", "text": "ok"}]


@pytest.fixture(autouse=True)
def _registered_and_clean():
    """Ensure the test connector is registered (other modules may clear the registry)."""
    if ConnectorRegistry.get(_CONNECTOR) is None:
        ConnectorRegistry.auto_register(_ManagedKeyEchoConnector)
    _RECEIVED.clear()
    yield
    _RECEIVED.clear()


def _settings(apps: dict) -> BrokerSettings:
    """A minimal valid BrokerSettings with the given apps subtree."""
    return BrokerSettings(
        broker=BrokerConfig(
            admin_key="test-admin-key-long",
            encryption_keys=["dummy-key"],
            state_secret="test-state-secret-key",
        ),
        apps=apps,
    )


def _request(app_key: str, body: bytes) -> MagicMock:
    """A MagicMock request carrying middleware-set identity + a JSON-RPC body."""
    request = MagicMock()
    request.state.identity.app_key = app_key
    request.method = "POST"
    request.client.host = "127.0.0.1"
    request.headers = {}
    request.body = AsyncMock(return_value=body)
    return request


_TOOLS_CALL = (
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"capture","arguments":{}}}'
)


# === resolution helper ===


def test_resolve_returns_configured_key() -> None:
    settings = _settings({"acme": {"chat": {_CONNECTOR: {"api_key": _KEY}}}})
    assert _resolve_managed_key(_CONNECTOR, _APP_KEY, settings) == _KEY


def test_resolve_missing_app_returns_503() -> None:
    settings = _settings({})
    result = _resolve_managed_key(_CONNECTOR, _APP_KEY, settings)
    assert isinstance(result, JSONResponse)
    assert result.status_code == 503  # noqa: PLR2004 — HTTP status


def test_resolve_present_app_without_api_key_returns_503() -> None:
    settings = _settings({"acme": {"chat": {_CONNECTOR: {"client_id": "x"}}}})
    result = _resolve_managed_key(_CONNECTOR, _APP_KEY, settings)
    assert isinstance(result, JSONResponse)
    assert result.status_code == 503  # noqa: PLR2004 — HTTP status


# === end-to-end injection through the proxy ===


async def test_proxy_injects_per_app_key(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    settings = _settings({"acme": {"chat": {_CONNECTOR: {"api_key": _KEY}}}})
    request = _request(_APP_KEY, _TOOLS_CALL)

    response = await proxy_mcp_request(
        _CONNECTOR, request, store=MagicMock(), oauth_handler=MagicMock(), settings=settings
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 200  # noqa: PLR2004 — HTTP status
    assert _RECEIVED == [_KEY], "handler did not receive the per-app key as access_token"
    assert _KEY not in caplog.text, "the per-app key leaked into logs"


async def test_proxy_two_apps_get_their_own_keys() -> None:
    key_b = "sk-test-managed-key-OTHER-app"
    settings = _settings(
        {
            "acme": {"chat": {_CONNECTOR: {"api_key": _KEY}}},
            "globex": {"chat": {_CONNECTOR: {"api_key": key_b}}},
        }
    )
    await proxy_mcp_request(
        _CONNECTOR,
        _request("acme:chat", _TOOLS_CALL),
        store=MagicMock(),
        oauth_handler=MagicMock(),
        settings=settings,
    )
    await proxy_mcp_request(
        _CONNECTOR,
        _request("globex:chat", _TOOLS_CALL),
        store=MagicMock(),
        oauth_handler=MagicMock(),
        settings=settings,
    )
    assert [_KEY, key_b] == _RECEIVED, "per-app isolation broken — apps shared a key"


async def test_proxy_not_configured_returns_503_and_does_not_dispatch() -> None:
    settings = _settings({"acme": {"chat": {}}})
    response = await proxy_mcp_request(
        _CONNECTOR,
        _request(_APP_KEY, _TOOLS_CALL),
        store=MagicMock(),
        oauth_handler=MagicMock(),
        settings=settings,
    )
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503  # noqa: PLR2004 — HTTP status
    assert _RECEIVED == [], "handler ran despite no configured key"
