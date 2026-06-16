"""
Regression tests for the generic per-connection ``provider_metadata`` seam.

This is the broker-core change that lets a connector carry a non-secret
per-connection identifier (e.g. QuickBooks' realmId) from the OAuth callback to
native tool handlers without hard-coding a provider concept in the proxy/oauth
core. The tests lock in:

- it round-trips through the encrypted SQLite store AS PLAINTEXT (no encryption
  change needed) while the access token stays encrypted,
- token refresh preserves it,
- native dispatch forwards it ONLY to handlers that opt in (existing handlers,
  e.g. Twitter's, keep their access_token-only signature and are unaffected).
"""

from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet

from broker.connectors.native import NativeConnector, NativeToolMeta, native_tool
from broker.models.connection import AppConnection
from broker.models.connector_config import ConnectorMeta
from broker.services.oauth import _apply_refreshed_token
from broker.services.store import EncryptedTokenStore, SQLiteTokenStore

# === test connectors (define handlers with and without the opt-in parameter) ===

_EMPTY_SCHEMA = {"type": "object", "properties": {}}


class _MetadataConnector(NativeConnector):
    """A handler that opts into provider_metadata by declaring the parameter."""

    meta = ConnectorMeta(
        name="meta_test",
        display_name="Meta Test",
        oauth_authorize_url="https://example.com/authorize",
        oauth_token_url="https://example.com/token",  # noqa: S106 -- endpoint URL
    )

    @native_tool(NativeToolMeta(name="echo_meta", description="echo", input_schema=_EMPTY_SCHEMA))
    async def echo_meta(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None
    ) -> list[dict[str, str]]:
        return [{"type": "text", "text": json.dumps(provider_metadata or {})}]


class _PlainConnector(NativeConnector):
    """A handler with the legacy access_token-only signature."""

    meta = ConnectorMeta(
        name="plain_test",
        display_name="Plain Test",
        oauth_authorize_url="https://example.com/authorize",
        oauth_token_url="https://example.com/token",  # noqa: S106 -- endpoint URL
    )

    @native_tool(NativeToolMeta(name="echo_plain", description="echo", input_schema=_EMPTY_SCHEMA))
    async def echo_plain(self, *, access_token: str) -> list[dict[str, str]]:
        return [{"type": "text", "text": "ok"}]


# === storage round-trip ===


class TestStorageRoundTrip:
    async def test_provider_metadata_round_trips_and_token_stays_encrypted(self, tmp_path):
        sqlite = SQLiteTokenStore(db_path=str(tmp_path / "tokens.db"))
        encrypted = EncryptedTokenStore(keys=[Fernet.generate_key().decode()], delegate=sqlite)
        connection = AppConnection(
            connector_name="quickbooks",
            access_token="super-secret-token",
            provider_metadata={"realm_id": "1234567890"},
        )

        await encrypted.save("acme:app1", "quickbooks", connection)
        loaded = await encrypted.get("acme:app1", "quickbooks")

        assert loaded.provider_metadata == {"realm_id": "1234567890"}
        assert loaded.access_token == "super-secret-token"

        # At rest (delegate sees the encrypted form): realm is plaintext, token is not.
        at_rest = await sqlite.get("acme:app1", "quickbooks")
        assert at_rest.provider_metadata == {"realm_id": "1234567890"}
        assert at_rest.access_token != "super-secret-token"

    def test_default_provider_metadata_is_empty(self):
        connection = AppConnection(connector_name="quickbooks", access_token="t")
        assert connection.provider_metadata == {}


# === refresh preservation ===


class TestRefreshPreservation:
    def test_refresh_keeps_provider_metadata(self):
        connection = AppConnection(
            connector_name="quickbooks",
            access_token="old",
            refresh_token="r",
            provider_metadata={"realm_id": "123"},
        )
        refreshed = _apply_refreshed_token(connection, {"access_token": "new", "expires_in": 3600})

        assert refreshed.access_token == "new"
        assert refreshed.provider_metadata == {"realm_id": "123"}


# === opt-in dispatch ===


class TestOptInDispatch:
    def test_accepts_metadata_flag_reflects_signature(self):
        assert _MetadataConnector._tools["echo_meta"].accepts_metadata is True
        assert _PlainConnector._tools["echo_plain"].accepts_metadata is False

    async def test_opted_in_handler_receives_metadata(self):
        response = await _MetadataConnector().handle_mcp_request(
            method="tools/call",
            params={"name": "echo_meta", "arguments": {}},
            request_id=1,
            access_token="t",
            provider_metadata={"realm_id": "abc"},
        )
        assert json.loads(response["result"]["content"][0]["text"]) == {"realm_id": "abc"}

    async def test_legacy_handler_unaffected_by_metadata(self):
        # Passing provider_metadata must NOT break a handler that doesn't declare it.
        response = await _PlainConnector().handle_mcp_request(
            method="tools/call",
            params={"name": "echo_plain", "arguments": {}},
            request_id=2,
            access_token="t",
            provider_metadata={"realm_id": "abc"},
        )
        assert response["result"]["content"][0]["text"] == "ok"

    def test_parse_callback_params_default_is_empty(self):
        assert _PlainConnector().parse_callback_params({"realmId": "x"}) == {}


@pytest.fixture(autouse=True)
def _noop():
    # The test connectors register at import; nothing else needs setup/teardown.
    yield
