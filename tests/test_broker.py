"""
MCP Broker Unit Tests

Tests for: ConnectorRegistry, TokenStore (SQLite + Encrypted), OAuthHandler,
proxy_mcp_request, models, config, OAuth discovery, dynamic registration,
resolve_oauth composition, list_expiring, and admin auth.
"""

import time
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from cryptography.fernet import Fernet
from httpx import Response
from pydantic import ValidationError

from broker.config import BrokerConfig, BrokerSettings
from broker.connectors.base import BaseConnector
from broker.connectors.registry import ConnectorRegistry
from broker.models.connection import AppConnection
from broker.models.connector_config import (
    AppConnectorCredentials,
    ConnectorMeta,
    DynamicRegistration,
    ResolvedOAuth,
)
from broker.services.discovery import OAuthDiscovery, resolve_oauth
from broker.services.oauth import OAuthHandler
from broker.services.store import EncryptedTokenStore, SQLiteTokenStore

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear connector registry before each test."""
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture(autouse=True)
def clear_registration_locks():
    """Clear module-level registration locks between tests."""
    from broker.services.discovery import _registration_locks

    _registration_locks.clear()
    yield
    _registration_locks.clear()


@pytest.fixture
def test_meta() -> ConnectorMeta:
    return ConnectorMeta(
        name="test_connector",
        display_name="Test",
        mcp_url="https://mcp.test.com/mcp",
        oauth_authorize_url="https://test.com/oauth/authorize",
        oauth_token_url="https://test.com/oauth/token",
        scopes=["read", "write"],
    )


@pytest.fixture
def test_credentials() -> AppConnectorCredentials:
    return AppConnectorCredentials(
        client_id="test_client_id",
        client_secret="test_client_secret",
    )


@pytest.fixture
def test_connection() -> AppConnection:
    return AppConnection(
        connector_name="test_connector",
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        expires_at=int(time.time()) + 3600,
        scopes=["read", "write"],
    )


@pytest.fixture
def sqlite_store(tmp_path: Path) -> SQLiteTokenStore:
    db_path = str(tmp_path / "test_tokens.db")
    return SQLiteTokenStore(db_path=db_path)


@pytest.fixture
def encryption_key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def encrypted_store(sqlite_store: SQLiteTokenStore, encryption_key: str) -> EncryptedTokenStore:
    return EncryptedTokenStore(keys=[encryption_key], delegate=sqlite_store)


@pytest.fixture
def test_resolved(
    test_meta: ConnectorMeta, test_credentials: AppConnectorCredentials
) -> ResolvedOAuth:
    return ResolvedOAuth(
        authorize_url=test_meta.oauth_authorize_url,
        token_url=test_meta.oauth_token_url,
        credentials=test_credentials,
    )


@pytest.fixture
def oauth_handler() -> OAuthHandler:
    return OAuthHandler(state_secret="test-secret-key-for-signing")


# =============================================================================
# FACTORIES
# =============================================================================


def make_discovery_meta(**overrides: Any) -> ConnectorMeta:
    """ConnectorMeta with mcp_oauth_url (discovery-enabled)."""
    defaults: dict[str, Any] = {
        "name": "discovery_connector",
        "display_name": "Discovery Test",
        "mcp_url": "https://mcp.test.com/mcp",
        "oauth_authorize_url": "https://mcp.test.com/authorize",
        "oauth_token_url": "https://mcp.test.com/token",
        "mcp_oauth_url": "https://mcp.test.com",
    }
    return ConnectorMeta(**(defaults | overrides))


def make_registration(**overrides: Any) -> DynamicRegistration:
    """DynamicRegistration with test credentials."""
    defaults: dict[str, Any] = {
        "connector_name": "discovery_connector",
        "client_id": "dyn_client_id",
        "client_secret": "dyn_client_secret",
        "redirect_uri": "http://localhost/oauth/discovery_connector/callback",
    }
    return DynamicRegistration(**(defaults | overrides))


def make_wellknown_resource(auth_server: str = "https://auth.test.com") -> dict:
    """Protected resource .well-known response."""
    return {"authorization_servers": [auth_server]}


def make_wellknown_server(**overrides: Any) -> dict:
    """Authorization server .well-known response."""
    defaults = {
        "authorization_endpoint": "https://auth.test.com/authorize",
        "token_endpoint": "https://auth.test.com/token",
        "registration_endpoint": "https://auth.test.com/register",
    }
    return defaults | overrides


def make_registration_response(**overrides: Any) -> dict:
    """Dynamic registration endpoint response."""
    defaults = {
        "client_id": "dyn_client_id",
        "client_secret": "dyn_client_secret",
        "token_endpoint_auth_method": "client_secret_basic",
    }
    return defaults | overrides


# =============================================================================
# CONNECTOR REGISTRY
# =============================================================================


class TestConnectorRegistry:
    def test_auto_register(self, test_meta: ConnectorMeta) -> None:
        """Subclass with meta auto-registers."""

        class TestConn(BaseConnector):
            meta = test_meta

        conn = ConnectorRegistry.get("test_connector")
        assert conn is not None
        assert conn.meta.name == "test_connector"

    def test_no_meta_skips_registration(self) -> None:
        """Subclass without meta does NOT register."""

        class NoMetaConn(BaseConnector):
            pass

        assert ConnectorRegistry.get_stats()["total_connectors"] == 0

    def test_list_all(self, test_meta: ConnectorMeta) -> None:
        class TestConn(BaseConnector):
            meta = test_meta

        connectors = ConnectorRegistry.list_all()
        assert len(connectors) == 1
        assert connectors[0].meta.name == "test_connector"

    def test_clear(self, test_meta: ConnectorMeta) -> None:
        class TestConn(BaseConnector):
            meta = test_meta

        assert ConnectorRegistry.get_stats()["total_connectors"] == 1
        ConnectorRegistry.clear()
        assert ConnectorRegistry.get_stats()["total_connectors"] == 0

    def test_get_nonexistent(self) -> None:
        assert ConnectorRegistry.get("nonexistent") is None

    def test_hooks_default(self, test_meta: ConnectorMeta) -> None:
        """Default hooks pass through."""

        class TestConn(BaseConnector):
            meta = test_meta

        conn = ConnectorRegistry.get("test_connector")
        assert conn is not None
        # customize_authorize_params — pass through
        params = {"key": "value"}
        assert conn.customize_authorize_params(params) == params
        # build_auth_header — Bearer token
        assert conn.build_auth_header("tok123") == {"Authorization": "Bearer tok123"}
        # parse_token_response — pass through
        data = {"access_token": "tok"}
        assert conn.parse_token_response(data) == data


# =============================================================================
# TOKEN STORE (SQLITE)
# =============================================================================


class TestSQLiteTokenStore:
    async def test_save_and_get(
        self, sqlite_store: SQLiteTokenStore, test_connection: AppConnection
    ) -> None:
        await sqlite_store.save("app:test", "test_connector", test_connection)
        result = await sqlite_store.get("app:test", "test_connector")
        assert result is not None
        assert result.access_token == "test_access_token"
        assert result.connector_name == "test_connector"

    async def test_get_nonexistent(self, sqlite_store: SQLiteTokenStore) -> None:
        result = await sqlite_store.get("app:test", "nonexistent")
        assert result is None

    async def test_delete(
        self, sqlite_store: SQLiteTokenStore, test_connection: AppConnection
    ) -> None:
        await sqlite_store.save("app:test", "test_connector", test_connection)
        await sqlite_store.delete("app:test", "test_connector")
        result = await sqlite_store.get("app:test", "test_connector")
        assert result is None

    async def test_list_for_app(
        self, sqlite_store: SQLiteTokenStore, test_connection: AppConnection
    ) -> None:
        conn2 = AppConnection(
            connector_name="other_connector",
            access_token="other_token",
        )
        await sqlite_store.save("app:test", "test_connector", test_connection)
        await sqlite_store.save("app:test", "other_connector", conn2)
        await sqlite_store.save("other:app", "test_connector", test_connection)

        results = await sqlite_store.list_for_app("app:test")
        assert len(results) == 2

    async def test_upsert(
        self, sqlite_store: SQLiteTokenStore, test_connection: AppConnection
    ) -> None:
        """Save twice with same key updates the record."""
        await sqlite_store.save("app:test", "test_connector", test_connection)
        updated = test_connection.model_copy(update={"access_token": "new_token"})
        await sqlite_store.save("app:test", "test_connector", updated)
        result = await sqlite_store.get("app:test", "test_connector")
        assert result is not None
        assert result.access_token == "new_token"


# =============================================================================
# ENCRYPTED TOKEN STORE
# =============================================================================


class TestEncryptedTokenStore:
    async def test_round_trip(
        self, encrypted_store: EncryptedTokenStore, test_connection: AppConnection
    ) -> None:
        """Save then get returns decrypted original values."""
        await encrypted_store.save("app:test", "test_connector", test_connection)
        result = await encrypted_store.get("app:test", "test_connector")
        assert result is not None
        assert result.access_token == "test_access_token"
        assert result.refresh_token == "test_refresh_token"

    async def test_stored_encrypted(
        self,
        encrypted_store: EncryptedTokenStore,
        sqlite_store: SQLiteTokenStore,
        test_connection: AppConnection,
    ) -> None:
        """Tokens in underlying store are encrypted (not plaintext)."""
        await encrypted_store.save("app:test", "test_connector", test_connection)
        # Read from underlying store directly
        raw = await sqlite_store.get("app:test", "test_connector")
        assert raw is not None
        assert raw.access_token != "test_access_token"
        assert raw.refresh_token != "test_refresh_token"

    async def test_no_refresh_token(self, encrypted_store: EncryptedTokenStore) -> None:
        """Connection without refresh_token encrypts/decrypts cleanly."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            refresh_token=None,
        )
        await encrypted_store.save("app:test", "test", conn)
        result = await encrypted_store.get("app:test", "test")
        assert result is not None
        assert result.access_token == "tok"
        assert result.refresh_token is None

    async def test_list_for_app_decrypted(
        self, encrypted_store: EncryptedTokenStore, test_connection: AppConnection
    ) -> None:
        """list_for_app returns decrypted connections."""
        await encrypted_store.save("app:test", "test_connector", test_connection)
        results = await encrypted_store.list_for_app("app:test")
        assert len(results) == 1
        assert results[0].access_token == "test_access_token"

    def test_no_keys_raises(self, sqlite_store: SQLiteTokenStore) -> None:
        with pytest.raises(ValueError, match="At least one encryption key"):
            EncryptedTokenStore(keys=[], delegate=sqlite_store)


# =============================================================================
# OAUTH HANDLER
# =============================================================================


class TestOAuthHandler:
    def test_build_authorize_url_has_pkce(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_resolved: ResolvedOAuth,
    ) -> None:
        class TestConn(BaseConnector):
            meta = test_meta

        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None
        url = oauth_handler.build_authorize_url(
            connector, "app:test", test_resolved, "http://localhost/callback"
        )

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert "code_challenge" in params
        assert params["code_challenge_method"] == ["S256"]
        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["test_client_id"]
        assert params["redirect_uri"] == ["http://localhost/callback"]
        assert "state" in params
        assert params["scope"] == ["read write"]

    def test_build_authorize_url_calls_hook(
        self, oauth_handler: OAuthHandler, test_credentials: AppConnectorCredentials
    ) -> None:
        """Connector's customize_authorize_params hook is called."""
        hook_called = False

        hook_meta = ConnectorMeta(
            name="hook_test",
            display_name="Hook Test",
            mcp_url="https://test.com/mcp",
            oauth_authorize_url="https://test.com/oauth/authorize",
            oauth_token_url="https://test.com/oauth/token",
        )

        class HookConn(BaseConnector):
            meta = hook_meta

            def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
                nonlocal hook_called
                hook_called = True
                params["custom"] = "value"
                return params

        connector = ConnectorRegistry.get("hook_test")
        assert connector is not None
        resolved = ResolvedOAuth(
            authorize_url=hook_meta.oauth_authorize_url,
            token_url=hook_meta.oauth_token_url,
            credentials=test_credentials,
        )
        url = oauth_handler.build_authorize_url(
            connector, "app:test", resolved, "http://localhost/callback"
        )
        assert hook_called
        assert "custom=value" in url

    async def test_exchange_code_validates_state(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_resolved: ResolvedOAuth,
    ) -> None:
        """exchange_code rejects invalid state."""

        class TestConn(BaseConnector):
            meta = test_meta

        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None
        with pytest.raises(ValueError, match="Invalid OAuth state"):
            await oauth_handler.exchange_code(
                connector, "code123", "invalid-state", test_resolved, "http://localhost/callback"
            )

    async def test_refresh_not_expired(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_connection: AppConnection,
        test_resolved: ResolvedOAuth,
    ) -> None:
        """refresh_if_expired returns unchanged if not expired."""

        class TestConn(BaseConnector):
            meta = test_meta

        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None
        result = await oauth_handler.refresh_if_expired(connector, test_connection, test_resolved)
        assert result is test_connection  # Same object — no refresh needed

    async def test_refresh_no_refresh_token(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_resolved: ResolvedOAuth,
    ) -> None:
        """refresh_if_expired returns unchanged if no refresh_token."""

        class TestConn(BaseConnector):
            meta = test_meta

        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=int(time.time()) - 100,  # Expired
            refresh_token=None,  # But no refresh token
        )
        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None
        result = await oauth_handler.refresh_if_expired(connector, conn, test_resolved)
        assert result is conn  # Unchanged


# =============================================================================
# PROXY (unit tests with mocks)
# =============================================================================


class TestProxyAuth:
    async def test_no_identity_returns_401(self) -> None:
        """Proxy rejects requests without middleware-set identity."""
        from broker.services.proxy import proxy_mcp_request

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-value-x",
                encryption_keys=["dummy"],
                state_secret="dummy-state-secret",
            ),
        )

        request = MagicMock()
        request.state = MagicMock(spec=[])  # no identity attribute

        store = AsyncMock()
        oauth = MagicMock()

        result = await proxy_mcp_request("notion", request, store, oauth, settings)
        assert result.status_code == 401

    async def test_identity_present_proceeds(self) -> None:
        """Proxy extracts app_key from middleware-set identity."""
        from broker.services.api_key_store import BrokerAppIdentity
        from broker.services.proxy import _extract_app_key

        identity = BrokerAppIdentity(app_key="app:test", scopes=["proxy"])
        request = MagicMock()
        request.state.identity = identity

        result = _extract_app_key(request)
        assert result == "app:test"


# =============================================================================
# MODELS
# =============================================================================


class TestModels:
    def test_app_connection_round_trip(self, test_connection: AppConnection) -> None:
        """AppConnection serializes and deserializes correctly."""
        json_str = test_connection.model_dump_json()
        restored = AppConnection.model_validate_json(json_str)
        assert restored.access_token == test_connection.access_token
        assert restored.connector_name == test_connection.connector_name
        assert restored.expires_at == test_connection.expires_at

    def test_app_connection_defaults(self) -> None:
        """AppConnection has sensible defaults."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
        )
        assert conn.refresh_token is None
        assert conn.expires_at is None
        assert conn.scopes == []
        assert isinstance(conn.connected_at, datetime)

    def test_connector_meta_frozen(self, test_meta: ConnectorMeta) -> None:
        """ConnectorMeta is immutable."""
        with pytest.raises(ValidationError):
            test_meta.name = "changed"

    def test_credentials_extra_forbid(self) -> None:
        """AppConnectorCredentials rejects extra fields."""
        with pytest.raises(ValidationError):
            AppConnectorCredentials(
                client_id="id",
                client_secret="secret",
                extra_field="nope",  # type: ignore[call-arg]
            )


# =============================================================================
# CONFIG
# =============================================================================


class TestConfig:
    def test_get_app_credentials(self) -> None:
        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
            apps={
                "test_company": {
                    "chat": {
                        "notion": {
                            "client_id": "cid",
                            "client_secret": "csecret",
                        }
                    }
                }
            },
        )

        creds = settings.get_app_credentials("test_company:chat", "notion")
        assert creds["client_id"] == "cid"
        assert creds["client_secret"] == "csecret"

    def test_get_app_credentials_missing(self) -> None:
        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
        )

        with pytest.raises(KeyError):
            settings.get_app_credentials("test_company:chat", "notion")


# =============================================================================
# CONNECTOR META — DISCOVERY PROPERTY
# =============================================================================


class TestConnectorMetaDiscovery:
    def test_uses_discovery_true(self) -> None:
        """mcp_oauth_url set -> uses_discovery is True."""
        meta = make_discovery_meta()
        assert meta.uses_discovery is True

    def test_uses_discovery_false(self) -> None:
        """mcp_oauth_url None -> uses_discovery is False."""
        meta = ConnectorMeta(
            name="static_connector",
            display_name="Static",
            mcp_url="https://mcp.test.com/mcp",
            oauth_authorize_url="https://test.com/authorize",
            oauth_token_url="https://test.com/token",
        )
        assert meta.uses_discovery is False

    def test_mcp_oauth_url_optional(self) -> None:
        """ConnectorMeta works without mcp_oauth_url."""
        meta = ConnectorMeta(
            name="no_discovery",
            display_name="No Discovery",
            mcp_url="https://mcp.test.com/mcp",
            oauth_authorize_url="https://test.com/authorize",
            oauth_token_url="https://test.com/token",
        )
        assert meta.mcp_oauth_url is None
        assert meta.uses_discovery is False


# =============================================================================
# DYNAMIC REGISTRATION MODEL
# =============================================================================


class TestDynamicRegistrationModel:
    def test_round_trip(self) -> None:
        """Serialize/deserialize preserves all fields."""
        reg = make_registration()
        json_str = reg.model_dump_json()
        restored = DynamicRegistration.model_validate_json(json_str)
        assert restored.connector_name == reg.connector_name
        assert restored.client_id == reg.client_id
        assert restored.client_secret == reg.client_secret
        assert restored.redirect_uri == reg.redirect_uri

    def test_defaults(self) -> None:
        """Default values for optional fields."""
        reg = make_registration()
        assert reg.token_endpoint_auth_method == "client_secret_basic"
        assert reg.client_secret_expires_at is None

    def test_frozen(self) -> None:
        """DynamicRegistration is immutable."""
        reg = make_registration()
        with pytest.raises(ValidationError):
            reg.client_id = "changed"


# =============================================================================
# REGISTRATION STORE (SQLITE + ENCRYPTED)
# =============================================================================


class TestRegistrationStore:
    async def test_save_and_get_registration(self, sqlite_store: SQLiteTokenStore) -> None:
        """Save DynamicRegistration, retrieve by connector_name."""
        reg = make_registration()
        await sqlite_store.save_registration("discovery_connector", reg)
        result = await sqlite_store.get_registration("discovery_connector")
        assert result is not None
        assert result.client_id == "dyn_client_id"
        assert result.client_secret == "dyn_client_secret"
        assert result.redirect_uri == "http://localhost/oauth/discovery_connector/callback"

    async def test_get_registration_nonexistent(self, sqlite_store: SQLiteTokenStore) -> None:
        """Returns None for unknown connector."""
        result = await sqlite_store.get_registration("nonexistent")
        assert result is None

    async def test_upsert_registration(self, sqlite_store: SQLiteTokenStore) -> None:
        """Save twice overwrites."""
        reg1 = make_registration(client_id="first_id")
        reg2 = make_registration(client_id="second_id")
        await sqlite_store.save_registration("discovery_connector", reg1)
        await sqlite_store.save_registration("discovery_connector", reg2)
        result = await sqlite_store.get_registration("discovery_connector")
        assert result is not None
        assert result.client_id == "second_id"

    async def test_encrypted_registration_round_trip(
        self, encrypted_store: EncryptedTokenStore
    ) -> None:
        """EncryptedTokenStore encrypts client_secret, decrypts on read."""
        reg = make_registration()
        await encrypted_store.save_registration("discovery_connector", reg)
        result = await encrypted_store.get_registration("discovery_connector")
        assert result is not None
        assert result.client_secret == "dyn_client_secret"

    async def test_encrypted_registration_stored_encrypted(
        self,
        encrypted_store: EncryptedTokenStore,
        sqlite_store: SQLiteTokenStore,
    ) -> None:
        """Verify underlying store has encrypted client_secret (not plaintext)."""
        reg = make_registration()
        await encrypted_store.save_registration("discovery_connector", reg)
        raw = await sqlite_store.get_registration("discovery_connector")
        assert raw is not None
        assert raw.client_secret != "dyn_client_secret"


# =============================================================================
# LIST EXPIRING
# =============================================================================


class TestListExpiring:
    async def test_list_expiring_returns_soon_expiring(
        self, sqlite_store: SQLiteTokenStore
    ) -> None:
        """Connection expiring in 5 minutes included with 10-minute buffer."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=int(time.time()) + 300,  # 5 minutes
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=600)
        assert len(results) == 1
        assert results[0][0] == "app:test"
        assert results[0][1] == "test"

    async def test_list_expiring_skips_fresh(self, sqlite_store: SQLiteTokenStore) -> None:
        """Connection expiring in 2 hours excluded."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=int(time.time()) + 7200,  # 2 hours
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=600)
        assert len(results) == 0

    async def test_list_expiring_includes_already_expired(
        self, sqlite_store: SQLiteTokenStore
    ) -> None:
        """Already-expired connections included."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=int(time.time()) - 100,  # Already expired
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=600)
        assert len(results) == 1

    async def test_list_expiring_skips_no_expiry(self, sqlite_store: SQLiteTokenStore) -> None:
        """Connections with expires_at=None excluded."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=None,
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=600)
        assert len(results) == 0

    async def test_list_expiring_encrypted(self, encrypted_store: EncryptedTokenStore) -> None:
        """list_expiring works through EncryptedTokenStore wrapper."""
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=int(time.time()) + 300,  # 5 minutes
        )
        await encrypted_store.save("app:test", "test", conn)
        results = await encrypted_store.list_expiring(buffer_seconds=600)
        assert len(results) == 1
        # Verify decrypted
        assert results[0][2].access_token == "tok"


# =============================================================================
# OAUTH DISCOVERY (HTTP calls mocked with respx)
# =============================================================================


class TestOAuthDiscovery:
    @respx.mock
    async def test_discover_metadata(self) -> None:
        """Two-step .well-known fetch returns cached metadata."""
        respx.get("https://mcp.test.com/.well-known/oauth-protected-resource").mock(
            return_value=Response(200, json=make_wellknown_resource())
        )
        respx.get("https://auth.test.com/.well-known/oauth-authorization-server").mock(
            return_value=Response(200, json=make_wellknown_server())
        )

        discovery = OAuthDiscovery()
        metadata = await discovery.discover_metadata("test_conn", "https://mcp.test.com")

        assert metadata["authorization_endpoint"] == "https://auth.test.com/authorize"
        assert metadata["token_endpoint"] == "https://auth.test.com/token"
        assert metadata["registration_endpoint"] == "https://auth.test.com/register"
        # Should be cached
        assert discovery.get_cached_metadata("test_conn") is metadata

    @respx.mock
    async def test_discover_metadata_caches(self) -> None:
        """Second call returns cached result — no second HTTP call."""
        respx.get("https://mcp.test.com/.well-known/oauth-protected-resource").mock(
            return_value=Response(200, json=make_wellknown_resource())
        )
        respx.get("https://auth.test.com/.well-known/oauth-authorization-server").mock(
            return_value=Response(200, json=make_wellknown_server())
        )

        discovery = OAuthDiscovery()
        first = await discovery.discover_metadata("test_conn", "https://mcp.test.com")
        second = discovery.get_cached_metadata("test_conn")
        assert first is second
        # respx tracks call counts — each route called exactly once
        assert respx.calls.call_count == 2

    def test_get_cached_metadata_missing(self) -> None:
        """Returns None for unknown connector (no HTTP)."""
        discovery = OAuthDiscovery()
        assert discovery.get_cached_metadata("unknown") is None

    @respx.mock
    async def test_register_client(self) -> None:
        """POST /register returns DynamicRegistration with correct fields."""
        respx.post("https://auth.test.com/register").mock(
            return_value=Response(201, json=make_registration_response())
        )

        discovery = OAuthDiscovery()
        reg = await discovery.register_client(
            "https://auth.test.com/register",
            "test_conn",
            "http://localhost/oauth/test_conn/callback",
        )

        assert isinstance(reg, DynamicRegistration)
        assert reg.client_id == "dyn_client_id"
        assert reg.client_secret == "dyn_client_secret"
        assert reg.connector_name == "test_conn"
        assert reg.redirect_uri == "http://localhost/oauth/test_conn/callback"
        assert reg.token_endpoint_auth_method == "client_secret_basic"


# =============================================================================
# RESOLVE OAUTH (composition function)
# =============================================================================


class TestResolveOAuth:
    async def test_static_path(self) -> None:
        """Non-discovery connector uses settings credentials + static URLs."""
        static_meta = ConnectorMeta(
            name="static_conn",
            display_name="Static",
            mcp_url="https://mcp.test.com/mcp",
            oauth_authorize_url="https://test.com/authorize",
            oauth_token_url="https://test.com/token",
        )

        class StaticConn(BaseConnector):
            meta = static_meta

        connector = ConnectorRegistry.get("static_conn")
        assert connector is not None

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
            apps={
                "app": {
                    "test": {
                        "static_conn": {
                            "client_id": "static_cid",
                            "client_secret": "static_csecret",
                        }
                    }
                }
            },
        )

        store = AsyncMock()
        result = await resolve_oauth(
            connector, "app:test", "http://localhost/callback", settings, store, None
        )

        assert result.authorize_url == "https://test.com/authorize"
        assert result.token_url == "https://test.com/token"
        assert result.credentials.client_id == "static_cid"
        assert result.credentials.client_secret == "static_csecret"

    async def test_discovery_path_existing_registration(self) -> None:
        """Discovery connector with stored registration uses cached metadata + stored credentials."""
        disc_meta = make_discovery_meta()

        class DiscConn(BaseConnector):
            meta = disc_meta

        connector = ConnectorRegistry.get("discovery_connector")
        assert connector is not None

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
        )

        store = AsyncMock()
        store.get_registration.return_value = make_registration()

        discovery = OAuthDiscovery()
        discovery._metadata_cache["discovery_connector"] = {
            "authorization_endpoint": "https://auth.test.com/authorize",
            "token_endpoint": "https://auth.test.com/token",
            "registration_endpoint": "https://auth.test.com/register",
        }

        result = await resolve_oauth(
            connector, "app:test", "http://localhost/callback", settings, store, discovery
        )

        assert result.authorize_url == "https://auth.test.com/authorize"
        assert result.token_url == "https://auth.test.com/token"
        assert result.credentials.client_id == "dyn_client_id"
        assert result.credentials.client_secret == "dyn_client_secret"

    async def test_discovery_path_new_registration(self) -> None:
        """Discovery connector without stored registration calls register_client."""
        disc_meta = make_discovery_meta()

        class DiscConn(BaseConnector):
            meta = disc_meta

        connector = ConnectorRegistry.get("discovery_connector")
        assert connector is not None

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
        )

        store = AsyncMock()
        store.get_registration.return_value = None

        discovery = AsyncMock(spec=OAuthDiscovery)
        discovery.get_cached_metadata.return_value = {
            "authorization_endpoint": "https://auth.test.com/authorize",
            "token_endpoint": "https://auth.test.com/token",
            "registration_endpoint": "https://auth.test.com/register",
        }
        discovery.register_client.return_value = make_registration()

        result = await resolve_oauth(
            connector, "app:test", "http://localhost/callback", settings, store, discovery
        )

        discovery.register_client.assert_awaited_once_with(
            "https://auth.test.com/register",
            "discovery_connector",
            "http://localhost/callback",
        )
        store.save_registration.assert_awaited_once()
        assert result.credentials.client_id == "dyn_client_id"

    async def test_discovery_path_expired_registration(self) -> None:
        """Stored registration with expired client_secret triggers re-registration."""
        disc_meta = make_discovery_meta()

        class DiscConn(BaseConnector):
            meta = disc_meta

        connector = ConnectorRegistry.get("discovery_connector")
        assert connector is not None

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
        )

        expired_reg = make_registration(
            client_id="expired_id",
            client_secret_expires_at=int(time.time()) - 100,
        )
        new_reg = make_registration(client_id="new_id")

        store = AsyncMock()
        store.get_registration.return_value = expired_reg

        discovery = AsyncMock(spec=OAuthDiscovery)
        discovery.get_cached_metadata.return_value = {
            "authorization_endpoint": "https://auth.test.com/authorize",
            "token_endpoint": "https://auth.test.com/token",
            "registration_endpoint": "https://auth.test.com/register",
        }
        discovery.register_client.return_value = new_reg

        result = await resolve_oauth(
            connector, "app:test", "http://localhost/callback", settings, store, discovery
        )

        discovery.register_client.assert_awaited_once()
        assert result.credentials.client_id == "new_id"

    async def test_discovery_path_concurrent_registration(self) -> None:
        """Two concurrent calls with no registration — only one register_client call."""
        import asyncio

        disc_meta = make_discovery_meta()

        class DiscConn(BaseConnector):
            meta = disc_meta

        connector = ConnectorRegistry.get("discovery_connector")
        assert connector is not None

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-secure!",
                encryption_keys=["k"],
                state_secret="test-state-secret-key",
            ),
        )

        call_count = 0

        async def mock_register(endpoint: str, name: str, redirect_uri: str) -> DynamicRegistration:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)  # Simulate network delay
            return make_registration()

        # First call to get_registration returns None, second (after lock re-check) returns the reg
        store = AsyncMock()
        store.get_registration.side_effect = [None, None, make_registration()]

        discovery = AsyncMock(spec=OAuthDiscovery)
        discovery.get_cached_metadata.return_value = {
            "authorization_endpoint": "https://auth.test.com/authorize",
            "token_endpoint": "https://auth.test.com/token",
            "registration_endpoint": "https://auth.test.com/register",
        }
        discovery.register_client.side_effect = mock_register

        # Launch two concurrent resolve_oauth calls
        results = await asyncio.gather(
            resolve_oauth(
                connector, "app:test", "http://localhost/callback", settings, store, discovery
            ),
            resolve_oauth(
                connector, "app:test", "http://localhost/callback", settings, store, discovery
            ),
        )

        # Lock prevents duplicate — only one register_client call
        assert call_count == 1
        assert all(r.credentials.client_id == "dyn_client_id" for r in results)


# =============================================================================
# ADMIN REFRESH AUTH
# =============================================================================


class TestAdminRefresh:
    async def test_admin_refresh_valid_key(self) -> None:
        """Correct X-Admin-Key returns 200."""
        from broker.api.admin import AdminEndpoints

        async def mock_refresh() -> dict[str, int]:
            return {"refreshed": 0, "failed": 0, "skipped": 0}

        endpoints = AdminEndpoints(
            key_store=MagicMock(),
            admin_key="test-admin-key-long",
            client_registry=MagicMock(),
            connect_token_store=MagicMock(),
            refresh_callback=mock_refresh,
        )

        request = MagicMock()
        request.headers = {"x-admin-key": "test-admin-key-long"}
        response = await endpoints.refresh_tokens(request)
        assert response.status_code == 200

    async def test_admin_refresh_invalid_key(self) -> None:
        """Wrong X-Admin-Key returns 401."""
        from broker.api.admin import AdminEndpoints

        endpoints = AdminEndpoints(
            key_store=MagicMock(),
            admin_key="test-admin-key-long",
            client_registry=MagicMock(),
            connect_token_store=MagicMock(),
        )

        request = MagicMock()
        request.headers = {"x-admin-key": "wrong-key"}
        response = await endpoints.refresh_tokens(request)
        assert response.status_code == 401

    async def test_admin_refresh_missing_key(self) -> None:
        """No X-Admin-Key header returns 401."""
        from broker.api.admin import AdminEndpoints

        endpoints = AdminEndpoints(
            key_store=MagicMock(),
            admin_key="test-admin-key-long",
            client_registry=MagicMock(),
            connect_token_store=MagicMock(),
        )

        request = MagicMock()
        request.headers = {}
        response = await endpoints.refresh_tokens(request)
        assert response.status_code == 401


# =============================================================================
# NONCE SINGLE-USE (replay protection)
# =============================================================================


class TestNonceSingleUse:
    async def test_replay_state_raises(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_resolved: ResolvedOAuth,
    ) -> None:
        """Using the same state token twice raises ValueError (replay)."""

        class TestConn(BaseConnector):
            meta = test_meta

        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None

        # Build authorize URL — generates nonce + state
        url = oauth_handler.build_authorize_url(
            connector, "app:test", test_resolved, "http://localhost/callback"
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        state = params["state"][0]

        # Mock the HTTP call for first exchange
        with patch.object(
            oauth_handler, "_post_token_request", new_callable=AsyncMock
        ) as mock_post:
            mock_post.return_value = {
                "access_token": "tok",
                "token_type": "bearer",
            }
            await oauth_handler.exchange_code(
                connector, "code123", state, test_resolved, "http://localhost/callback"
            )

        # Second exchange with same state should fail
        with pytest.raises(ValueError, match="already used"):
            await oauth_handler.exchange_code(
                connector, "code456", state, test_resolved, "http://localhost/callback"
            )


# =============================================================================
# CROSS-APP KEY ISOLATION
# =============================================================================


class TestCrossAppKeyIsolation:
    async def test_wrong_app_broker_key_rejected(self, tmp_path: Path) -> None:
        """Using app A's key with app B's identity claim returns 401 at middleware."""
        from broker.config import BrokerAppConfig
        from broker.middleware.auth import BrokerAuthMiddleware
        from broker.services.client_registry import BrokerClientRegistry
        from broker.services.sqlite_api_key_store import SQLiteBrokerKeyStore

        # Set up key store with keys for both apps
        key_store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await key_store.setup()
        key_a = await key_store.create_key("app_a:test")
        await key_store.create_key("app_b:test")

        # Set up registry
        registry = BrokerClientRegistry(
            {"app_a": {"test": BrokerAppConfig()}, "app_b": {"test": BrokerAppConfig()}}
        )

        # Simulate middleware verification
        request = MagicMock()
        # App A's key sent with App B's identity claim
        request.headers = {"x-broker-key": key_a, "x-app-id": "app_b:test"}
        request.url.path = "/proxy/notion/mcp"
        request.query_params = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        middleware = BrokerAuthMiddleware(
            app=MagicMock(),
            get_key_store=lambda: key_store,
            get_client_registry=lambda: registry,
            get_connect_token_store=lambda: None,
        )

        from starlette.responses import Response

        result = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert isinstance(result, Response)
        assert result.status_code == 401


# =============================================================================
# REFRESH HAPPY PATH
# =============================================================================


class TestRefreshHappyPath:
    @respx.mock
    async def test_expired_token_refreshed(
        self,
        oauth_handler: OAuthHandler,
        test_meta: ConnectorMeta,
        test_resolved: ResolvedOAuth,
    ) -> None:
        """Expired token with refresh_token triggers refresh and returns new token."""

        class TestConn(BaseConnector):
            meta = test_meta

        connector = ConnectorRegistry.get("test_connector")
        assert connector is not None

        expired_connection = AppConnection(
            connector_name="test_connector",
            access_token="old_token",
            refresh_token="valid_refresh_token",
            expires_at=int(time.time()) - 100,  # Already expired
            scopes=["read"],
        )

        # Mock the token endpoint
        respx.post(test_resolved.token_url).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "new_token",
                    "refresh_token": "new_refresh",
                    "expires_in": 3600,
                    "token_type": "bearer",
                },
            )
        )

        refreshed = await oauth_handler.refresh_if_expired(
            connector, expired_connection, test_resolved
        )

        assert refreshed.access_token == "new_token"
        assert refreshed.refresh_token == "new_refresh"
        assert refreshed is not expired_connection


# =============================================================================
# ENCRYPTION KEY ROTATION
# =============================================================================


class TestEncryptionKeyRotation:
    async def test_read_with_rotated_key(self, sqlite_store: SQLiteTokenStore) -> None:
        """Write with key A, add key B as primary, read back succeeds."""
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()

        # Write with key A as primary
        store_a = EncryptedTokenStore(keys=[key_a], delegate=sqlite_store)
        connection = AppConnection(
            connector_name="test",
            access_token="secret_token",
            refresh_token="secret_refresh",
        )
        await store_a.save("app:test", "test", connection)

        # Read with key B as primary, key A as fallback
        store_rotated = EncryptedTokenStore(keys=[key_b, key_a], delegate=sqlite_store)
        restored = await store_rotated.get("app:test", "test")
        assert restored is not None
        assert restored.access_token == "secret_token"
        assert restored.refresh_token == "secret_refresh"


# =============================================================================
# LIST EXPIRING BOUNDARY
# =============================================================================


class TestListExpiringBoundary:
    async def test_exact_boundary_included(self, sqlite_store: SQLiteTokenStore) -> None:
        """Token expiring at exactly now + buffer_seconds is included."""
        now = int(time.time())
        buffer = 600
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=now + buffer,  # Exactly at threshold
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=buffer)
        assert len(results) == 1

    async def test_one_second_past_boundary_excluded(self, sqlite_store: SQLiteTokenStore) -> None:
        """Token expiring 1 second after boundary is excluded."""
        now = int(time.time())
        buffer = 600
        conn = AppConnection(
            connector_name="test",
            access_token="tok",
            expires_at=now + buffer + 1,  # 1 second past threshold
        )
        await sqlite_store.save("app:test", "test", conn)
        results = await sqlite_store.list_expiring(buffer_seconds=buffer)
        assert len(results) == 0


# =============================================================================
# MCP METHOD VALIDATION (P0-05)
# =============================================================================


class TestMcpMethodValidation:
    """Tests for _validate_mcp_payload — JSON-RPC method allowlist enforcement."""

    def test_allowed_method_passes(self, test_meta: ConnectorMeta) -> None:
        """Standard MCP methods in the default allowlist pass validation."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
        assert _validate_mcp_payload(payload, connector) is None

    def test_blocked_method_returns_403(self, test_meta: ConnectorMeta) -> None:
        """Methods outside the allowlist are rejected with 403."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'{"jsonrpc":"2.0","method":"resources/list","id":1}'
        error_response = _validate_mcp_payload(payload, connector)
        assert error_response is not None
        assert error_response.status_code == 403

    def test_batch_with_blocked_method_returns_403(self, test_meta: ConnectorMeta) -> None:
        """A batch containing one blocked method rejects the whole batch."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'[{"jsonrpc":"2.0","method":"tools/list","id":1},{"jsonrpc":"2.0","method":"resources/read","id":2}]'
        error_response = _validate_mcp_payload(payload, connector)
        assert error_response is not None
        assert error_response.status_code == 403

    def test_batch_all_allowed_passes(self, test_meta: ConnectorMeta) -> None:
        """A batch where all methods are allowed passes validation."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'[{"jsonrpc":"2.0","method":"tools/list","id":1},{"jsonrpc":"2.0","method":"tools/call","id":2}]'
        assert _validate_mcp_payload(payload, connector) is None

    def test_invalid_json_returns_400(self, test_meta: ConnectorMeta) -> None:
        """Malformed JSON body returns 400."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        error_response = _validate_mcp_payload(b"not json", connector)
        assert error_response is not None
        assert error_response.status_code == 400

    def test_non_dict_payload_returns_400(self, test_meta: ConnectorMeta) -> None:
        """A JSON-RPC batch entry that is not a dict returns 400."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'["not a dict"]'
        error_response = _validate_mcp_payload(payload, connector)
        assert error_response is not None
        assert error_response.status_code == 400

    def test_missing_method_key_blocked(self, test_meta: ConnectorMeta) -> None:
        """Payload with no 'method' key defaults to empty string — blocked."""
        from broker.services.proxy import _validate_mcp_payload

        connector = MagicMock()
        connector.meta = test_meta

        payload = b'{"jsonrpc":"2.0","id":1}'
        error_response = _validate_mcp_payload(payload, connector)
        assert error_response is not None
        assert error_response.status_code == 403


class TestHttpMethodValidation:
    """Tests for HTTP method enforcement in _build_and_stream."""

    async def test_put_method_returns_405(self) -> None:
        """PUT requests are rejected with 405."""
        from broker.services.proxy import _build_and_stream

        request = MagicMock()
        request.method = "PUT"

        connector = MagicMock()
        connection = MagicMock()

        error_response = await _build_and_stream(request, connector, "test", connection=connection)
        assert error_response.status_code == 405

    async def test_patch_method_returns_405(self) -> None:
        """PATCH requests are rejected with 405."""
        from broker.services.proxy import _build_and_stream

        request = MagicMock()
        request.method = "PATCH"

        connector = MagicMock()
        connection = MagicMock()

        error_response = await _build_and_stream(request, connector, "test", connection=connection)
        assert error_response.status_code == 405


class TestBodySizeLimit:
    """Tests for _MAX_BODY_BYTES enforcement."""

    async def test_oversized_body_returns_413(self) -> None:
        """Request body exceeding 1MB is rejected with 413."""
        from broker.services.proxy import _MAX_BODY_BYTES, _build_and_stream

        request = MagicMock()
        request.method = "POST"
        request.headers = {"content-type": "application/json", "x-app-id": "test"}
        request.body = AsyncMock(return_value=b"x" * (_MAX_BODY_BYTES + 1))

        connector = MagicMock()
        connector.meta.mcp_url = "https://mcp.test.com/mcp"
        connector.meta.display_name = "Test"
        connector.build_auth_header.return_value = {"authorization": "Bearer tok"}
        connection = MagicMock()
        connection.access_token = "tok"

        # Inject a mock client
        from broker.services import proxy

        proxy.clients["test"] = MagicMock()

        error_response = await _build_and_stream(request, connector, "test", connection=connection)
        assert error_response.status_code == 413

        del proxy.clients["test"]


# =============================================================================
# SIDECAR AUTH MODE
# =============================================================================


class TestSidecarAuthMode:
    """Tests for auth_mode='sidecar' — sidecar manages its own credentials."""

    def test_sidecar_meta_no_oauth_urls(self) -> None:
        """Sidecar connectors don't require OAuth URLs."""
        meta = ConnectorMeta(
            name="sidecar_test",
            display_name="Sidecar Test",
            mcp_url="http://sidecar-host:8000",
            auth_mode="sidecar",
        )
        assert meta.is_sidecar_managed is True
        assert meta.oauth_authorize_url is None
        assert meta.oauth_token_url is None

    def test_broker_meta_requires_oauth_urls(self) -> None:
        """Broker connectors still require OAuth URLs."""
        with pytest.raises(ValidationError, match="oauth_authorize_url is required"):
            ConnectorMeta(
                name="broker_test",
                display_name="Broker Test",
                mcp_url="https://mcp.test.com/mcp",
                auth_mode="broker",
            )

    def test_broker_meta_is_not_sidecar_managed(self, test_meta: ConnectorMeta) -> None:
        """Default auth_mode='broker' connectors are not sidecar-managed."""
        assert test_meta.is_sidecar_managed is False

    async def test_proxy_skips_token_for_sidecar(self) -> None:
        """Sidecar-managed connectors skip token lookup in proxy."""
        from broker.services.proxy import proxy_mcp_request

        settings = BrokerSettings(
            broker=BrokerConfig(
                connectors=["test"],
                admin_key="admin-key-value-x",
                encryption_keys=["dummy"],
                state_secret="dummy-state-secret",
            ),
        )

        request = MagicMock()
        request.headers = {"x-broker-key": "correct-key", "x-app-id": "app:test"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.method = "POST"
        request.body = AsyncMock(return_value=b'{"jsonrpc":"2.0","method":"tools/list","id":1}')

        # Register a sidecar-managed connector
        class SidecarTestConnector(BaseConnector):
            meta = ConnectorMeta(
                name="sidecar_proxy_test",
                display_name="Sidecar Proxy Test",
                mcp_url="http://sidecar-host:8000",
                auth_mode="sidecar",
            )

        # Inject a mock httpx client
        from broker.services import proxy

        mock_client = MagicMock()
        mock_request = MagicMock()
        mock_client.build_request.return_value = mock_request
        proxy.clients["sidecar_proxy_test"] = mock_client

        # Mock _send_and_stream to avoid actual HTTP
        with patch("broker.services.proxy._send_and_stream") as mock_stream:
            mock_stream.return_value = MagicMock(status_code=200)
            store = AsyncMock()
            oauth = MagicMock()

            result = await proxy_mcp_request("sidecar_proxy_test", request, store, oauth, settings)

            # Token store should NOT have been called
            store.get.assert_not_called()
            assert result.status_code == 200

        del proxy.clients["sidecar_proxy_test"]

    async def test_passthrough_headers_no_authorization(self) -> None:
        """Sidecar passthrough headers must not include Authorization."""
        from broker.services.proxy import _build_passthrough_headers

        request = MagicMock()
        request.headers = MagicMock()
        request.headers.items.return_value = [
            ("content-type", "application/json"),
            ("authorization", "Bearer leaked-token"),
            ("x-broker-key", "secret"),
            ("x-custom", "keep-this"),
        ]

        headers = _build_passthrough_headers(request, "http://sidecar:8000/mcp")
        assert "authorization" not in {k.lower() for k in headers}
        assert "x-broker-key" not in {k.lower() for k in headers}
        assert headers["x-custom"] == "keep-this"
        assert headers["host"] == "sidecar:8000"


class TestSidecarOAuthGuard:
    """OAuth routes reject sidecar-managed connectors."""

    def _setup_mocked_auth(self):
        """Set module-level auth mocks so middleware passes. Returns restore tuple."""
        import broker.main as broker_main

        mock_key_store = MagicMock()
        mock_key_store.verify = AsyncMock(return_value="test:app")
        mock_registry = MagicMock()
        mock_registry.get.return_value = MagicMock(scopes=["proxy"], allowed_connectors=[])

        old = (
            broker_main._key_store,
            broker_main._client_registry,
            broker_main._connect_token_store,
        )
        broker_main._key_store = mock_key_store
        broker_main._client_registry = mock_registry
        broker_main._connect_token_store = MagicMock()
        return old

    def _restore_auth(self, old):
        import broker.main as broker_main

        broker_main._key_store, broker_main._client_registry, broker_main._connect_token_store = old

    def test_oauth_connect_rejects_sidecar(self) -> None:
        """GET /oauth/{connector}/connect returns 404 for sidecar connectors."""
        from fastapi.testclient import TestClient

        from broker.main import app

        mock_connector = MagicMock()
        mock_connector.meta.is_sidecar_managed = True
        mock_connector.meta.display_name = "Test Sidecar"

        old = self._setup_mocked_auth()
        try:
            with patch("broker.main._get_connector_or_404", return_value=mock_connector):
                client = TestClient(app)
                response = client.get(
                    "/oauth/sidecar_test/connect",
                    headers={"x-app-id": "test:app", "x-broker-key": "fake"},
                )
                assert response.status_code == 404
                assert "manages its own authentication" in response.json()["detail"]
        finally:
            self._restore_auth(old)

    def test_oauth_disconnect_rejects_sidecar(self) -> None:
        """POST /oauth/{connector}/disconnect returns 404 for sidecar connectors."""
        from fastapi.testclient import TestClient

        from broker.main import app

        mock_connector = MagicMock()
        mock_connector.meta.is_sidecar_managed = True
        mock_connector.meta.display_name = "Test Sidecar"

        old = self._setup_mocked_auth()
        try:
            with patch("broker.main._get_connector_or_404", return_value=mock_connector):
                client = TestClient(app)
                response = client.post(
                    "/oauth/sidecar_test/disconnect",
                    headers={"x-app-id": "test:app", "x-broker-key": "fake"},
                )
                assert response.status_code == 404
                assert "manages its own authentication" in response.json()["detail"]
        finally:
            self._restore_auth(old)


class TestHealthAuthMode:
    """Health endpoint includes auth_mode."""

    def test_health_shows_auth_mode(self) -> None:
        """GET /health includes auth_mode for each connector."""

        # Register a sidecar connector
        class HealthTestConnector(BaseConnector):
            meta = ConnectorMeta(
                name="health_sidecar_test",
                display_name="Health Sidecar",
                mcp_url="http://sidecar:8000",
                auth_mode="sidecar",
            )

        from fastapi.testclient import TestClient

        from broker.main import app

        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200

        connectors = response.json()["connectors"]
        sidecar_entry = next((c for c in connectors if c["name"] == "health_sidecar_test"), None)
        assert sidecar_entry is not None
        assert sidecar_entry["auth_mode"] == "sidecar"


class TestWorkspaceMcpConnector:
    """Tests for the workspace_mcp connector configuration."""

    def test_workspace_mcp_is_broker_managed(self) -> None:
        """workspace_mcp should use broker-managed auth, not sidecar."""
        from connectors.workspace_mcp.adapter import WorkspaceMcpConnector

        meta = WorkspaceMcpConnector.meta
        assert meta.auth_mode == "broker"
        assert meta.is_sidecar_managed is False

    def test_workspace_mcp_has_google_oauth_urls(self) -> None:
        """workspace_mcp must have Google OAuth authorize and token URLs."""
        from connectors.workspace_mcp.adapter import WorkspaceMcpConnector

        meta = WorkspaceMcpConnector.meta
        assert meta.oauth_authorize_url == "https://accounts.google.com/o/oauth2/v2/auth"
        assert meta.oauth_token_url == "https://oauth2.googleapis.com/token"

    def test_workspace_mcp_has_google_scopes(self) -> None:
        """workspace_mcp must request Google Workspace scopes."""
        from connectors.workspace_mcp.adapter import WorkspaceMcpConnector

        meta = WorkspaceMcpConnector.meta
        assert "openid" in meta.scopes
        assert "email" in meta.scopes
        assert any("gmail" in s for s in meta.scopes)
        assert any("drive" in s for s in meta.scopes)
        assert any("calendar" in s for s in meta.scopes)

    def test_workspace_mcp_adds_offline_access(self) -> None:
        """customize_authorize_params must add access_type=offline for refresh tokens."""
        from connectors.workspace_mcp.adapter import WorkspaceMcpConnector

        connector = WorkspaceMcpConnector()
        params = connector.customize_authorize_params({"client_id": "test"})
        assert params["access_type"] == "offline"
        assert params["prompt"] == "consent"
        assert params["client_id"] == "test"
