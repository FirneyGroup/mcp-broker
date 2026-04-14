"""
Tests for per-app auth: key store, client registry, middleware, admin API.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from broker.config import BrokerAppConfig
from broker.services.api_key_store import (
    CONNECT_TOKEN_PREFIX,
    KEY_PREFIX,
    BrokerAppIdentity,
    ConnectTokenStore,
    generate_api_key,
    hash_api_key,
)
from broker.services.client_registry import BrokerClientRegistry
from broker.services.sqlite_api_key_store import SQLiteBrokerKeyStore

# =============================================================================
# KEY GENERATION + HASHING
# =============================================================================


class TestKeyGeneration:
    def test_generate_has_prefix(self) -> None:
        key = generate_api_key()
        assert key.startswith(KEY_PREFIX)

    def test_generate_unique(self) -> None:
        keys = {generate_api_key() for _ in range(50)}
        assert len(keys) == 50

    def test_hash_deterministic(self) -> None:
        key = generate_api_key()
        assert hash_api_key(key) == hash_api_key(key)

    def test_hash_different_keys_differ(self) -> None:
        assert hash_api_key("key_a") != hash_api_key("key_b")


# =============================================================================
# IDENTITY MODEL
# =============================================================================


class TestBrokerAppIdentity:
    def test_has_scope(self) -> None:
        identity = BrokerAppIdentity(app_key="a:b", scopes=["proxy", "status"])
        assert identity.has_scope("proxy")
        assert not identity.has_scope("admin")

    def test_can_access_connector_empty_allows_all(self) -> None:
        identity = BrokerAppIdentity(app_key="a:b", allowed_connectors=[])
        assert identity.can_access_connector("notion")
        assert identity.can_access_connector("anything")

    def test_can_access_connector_restricted(self) -> None:
        identity = BrokerAppIdentity(app_key="a:b", allowed_connectors=["notion", "hubspot"])
        assert identity.can_access_connector("notion")
        assert identity.can_access_connector("hubspot")
        assert not identity.can_access_connector("twitter")

    def test_frozen(self) -> None:
        identity = BrokerAppIdentity(app_key="a:b")
        with pytest.raises(Exception):  # noqa: B017, PT011 — pydantic frozen
            identity.app_key = "changed"


# =============================================================================
# SQLITE KEY STORE
# =============================================================================


@pytest.fixture
async def key_store(tmp_path: Path) -> SQLiteBrokerKeyStore:
    store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
    await store.setup()
    return store


class TestSQLiteBrokerKeyStore:
    async def test_create_and_verify(self, key_store: SQLiteBrokerKeyStore) -> None:
        raw_key = await key_store.create_key("client:app")
        assert raw_key.startswith(KEY_PREFIX)
        verified = await key_store.verify(raw_key)
        assert verified == "client:app"

    async def test_verify_wrong_key(self, key_store: SQLiteBrokerKeyStore) -> None:
        await key_store.create_key("client:app")
        assert await key_store.verify("br_wrong-key") is None

    async def test_verify_empty_key(self, key_store: SQLiteBrokerKeyStore) -> None:
        assert await key_store.verify("") is None

    async def test_create_duplicate_raises(self, key_store: SQLiteBrokerKeyStore) -> None:
        await key_store.create_key("client:app")
        with pytest.raises(ValueError, match="already has a key"):
            await key_store.create_key("client:app")

    async def test_rotate(self, key_store: SQLiteBrokerKeyStore) -> None:
        old_key = await key_store.create_key("client:app")
        new_key = await key_store.rotate("client:app")
        assert new_key is not None
        assert new_key != old_key
        assert await key_store.verify(old_key) is None
        assert await key_store.verify(new_key) == "client:app"

    async def test_rotate_nonexistent(self, key_store: SQLiteBrokerKeyStore) -> None:
        assert await key_store.rotate("nonexistent:app") is None

    async def test_list_keys(self, key_store: SQLiteBrokerKeyStore) -> None:
        await key_store.create_key("a:1")
        await key_store.create_key("b:2")
        keys = await key_store.list_keys()
        assert len(keys) == 2
        app_keys = [k["app_key"] for k in keys]
        assert "a:1" in app_keys
        assert "b:2" in app_keys
        assert all("key_hash" not in k for k in keys)

    async def test_delete(self, key_store: SQLiteBrokerKeyStore) -> None:
        raw_key = await key_store.create_key("client:app")
        assert await key_store.delete_key("client:app")
        assert await key_store.verify(raw_key) is None
        new_key = await key_store.create_key("client:app")
        assert await key_store.verify(new_key) == "client:app"

    async def test_delete_nonexistent(self, key_store: SQLiteBrokerKeyStore) -> None:
        assert not await key_store.delete_key("nonexistent:app")

    async def test_teardown(self, key_store: SQLiteBrokerKeyStore) -> None:
        """Teardown is a no-op but shouldn't raise."""
        await key_store.teardown()


# =============================================================================
# CLIENT REGISTRY
# =============================================================================


class TestBrokerClientRegistry:
    def test_get_existing(self) -> None:
        config = BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"])
        registry = BrokerClientRegistry({"my_company": {"app1": config}})
        assert registry.get("my_company:app1") is config

    def test_get_nonexistent(self) -> None:
        registry = BrokerClientRegistry({"my_company": {"app1": BrokerAppConfig()}})
        assert registry.get("unknown:app") is None

    def test_list_apps(self) -> None:
        registry = BrokerClientRegistry(
            {
                "my_company": {
                    "app1": BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"]),
                },
                "other": {
                    "demo": BrokerAppConfig(scopes=["status"]),
                },
            }
        )
        apps = registry.list_apps()
        assert len(apps) == 2
        app_keys = [a["app_key"] for a in apps]
        assert "my_company:app1" in app_keys
        assert "other:demo" in app_keys

    def test_rejects_colon_in_client_name(self) -> None:
        with pytest.raises(ValueError, match="must not contain ':'"):
            BrokerClientRegistry({"bad:name": {"app": BrokerAppConfig()}})

    def test_rejects_colon_in_app_name(self) -> None:
        with pytest.raises(ValueError, match="must not contain ':'"):
            BrokerClientRegistry({"client": {"bad:app": BrokerAppConfig()}})


# =============================================================================
# AUTH MIDDLEWARE
# =============================================================================


class TestBrokerAuthMiddleware:
    def _make_middleware(self, key_store=None, client_registry=None, connect_token_store=None):
        from broker.middleware.auth import BrokerAuthMiddleware

        return BrokerAuthMiddleware(
            app=MagicMock(),
            get_key_store=lambda: key_store,
            get_client_registry=lambda: client_registry,
            get_connect_token_store=lambda: connect_token_store,
        )

    def test_exempt_health(self) -> None:
        middleware = self._make_middleware()
        assert middleware._is_exempt("/health")

    def test_exempt_admin(self) -> None:
        middleware = self._make_middleware()
        assert middleware._is_exempt("/admin/keys")

    def test_exempt_oauth_callback(self) -> None:
        middleware = self._make_middleware()
        assert middleware._is_exempt("/oauth/notion/callback")

    def test_not_exempt_proxy(self) -> None:
        middleware = self._make_middleware()
        assert not middleware._is_exempt("/proxy/notion/mcp")

    def test_not_exempt_oauth_connect(self) -> None:
        middleware = self._make_middleware()
        assert not middleware._is_exempt("/oauth/notion/connect")

    async def test_extract_with_valid_headers(self, tmp_path: Path) -> None:
        """Valid headers produce BrokerAppIdentity."""
        store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await store.setup()
        raw_key = await store.create_key("client:app")

        config = BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"])
        registry = BrokerClientRegistry({"client": {"app": config}})
        middleware = self._make_middleware(store, registry)

        request = MagicMock()
        request.headers = {"x-app-id": "client:app", "x-broker-key": raw_key}
        request.url.path = "/proxy/notion/mcp"
        request.query_params = {}
        request.client.host = "127.0.0.1"

        result = await middleware._extract_and_verify(request, "/proxy/notion/mcp", store, registry)
        assert isinstance(result, BrokerAppIdentity)
        assert result.app_key == "client:app"
        assert result.scopes == ["proxy"]
        assert result.allowed_connectors == ["notion"]

    async def test_extract_browser_oauth_connect(self, tmp_path: Path) -> None:
        """OAuth connect uses connect_token when no headers present."""
        store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await store.setup()

        config = BrokerAppConfig()
        registry = BrokerClientRegistry({"client": {"app": config}})
        ct_store = ConnectTokenStore()
        token = ct_store.create("client:app")
        middleware = self._make_middleware(store, registry, ct_store)

        request = MagicMock()
        request.headers = {}
        request.query_params = {"connect_token": token}
        request.url.path = "/oauth/notion/connect"
        request.client.host = "127.0.0.1"

        result = await middleware._extract_and_verify(
            request, "/oauth/notion/connect", store, registry
        )
        assert isinstance(result, BrokerAppIdentity)
        assert result.app_key == "client:app"

    async def test_extract_missing_headers_returns_401(self) -> None:
        """Missing headers return 401."""
        from starlette.responses import Response

        store = MagicMock()
        registry = MagicMock()
        middleware = self._make_middleware(store, registry)

        request = MagicMock()
        request.headers = {}
        request.query_params = {}
        request.url.path = "/proxy/notion/mcp"

        result = await middleware._extract_and_verify(request, "/proxy/notion/mcp", store, registry)
        assert isinstance(result, Response)
        assert result.status_code == 401

    async def test_extract_key_identity_mismatch_returns_401(self, tmp_path: Path) -> None:
        """Key that doesn't match claimed identity returns 401."""
        from starlette.responses import Response

        store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await store.setup()
        raw_key_a = await store.create_key("app_a:test")
        await store.create_key("app_b:test")

        registry = BrokerClientRegistry(
            {
                "app_a": {"test": BrokerAppConfig()},
                "app_b": {"test": BrokerAppConfig()},
            }
        )
        middleware = self._make_middleware(store, registry)

        request = MagicMock()
        request.headers = {"x-app-id": "app_b:test", "x-broker-key": raw_key_a}
        request.url.path = "/proxy/notion/mcp"
        request.query_params = {}
        request.client.host = "127.0.0.1"

        result = await middleware._extract_and_verify(request, "/proxy/notion/mcp", store, registry)
        assert isinstance(result, Response)
        assert result.status_code == 401

    def test_service_unavailable_before_init(self) -> None:
        """Returns 503 when store not initialized."""
        from broker.middleware.auth import _service_unavailable

        response = _service_unavailable()
        assert response.status_code == 503
        body = json.loads(response.body)
        assert "starting up" in body["error"]


# =============================================================================
# ADMIN API
# =============================================================================


class TestAdminAPI:
    @pytest.fixture
    async def admin_setup(self, tmp_path: Path):
        """Set up admin API dependencies."""
        store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await store.setup()

        registry = BrokerClientRegistry(
            {
                "my_company": {
                    "app1": BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"])
                },
            }
        )

        return store, registry

    def _make_client(self, store, registry, admin_key="test-admin-key-long"):
        from fastapi.testclient import TestClient

        import broker.main as broker_main
        from broker.main import app

        ct_store = ConnectTokenStore()

        # Set module-level state so lazy _get_admin_endpoints() resolves correctly
        old_ks, old_reg, old_ct, old_settings = (
            broker_main._key_store,
            broker_main._client_registry,
            broker_main._connect_token_store,
            broker_main._settings,
        )
        broker_main._key_store = store
        broker_main._client_registry = registry
        broker_main._connect_token_store = ct_store
        # Admin endpoints need _settings for admin_key
        if not broker_main._settings:
            from broker.config import BrokerConfig, BrokerSettings

            broker_main._settings = BrokerSettings(
                broker=BrokerConfig(
                    admin_key=admin_key,
                    encryption_keys=["dummy"],
                    state_secret="test-state-secret-key",
                ),
            )
        client = TestClient(app)
        return client, old_ks, old_reg, old_ct, old_settings

    async def test_create_key(self, admin_setup) -> None:
        store, registry = admin_setup
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.post(
                "/admin/keys",
                json={"app_key": "my_company:app1"},
                headers={"x-admin-key": "test-admin-key-long"},
            )
            assert response.status_code == 201
            body = response.json()
            assert body["app_key"] == "my_company:app1"
            assert body["api_key"].startswith("br_")
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_create_key_unknown_app(self, admin_setup) -> None:
        store, registry = admin_setup
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.post(
                "/admin/keys",
                json={"app_key": "unknown:app"},
                headers={"x-admin-key": "test-admin-key-long"},
            )
            assert response.status_code == 400
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_create_key_unauthorized(self, admin_setup) -> None:
        store, registry = admin_setup
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.post(
                "/admin/keys",
                json={"app_key": "my_company:app1"},
                headers={"x-admin-key": "wrong-key"},
            )
            assert response.status_code == 401
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_list_keys(self, admin_setup) -> None:
        store, registry = admin_setup
        await store.create_key("my_company:app1")
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.get(
                "/admin/keys",
                headers={"x-admin-key": "test-admin-key-long"},
            )
            assert response.status_code == 200
            body = response.json()
            assert len(body["apps"]) == 1
            assert body["apps"][0]["app_key"] == "my_company:app1"
            assert body["apps"][0]["has_key"] is True
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_rotate_key(self, admin_setup) -> None:
        store, registry = admin_setup
        old_key = await store.create_key("my_company:app1")
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.post(
                "/admin/keys/my_company:app1/rotate",
                headers={"x-admin-key": "test-admin-key-long"},
            )
            assert response.status_code == 200
            body = response.json()
            assert body["api_key"] != old_key
            assert body["api_key"].startswith("br_")
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_delete_key(self, admin_setup) -> None:
        store, registry = admin_setup
        await store.create_key("my_company:app1")
        client, old_ks, old_reg, old_ct, old_settings = self._make_client(store, registry)
        import broker.main as broker_main

        try:
            response = client.delete(
                "/admin/keys/my_company:app1",
                headers={"x-admin-key": "test-admin-key-long"},
            )
            assert response.status_code == 200
            assert response.json()["deleted"] is True
        finally:
            broker_main._key_store = old_ks
            broker_main._client_registry = old_reg
            broker_main._connect_token_store = old_ct
            broker_main._settings = old_settings

    async def test_delete_key_cascades_to_tokens(self, admin_setup, tmp_path: Path) -> None:
        """Deleting a broker key must also drop OAuth tokens for the app.

        Prevents silent resurrection of third-party access when a key is
        re-provisioned under the same app_key after rotation / compromise.
        """
        from broker.api.admin import AdminEndpoints
        from broker.models.connection import AppConnection
        from broker.services.store import SQLiteTokenStore

        store, registry = admin_setup
        await store.create_key("my_company:app1")

        token_store = SQLiteTokenStore(db_path=str(tmp_path / "tokens.db"))
        await token_store.save(
            "my_company:app1",
            "notion",
            AppConnection(connector_name="notion", access_token="secret-access"),
        )
        await token_store.save(
            "my_company:app1",
            "hubspot",
            AppConnection(connector_name="hubspot", access_token="secret-access"),
        )
        assert len(await token_store.list_for_app("my_company:app1")) == 2

        endpoints = AdminEndpoints(
            store, "test-admin-key-long", registry, ConnectTokenStore(), token_store=token_store
        )
        request = MagicMock()
        request.headers = {"x-admin-key": "test-admin-key-long"}

        response = await endpoints.delete_key("my_company:app1", request)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["deleted"] is True
        assert body["tokens_deleted"] == 2

        assert await token_store.list_for_app("my_company:app1") == []

    async def test_delete_key_no_token_store_is_safe(self, admin_setup) -> None:
        """delete_key with no token_store injected must still succeed."""
        from broker.api.admin import AdminEndpoints

        store, registry = admin_setup
        await store.create_key("my_company:app1")
        endpoints = AdminEndpoints(store, "test-admin-key-long", registry, ConnectTokenStore())

        request = MagicMock()
        request.headers = {"x-admin-key": "test-admin-key-long"}
        response = await endpoints.delete_key("my_company:app1", request)
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["deleted"] is True
        assert body["tokens_deleted"] == 0

    async def test_create_connect_token(self, admin_setup) -> None:
        """Test connect token creation directly via endpoint handler."""

        from broker.api.admin import AdminEndpoints

        store, registry = admin_setup
        await store.create_key("my_company:app1")
        ct_store = ConnectTokenStore()
        endpoints = AdminEndpoints(store, "test-admin-key-long", registry, ct_store)

        request = MagicMock()
        request.headers = {"x-admin-key": "test-admin-key-long"}
        request.json = AsyncMock(return_value={"app_key": "my_company:app1"})

        response = await endpoints.create_connect_token(request)
        assert response.status_code == 201
        body = json.loads(response.body)
        assert body["app_key"] == "my_company:app1"
        assert body["connect_token"].startswith(CONNECT_TOKEN_PREFIX)
        assert body["ttl_seconds"] == 300

    async def test_create_connect_token_no_key(self, admin_setup) -> None:
        """Reject connect token for app without API key."""
        from broker.api.admin import AdminEndpoints

        store, registry = admin_setup
        ct_store = ConnectTokenStore()
        endpoints = AdminEndpoints(store, "test-admin-key-long", registry, ct_store)

        request = MagicMock()
        request.headers = {"x-admin-key": "test-admin-key-long"}
        request.json = AsyncMock(return_value={"app_key": "my_company:app1"})

        response = await endpoints.create_connect_token(request)
        assert response.status_code == 400
        body = json.loads(response.body)
        assert "no API key" in body["error"]


# =============================================================================
# CONNECT TOKEN STORE
# =============================================================================


class TestConnectTokenStore:
    def test_create_and_consume(self) -> None:
        store = ConnectTokenStore()
        token = store.create("client:app")
        assert token.startswith(CONNECT_TOKEN_PREFIX)
        assert store.consume(token) == "client:app"

    def test_single_use(self) -> None:
        """Token consumed on first use, second use returns None."""
        store = ConnectTokenStore()
        token = store.create("client:app")
        assert store.consume(token) == "client:app"
        assert store.consume(token) is None

    def test_invalid_token(self) -> None:
        store = ConnectTokenStore()
        assert store.consume("ct_nonexistent") is None

    def test_expired_token(self) -> None:
        """Expired tokens return None."""
        import time
        from unittest.mock import patch

        store = ConnectTokenStore()
        token = store.create("client:app")

        # Fast-forward past TTL
        with patch("broker.services.api_key_store.time") as mock_time:
            mock_time.time.return_value = time.time() + 400
            assert store.consume(token) is None

    async def test_middleware_connect_token_flow(self, tmp_path: Path) -> None:
        """Middleware validates connect token for /oauth/*/connect."""
        from broker.middleware.auth import BrokerAuthMiddleware

        key_store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await key_store.setup()

        config = BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"])
        registry = BrokerClientRegistry({"client": {"app": config}})
        ct_store = ConnectTokenStore()

        token = ct_store.create("client:app")

        middleware = BrokerAuthMiddleware(
            app=MagicMock(),
            get_key_store=lambda: key_store,
            get_client_registry=lambda: registry,
            get_connect_token_store=lambda: ct_store,
        )

        request = MagicMock()
        request.headers = {}
        request.query_params = {"connect_token": token}
        request.url.path = "/oauth/notion/connect"
        request.client.host = "127.0.0.1"

        result = await middleware._extract_and_verify(
            request, "/oauth/notion/connect", key_store, registry
        )
        assert isinstance(result, BrokerAppIdentity)
        assert result.app_key == "client:app"

    async def test_middleware_rejects_raw_broker_key_in_query(self, tmp_path: Path) -> None:
        """Middleware rejects raw broker_key query param (must use connect_token)."""
        from starlette.responses import Response

        from broker.middleware.auth import BrokerAuthMiddleware

        key_store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
        await key_store.setup()
        raw_key = await key_store.create_key("client:app")

        config = BrokerAppConfig()
        registry = BrokerClientRegistry({"client": {"app": config}})
        ct_store = ConnectTokenStore()

        middleware = BrokerAuthMiddleware(
            app=MagicMock(),
            get_key_store=lambda: key_store,
            get_client_registry=lambda: registry,
            get_connect_token_store=lambda: ct_store,
        )

        # Old-style query param with broker_key — should be rejected
        request = MagicMock()
        request.headers = {}
        request.query_params = {"app_key": "client:app", "broker_key": raw_key}
        request.url.path = "/oauth/notion/connect"
        request.client.host = "127.0.0.1"

        result = await middleware._extract_and_verify(
            request, "/oauth/notion/connect", key_store, registry
        )
        assert isinstance(result, Response)
        assert result.status_code == 401
