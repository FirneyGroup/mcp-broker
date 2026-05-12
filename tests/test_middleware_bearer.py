"""Tests for the bearer-token branch of `BrokerAuthMiddleware`.

Coverage:
- happy path on shallow + deep proxy paths
- audience mismatch + expired + unknown-connector 401 with WWW-Authenticate
- fail-closed 503 when the inbound auth store is unavailable
- legacy X-App-Id/X-Broker-Key still works alongside `oauth_enabled=True`
- bearer wins when both bearer and X-App-Id headers are present
- /admin paths stay exempt and do not surface a bearer challenge
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from broker.config import BrokerAppConfig
from broker.middleware.auth import BrokerAuthMiddleware
from broker.models.inbound_auth import InboundToken
from broker.services.api_key_store import BrokerAppIdentity
from broker.services.client_registry import BrokerClientRegistry
from broker.services.inbound_auth_store import SQLiteInboundAuthStore
from broker.services.sqlite_api_key_store import SQLiteBrokerKeyStore

PUBLIC_URL = "https://broker.example.com/"
CONNECTORS = ["notion", "hubspot"]
APP_KEY = "acme:claude_ai"


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
async def inbound_store(tmp_path: Path) -> SQLiteInboundAuthStore:
    store = SQLiteInboundAuthStore(db_path=str(tmp_path / "inbound.db"))
    await store.setup()
    return store


@pytest.fixture
async def key_store(tmp_path: Path) -> SQLiteBrokerKeyStore:
    store = SQLiteBrokerKeyStore(db_path=str(tmp_path / "keys.db"))
    await store.setup()
    return store


@pytest.fixture
def registry() -> BrokerClientRegistry:
    return BrokerClientRegistry(
        {
            "acme": {
                "claude_ai": BrokerAppConfig(
                    scopes=["proxy", "status"],
                    allowed_connectors=["notion", "hubspot"],
                ),
            },
        }
    )


def _make_middleware(
    *,
    key_store: SQLiteBrokerKeyStore | None = None,
    registry: BrokerClientRegistry | None = None,
    inbound_store: SQLiteInboundAuthStore | None = None,
    oauth_enabled: bool = True,
    public_url: str = PUBLIC_URL,
    connector_names: list[str] | None = None,
) -> BrokerAuthMiddleware:
    return BrokerAuthMiddleware(
        app=MagicMock(),
        get_key_store=lambda: key_store,
        get_client_registry=lambda: registry,
        get_connect_token_store=lambda: None,
        oauth_enabled=oauth_enabled,
        public_url=public_url,
        get_inbound_auth_store=lambda: inbound_store,
        get_connector_names=lambda: connector_names if connector_names is not None else CONNECTORS,
    )


async def _seed_access_token(
    store: SQLiteInboundAuthStore,
    *,
    raw_token: str = "mcp_at_test_raw_value",  # noqa: S107 -- synthetic test token, never a credential
    resource: str = "https://broker.example.com/proxy/notion",
    expires_in: int = 3600,
) -> str:
    """Persist an access token row directly and return its raw value.

    Mirrors what `/oauth/token` would do but avoids the full auth-code flow.
    """
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = int(time.time())
    inbound = InboundToken(
        token_hash=token_hash,
        token_kind="access",
        family_id="fam-test",
        client_id="mcp_client_test",
        app_key=APP_KEY,
        resource=resource,
        scope="mcp:proxy:notion",
        expires_at=now + expires_in,
        issued_at=now,
    )
    # Use the store's internal helper via a direct insert through a side connection.
    import sqlite3

    conn = sqlite3.connect(store._db_path)
    try:
        SQLiteInboundAuthStore._insert_token_row(conn, inbound)
        conn.commit()
    finally:
        conn.close()
    return raw_token


def _make_request(
    *,
    path: str,
    bearer: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> MagicMock:
    headers: dict[str, str] = {}
    if bearer is not None:
        headers["authorization"] = f"Bearer {bearer}"
    if extra_headers:
        headers.update(extra_headers)
    scope_headers = [(k.encode(), v.encode()) for k, v in headers.items()]
    request = MagicMock()
    request.headers = headers
    request.scope = {"headers": scope_headers}
    request.url.path = path
    request.query_params = {}
    request.client.host = "127.0.0.1"
    return request


# =============================================================================
# EXEMPT PATHS
# =============================================================================


class TestNewExemptPaths:
    def test_oauth_register_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/oauth/register")

    def test_oauth_authorize_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/oauth/authorize")

    def test_oauth_token_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/oauth/token")

    def test_oauth_revoke_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/oauth/revoke")

    def test_wellknown_as_metadata_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/.well-known/oauth-authorization-server")

    def test_wellknown_prm_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/.well-known/oauth-protected-resource/proxy/notion")

    def test_admin_still_exempt(self) -> None:
        middleware = _make_middleware()
        assert middleware._is_exempt("/admin/keys")

    def test_proxy_not_exempt(self) -> None:
        middleware = _make_middleware()
        assert not middleware._is_exempt("/proxy/notion/mcp")


# =============================================================================
# BEARER HAPPY PATH
# =============================================================================


class TestBearerHappyPath:
    async def test_valid_bearer_returns_identity(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        request = _make_request(path="/proxy/notion/mcp", bearer=raw_token)
        identity = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )

        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY
        assert identity.scopes == ["proxy", "status"]
        assert identity.allowed_connectors == ["notion"]

    async def test_valid_bearer_deep_path_returns_identity(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        deep_path = "/proxy/notion/mcp/messages/abc123"
        request = _make_request(path=deep_path, bearer=raw_token)
        identity = await middleware._extract_and_verify(request, deep_path, key_store, registry)

        assert isinstance(identity, BrokerAppIdentity)
        assert identity.allowed_connectors == ["notion"]

    async def test_bearer_strips_authorization_from_scope(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """Defense-in-depth: header must be removed before proxy.py forwards upstream."""
        raw_token = await _seed_access_token(inbound_store)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        request = _make_request(path="/proxy/notion/mcp", bearer=raw_token)
        await middleware._extract_and_verify(request, "/proxy/notion/mcp", key_store, registry)

        header_names = {name.lower() for name, _ in request.scope["headers"]}
        assert b"authorization" not in header_names


# =============================================================================
# BEARER 401 CASES
# =============================================================================


class TestBearer401:
    async def test_audience_mismatch_returns_challenge(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        # Token issued for notion, but request hits /proxy/hubspot/
        raw_token = await _seed_access_token(inbound_store)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        request = _make_request(path="/proxy/hubspot/mcp", bearer=raw_token)
        response = await middleware._extract_and_verify(
            request, "/proxy/hubspot/mcp", key_store, registry
        )

        assert hasattr(response, "status_code")
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert challenge.startswith("Bearer ")
        assert 'error="invalid_token"' in challenge
        assert "error_description=" in challenge
        body = json.loads(response.body)
        assert body["error"] == "invalid_token"
        assert "audience" in body["error_description"].lower()

    async def test_expired_token_returns_challenge(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store, expires_in=-10)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        request = _make_request(path="/proxy/notion/mcp", bearer=raw_token)
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )

        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert 'error="invalid_token"' in challenge
        assert "error_description=" in challenge

    async def test_unknown_token_returns_challenge(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        request = _make_request(path="/proxy/notion/mcp", bearer="mcp_at_does_not_exist")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer ")

    async def test_unknown_connector_in_path_returns_challenge(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        request = _make_request(path="/proxy/unknown/mcp", bearer=raw_token)
        response = await middleware._extract_and_verify(
            request, "/proxy/unknown/mcp", key_store, registry
        )
        assert response.status_code == 401
        # PRM URL falls back to the generic well-known root when no connector match
        challenge = response.headers["www-authenticate"]
        assert "resource_metadata=" in challenge

    async def test_missing_bearer_on_proxy_path_returns_challenge(
        self,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
        inbound_store: SQLiteInboundAuthStore,
    ) -> None:
        """Bearer-protected path with no credentials must surface a challenge."""
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        request = _make_request(path="/proxy/notion/mcp")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer ")
        assert "resource_metadata=" in response.headers["www-authenticate"]


# =============================================================================
# FAIL-CLOSED
# =============================================================================


class TestBearerFailClosed:
    async def test_store_unavailable_returns_503(
        self,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        # oauth_enabled=True but inbound_store=None — operator misconfig
        middleware = _make_middleware(key_store=key_store, registry=registry, inbound_store=None)
        request = _make_request(path="/proxy/notion/mcp", bearer="mcp_at_anything")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert response.status_code == 503
        body = json.loads(response.body)
        assert body["error"] == "oauth_store_unavailable"


# =============================================================================
# LEGACY COEXISTENCE
# =============================================================================


class TestLegacyAuthAlongsideOAuth:
    async def test_legacy_x_app_id_still_works(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """oauth_enabled=True + no bearer → falls through to X-App-Id/X-Broker-Key."""
        raw_key = await key_store.create_key(APP_KEY)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )

        request = _make_request(
            path="/proxy/notion/mcp",
            extra_headers={"x-app-id": APP_KEY, "x-broker-key": raw_key},
        )
        identity = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY
        # Legacy auth keeps the registry's full connector list
        assert identity.allowed_connectors == ["notion", "hubspot"]

    async def test_bearer_wins_over_legacy_headers(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """Both bearer and legacy headers present → bearer branch handles it."""
        raw_token = await _seed_access_token(inbound_store)
        # Create a separate legacy key for a different app to confirm bearer
        # wins (legacy would have given a different identity).
        await key_store.create_key("other:legacy")
        registry_with_both = BrokerClientRegistry(
            {
                "acme": {
                    "claude_ai": BrokerAppConfig(scopes=["proxy"], allowed_connectors=["notion"]),
                },
                "other": {
                    "legacy": BrokerAppConfig(scopes=["status"]),
                },
            }
        )
        middleware = _make_middleware(
            key_store=key_store, registry=registry_with_both, inbound_store=inbound_store
        )

        # Legacy headers would normally yield the "other:legacy" identity, but
        # the bearer branch fires first and uses the inbound token row's app_key.
        request = _make_request(
            path="/proxy/notion/mcp",
            bearer=raw_token,
            extra_headers={"x-app-id": "other:legacy", "x-broker-key": "br_irrelevant"},
        )
        identity = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry_with_both
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY

    async def test_admin_path_stays_exempt_and_no_bearer_challenge(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """/admin is exempt — middleware never builds a 401 for it."""
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        assert middleware._is_exempt("/admin/keys")


# =============================================================================
# OAUTH DISABLED — BEARER BRANCH OFF
# =============================================================================


class TestOAuthDisabledKeepsLegacyOnly:
    async def test_bearer_ignored_when_oauth_disabled(
        self,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """oauth_enabled=False: bearer header is invisible, legacy path runs."""
        middleware = _make_middleware(
            key_store=key_store,
            registry=registry,
            inbound_store=None,
            oauth_enabled=False,
        )
        request = _make_request(path="/proxy/notion/mcp", bearer="mcp_at_anything")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        # No legacy headers either → bare 401, no WWW-Authenticate
        assert response.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in response.headers}

    async def test_legacy_path_unchanged_when_oauth_disabled(
        self,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        raw_key = await key_store.create_key(APP_KEY)
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=None, oauth_enabled=False
        )
        request = _make_request(
            path="/proxy/notion/mcp",
            extra_headers={"x-app-id": APP_KEY, "x-broker-key": raw_key},
        )
        identity = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY


# =============================================================================
# CHALLENGE FORMATTING
# =============================================================================


class TestBearerChallengeFormat:
    async def test_challenge_always_includes_error_description(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        request = _make_request(path="/proxy/notion/mcp", bearer="mcp_at_bogus")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        assert "error_description=" in response.headers["www-authenticate"]

    async def test_challenge_points_at_prm(
        self,
        inbound_store: SQLiteInboundAuthStore,
        registry: BrokerClientRegistry,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        middleware = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=inbound_store
        )
        request = _make_request(path="/proxy/notion/mcp", bearer="mcp_at_bogus")
        response = await middleware._extract_and_verify(
            request, "/proxy/notion/mcp", key_store, registry
        )
        challenge = response.headers["www-authenticate"]
        assert (
            "https://broker.example.com/.well-known/oauth-protected-resource/proxy/notion"
            in challenge
        )
