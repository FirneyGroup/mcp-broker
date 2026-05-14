"""Tests for the bearer-token branch of `BrokerAuthMiddleware`.

Coverage:
- happy path on shallow + deep proxy paths
- audience mismatch + expired + unknown-connector 401 with WWW-Authenticate
- fail-closed 503 when the inbound auth store is unavailable
- fail-propagation when store.get_access raises mid-flight
- legacy X-App-Id/X-Broker-Key still works alongside `oauth_enabled=True`
- bearer wins when both bearer and X-App-Id headers are present
- /admin paths stay exempt and do not surface a bearer challenge
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any
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


@pytest.fixture
def middleware(
    key_store: SQLiteBrokerKeyStore,
    registry: BrokerClientRegistry,
    inbound_store: SQLiteInboundAuthStore,
) -> BrokerAuthMiddleware:
    return _make_middleware(key_store=key_store, registry=registry, inbound_store=inbound_store)


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


async def _verify(
    middleware: BrokerAuthMiddleware,
    *,
    path: str,
    key_store: SQLiteBrokerKeyStore,
    registry: BrokerClientRegistry,
    bearer: str | None = None,
    extra_headers: dict[str, str] | None = None,
):
    """Build a mock request and call _extract_and_verify in one call.

    Collapses the repeated `_make_request(...); middleware._extract_and_verify(...)`
    pattern. The one test that needs to inspect `request.scope` after the call
    (`test_bearer_strips_authorization_from_scope`) builds its request manually.
    """
    request = _make_request(path=path, bearer=bearer, extra_headers=extra_headers)
    return await middleware._extract_and_verify(request, path, key_store, registry)


def _assert_invalid_token_challenge(response: Any) -> None:
    """Assert the canonical invalid_token 401 shape.

    Checks: status 401, WWW-Authenticate starts with 'Bearer ', error field is
    'invalid_token', and error_description is present.
    """
    assert hasattr(response, "status_code")
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert "error_description=" in challenge


# =============================================================================
# EXEMPT PATHS
# =============================================================================


class TestExemptPaths:
    @pytest.mark.parametrize(
        "path,expected_exempt",
        [
            ("/oauth/register", True),
            ("/oauth/authorize", True),
            ("/oauth/token", True),
            ("/oauth/revoke", True),
            ("/.well-known/oauth-authorization-server", True),
            ("/.well-known/oauth-protected-resource/proxy/notion", True),
            ("/admin/keys", True),
            ("/proxy/notion/mcp", False),
        ],
    )
    async def test_exempt_classification(
        self, middleware: BrokerAuthMiddleware, path: str, expected_exempt: bool
    ) -> None:
        assert middleware._is_exempt(path) is expected_exempt


# =============================================================================
# BEARER HAPPY PATH
# =============================================================================


class TestBearerHappyPath:
    async def test_valid_bearer_returns_identity(
        self,
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        identity = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            bearer=raw_token,
            key_store=key_store,
            registry=registry,
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY
        assert identity.scopes == ["proxy", "status"]
        assert identity.allowed_connectors == ["notion"]

    async def test_valid_bearer_deep_path_returns_identity(
        self,
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        deep_path = "/proxy/notion/mcp/messages/abc123"
        identity = await _verify(
            middleware,
            path=deep_path,
            bearer=raw_token,
            key_store=key_store,
            registry=registry,
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.allowed_connectors == ["notion"]

    async def test_bearer_strips_authorization_from_scope(
        self,
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        """Defense-in-depth: header must be removed before proxy.py forwards upstream."""
        raw_token = await _seed_access_token(inbound_store)

        # Build request manually — we need to inspect request.scope after the call.
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
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        # Token issued for notion, but request hits /proxy/hubspot/
        raw_token = await _seed_access_token(inbound_store)
        response = await _verify(
            middleware,
            path="/proxy/hubspot/mcp",
            bearer=raw_token,
            key_store=key_store,
            registry=registry,
        )
        _assert_invalid_token_challenge(response)
        body = json.loads(response.body)
        assert body["error"] == "invalid_token"
        assert "audience" in body["error_description"].lower()

    async def test_expired_token_returns_challenge(
        self,
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store, expires_in=-10)
        response = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            bearer=raw_token,
            key_store=key_store,
            registry=registry,
        )
        _assert_invalid_token_challenge(response)

    async def test_unknown_token_returns_challenge(
        self,
        middleware: BrokerAuthMiddleware,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        response = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            bearer="mcp_at_does_not_exist",
            key_store=key_store,
            registry=registry,
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer ")

    async def test_unknown_connector_in_path_returns_challenge(
        self,
        middleware: BrokerAuthMiddleware,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        raw_token = await _seed_access_token(inbound_store)
        response = await _verify(
            middleware,
            path="/proxy/unknown/mcp",
            bearer=raw_token,
            key_store=key_store,
            registry=registry,
        )
        assert response.status_code == 401
        # PRM URL falls back to the generic well-known root when no connector match
        challenge = response.headers["www-authenticate"]
        assert "resource_metadata=" in challenge

    async def test_missing_bearer_on_proxy_path_returns_challenge(
        self,
        middleware: BrokerAuthMiddleware,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        """Bearer-protected path with no credentials must surface a challenge."""
        response = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            key_store=key_store,
            registry=registry,
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
        mw = _make_middleware(key_store=key_store, registry=registry, inbound_store=None)
        response = await _verify(
            mw,
            path="/proxy/notion/mcp",
            bearer="mcp_at_anything",
            key_store=key_store,
            registry=registry,
        )
        assert response.status_code == 503
        body = json.loads(response.body)
        assert body["error"] == "oauth_store_unavailable"

    async def test_store_get_access_raises_propagates(
        self,
        tmp_path: Path,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Contract: store.get_access raising propagates through _extract_and_verify.

        The middleware has no try/except around the store call — the exception
        propagates to the ASGI framework boundary, where Starlette converts it
        to a 500. Tested by calling _extract_and_verify directly and asserting
        the OperationalError is raised (not silently swallowed or turned into 503).
        """
        broken_store = SQLiteInboundAuthStore(db_path=str(tmp_path / "broken.db"))
        await broken_store.setup()

        async def _raise_on_get_access(*args: object, **kwargs: object) -> None:
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(broken_store, "get_access", _raise_on_get_access)

        mw = _make_middleware(key_store=key_store, registry=registry, inbound_store=broken_store)
        with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
            await _verify(
                mw,
                path="/proxy/notion/mcp",
                bearer="mcp_at_x",
                key_store=key_store,
                registry=registry,
            )


# =============================================================================
# LEGACY COEXISTENCE
# =============================================================================


class TestLegacyAuthAlongsideOAuth:
    async def test_legacy_x_app_id_still_works(
        self,
        middleware: BrokerAuthMiddleware,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        """oauth_enabled=True + no bearer → falls through to X-App-Id/X-Broker-Key."""
        raw_key = await key_store.create_key(APP_KEY)
        identity = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            key_store=key_store,
            registry=registry,
            extra_headers={"x-app-id": APP_KEY, "x-broker-key": raw_key},
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY
        # Legacy auth keeps the registry's full connector list
        assert identity.allowed_connectors == ["notion", "hubspot"]

    async def test_bearer_wins_over_legacy_headers(
        self,
        inbound_store: SQLiteInboundAuthStore,
        key_store: SQLiteBrokerKeyStore,
    ) -> None:
        """Both bearer and legacy headers present → bearer branch handles it.

        Uses a real legacy key for 'other:legacy' to prove bearer wins over a
        legitimately-valid legacy credential, not just a broken one.
        """
        raw_token = await _seed_access_token(inbound_store)
        # Create a real key for the legacy app so both auth paths are valid.
        real_legacy_key = await key_store.create_key("other:legacy")
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
        mw = _make_middleware(
            key_store=key_store, registry=registry_with_both, inbound_store=inbound_store
        )

        # Legacy headers would yield 'other:legacy', but bearer fires first.
        identity = await _verify(
            mw,
            path="/proxy/notion/mcp",
            bearer=raw_token,
            key_store=key_store,
            registry=registry_with_both,
            extra_headers={"x-app-id": "other:legacy", "x-broker-key": real_legacy_key},
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY

    async def test_admin_path_stays_exempt_and_no_bearer_challenge(
        self,
        middleware: BrokerAuthMiddleware,
    ) -> None:
        """/admin is exempt — middleware never builds a 401 for it."""
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
        mw = _make_middleware(
            key_store=key_store,
            registry=registry,
            inbound_store=None,
            oauth_enabled=False,
        )
        response = await _verify(
            mw,
            path="/proxy/notion/mcp",
            bearer="mcp_at_anything",
            key_store=key_store,
            registry=registry,
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
        mw = _make_middleware(
            key_store=key_store, registry=registry, inbound_store=None, oauth_enabled=False
        )
        identity = await _verify(
            mw,
            path="/proxy/notion/mcp",
            key_store=key_store,
            registry=registry,
            extra_headers={"x-app-id": APP_KEY, "x-broker-key": raw_key},
        )
        assert isinstance(identity, BrokerAppIdentity)
        assert identity.app_key == APP_KEY


# =============================================================================
# CHALLENGE FORMATTING
# =============================================================================


class TestBearerChallengeFormat:
    async def test_challenge_always_includes_error_description(
        self,
        middleware: BrokerAuthMiddleware,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        response = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            bearer="mcp_at_bogus",
            key_store=key_store,
            registry=registry,
        )
        assert "error_description=" in response.headers["www-authenticate"]

    async def test_challenge_points_at_prm(
        self,
        middleware: BrokerAuthMiddleware,
        key_store: SQLiteBrokerKeyStore,
        registry: BrokerClientRegistry,
    ) -> None:
        response = await _verify(
            middleware,
            path="/proxy/notion/mcp",
            bearer="mcp_at_bogus",
            key_store=key_store,
            registry=registry,
        )
        challenge = response.headers["www-authenticate"]
        assert (
            "https://broker.example.com/.well-known/oauth-protected-resource/proxy/notion"
            in challenge
        )
