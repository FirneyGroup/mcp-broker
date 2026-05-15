"""Tests for the OAuth 2.1 AS endpoints (DCR, authorize, token, revoke).

Tests drive ``OAuthServerEndpoints`` directly via ``MagicMock``-shaped requests
to keep the test surface independent of the bearer-middleware wiring (that
lives in T03 / ``test_middleware_bearer.py``). Real ``SQLiteInboundAuthStore``
backs every test so the audit + atomic-rotation semantics are exercised end to
end on the actual schema.

Generic identifiers throughout — `acme:claude_ai`, `broker.example.com`,
`alice@example.com` — per the framework's anti-PII fixture rule.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from broker.api.oauth_server import (
    OAuthServerEndpoints,
    _DCRRateLimiter,
    _kinds_from_hint,
    _scope_is_subset,
)
from broker.config import OAuthInboundConfig
from broker.services.inbound_auth_store import SQLiteInboundAuthStore

# === CONSTANTS / FIXTURES ===

GENERIC_APP_KEY = "acme:claude_ai"
GENERIC_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
GENERIC_PUBLIC_URL = "https://broker.example.com/"
GENERIC_RESOURCE = "https://broker.example.com/proxy/notion"
GENERIC_SCOPE = "mcp:proxy:notion mcp:status"
GENERIC_CLIENT_IP = "203.0.113.10"

# 64-char base64url string — PKCE S256 challenge for `_VALID_VERIFIER`.
_VALID_VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"


def _challenge_for(verifier: str) -> str:
    """RFC 7636 §4.2 — base64url(sha256(verifier)) with padding stripped."""
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def _make_config(**overrides: Any) -> OAuthInboundConfig:
    """Construct an enabled `OAuthInboundConfig` with permissive defaults."""
    defaults: dict[str, Any] = {
        "enabled": True,
        "app_key": GENERIC_APP_KEY,
        "db_path": "unused-overwritten-per-test.db",
        "access_token_ttl_seconds": 3600,
        "refresh_token_ttl_seconds": 2592000,
        "code_ttl_seconds": 60,
        "dcr_rate_limit_per_ip": 10,
        "dcr_rate_limit_window_seconds": 900,
    }
    defaults.update(overrides)
    return OAuthInboundConfig(**defaults)


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteInboundAuthStore:
    """Fresh SQLite-backed store per test."""
    initialized = SQLiteInboundAuthStore(str(tmp_path / "inbound_oauth.db"))
    await initialized.setup()
    return initialized


@pytest.fixture
def connector_names() -> list[str]:
    return ["notion", "hubspot"]


@pytest.fixture
def endpoints(store: SQLiteInboundAuthStore, connector_names: list[str]) -> OAuthServerEndpoints:
    return OAuthServerEndpoints(
        inbound_auth_store=store,
        config=_make_config(),
        connector_names_provider=lambda: connector_names,
        public_url=GENERIC_PUBLIC_URL,
    )


# === REQUEST FAKES ===


def _request_with_json(body: dict[str, Any], client_ip: str = GENERIC_CLIENT_IP):
    """Build a ``Request``-like mock for JSON-body endpoints."""
    request = MagicMock()
    request.json = AsyncMock(return_value=body)
    request.headers = {"x-forwarded-for": client_ip}
    request.query_params = {}
    request.client.host = client_ip
    return request


def _request_with_form(form: dict[str, str], headers: dict[str, str] | None = None):
    """Build a ``Request``-like mock for form-body endpoints (`/token`, `/revoke`)."""
    request = MagicMock()
    request.form = AsyncMock(return_value=form)
    request.headers = headers or {}
    request.query_params = {}
    request.client.host = GENERIC_CLIENT_IP
    return request


def _request_with_json_explicit_ips(
    body: dict[str, Any], immediate_ip: str, forwarded_for: str | None
):
    """Build a JSON-body request mock with separate ``client.host`` and XFF values.

    Lets a test verify how ``_client_ip`` resolves the rate-limit key when the
    proxy IP and the forwarded IP differ.
    """
    request = MagicMock()
    request.json = AsyncMock(return_value=body)
    request.headers = {"x-forwarded-for": forwarded_for} if forwarded_for else {}
    request.query_params = {}
    request.client.host = immediate_ip
    return request


def _request_with_query(query: dict[str, str]):
    """Build a ``Request``-like mock for GET /authorize."""
    request = MagicMock()
    request.query_params = query
    request.headers = {}
    request.client.host = GENERIC_CLIENT_IP
    return request


def _registration_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "client_name": "Acme Claude",
        "redirect_uris": [GENERIC_REDIRECT_URI],
        "token_endpoint_auth_method": "none",
    }
    payload.update(overrides)
    return payload


def _response_body(response: Any) -> dict[str, Any]:
    """Decode ``JSONResponse.body`` (bytes) → dict for assertions."""
    return json.loads(response.body)


# =============================================================================
# DCR (POST /oauth/register)
# =============================================================================


class TestDCR:
    async def test_public_client_201(self, endpoints: OAuthServerEndpoints) -> None:
        request = _request_with_json(_registration_payload())
        response = await endpoints.register(request)
        assert response.status_code == 201
        body = _response_body(response)
        assert body["client_id"].startswith("mcp_client_")
        assert "client_secret" not in body
        # RFC 7591 §3.2.1: registration response with client_secret MUST be no-store.
        # Always set so the public-client branch can't diverge under refactor.
        assert response.headers.get("Cache-Control") == "no-store"
        assert response.headers.get("Pragma") == "no-cache"

    async def test_confidential_client_returns_secret_once(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        request = _request_with_json(
            _registration_payload(token_endpoint_auth_method="client_secret_basic")
        )
        response = await endpoints.register(request)
        body = _response_body(response)
        assert response.status_code == 201
        assert body["client_secret"]
        assert body["token_endpoint_auth_method"] == "client_secret_basic"

    async def test_rate_limit_returns_429_after_cap(
        self, store: SQLiteInboundAuthStore, connector_names: list[str]
    ) -> None:
        tight = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=_make_config(dcr_rate_limit_per_ip=2),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        first = await tight.register(_request_with_json(_registration_payload()))
        second = await tight.register(_request_with_json(_registration_payload()))
        third = await tight.register(_request_with_json(_registration_payload()))
        assert first.status_code == 201
        assert second.status_code == 201
        assert third.status_code == 429
        assert _response_body(third)["error"] == "invalid_request"

    async def test_disabled_returns_404(
        self, store: SQLiteInboundAuthStore, connector_names: list[str]
    ) -> None:
        disabled = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=OAuthInboundConfig(enabled=False),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        response = await disabled.register(_request_with_json(_registration_payload()))
        assert response.status_code == 404

    async def test_non_allowlisted_redirect_400(self, endpoints: OAuthServerEndpoints) -> None:
        request = _request_with_json(
            _registration_payload(redirect_uris=["https://attacker.example/cb"])
        )
        response = await endpoints.register(request)
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_redirect_uri"

    async def test_fragment_in_redirect_400(self, endpoints: OAuthServerEndpoints) -> None:
        request = _request_with_json(
            _registration_payload(redirect_uris=[f"{GENERIC_REDIRECT_URI}#fragment"])
        )
        response = await endpoints.register(request)
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_redirect_uri"

    async def test_invalid_json_body_400(self, endpoints: OAuthServerEndpoints) -> None:
        request = MagicMock()
        request.json = AsyncMock(side_effect=ValueError("bad json"))
        request.headers = {}
        request.client.host = GENERIC_CLIENT_IP
        response = await endpoints.register(request)
        assert response.status_code == 400


# =============================================================================
# AUTHORIZE (GET /oauth/authorize)
# =============================================================================


async def _register_public_client(endpoints: OAuthServerEndpoints) -> str:
    """Helper — register a public client and return the ``client_id``."""
    response = await endpoints.register(_request_with_json(_registration_payload()))
    return _response_body(response)["client_id"]


def _authorize_params(client_id: str, **overrides: str) -> dict[str, str]:
    base = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": GENERIC_REDIRECT_URI,
        "code_challenge": _challenge_for(_VALID_VERIFIER),
        "code_challenge_method": "S256",
        "state": "client-state-abc",
        "scope": "mcp:proxy:notion",
        "resource": GENERIC_RESOURCE,
    }
    base.update(overrides)
    return base


class TestAuthorizeGet:
    async def test_valid_renders_consent_with_security_headers(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(_request_with_query(_authorize_params(client_id)))
        assert response.status_code == 200
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        body = response.body.decode()
        assert "Approve" in body and "Deny" in body
        # html.escape applied to dynamic values
        assert "Acme Claude" in body

    async def test_unknown_client_id_400_html(self, endpoints: OAuthServerEndpoints) -> None:
        response = await endpoints.authorize_get(
            _request_with_query(_authorize_params("mcp_client_unknown"))
        )
        assert response.status_code == 400

    async def test_wrong_redirect_400_html(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(
            _request_with_query(
                _authorize_params(
                    client_id, redirect_uri="https://claude.com/api/mcp/auth_callback"
                )
            )
        )
        # claude.com is allowlisted but NOT registered for this DCR'd client
        assert response.status_code == 400

    async def test_missing_code_challenge_post_redirect(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id = await _register_public_client(endpoints)
        params = _authorize_params(client_id)
        del params["code_challenge"]
        response = await endpoints.authorize_get(_request_with_query(params))
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]

    async def test_plain_challenge_method_post_redirect(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(
            _request_with_query(_authorize_params(client_id, code_challenge_method="plain"))
        )
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]

    async def test_unknown_resource_post_redirect(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(
            _request_with_query(
                _authorize_params(
                    client_id, resource="https://broker.example.com/proxy/unknown_connector"
                )
            )
        )
        assert response.status_code == 302
        assert "error=invalid_target" in response.headers["location"]

    async def test_fragment_in_resource_post_redirect(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(
            _request_with_query(_authorize_params(client_id, resource=f"{GENERIC_RESOURCE}#frag"))
        )
        # Fragment → normalize_resource raises → invalid_request post-redirect (not 500).
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]

    async def test_scope_widening_outside_connector_rejected(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.authorize_get(
            _request_with_query(_authorize_params(client_id, scope="mcp:proxy:hubspot"))
        )
        assert response.status_code == 302
        assert "error=invalid_scope" in response.headers["location"]


# =============================================================================
# AUTHORIZE (POST /oauth/authorize)
# =============================================================================


class TestAuthorizePost:
    async def test_approve_mints_code_and_redirects(
        self, endpoints: OAuthServerEndpoints, store: SQLiteInboundAuthStore
    ) -> None:
        client_id = await _register_public_client(endpoints)
        params = _authorize_params(client_id) | {"action": "approve"}
        response = await endpoints.authorize_post(_request_with_form(params))
        assert response.status_code == 302
        assert response.headers["location"].startswith(GENERIC_REDIRECT_URI + "?code=")
        assert "state=client-state-abc" in response.headers["location"]
        # Code persisted in oauth_codes
        conn = sqlite3.connect(store._db_path)
        try:
            row = conn.execute("SELECT client_id, app_key FROM oauth_codes").fetchone()
        finally:
            conn.close()
        assert row[0] == client_id
        assert row[1] == GENERIC_APP_KEY

    async def test_deny_redirects_with_access_denied(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        params = _authorize_params(client_id) | {"action": "deny"}
        response = await endpoints.authorize_post(_request_with_form(params))
        assert response.status_code == 302
        assert "error=access_denied" in response.headers["location"]

    @pytest.mark.parametrize("bad_action", ["", "surprise", "approve\n", "APPROVE"])
    async def test_action_must_be_explicit_approve_or_deny(
        self, endpoints: OAuthServerEndpoints, bad_action: str
    ) -> None:
        """Regression: only ``action == "approve"`` mints a code.

        Previously any non-"deny" value (empty, unknown, or case-mismatched)
        fell through to ``_mint_authorization_code``. PKCE made it
        unexploitable, but the intent is clearly approve-or-deny and the
        fallthrough was surprising. The fix rejects unknown values with 400.
        """
        client_id = await _register_public_client(endpoints)
        params = _authorize_params(client_id) | {"action": bad_action}
        response = await endpoints.authorize_post(_request_with_form(params))
        assert response.status_code == 400, (
            f"action={bad_action!r} should have been rejected with 400, got {response.status_code}"
        )


# =============================================================================
# TOKEN (authorization_code)
# =============================================================================


async def _approve_to_get_code(
    endpoints: OAuthServerEndpoints,
    *,
    resource: str = GENERIC_RESOURCE,
    scope: str = "mcp:proxy:notion",
) -> tuple[str, str]:
    """Helper — register, approve a code, and return (client_id, raw_code)."""
    client_id = await _register_public_client(endpoints)
    params = _authorize_params(client_id, resource=resource, scope=scope) | {"action": "approve"}
    response = await endpoints.authorize_post(_request_with_form(params))
    location = response.headers["location"]
    code = location.split("code=", 1)[1].split("&", 1)[0]
    return client_id, code


class TestTokenAuthCode:
    async def test_happy_path(self, endpoints: OAuthServerEndpoints) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        token_request = _request_with_form(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": GENERIC_REDIRECT_URI,
                "code_verifier": _VALID_VERIFIER,
                "client_id": client_id,
                "resource": GENERIC_RESOURCE,
            }
        )
        response = await endpoints.token(token_request)
        assert response.status_code == 200
        body = _response_body(response)
        assert body["access_token"].startswith("mcp_at_")
        assert body["refresh_token"].startswith("mcp_rt_")
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        # RFC 6749 §5.1: token endpoint responses MUST NOT be cached.
        assert response.headers.get("Cache-Control") == "no-store"
        assert response.headers.get("Pragma") == "no-cache"

    async def test_used_code_invalid_grant(self, endpoints: OAuthServerEndpoints) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": GENERIC_REDIRECT_URI,
            "code_verifier": _VALID_VERIFIER,
            "client_id": client_id,
            "resource": GENERIC_RESOURCE,
        }
        first = await endpoints.token(_request_with_form(dict(form)))
        assert first.status_code == 200
        replay = await endpoints.token(_request_with_form(dict(form)))
        assert replay.status_code == 400
        assert _response_body(replay)["error"] == "invalid_grant"

    async def test_pkce_verifier_mismatch_invalid_grant(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": GENERIC_REDIRECT_URI,
                    "code_verifier": "wrong-verifier-of-sufficient-length-aaaaaaa",
                    "client_id": client_id,
                    "resource": GENERIC_RESOURCE,
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_grant"

    async def test_redirect_uri_mismatch_invalid_grant(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://claude.com/api/mcp/auth_callback",
                    "code_verifier": _VALID_VERIFIER,
                    "client_id": client_id,
                    "resource": GENERIC_RESOURCE,
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_grant"

    async def test_resource_trailing_slash_normalizes(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        # Stored as `https://broker.example.com/proxy/notion`; client now sends
        # the trailing-slash variant per WHATWG normalization (claude-code#52871).
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": GENERIC_REDIRECT_URI,
                    "code_verifier": _VALID_VERIFIER,
                    "client_id": client_id,
                    "resource": GENERIC_RESOURCE + "/",
                }
            )
        )
        assert response.status_code == 200

    async def test_resource_for_wrong_connector_invalid_target(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id, code = await _approve_to_get_code(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": GENERIC_REDIRECT_URI,
                    "code_verifier": _VALID_VERIFIER,
                    "client_id": client_id,
                    "resource": "https://broker.example.com/proxy/hubspot",
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_target"

    async def test_unsupported_grant_type(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.token(
            _request_with_form({"grant_type": "password", "client_id": client_id})
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "unsupported_grant_type"


# =============================================================================
# TOKEN (refresh_token)
# =============================================================================


async def _mint_initial_pair(
    endpoints: OAuthServerEndpoints,
) -> tuple[str, str, str]:
    """Helper — auth_code flow → return (client_id, access_token, refresh_token)."""
    client_id, code = await _approve_to_get_code(endpoints)
    response = await endpoints.token(
        _request_with_form(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": GENERIC_REDIRECT_URI,
                "code_verifier": _VALID_VERIFIER,
                "client_id": client_id,
                "resource": GENERIC_RESOURCE,
            }
        )
    )
    body = _response_body(response)
    return client_id, body["access_token"], body["refresh_token"]


class TestTokenRefresh:
    async def test_happy_path_rotates(self, endpoints: OAuthServerEndpoints) -> None:
        client_id, _, refresh = await _mint_initial_pair(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                }
            )
        )
        assert response.status_code == 200
        body = _response_body(response)
        assert body["access_token"].startswith("mcp_at_")
        assert body["refresh_token"].startswith("mcp_rt_")
        # New refresh differs from the old one.
        assert body["refresh_token"] != refresh

    async def test_replay_triggers_family_revoke(
        self, endpoints: OAuthServerEndpoints, store: SQLiteInboundAuthStore
    ) -> None:
        client_id, _, refresh = await _mint_initial_pair(endpoints)
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
        }
        first = await endpoints.token(_request_with_form(dict(form)))
        assert first.status_code == 200
        replay = await endpoints.token(_request_with_form(dict(form)))
        assert replay.status_code == 400
        assert _response_body(replay)["error"] == "invalid_grant"
        # Family must be empty after replay-revoke.
        conn = sqlite3.connect(store._db_path)
        try:
            family_count = conn.execute("SELECT COUNT(*) FROM inbound_tokens").fetchone()[0]
        finally:
            conn.close()
        assert family_count == 0

    async def test_scope_widening_rejected(self, endpoints: OAuthServerEndpoints) -> None:
        client_id, _, refresh = await _mint_initial_pair(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                    "scope": "mcp:proxy:notion mcp:status mcp:proxy:hubspot",
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_scope"

    async def test_unknown_refresh_invalid_grant(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": "mcp_rt_does_not_exist",
                    "client_id": client_id,
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_grant"

    async def test_cross_client_with_wide_scope_returns_invalid_grant_not_invalid_scope(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        """Regression: cross-client refresh attempt must NOT leak whether the
        token_hash exists via the scope-check response shape.

        Original defect: `_rotate_refresh_with_scope_check` looked the prior
        refresh up by hash alone (no client_id filter), then ran the scope
        check against the *victim's* scope. An attacker submitting
        `{their_client_id, victim_token_hash, deliberately_wide_scope}` would
        get `invalid_scope` (confirming the hash exists) versus `invalid_grant`
        (confirming the hash doesn't exist).

        Fix: client_id mismatch returns the same `invalid_grant` as "not found".
        """
        # Victim mints a real refresh token bound to their own client_id.
        victim_client_id, _, victim_refresh = await _mint_initial_pair(endpoints)
        # Attacker registers their own DCR client.
        attacker_client_id = await _register_public_client(endpoints)
        assert attacker_client_id != victim_client_id

        # Attacker submits victim's refresh token + a scope WIDER than what
        # victim was granted. Under the bug, the response would distinguish
        # the two failure modes.
        response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": victim_refresh,
                    "client_id": attacker_client_id,
                    "scope": "mcp:proxy:notion mcp:proxy:hubspot mcp:status",
                }
            )
        )
        assert response.status_code == 400
        assert _response_body(response)["error"] == "invalid_grant", (
            "Cross-client request must return invalid_grant (matching the "
            "not-found shape), NOT invalid_scope — otherwise the response "
            "leaks whether the token_hash exists."
        )


# =============================================================================
# REVOKE
# =============================================================================


class TestRevoke:
    async def test_access_token_silent_200(
        self, endpoints: OAuthServerEndpoints, store: SQLiteInboundAuthStore
    ) -> None:
        client_id, access, _ = await _mint_initial_pair(endpoints)
        response = await endpoints.revoke(
            _request_with_form(
                {"token": access, "client_id": client_id, "token_type_hint": "access_token"}
            )
        )
        assert response.status_code == 200
        # Access row should be gone.
        conn = sqlite3.connect(store._db_path)
        try:
            access_count = conn.execute(
                "SELECT COUNT(*) FROM inbound_tokens WHERE token_kind = 'access'"
            ).fetchone()[0]
        finally:
            conn.close()
        assert access_count == 0

    async def test_refresh_revoke_cascades_family(
        self, endpoints: OAuthServerEndpoints, store: SQLiteInboundAuthStore
    ) -> None:
        client_id, _, refresh = await _mint_initial_pair(endpoints)
        response = await endpoints.revoke(
            _request_with_form(
                {"token": refresh, "client_id": client_id, "token_type_hint": "refresh_token"}
            )
        )
        assert response.status_code == 200
        conn = sqlite3.connect(store._db_path)
        try:
            total = conn.execute("SELECT COUNT(*) FROM inbound_tokens").fetchone()[0]
        finally:
            conn.close()
        assert total == 0

    async def test_non_existent_token_silent_200(self, endpoints: OAuthServerEndpoints) -> None:
        client_id = await _register_public_client(endpoints)
        response = await endpoints.revoke(
            _request_with_form({"token": "mcp_at_unknown", "client_id": client_id})
        )
        assert response.status_code == 200

    async def test_non_owner_silent_200(
        self, endpoints: OAuthServerEndpoints, store: SQLiteInboundAuthStore
    ) -> None:
        _, access, _ = await _mint_initial_pair(endpoints)
        other_client_id = await _register_public_client(endpoints)
        response = await endpoints.revoke(
            _request_with_form({"token": access, "client_id": other_client_id})
        )
        assert response.status_code == 200
        # Original token NOT revoked — non-owner attempt silently no-ops.
        conn = sqlite3.connect(store._db_path)
        try:
            access_count = conn.execute(
                "SELECT COUNT(*) FROM inbound_tokens WHERE token_kind = 'access'"
            ).fetchone()[0]
        finally:
            conn.close()
        assert access_count == 1

    async def test_invalid_client_silent_200(self, endpoints: OAuthServerEndpoints) -> None:
        """RFC 7009 §2.2 — invalid client auth must NOT leak via 401."""
        response = await endpoints.revoke(
            _request_with_form({"token": "mcp_at_anything", "client_id": "mcp_client_unknown"})
        )
        assert response.status_code == 200


# =============================================================================
# DISABLED OAUTH
# =============================================================================


class TestDisabled:
    async def test_all_endpoints_404_when_disabled(
        self, store: SQLiteInboundAuthStore, connector_names: list[str]
    ) -> None:
        disabled = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=OAuthInboundConfig(enabled=False),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        assert (await disabled.register(_request_with_json({}))).status_code == 404
        assert (await disabled.authorize_get(_request_with_query({}))).status_code == 404
        assert (await disabled.authorize_post(_request_with_form({}))).status_code == 404
        assert (await disabled.token(_request_with_form({}))).status_code == 404
        assert (await disabled.revoke(_request_with_form({}))).status_code == 404


# =============================================================================
# UNIT TESTS (pure helpers)
# =============================================================================


class TestRateLimiter:
    def test_under_cap_allows(self) -> None:
        limiter = _DCRRateLimiter(max_per_window=3, window_seconds=10)
        assert limiter.allow("client-a")
        assert limiter.allow("client-a")
        assert limiter.allow("client-a")
        assert not limiter.allow("client-a")

    def test_separate_ips_independent(self) -> None:
        limiter = _DCRRateLimiter(max_per_window=1, window_seconds=10)
        assert limiter.allow("client-a")
        assert limiter.allow("client-b")
        assert not limiter.allow("client-a")


class TestXForwardedForGate:
    """X-Forwarded-For is honored only when the immediate client is a trusted proxy."""

    async def test_xff_trusted_proxy_honored(
        self, store: SQLiteInboundAuthStore, connector_names: list[str]
    ) -> None:
        # cap=1: a trusted proxy delivering two requests with different XFF
        # values should NOT trip the limiter, because the rate-limit key is the
        # forwarded IP, not the proxy IP.
        endpoints = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=_make_config(dcr_rate_limit_per_ip=1, trusted_proxy_ips=["10.0.0.1"]),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        first = await endpoints.register(
            _request_with_json_explicit_ips(
                _registration_payload(), immediate_ip="10.0.0.1", forwarded_for="1.2.3.4"
            )
        )
        second = await endpoints.register(
            _request_with_json_explicit_ips(
                _registration_payload(), immediate_ip="10.0.0.1", forwarded_for="5.6.7.8"
            )
        )
        assert first.status_code == 201
        assert second.status_code == 201

    async def test_xff_untrusted_proxy_ignored(
        self, store: SQLiteInboundAuthStore, connector_names: list[str]
    ) -> None:
        # Empty trusted_proxy_ips: the limiter MUST key on request.client.host
        # (203.0.113.10), not the spoofed XFF values. Two requests from the
        # same direct client hit the cap of 1.
        endpoints = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=_make_config(dcr_rate_limit_per_ip=1),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        first = await endpoints.register(
            _request_with_json_explicit_ips(
                _registration_payload(),
                immediate_ip="203.0.113.10",
                forwarded_for="1.2.3.4",
            )
        )
        second = await endpoints.register(
            _request_with_json_explicit_ips(
                _registration_payload(),
                immediate_ip="203.0.113.10",
                forwarded_for="5.6.7.8",
            )
        )
        assert first.status_code == 201
        assert second.status_code == 429


class TestConfidentialClientAuth:
    """Confidential clients authenticate via Basic header or client_secret form field."""

    async def test_confidential_client_basic_auth_via_token_endpoint(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        # Register a confidential client and capture its raw secret.
        register_response = await endpoints.register(
            _request_with_json(
                _registration_payload(token_endpoint_auth_method="client_secret_basic")
            )
        )
        register_body = _response_body(register_response)
        client_id = register_body["client_id"]
        raw_secret = register_body["client_secret"]

        # Drive the full auth_code flow with this confidential client so we
        # have a real code to exchange (PKCE rules apply regardless of
        # client_secret usage).
        params = _authorize_params(client_id) | {"action": "approve"}
        approve = await endpoints.authorize_post(_request_with_form(params))
        code = approve.headers["location"].split("code=", 1)[1].split("&", 1)[0]

        basic_header = base64.b64encode(f"{client_id}:{raw_secret}".encode()).decode()
        token_response = await endpoints.token(
            _request_with_form(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": GENERIC_REDIRECT_URI,
                    "code_verifier": _VALID_VERIFIER,
                    "resource": GENERIC_RESOURCE,
                },
                headers={"authorization": f"Basic {basic_header}"},
            )
        )
        assert token_response.status_code == 200
        assert _response_body(token_response)["access_token"].startswith("mcp_at_")

    async def test_confidential_client_wrong_secret_fails(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        register_response = await endpoints.register(
            _request_with_json(
                _registration_payload(token_endpoint_auth_method="client_secret_basic")
            )
        )
        client_id = _response_body(register_response)["client_id"]

        bad_header = base64.b64encode(f"{client_id}:wrong-secret".encode()).decode()
        # Grant params don't need to be real — the auth check runs before grant
        # dispatch and short-circuits on the bad secret.
        response = await endpoints.token(
            _request_with_form(
                {"grant_type": "authorization_code"},
                headers={"authorization": f"Basic {bad_header}"},
            )
        )
        assert response.status_code == 401
        assert _response_body(response)["error"] == "invalid_client"


class TestScopeSubset:
    def test_subset_passes(self) -> None:
        assert _scope_is_subset("a", "a b")

    def test_widening_blocked(self) -> None:
        assert not _scope_is_subset("a c", "a b")

    def test_equal_passes(self) -> None:
        assert _scope_is_subset("a b", "a b")


class TestKindsFromHint:
    def test_access_hint(self) -> None:
        assert _kinds_from_hint("access_token") == ("access",)

    def test_refresh_hint(self) -> None:
        assert _kinds_from_hint("refresh_token") == ("refresh",)

    def test_unknown_hint_tries_both(self) -> None:
        assert _kinds_from_hint("") == ("access", "refresh")
        assert _kinds_from_hint("nonsense") == ("access", "refresh")


# =============================================================================
# CONCURRENCY (atomic rotation under load)
# =============================================================================


class TestConcurrentRotation:
    """Two concurrent /token refresh calls on the same token — exactly one wins."""

    async def test_at_most_one_concurrent_rotation_succeeds(
        self, endpoints: OAuthServerEndpoints
    ) -> None:
        client_id, _, refresh = await _mint_initial_pair(endpoints)
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
        }
        responses = await asyncio.gather(
            endpoints.token(_request_with_form(dict(form))),
            endpoints.token(_request_with_form(dict(form))),
        )
        status_codes = sorted(r.status_code for r in responses)
        # At least one must succeed (200); the loser MUST be invalid_grant (400).
        # Both succeeding would mean replay-resistant rotation is broken.
        assert 200 in status_codes
        assert status_codes.count(200) == 1
        assert status_codes.count(400) == 1


# =============================================================================
# REGRESSION: _get_oauth_endpoints singleton (DCR rate-limit persistence)
# =============================================================================


class TestOAuthEndpointsSingleton:
    """Regression for the DCR-rate-limiter-reset bug.

    Original defect: ``broker.main._get_oauth_endpoints()`` constructed a fresh
    ``OAuthServerEndpoints`` on every call, which constructed a fresh
    ``_DCRRateLimiter`` with ``_events = {}``. The advertised 10/15min/IP
    cap was therefore never enforced — every request started from zero.

    Fix: the endpoints are initialized once during lifespan and the accessor
    returns the same instance, so ``_DCRRateLimiter._events`` accumulates
    state across requests.
    """

    async def test_factory_returns_same_instance_across_calls(
        self,
        store: SQLiteInboundAuthStore,
        connector_names: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from broker import main as broker_main

        singleton = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=_make_config(),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        monkeypatch.setattr(broker_main, "_oauth_endpoints", singleton)

        first = broker_main._get_oauth_endpoints()
        second = broker_main._get_oauth_endpoints()
        assert first is second
        assert first is singleton

    async def test_rate_limiter_state_persists_across_factory_calls(
        self,
        store: SQLiteInboundAuthStore,
        connector_names: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from broker import main as broker_main

        singleton = OAuthServerEndpoints(
            inbound_auth_store=store,
            config=_make_config(),
            connector_names_provider=lambda: connector_names,
            public_url=GENERIC_PUBLIC_URL,
        )
        monkeypatch.setattr(broker_main, "_oauth_endpoints", singleton)

        # Hit the limiter via two separate factory invocations — under the
        # original bug, each invocation would yield a fresh limiter and the
        # second call would see an empty `_events` dict for "1.2.3.4".
        broker_main._get_oauth_endpoints()._dcr_rate_limiter.allow("1.2.3.4")
        broker_main._get_oauth_endpoints()._dcr_rate_limiter.allow("1.2.3.4")
        assert len(singleton._dcr_rate_limiter._events["1.2.3.4"]) == 2

    async def test_factory_raises_when_oauth_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from broker import main as broker_main

        monkeypatch.setattr(broker_main, "_oauth_endpoints", None)
        with pytest.raises(RuntimeError, match="OAuthServerEndpoints not initialized"):
            broker_main._get_oauth_endpoints()
