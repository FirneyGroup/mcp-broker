"""Tests for ``scripts/connect.py`` show-config helpers.

Covers the dual-auth output added alongside the inbound OAuth feature:
- ``_oauth_config`` extracts ``broker.oauth.enabled`` + ``allowed_redirect_uris``
  safely whether the section is present, partial, or missing.
- ``_show_mcp_config`` honors ``ctx.auth_mode`` — apikey, oauth, or both.
- ``_show_apikey_block`` emits the X-Broker-Key shape.
- ``_show_oauth_block`` emits the URL-paste shape and reflects whether
  ``oauth_enabled`` is true and whether ``allowed_redirect_uris`` is populated.

These tests exercise the *output contract* the operator depends on — a
breaking change to the JSON shape or the OAuth status line would be a public
surface change per AGENTS.md's `./start CLI subcommands and output formats`
clause.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError


def _load_connect_module():
    """Load ``scripts/connect.py`` as a module despite the unusual layout.

    The script lives outside ``src/`` and is run as ``python scripts/connect.py``
    in production, so it has no canonical importable name. Synthesize one
    here for the test session.
    """
    repo_root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location(
        "broker_connect_script",
        repo_root / "scripts" / "connect.py",
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 -- test setup invariant
    module = importlib.util.module_from_spec(spec)
    sys.modules["broker_connect_script"] = module
    spec.loader.exec_module(module)
    return module


connect = _load_connect_module()


# =============================================================================
# _oauth_config
# =============================================================================


class TestOauthConfig:
    def test_missing_section_defaults_to_disabled(self) -> None:
        enabled, uris = connect._oauth_config({"broker": {}})
        assert enabled is False
        assert uris == []

    def test_missing_broker_key_does_not_crash(self) -> None:
        enabled, uris = connect._oauth_config({})
        assert enabled is False
        assert uris == []

    def test_enabled_true_with_allowlist(self) -> None:
        settings = {
            "broker": {
                "oauth": {
                    "enabled": True,
                    "allowed_redirect_uris": [
                        "https://claude.ai/api/mcp/auth_callback",
                        "https://claude.com/api/mcp/auth_callback",
                    ],
                }
            }
        }
        enabled, uris = connect._oauth_config(settings)
        assert enabled is True
        assert uris == [
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
        ]

    def test_null_allowed_uris_normalised_to_empty_list(self) -> None:
        # YAML can produce `null` for an explicit empty list — the operator
        # might write `allowed_redirect_uris:` with no value. Don't crash.
        settings = {"broker": {"oauth": {"enabled": True, "allowed_redirect_uris": None}}}
        enabled, uris = connect._oauth_config(settings)
        assert enabled is True
        assert uris == []


# =============================================================================
# Fixtures + context factory
# =============================================================================


GENERIC_BROKER_URL = "https://broker.example.com"
GENERIC_APP_KEY = "acme:claude_ai"
GENERIC_BROKER_KEY = "br_synthetic_test_value"  # noqa: S105 -- synthetic test key, not a credential


def _ctx(**overrides: Any):
    """Build an ``McpConfigContext`` with generic defaults."""
    defaults: dict[str, Any] = {
        "broker_url": GENERIC_BROKER_URL,
        "app_key": GENERIC_APP_KEY,
        "broker_key": GENERIC_BROKER_KEY,
        "oauth_enabled": False,
        "allowed_redirect_uris": [],
        "auth_mode": "both",
    }
    defaults.update(overrides)
    return connect.McpConfigContext(**defaults)


def _server_json(command: str) -> dict[str, Any]:
    """Parse the server-config JSON back out of a rendered claude command.

    ``shlex.split`` is the inverse of the renderer's ``shlex.quote``; the final
    token is the server JSON. Round-tripping through it proves the shell quoting
    is correct as well as the JSON shape.
    """
    return json.loads(shlex.split(command)[-1])


# =============================================================================
# _show_mcp_config — auth_mode dispatch
# =============================================================================


class TestShowMcpConfigDispatch:
    def test_apikey_only_prints_headers_block_no_oauth_block(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="apikey"))
        out = capsys.readouterr().out
        assert "── slack ──" in out
        assert "X-Broker-Key" in out
        assert "Bearer" not in out
        assert "OAuth" not in out

    def test_oauth_only_prints_url_block_no_headers(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="oauth"))
        out = capsys.readouterr().out
        assert "── slack ──" in out
        assert "OAuth 2.1" in out
        assert f"{GENERIC_BROKER_URL}/proxy/slack/mcp" in out
        # Headers block must be absent — no static credential on the OAuth path.
        assert "X-Broker-Key" not in out
        assert GENERIC_BROKER_KEY not in out

    def test_both_prints_both_blocks(self, capsys: pytest.CaptureFixture[str]) -> None:
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="both"))
        out = capsys.readouterr().out
        assert "X-Broker-Key" in out
        assert "OAuth 2.1" in out
        # Apikey appears first (operator scanning for headers should see them).
        assert out.index("X-Broker-Key") < out.index("OAuth 2.1")


# =============================================================================
# _show_apikey_block — header contract
# =============================================================================


class TestShowApikeyBlock:
    def test_emits_app_id_and_broker_key_headers(self, capsys: pytest.CaptureFixture[str]) -> None:
        connect._show_apikey_block("slack", "streamable_http", _ctx())
        out = capsys.readouterr().out
        assert f'"X-App-Id": "{GENERIC_APP_KEY}"' in out
        assert f'"X-Broker-Key": "{GENERIC_BROKER_KEY}"' in out
        assert f'"url": "{GENERIC_BROKER_URL}/proxy/slack/mcp"' in out
        assert '"transport": "streamable_http"' in out


# =============================================================================
# _show_oauth_block — status line reflects oauth_enabled
# =============================================================================


class TestShowOauthBlock:
    def test_enabled_with_allowlist_shows_ready_and_lists_uris(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        uris = [
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
        ]
        connect._show_oauth_block(
            "slack",
            _ctx(oauth_enabled=True, allowed_redirect_uris=uris),
        )
        out = capsys.readouterr().out
        assert "broker.oauth.enabled = true" in out
        assert "ready to handshake" in out
        for uri in uris:
            assert uri in out
        assert f"{GENERIC_BROKER_URL}/proxy/slack/mcp" in out

    def test_enabled_but_empty_allowlist_warns(self, capsys: pytest.CaptureFixture[str]) -> None:
        connect._show_oauth_block("slack", _ctx(oauth_enabled=True, allowed_redirect_uris=[]))
        out = capsys.readouterr().out
        assert "WARNING" in out
        assert "allowed_redirect_uris is empty" in out

    def test_disabled_shows_dormant_status_and_enable_hint(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        connect._show_oauth_block("slack", _ctx(oauth_enabled=False))
        out = capsys.readouterr().out
        assert "broker.oauth.enabled = false" in out
        assert "dormant" in out
        # Operator should see the actionable next step inline.
        assert "broker.oauth.enabled" in out
        assert "broker.oauth.app_key" in out

    def test_does_not_leak_static_broker_key(self, capsys: pytest.CaptureFixture[str]) -> None:
        """The OAuth block is for third-party MCP clients who should NEVER
        see a static broker key. Regression guard against the obvious bug
        where the URL-only block accidentally interpolates ctx.broker_key."""
        connect._show_oauth_block(
            "slack", _ctx(oauth_enabled=True, allowed_redirect_uris=["https://x/"])
        )
        out = capsys.readouterr().out
        assert GENERIC_BROKER_KEY not in out


# =============================================================================
# McpConfigContext — Pydantic invariants
# =============================================================================


class TestMcpConfigContext:
    def test_frozen_rejects_mutation(self) -> None:
        ctx = _ctx()
        with pytest.raises(ValidationError):
            ctx.broker_key = "different"

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            connect.McpConfigContext(
                broker_url=GENERIC_BROKER_URL,
                app_key=GENERIC_APP_KEY,
                broker_key=GENERIC_BROKER_KEY,
                oauth_enabled=False,
                allowed_redirect_uris=[],
                auth_mode="both",
                unknown_field="oops",
            )

    @pytest.mark.parametrize("mode", ["apikey", "oauth", "both"])
    def test_valid_auth_modes_accepted(self, mode: str) -> None:
        ctx = _ctx(auth_mode=mode)
        assert ctx.auth_mode == mode

    def test_invalid_auth_mode_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _ctx(auth_mode="other")


# =============================================================================
# _render_claude_command — runnable `claude mcp add-json` one-liner
# =============================================================================


class TestRenderClaudeCommand:
    def test_command_prefix_and_server_name(self) -> None:
        tokens = shlex.split(connect._render_claude_command("slack", "streamable_http", _ctx()))
        # Server name is `{connector}-broker` per the documented convention.
        assert tokens[:4] == ["claude", "mcp", "add-json", "slack-broker"]

    def test_apikey_headers_url_and_http_type(self) -> None:
        server = _server_json(connect._render_claude_command("slack", "streamable_http", _ctx()))
        assert server["type"] == "http"
        assert server["url"] == f"{GENERIC_BROKER_URL}/proxy/slack/mcp"
        assert server["headers"]["X-App-Id"] == GENERIC_APP_KEY
        assert server["headers"]["X-Broker-Key"] == GENERIC_BROKER_KEY

    def test_sse_transport_maps_to_sse_type(self) -> None:
        server = _server_json(connect._render_claude_command("hubspot", "sse", _ctx()))
        assert server["type"] == "sse"

    def test_unknown_transport_defaults_to_http(self) -> None:
        server = _server_json(connect._render_claude_command("slack", "weird", _ctx()))
        assert server["type"] == "http"

    def test_cf_access_headers_included_when_env_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Stays in lockstep with _show_apikey_block: both source CF-Access from env.
        monkeypatch.setenv("CF_ACCESS_CLIENT_ID", "cf-id-value")
        monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "cf-secret-value")
        server = _server_json(connect._render_claude_command("slack", "streamable_http", _ctx()))
        assert server["headers"]["CF-Access-Client-Id"] == "cf-id-value"
        assert server["headers"]["CF-Access-Client-Secret"] == "cf-secret-value"

    def test_cf_access_headers_absent_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Fail-closed: a half-configured environment must not emit a lone CF header.
        monkeypatch.delenv("CF_ACCESS_CLIENT_ID", raising=False)
        monkeypatch.delenv("CF_ACCESS_CLIENT_SECRET", raising=False)
        server = _server_json(connect._render_claude_command("slack", "streamable_http", _ctx()))
        assert "CF-Access-Client-Id" not in server["headers"]
        assert "CF-Access-Client-Secret" not in server["headers"]


# =============================================================================
# _show_mcp_config — runnable command rides the API-key shape only
# =============================================================================


class TestShowMcpConfigClaudeCommand:
    def test_apikey_mode_prints_runnable_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="apikey"))
        assert "claude mcp add-json slack-broker" in capsys.readouterr().out

    def test_both_mode_prints_runnable_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="both"))
        assert "claude mcp add-json slack-broker" in capsys.readouterr().out

    def test_oauth_mode_omits_runnable_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        # The OAuth shape has no static headers, so no runnable static-auth command.
        connect._show_mcp_config("slack", "streamable_http", _ctx(auth_mode="oauth"))
        assert "claude mcp add-json" not in capsys.readouterr().out


class TestRunConnectFlowHonorsAuthMode:
    """Regression: the post-connect summary must honor --auth, not hardcode "both".

    Before the fix, _run_connect_flow built the context with auth_mode="both", so
    `./start connect --auth=oauth` still printed the static X-Broker-Key block.
    """

    @staticmethod
    def _stub_network(monkeypatch: pytest.MonkeyPatch) -> None:
        # Stub the token/browser/poll/transport steps so only the summary runs.
        monkeypatch.setattr(connect, "_create_connect_token", lambda *a, **k: "ct_test")
        monkeypatch.setattr(
            connect, "_get_authorize_url", lambda *a, **k: "https://api.example/authorize"
        )
        monkeypatch.setattr(connect, "_open_browser", lambda *a, **k: None)
        monkeypatch.setattr(connect, "_poll_until_connected", lambda *a, **k: True)
        monkeypatch.setattr(connect, "_get_connector_transport", lambda *a, **k: "streamable_http")

    @staticmethod
    def _run(auth_mode: str) -> None:
        connect._run_connect_flow(
            GENERIC_BROKER_URL,
            "slack",
            GENERIC_APP_KEY,
            GENERIC_BROKER_KEY,
            "unused",
            False,
            [],
            auth_mode,
        )

    def test_oauth_mode_summary_omits_static_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._stub_network(monkeypatch)
        self._run("oauth")
        out = capsys.readouterr().out
        assert "X-Broker-Key" not in out
        assert GENERIC_BROKER_KEY not in out

    def test_both_mode_summary_includes_static_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._stub_network(monkeypatch)
        self._run("both")
        assert "X-Broker-Key" in capsys.readouterr().out
