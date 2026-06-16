"""
QuickBooks Online Connector Tests (read-only v1).

Covers: auto-registration + metadata, OAuth Basic-Auth override, realmId capture
from the callback, the read-only tool surface, realm threading via
provider_metadata, and tool execution against a stubbed QBO REST API.

Per the broker testing rules, only the outbound HTTP to QBO is mocked (respx);
the connector, client, query/report building, and JSON-RPC dispatch run for real.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from broker.connectors.registry import ConnectorRegistry

# Sandbox host is the client default with no QUICKBOOKS_* env set.
_QBO = "https://sandbox-quickbooks.api.intuit.com/v3/company"

EXPECTED_TOOLS = {
    "get_profit_and_loss",
    "get_balance_sheet",
    "get_cash_flow",
    "get_trial_balance",
    "get_general_ledger",
    "get_customer_sales",
    "get_aged_receivables",
    "get_aged_payables",
    "get_company_info",
    "list_customers",
    "list_invoices",
    "list_items",
    "list_vendors",
    "list_bills",
    "list_accounts",
    "list_payments",
}


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear connector registry before and after each test."""
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture
def qbo_connector():
    """Import the QuickBooks adapter and re-register if the registry was cleared."""
    from connectors.quickbooks.adapter import QuickBooksConnector

    connector = ConnectorRegistry.get("quickbooks")
    if connector is None:
        ConnectorRegistry.auto_register(QuickBooksConnector)
        connector = ConnectorRegistry.get("quickbooks")
    assert connector is not None
    return connector


# =============================================================================
# REGISTRATION & METADATA
# =============================================================================


class TestRegistration:
    def test_auto_registers_with_name_quickbooks(self, qbo_connector):
        assert qbo_connector.meta.name == "quickbooks"

    def test_display_name(self, qbo_connector):
        assert qbo_connector.meta.display_name == "QuickBooks Online"

    def test_is_native_connector(self, qbo_connector):
        assert qbo_connector.meta.mcp_url is None
        assert qbo_connector.meta.is_native

    def test_oauth_urls_are_intuit(self, qbo_connector):
        assert (
            qbo_connector.meta.oauth_authorize_url == "https://appcenter.intuit.com/connect/oauth2"
        )
        assert (
            qbo_connector.meta.oauth_token_url
            == "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
        )

    def test_accounting_scope(self, qbo_connector):
        assert qbo_connector.meta.scopes == ("com.intuit.quickbooks.accounting",)

    def test_supports_pkce(self, qbo_connector):
        assert qbo_connector.meta.supports_pkce is True

    def test_registers_sixteen_readonly_tools(self, qbo_connector):
        assert set(qbo_connector._tools.keys()) == EXPECTED_TOOLS

    def test_no_write_tools_registered(self, qbo_connector):
        # Read-only is enforced by the tool set (QBO has no read-only scope).
        for name in qbo_connector._tools:
            assert not name.startswith(("create_", "update_", "delete_"))

    def test_all_tools_opt_into_provider_metadata(self, qbo_connector):
        # Every QBO tool needs the realm, so every handler must receive metadata.
        for name, tool in qbo_connector._tools.items():
            assert tool.accepts_metadata, f"{name} must declare provider_metadata"


# =============================================================================
# OAUTH
# =============================================================================


class TestOAuth:
    def test_token_exchange_uses_basic_auth(self, qbo_connector):
        from base64 import b64decode

        from broker.models.connector_config import AppConnectorCredentials

        credentials = AppConnectorCredentials(client_id="my_id", client_secret="my_secret")
        headers, body_credentials = qbo_connector.build_token_request_auth(credentials)

        assert body_credentials == {}
        assert headers["Authorization"].startswith("Basic ")
        decoded = b64decode(headers["Authorization"].removeprefix("Basic ")).decode()
        assert decoded == "my_id:my_secret"


class TestCallbackParams:
    def test_captures_realm_id(self, qbo_connector):
        metadata = qbo_connector.parse_callback_params(
            {"code": "abc", "state": "xyz", "realmId": "1234567890"}
        )
        assert metadata == {"realm_id": "1234567890"}

    def test_no_realm_returns_empty(self, qbo_connector):
        assert qbo_connector.parse_callback_params({"code": "abc", "state": "xyz"}) == {}


# =============================================================================
# MCP DISPATCH
# =============================================================================


class TestDispatch:
    async def test_initialize_returns_server_info(self, qbo_connector):
        response = await qbo_connector.handle_mcp_request(
            method="initialize", params={}, request_id=1, access_token="t"
        )
        assert response["result"]["serverInfo"]["name"] == "quickbooks"

    async def test_tools_list_returns_readonly_set(self, qbo_connector):
        response = await qbo_connector.handle_mcp_request(
            method="tools/list", params={}, request_id=2, access_token="t"
        )
        names = {tool["name"] for tool in response["result"]["tools"]}
        assert names == EXPECTED_TOOLS

    async def test_missing_realm_dispatch_returns_iserror(self, qbo_connector):
        # No company connected → provider_metadata empty → clean isError, not a crash.
        response = await qbo_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "get_company_info", "arguments": {}},
            request_id=3,
            access_token="t",
            provider_metadata={},
        )
        assert response["result"]["isError"] is True
        assert "No QuickBooks company" in response["result"]["content"][0]["text"]


# =============================================================================
# TOOL EXECUTION (QBO HTTP stubbed)
# =============================================================================


class TestMissingRealm:
    async def test_handler_raises_without_realm(self, qbo_connector):
        with pytest.raises(ValueError, match="No QuickBooks company"):
            await qbo_connector.get_company_info(access_token="t", provider_metadata={})


class TestControlCharGuard:
    """Native dispatch bypasses the proxy's control-char guard, so the connector
    must reject CRLF in the token (Authorization header) or realm (URL path)."""

    async def test_control_chars_in_token_rejected(self, qbo_connector):
        with pytest.raises(ValueError, match="control characters"):
            await qbo_connector.get_company_info(
                access_token="tok\r\nX-Injected: evil",
                provider_metadata={"realm_id": "123"},
            )

    async def test_control_chars_in_realm_rejected(self, qbo_connector):
        with pytest.raises(ValueError, match="control characters"):
            await qbo_connector.get_company_info(
                access_token="tok",
                provider_metadata={"realm_id": "123\r\nevil"},
            )


class TestLookups:
    @respx.mock
    async def test_get_company_info_returns_query_response(self, qbo_connector):
        route = respx.get(url__startswith=f"{_QBO}/123/query").mock(
            return_value=httpx.Response(
                200, json={"QueryResponse": {"CompanyInfo": [{"CompanyName": "Acme"}]}}
            )
        )
        blocks = await qbo_connector.get_company_info(
            access_token="tok", provider_metadata={"realm_id": "123"}
        )
        assert route.called
        # Bearer token + minorversion are injected by the client.
        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer tok"
        assert request.url.params["minorversion"]
        parsed = json.loads(blocks[0]["text"])
        assert parsed["CompanyInfo"][0]["CompanyName"] == "Acme"

    @respx.mock
    async def test_list_customers_builds_select_and_clamps(self, qbo_connector):
        route = respx.get(url__startswith=f"{_QBO}/123/query").mock(
            return_value=httpx.Response(200, json={"QueryResponse": {"Customer": []}})
        )
        # Above the 100 cap → clamped.
        await qbo_connector.list_customers(
            access_token="tok", provider_metadata={"realm_id": "123"}, max_results=500
        )
        statement = route.calls.last.request.url.params["query"]
        assert statement == "SELECT * FROM Customer MAXRESULTS 100"


class TestReports:
    @respx.mock
    async def test_profit_and_loss_passes_date_range(self, qbo_connector):
        route = respx.get(url__startswith=f"{_QBO}/123/reports/ProfitAndLoss").mock(
            return_value=httpx.Response(200, json={"Header": {"ReportName": "ProfitAndLoss"}})
        )
        blocks = await qbo_connector.get_profit_and_loss(
            access_token="tok",
            provider_metadata={"realm_id": "123"},
            start_date="2026-01-01",
            end_date="2026-03-31",
        )
        params = route.calls.last.request.url.params
        assert params["start_date"] == "2026-01-01"
        assert params["end_date"] == "2026-03-31"
        parsed = json.loads(blocks[0]["text"])
        assert parsed["Header"]["ReportName"] == "ProfitAndLoss"

    @respx.mock
    async def test_aged_receivables_passes_report_date(self, qbo_connector):
        route = respx.get(url__startswith=f"{_QBO}/123/reports/AgedReceivables").mock(
            return_value=httpx.Response(200, json={"Header": {"ReportName": "AgedReceivables"}})
        )
        await qbo_connector.get_aged_receivables(
            access_token="tok", provider_metadata={"realm_id": "123"}, report_date="2026-06-15"
        )
        assert route.calls.last.request.url.params["report_date"] == "2026-06-15"

    @respx.mock
    async def test_auth_error_surfaces_sanitized_message(self, qbo_connector):
        respx.get(url__startswith=f"{_QBO}/123/reports/BalanceSheet").mock(
            return_value=httpx.Response(401, json={"Fault": {"Error": [{"Detail": "secret"}]}})
        )
        with pytest.raises(ValueError, match="auth/permission") as exc_info:
            await qbo_connector.get_balance_sheet(
                access_token="tok", provider_metadata={"realm_id": "123"}
            )
        # The QBO error body is never echoed back to the client.
        assert "secret" not in str(exc_info.value)


# =============================================================================
# END-TO-END DISPATCH (realm flows from provider_metadata → handler → REST URL)
# =============================================================================


class TestDispatchEndToEnd:
    @respx.mock
    async def test_realm_threads_into_request_url(self, qbo_connector):
        route = respx.get(url__startswith=f"{_QBO}/999/query").mock(
            return_value=httpx.Response(
                200, json={"QueryResponse": {"CompanyInfo": [{"CompanyName": "Beta"}]}}
            )
        )
        response = await qbo_connector.handle_mcp_request(
            method="tools/call",
            params={"name": "get_company_info", "arguments": {}},
            request_id=10,
            access_token="tok",
            provider_metadata={"realm_id": "999"},
        )
        assert route.called  # company 999, proving realm threaded end to end
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed["CompanyInfo"][0]["CompanyName"] == "Beta"

    @respx.mock
    async def test_client_supplied_metadata_arg_is_ignored(self, qbo_connector):
        # A client must not be able to spoof realm via the tool arguments;
        # the broker-injected provider_metadata is authoritative.
        respx.get(url__startswith=f"{_QBO}/999/query").mock(
            return_value=httpx.Response(200, json={"QueryResponse": {"CompanyInfo": []}})
        )
        spoof = respx.get(url__startswith=f"{_QBO}/000/query").mock(
            return_value=httpx.Response(200, json={"QueryResponse": {"CompanyInfo": []}})
        )
        await qbo_connector.handle_mcp_request(
            method="tools/call",
            params={
                "name": "get_company_info",
                "arguments": {"provider_metadata": {"realm_id": "000"}},
            },
            request_id=11,
            access_token="tok",
            provider_metadata={"realm_id": "999"},
        )
        assert not spoof.called  # spoofed realm 000 never used


# =============================================================================
# CALLBACK → STORE GLUE (main.py wiring captures realmId onto the connection)
# =============================================================================


class TestCallbackPersistsRealm:
    """The OAuth callback must run the real connector's parse_callback_params and
    persist the realm onto the stored connection (main.py:_exchange_and_store_token).

    Exercises the real connector + real encrypted store; only the OAuth machinery
    that is tested elsewhere (state validation, token exchange, credential
    resolution) is stubbed. Catches a regression where the capture/model_copy glue
    is removed — the unit tests of the pieces would not.
    """

    def test_callback_captures_realm_into_store(self, qbo_connector, tmp_path):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from cryptography.fernet import Fernet
        from fastapi.testclient import TestClient

        import broker.main as main
        from broker.models.connection import AppConnection
        from broker.services.store import EncryptedTokenStore, SQLiteTokenStore

        store = EncryptedTokenStore(
            keys=[Fernet.generate_key().decode()],
            delegate=SQLiteTokenStore(db_path=str(tmp_path / "tokens.db")),
        )

        oauth = MagicMock()
        oauth.decode_state.return_value = {"app_key": "acme:app1"}
        # exchange_code returns a connection WITHOUT realm; the callback glue adds it.
        oauth.exchange_code = AsyncMock(
            return_value=(
                AppConnection(connector_name="quickbooks", access_token="tok"),
                "acme:app1",
            )
        )

        client = TestClient(main.app)
        with (
            patch.object(main, "_get_connector_or_404", return_value=qbo_connector),
            patch.object(main, "_get_store", return_value=store),
            patch.object(main, "_get_oauth_handler", return_value=oauth),
            patch.object(main, "_get_settings", return_value=MagicMock()),
            patch.object(main, "_get_discovery", return_value=None),
            patch.object(main, "resolve_oauth", new=AsyncMock(return_value=MagicMock())),
            patch.object(main, "_resolve_oauth_success_url", return_value="http://localhost/ok"),
        ):
            response = client.get(
                "/oauth/quickbooks/callback?code=c&state=s&realmId=1234567890",
                follow_redirects=False,
            )

        assert response.status_code in (302, 307)
        saved = asyncio.run(store.get("acme:app1", "quickbooks"))
        assert saved is not None
        assert saved.provider_metadata == {"realm_id": "1234567890"}
        assert saved.access_token == "tok"
