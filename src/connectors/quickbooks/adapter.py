"""
QuickBooks Online Connector (Native, read-only v1).

Flavour: Native — Intuit ships only a single-tenant, stdio Node MCP server, so we
wrap the QBO v3 REST API in-process instead. The broker drives Intuit OAuth and
injects a per-app token; the company id (``realmId``) is captured from the OAuth
callback (see ``parse_callback_params``) into ``provider_metadata`` and read back
here for every request.

Scope: read-only — reports + lookups. There is NO separate read-only OAuth scope
in QuickBooks (only ``com.intuit.quickbooks.accounting``), so "read-only" is
enforced purely by which tools are registered. Write/CRUD tools are deferred; see
SETUP.md for the coverage matrix.

Auto-registers on import via NativeConnector.__init_subclass__.
Reference example: src/connectors/twitter/adapter.py
"""

from __future__ import annotations

import json
from base64 import b64encode
from typing import Any

from broker.connectors.base import contains_control_chars
from broker.connectors.native import NativeConnector, native_tool
from broker.models.connector_config import AppConnectorCredentials, ConnectorMeta
from connectors.quickbooks import tools
from connectors.quickbooks.client import QboContext, QuickBooksClient

# === HELPERS ===


def _mcp_text_content(payload: Any) -> list[dict[str, Any]]:
    """Wrap a payload as a single MCP text content block."""
    return [{"type": "text", "text": json.dumps(payload, default=str)}]


# Report handlers receive their optional date filters via **params (not explicit
# keyword args) to stay within the connector's 4-arg limit; the JSON schema in
# tools.py is the LLM-facing contract for what each accepts. These extractors
# whitelist the known keys AND require string values, so an unexpected key or a
# malformed type from a raw client can never reach the QBO query string.
def _date_range(params: dict[str, Any]) -> dict[str, str]:
    """Extract the period-report date filters a client may have supplied."""
    return {
        key: params[key]
        for key in ("start_date", "end_date")
        if isinstance(params.get(key), str) and params[key]
    }


def _as_of(params: dict[str, Any]) -> dict[str, str]:
    """Extract the aged-report as-of date a client may have supplied."""
    return {
        key: params[key]
        for key in ("report_date",)
        if isinstance(params.get(key), str) and params[key]
    }


def _select(entity: str, max_results: int) -> str:
    """Build a read-only QBO query for a fixed entity.

    ``entity`` is always a hardcoded constant below (never client input), so there
    is no injection surface; ``max_results`` is clamped to the supported range.
    """
    capped = max(1, min(int(max_results), tools.MAX_QUERY_RESULTS))
    return f"SELECT * FROM {entity} MAXRESULTS {capped}"  # noqa: S608 -- entity is a hardcoded constant (never client input); capped is an int


# === CONNECTOR ===


class QuickBooksConnector(NativeConnector):
    """QuickBooks Online native connector — read-only reports + lookups."""

    meta = ConnectorMeta(
        name="quickbooks",
        display_name="QuickBooks Online",
        # mcp_url left unset → in-process native dispatch.
        oauth_authorize_url="https://appcenter.intuit.com/connect/oauth2",
        oauth_token_url="https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",  # noqa: S106 -- endpoint URL, not a password
        # QBO has no read-only scope; read-only is enforced by the tool set, not the scope.
        scopes=("com.intuit.quickbooks.accounting",),
        # supports_pkce defaults True — Intuit supports PKCE S256.
    )

    def __init__(self) -> None:
        """Create the connector with one shared QBO REST client (env-resolved base URL)."""
        # One client per connector instance; base URL resolved from the environment.
        self._client = QuickBooksClient()

    # --- OAuth overrides ---

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """Intuit's token endpoint uses HTTP Basic Auth (client_secret_basic)."""
        encoded = b64encode(
            f"{credentials.client_id}:{credentials.client_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {encoded}"}, {}

    def parse_callback_params(self, query_params: dict[str, str]) -> dict[str, str]:
        """Capture the company id Intuit returns on the OAuth callback as ``realmId``.

        Every QBO REST call is scoped to one company (``/v3/company/{realmId}/...``),
        and the realmId arrives only on the callback redirect — not in the token
        response — so it is captured here into provider_metadata. Intuit realm IDs
        are numeric; validating the shape at this trust boundary keeps a malformed
        value out of the request path and fails fast on a bad callback.
        """
        realm_id = query_params.get("realmId")
        if not realm_id or not realm_id.isdigit():
            return {}
        return {"realm_id": realm_id}

    # --- Internal ---

    def _context(self, access_token: str, provider_metadata: dict[str, str] | None) -> QboContext:
        """Build the QBO request context, requiring a connected company."""
        realm_id = (provider_metadata or {}).get("realm_id")
        if not realm_id:
            raise ValueError(
                "No QuickBooks company is connected for this app. Complete the "
                "QuickBooks OAuth connect so the broker captures the company (realmId)."
            )
        # Native connectors bypass the proxy's contains_control_chars guard, so enforce
        # it here: the token goes into an Authorization header and realm_id into the URL
        # path — a CRLF in either could split the header or the request line.
        if contains_control_chars(access_token) or contains_control_chars(realm_id):
            raise ValueError("QuickBooks credentials contain control characters")
        return QboContext(access_token=access_token, realm_id=realm_id)

    async def _report(
        self, context: QboContext, report_name: str, params: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Fetch a report and wrap it as MCP content."""
        report = await self._client.report(context, report_name, params)
        return _mcp_text_content(report)

    async def _list(
        self, context: QboContext, entity: str, max_results: int
    ) -> list[dict[str, Any]]:
        """Query a fixed entity and wrap the QueryResponse as MCP content."""
        query_response = await self._client.query(context, _select(entity, max_results))
        return _mcp_text_content(query_response.get("QueryResponse", query_response))

    # --- Report tools (period: start_date/end_date) ---

    @native_tool(tools.PROFIT_AND_LOSS)
    async def get_profit_and_loss(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Profit & Loss report for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "ProfitAndLoss", _date_range(params))

    @native_tool(tools.BALANCE_SHEET)
    async def get_balance_sheet(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Balance Sheet report for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "BalanceSheet", _date_range(params))

    @native_tool(tools.CASH_FLOW)
    async def get_cash_flow(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Statement of Cash Flows for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "CashFlow", _date_range(params))

    @native_tool(tools.TRIAL_BALANCE)
    async def get_trial_balance(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Trial Balance report for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "TrialBalance", _date_range(params))

    @native_tool(tools.GENERAL_LEDGER)
    async def get_general_ledger(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """General Ledger detail for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "GeneralLedger", _date_range(params))

    @native_tool(tools.CUSTOMER_SALES)
    async def get_customer_sales(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Sales grouped by customer for a date range."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "CustomerSales", _date_range(params))

    # --- Report tools (aged: report_date) ---

    @native_tool(tools.AGED_RECEIVABLES)
    async def get_aged_receivables(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Accounts Receivable aging summary."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "AgedReceivables", _as_of(params))

    @native_tool(tools.AGED_PAYABLES)
    async def get_aged_payables(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None, **params: Any
    ) -> list[dict[str, Any]]:
        """Accounts Payable aging summary."""
        context = self._context(access_token, provider_metadata)
        return await self._report(context, "AgedPayables", _as_of(params))

    # --- Lookup tools (QBO query) ---

    @native_tool(tools.GET_COMPANY_INFO)
    async def get_company_info(
        self, *, access_token: str, provider_metadata: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        """Get the connected company's profile."""
        context = self._context(access_token, provider_metadata)
        query_response = await self._client.query(context, "SELECT * FROM CompanyInfo")
        return _mcp_text_content(query_response.get("QueryResponse", query_response))

    @native_tool(tools.LIST_CUSTOMERS)
    async def list_customers(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List customers in the connected QuickBooks company."""
        return await self._list(
            self._context(access_token, provider_metadata), "Customer", max_results
        )

    @native_tool(tools.LIST_INVOICES)
    async def list_invoices(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List invoices in the connected QuickBooks company."""
        return await self._list(
            self._context(access_token, provider_metadata), "Invoice", max_results
        )

    @native_tool(tools.LIST_ITEMS)
    async def list_items(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List products/services (items)."""
        return await self._list(self._context(access_token, provider_metadata), "Item", max_results)

    @native_tool(tools.LIST_VENDORS)
    async def list_vendors(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List vendors (suppliers)."""
        return await self._list(
            self._context(access_token, provider_metadata), "Vendor", max_results
        )

    @native_tool(tools.LIST_BILLS)
    async def list_bills(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List bills (vendor invoices)."""
        return await self._list(self._context(access_token, provider_metadata), "Bill", max_results)

    @native_tool(tools.LIST_ACCOUNTS)
    async def list_accounts(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List chart-of-accounts entries."""
        return await self._list(
            self._context(access_token, provider_metadata), "Account", max_results
        )

    @native_tool(tools.LIST_PAYMENTS)
    async def list_payments(
        self,
        *,
        access_token: str,
        provider_metadata: dict[str, str] | None = None,
        max_results: int = tools.DEFAULT_QUERY_RESULTS,
    ) -> list[dict[str, Any]]:
        """List customer payments."""
        return await self._list(
            self._context(access_token, provider_metadata), "Payment", max_results
        )
