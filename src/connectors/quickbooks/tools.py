"""
QuickBooks Online tool metadata (read-only v1).

One ``NativeToolMeta`` per tool — the ``input_schema`` is delivered verbatim to
LLMs via ``tools/list``, so it is the contract for what each tool accepts. Kept
separate from ``adapter.py`` so the (currently read-only) surface can grow into
write/CRUD tools without the adapter becoming unreadable.

Two families:
- Reports  → QBO ``/reports/{name}`` endpoint. Period reports take an optional
  start_date/end_date; aged reports take an optional as-of report_date.
- Lookups  → QBO ``/query`` endpoint. ``SELECT * FROM <Entity>`` with an optional
  result cap.
"""

from __future__ import annotations

from broker.connectors.native import NativeToolMeta

# === SHARED SCHEMA PIECES ===

# Default / ceiling for list (query) tools. QBO allows up to 1000 rows per query;
# we cap lower to keep tool payloads small enough for an LLM to reason over.
DEFAULT_QUERY_RESULTS = 20
MAX_QUERY_RESULTS = 100

_NO_ARGS_SCHEMA = {"type": "object", "properties": {}}


def _date_range_schema() -> dict:
    """Schema for period reports — optional start_date / end_date (YYYY-MM-DD)."""
    return {
        "type": "object",
        "properties": {
            "start_date": {
                "type": "string",
                "description": "Period start, YYYY-MM-DD (optional; QBO defaults if omitted).",
            },
            "end_date": {
                "type": "string",
                "description": "Period end, YYYY-MM-DD (optional; QBO defaults if omitted).",
            },
        },
    }


def _as_of_schema() -> dict:
    """Schema for aged reports — optional as-of report_date (YYYY-MM-DD)."""
    return {
        "type": "object",
        "properties": {
            "report_date": {
                "type": "string",
                "description": "As-of date, YYYY-MM-DD (optional; defaults to today).",
            },
        },
    }


def _list_schema(noun: str) -> dict:
    """Schema for lookup tools — an optional result cap."""
    return {
        "type": "object",
        "properties": {
            "max_results": {
                "type": "integer",
                "description": f"Max {noun} to return (1-{MAX_QUERY_RESULTS}, default {DEFAULT_QUERY_RESULTS}).",
                "default": DEFAULT_QUERY_RESULTS,
            },
        },
    }


# === REPORT TOOLS ===

PROFIT_AND_LOSS = NativeToolMeta(
    name="get_profit_and_loss",
    description="Profit & Loss (income statement) for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

BALANCE_SHEET = NativeToolMeta(
    name="get_balance_sheet",
    description="Balance Sheet for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

CASH_FLOW = NativeToolMeta(
    name="get_cash_flow",
    description="Statement of Cash Flows for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

TRIAL_BALANCE = NativeToolMeta(
    name="get_trial_balance",
    description="Trial Balance for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

GENERAL_LEDGER = NativeToolMeta(
    name="get_general_ledger",
    description="General Ledger detail for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

CUSTOMER_SALES = NativeToolMeta(
    name="get_customer_sales",
    description="Sales grouped by customer for a date range from QuickBooks Online.",
    input_schema=_date_range_schema(),
)

AGED_RECEIVABLES = NativeToolMeta(
    name="get_aged_receivables",
    description="Accounts Receivable aging summary (who owes you) from QuickBooks Online.",
    input_schema=_as_of_schema(),
)

AGED_PAYABLES = NativeToolMeta(
    name="get_aged_payables",
    description="Accounts Payable aging summary (what you owe) from QuickBooks Online.",
    input_schema=_as_of_schema(),
)

# === LOOKUP (QUERY) TOOLS ===

GET_COMPANY_INFO = NativeToolMeta(
    name="get_company_info",
    description="Get the connected QuickBooks company's profile (name, address, fiscal year).",
    input_schema=_NO_ARGS_SCHEMA,
)

LIST_CUSTOMERS = NativeToolMeta(
    name="list_customers",
    description="List customers in the connected QuickBooks company.",
    input_schema=_list_schema("customers"),
)

LIST_INVOICES = NativeToolMeta(
    name="list_invoices",
    description="List invoices in the connected QuickBooks company.",
    input_schema=_list_schema("invoices"),
)

LIST_ITEMS = NativeToolMeta(
    name="list_items",
    description="List products/services (items) in the connected QuickBooks company.",
    input_schema=_list_schema("items"),
)

LIST_VENDORS = NativeToolMeta(
    name="list_vendors",
    description="List vendors (suppliers) in the connected QuickBooks company.",
    input_schema=_list_schema("vendors"),
)

LIST_BILLS = NativeToolMeta(
    name="list_bills",
    description="List bills (vendor invoices) in the connected QuickBooks company.",
    input_schema=_list_schema("bills"),
)

LIST_ACCOUNTS = NativeToolMeta(
    name="list_accounts",
    description="List chart-of-accounts entries in the connected QuickBooks company.",
    input_schema=_list_schema("accounts"),
)

LIST_PAYMENTS = NativeToolMeta(
    name="list_payments",
    description="List customer payments in the connected QuickBooks company.",
    input_schema=_list_schema("payments"),
)
