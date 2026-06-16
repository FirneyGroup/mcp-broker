# QuickBooks Online — Connector Setup

Flavour: **Native** (read-only v1). Intuit ships only a single-tenant, stdio Node
MCP server, so the broker wraps the QuickBooks Online v3 REST API in-process
instead. The broker drives Intuit OAuth and injects a per-app token; the company
id (`realmId`) is captured from the OAuth callback into the connection's
`provider_metadata` and used for every request.

## 1. Register an Intuit app (get client credentials)

1. Sign in at the [Intuit Developer portal](https://developer.intuit.com/) and
   create an app under **QuickBooks Online and Payments**.
2. From the app's **Keys & credentials**, copy the **Client ID** and
   **Client Secret** for the environment you want:
   - **Development** keys → sandbox companies (`sandbox-quickbooks.api.intuit.com`)
   - **Production** keys → real companies (`quickbooks.api.intuit.com`)
3. Add the redirect URI under **Redirect URIs** (must match exactly):
   - Dev: `http://localhost:8002/oauth/quickbooks/callback`
   - Prod: `https://<your-broker-domain>/oauth/quickbooks/callback`

   > Intuit requires production redirect URIs to be **HTTPS**. `http://localhost`
   > is accepted **only** with development/sandbox keys — production keys must use
   > an HTTPS callback.

## 2. Required scope

- `com.intuit.quickbooks.accounting` — read/write access to the company's
  accounting data.

> **Read-only is enforced by the tool set, not the scope.** QuickBooks has no
> read-only OAuth scope; the only accounting scope grants write too. This
> connector currently registers **only read tools**, so no write can occur. Do
> not add write tools without an explicit decision (see the coverage matrix).

## 3. Provider specifics

- **OAuth endpoints** (set in `adapter.py`, same for sandbox and production):
  - Authorize: `https://appcenter.intuit.com/connect/oauth2`
  - Token: `https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer`
  - (Reference only — the broker uses the static endpoints above, not discovery:
    OpenID config is at `https://developer.api.intuit.com/.well-known/openid_configuration`,
    sandbox `…/openid_sandbox_configuration`.)
- **Token exchange:** HTTP Basic Auth (`client_secret_basic`) — handled by
  `build_token_request_auth`.
- **PKCE:** S256, supported — handled by the broker.
- **Token lifetimes:** the access token lasts **3600s (1h)**; the refresh token is
  valid up to **~100 days** and its value may rotate roughly every 24h. The broker
  persists the latest refresh token automatically on each refresh.
- **API version:** requests pin `minorversion=75` (Intuit deprecated 1–74 in
  Aug 2025; 75 is the current default — see `client.py`).
- **realmId:** returned as a query param on the OAuth callback and captured via
  `parse_callback_params`. One connection = one company.

## Operational notes / limits

- **Environment is fixed at startup.** `QUICKBOOKS_ENVIRONMENT` (and the
  `QUICKBOOKS_API_BASE_URL` override) are read once when the connector is
  constructed — connectors are process-wide singletons. Changing them requires a
  **broker restart**, and one broker instance serves a single QBO environment
  (all-sandbox or all-production), not a per-tenant mix.
- **Lists are capped, not paginated.** Lookup tools return at most 100 rows and do
  not page (`MAXRESULTS` only, no `STARTPOSITION`). For a company with more rows,
  the result is silently truncated to the first 100 in this read-only v1 —
  pagination is a deferred enhancement (see the coverage matrix).

## 4. Broker configuration

`.env`:

```bash
QUICKBOOKS_CLIENT_ID=<your-client-id>
QUICKBOOKS_CLIENT_SECRET=<your-client-secret>
# sandbox (default) | production — selects the QBO API host
QUICKBOOKS_ENVIRONMENT=sandbox
```

`settings.yaml`:

```yaml
broker:
  connectors:
    - quickbooks            # add to the list

clients:
  my_company:
    app1:
      allowed_connectors: [..., quickbooks]   # or [] for all

apps:
  my_company:
    app1:
      quickbooks:
        client_id: ${QUICKBOOKS_CLIENT_ID}
        client_secret: ${QUICKBOOKS_CLIENT_SECRET}
```

## 5. Connect and verify

```bash
./start start
./start connect            # choose quickbooks → Intuit consent → pick a company
./start create-key         # → X-Broker-Key for the MCP client
```

```bash
curl -s -X POST http://localhost:8002/proxy/quickbooks/mcp \
  -H "X-Broker-Key: $BROKER_KEY" -H "X-App-Id: my_company:app1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 -m json.tool
```

A `tools/call` for `get_company_info` then returns the connected company — proof
that OAuth → realm capture → REST call works end to end.

## 6. Tool coverage matrix

Read-only v1 is intentionally a subset of Intuit's ~143-tool server. Track
expansion here.

### Implemented (read-only)

| Tool | QBO surface |
|------|-------------|
| `get_profit_and_loss` | report `ProfitAndLoss` |
| `get_balance_sheet` | report `BalanceSheet` |
| `get_cash_flow` | report `CashFlow` |
| `get_trial_balance` | report `TrialBalance` |
| `get_general_ledger` | report `GeneralLedger` |
| `get_customer_sales` | report `CustomerSales` |
| `get_aged_receivables` | report `AgedReceivables` |
| `get_aged_payables` | report `AgedPayables` |
| `get_company_info` | query `CompanyInfo` |
| `list_customers` | query `Customer` |
| `list_invoices` | query `Invoice` |
| `list_items` | query `Item` |
| `list_vendors` | query `Vendor` |
| `list_bills` | query `Bill` |
| `list_accounts` | query `Account` |
| `list_payments` | query `Payment` |

### Deferred (not yet implemented)

- **Read, more entities:** `get_*` by id and `list_*` for Estimate, Bill Payment,
  Purchase, Sales Receipt, Credit Memo, Refund Receipt, Purchase Order, Vendor
  Credit, Deposit, Transfer, Time Activity, Employee, Class, Department, Term,
  Payment Method, Tax Code/Rate/Agency, Journal Entry, Attachable.
- **Reports:** detail variants (`ProfitAndLossDetail`, `AgedReceivableDetail`,
  `AgedPayableDetail`), `ItemSales`, `CustomerBalance`, `VendorBalance`.
- **Write/CRUD (v2):** `create_*` / `update_*` / `delete_*` on Invoice, Customer,
  Item, Bill, Payment, Estimate, etc. Adding any write tool is a deliberate
  decision — the OAuth scope already permits it; only the tool registry gates it.

To expand: add a `NativeToolMeta` in `tools.py` and a thin `@native_tool` handler
in `adapter.py` (reports → `_report`; lookups → `_list`/`query`). Move the row
from Deferred to Implemented here.

## References

Intuit developer docs (verified June 2026):

- [Set up OAuth 2.0](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) — endpoints, scopes, redirect URIs.
- [OAuth 2.0 / authorization FAQ](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/faq) — token lifetimes, refresh rotation.
- [Handling OAuth token expiration](https://help.developer.intuit.com/s/article/Handling-OAuth-token-expiration) and [Validity of Refresh Token](https://help.developer.intuit.com/s/article/Validity-of-Refresh-Token).
- [Minor versions of our API](https://developer.intuit.com/app/developer/qbo/docs/learn/explore-the-quickbooks-online-api/minor-versions) — minorversion 75 (1–74 deprecated Aug 2025).
- [Reports API](https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/account) and [Query operations](https://developer.intuit.com/app/developer/qbo/docs/learn/explore-the-quickbooks-online-api/data-queries) — report names + `SELECT … MAXRESULTS`.
