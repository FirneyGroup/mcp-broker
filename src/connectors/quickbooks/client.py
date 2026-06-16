"""
QuickBooks Online REST client (async httpx).

Thin wrapper over the QuickBooks Online v3 Accounting API. Two primitives cover
the read-only tool surface:

- ``query``  — the QBO SQL-like query endpoint (read-only SELECT statements)
- ``report`` — the reports endpoint (ProfitAndLoss, BalanceSheet, ...)

The broker owns OAuth; this client only injects the bearer token and the company
``realmId`` (carried together in ``QboContext``) into each request. No SDK
dependency — QBO v3 is plain REST and httpx is already a broker dependency, so
calls are async-native (no ``run_in_executor`` needed, unlike the Twitter SDK).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# === CONSTANTS ===

# QBO API host. Production by default; set QUICKBOOKS_API_BASE_URL to the sandbox
# host (https://sandbox-quickbooks.api.intuit.com) for dev/CI. The OAuth endpoints
# are identical for both.
_PRODUCTION_BASE_URL = "https://quickbooks.api.intuit.com"

# Pins the API field set so responses don't shift under us. Intuit deprecated
# minor versions 1-74 in Aug 2025; 75 is the current default. See
# https://developer.intuit.com/app/developer/qbo/docs/learn/explore-the-quickbooks-online-api/minor-versions
_MINOR_VERSION = "75"

_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# HTTP statuses mapped to actionable, body-free error messages. We never echo the
# QBO response body — it can be large and carries company data.
_HTTP_BAD_REQUEST = 400
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_NOT_FOUND = 404


def _resolve_base_url() -> str:
    """Resolve the QBO API base URL.

    Defaults to the production host. Set ``QUICKBOOKS_API_BASE_URL`` to target the
    sandbox host (``https://sandbox-quickbooks.api.intuit.com``) or a local stub in
    tests/CI. Using a single env override — rather than a separate non-secret
    ``QUICKBOOKS_ENVIRONMENT`` value — keeps deployment config out of ``.env`` per
    the broker's config contract while remaining a documented escape hatch.
    """
    return os.getenv("QUICKBOOKS_API_BASE_URL", _PRODUCTION_BASE_URL).rstrip("/")


class QboContext(BaseModel):
    """The two values every QBO call needs, carried together.

    Grouping them keeps client/handler signatures within the 4-arg limit and
    makes it explicit that a token is only ever used against its own company.
    Never logged or serialized — the access token belongs to the broker's
    in-memory request flow only.
    """

    access_token: str
    realm_id: str
    model_config = ConfigDict(frozen=True)


class QuickBooksClient:
    """Async REST client for the QuickBooks Online v3 Accounting API."""

    def __init__(self, base_url: str | None = None) -> None:
        """Resolve the QBO API base URL (env-driven) once for this client instance."""
        # Resolve per instance so a process-wide QUICKBOOKS_API_BASE_URL / _ENVIRONMENT
        # is honoured; the connector constructs one client and reuses it.
        self._base_url = (base_url or _resolve_base_url()).rstrip("/")

    async def query(self, context: QboContext, statement: str) -> dict[str, Any]:
        """Run a read-only QBO query (``SELECT ...``). Returns the parsed body."""
        path = f"/v3/company/{context.realm_id}/query"
        return await self._get(context, path, {"query": statement})

    async def report(
        self, context: QboContext, report_name: str, params: dict[str, str]
    ) -> dict[str, Any]:
        """Fetch a QBO report (e.g. ``ProfitAndLoss``) for the company."""
        path = f"/v3/company/{context.realm_id}/reports/{report_name}"
        return await self._get(context, path, params)

    async def _get(self, context: QboContext, path: str, params: dict[str, str]) -> dict[str, Any]:
        """GET a QBO endpoint with the bearer token + minorversion, return JSON."""
        # Drop unset params only — keep legitimate falsy values (e.g. a future "0"
        # offset) rather than silently discarding them.
        query_params = {key: value for key, value in params.items() if value is not None}
        query_params["minorversion"] = _MINOR_VERSION
        headers = {
            "Authorization": f"Bearer {context.access_token}",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(
                f"{self._base_url}{path}", params=query_params, headers=headers
            )
        _raise_for_status(response, path)
        return response.json()


def _raise_for_status(response: httpx.Response, path: str) -> None:
    """Convert a non-2xx QBO response into a sanitized, client-safe ValueError.

    The response body is deliberately NOT surfaced (it can carry company data);
    only the status is logged, and ``path`` includes the non-secret realmId.
    """
    if response.is_success:
        return
    status = response.status_code
    logger.warning("[QuickBooks] %s returned %s", path, status)
    if status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
        raise ValueError(
            "QuickBooks rejected the request (auth/permission). Reconnect the "
            "QuickBooks company or check the granted scope."
        )
    if status == _HTTP_BAD_REQUEST:
        raise ValueError("QuickBooks rejected the request as malformed (HTTP 400).")
    if status == _HTTP_NOT_FOUND:
        raise ValueError("QuickBooks resource not found (HTTP 404).")
    raise ValueError(f"QuickBooks API error (HTTP {status}).")
