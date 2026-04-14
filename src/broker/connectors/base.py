"""
BaseConnector — base class for connector adapters.

Subclasses MUST set `meta` (ConnectorMeta) as a class variable.
Subclasses MAY override hook methods for non-standard OAuth flows.
All hooks receive credentials as params — connectors are stateless.

NOT an ABC — all methods have sensible defaults.
Auto-registers via __init_subclass__.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from broker.models.connector_config import ConnectorMeta

if TYPE_CHECKING:
    from broker.models.connector_config import AppConnectorCredentials

# Control characters that must never appear in URL fields (header injection prevention)
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# OAuth token response fields the broker stores — everything else is discarded
_ALLOWED_TOKEN_FIELDS = {"access_token", "refresh_token", "expires_in", "token_type", "scope"}


def _validate_meta_urls(meta: ConnectorMeta) -> None:
    """Reject ConnectorMeta with URLs containing control characters."""
    for field_name in ("mcp_url", "oauth_authorize_url", "oauth_token_url", "mcp_oauth_url"):
        url = getattr(meta, field_name)
        if url and _CONTROL_CHAR_PATTERN.search(url):
            raise ValueError(f"ConnectorMeta.{field_name} contains control characters: {meta.name}")


def filter_token_response(raw_response: dict) -> dict:
    """Strip unknown fields from token response to prevent secret leakage into store.

    Only retains standard OAuth fields. Raises ValueError if access_token is missing or empty.
    """
    access_token = raw_response.get("access_token")
    if not access_token:
        raise ValueError("Token response missing or empty access_token")
    return {key: raw_response[key] for key in _ALLOWED_TOKEN_FIELDS if key in raw_response}


class BaseConnector:
    """Base for connector adapters.

    Subclasses define `meta = ConnectorMeta(...)` as a class variable.
    Registration happens automatically via __init_subclass__.
    """

    meta: ClassVar[ConnectorMeta]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        has_meta = "meta" in cls.__dict__ and cls.__dict__["meta"] is not None
        if not has_meta:
            return

        _validate_meta_urls(cls.meta)

        # Deferred import to avoid circular dependency
        from broker.connectors.registry import ConnectorRegistry

        ConnectorRegistry.auto_register(cls)

    # --- Overridable hooks for non-standard OAuth ---

    def customize_authorize_params(self, params: dict[str, str]) -> dict[str, str]:
        """Add connector-specific OAuth authorize params. Default: pass-through."""
        return params

    def build_auth_header(self, access_token: str) -> dict[str, str]:
        """Build the auth header for MCP requests. Default: Bearer token."""
        if _CONTROL_CHAR_PATTERN.search(access_token):
            raise ValueError("access_token contains control characters (possible header injection)")
        return {"Authorization": f"Bearer {access_token}"}

    def build_token_request_auth(
        self,
        credentials: AppConnectorCredentials,
    ) -> tuple[dict, dict[str, str]]:
        """Build auth for token endpoint requests (exchange + refresh).

        Returns (auth_headers, body_credentials) — providers differ on where
        client credentials go. Default: in the POST body (standard OAuth2).
        Override for providers that require HTTP Basic Auth (e.g. Notion).
        """
        return {}, {
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
        }

    def parse_token_response(self, raw_response: dict) -> dict:
        """Extract token fields from OAuth response.

        Override for non-standard responses.
        Default: expects standard OAuth2 fields (access_token, refresh_token, expires_in).
        """
        return raw_response
