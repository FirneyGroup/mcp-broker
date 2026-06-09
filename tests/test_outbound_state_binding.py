"""Regression tests: outbound OAuth state is bound to the connector it was minted for.

The HMAC-signed state carries the connector name; ``exchange_code`` must reject a
state minted for connector A when it arrives on connector B's callback. Without the
binding check, a valid state for "hubspot" would complete "notion"'s flow.

Real signing (itsdangerous via OAuthHandler), real in-memory nonce store. Only the
outbound token POST is mocked (respx).
"""

import pytest
import respx
from httpx import Response

from broker.connectors.base import BaseConnector
from broker.connectors.registry import ConnectorRegistry
from broker.models.connector_config import (
    AppConnectorCredentials,
    ConnectorMeta,
    ResolvedOAuth,
)
from broker.services.oauth import OAuthHandler

_STATE_SECRET = "test-secret-key-for-signing-16+"
_CALLBACK_URL = "http://localhost/callback"


def _make_meta(name: str) -> ConnectorMeta:
    return ConnectorMeta(
        name=name,
        display_name=name.title(),
        mcp_url=f"https://mcp.{name}.com/mcp",
        oauth_authorize_url=f"https://{name}.com/oauth/authorize",
        oauth_token_url=f"https://{name}.com/oauth/token",
        # PKCE disabled here so the success path doesn't need a stored verifier —
        # the connector-binding check is independent of PKCE.
        supports_pkce=False,
    )


def _make_resolved(meta: ConnectorMeta) -> ResolvedOAuth:
    return ResolvedOAuth(
        authorize_url=meta.oauth_authorize_url,
        token_url=meta.oauth_token_url,
        credentials=AppConnectorCredentials(client_id="cid", client_secret="csecret"),
    )


@pytest.fixture(autouse=True)
def _clear_registry():
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture
def handler() -> OAuthHandler:
    return OAuthHandler(state_secret=_STATE_SECRET)


def _build_connector(name: str) -> BaseConnector:
    """Define + instantiate a connector subclass for ``name``."""
    connector_meta = _make_meta(name)

    class _Conn(BaseConnector):
        meta = connector_meta

    instance = ConnectorRegistry.get(name)
    assert instance is not None
    return instance


async def _mint_state_for(handler: OAuthHandler, connector: BaseConnector) -> str:
    """Mint a real signed state by running the authorize step, return the state param."""
    from urllib.parse import parse_qs, urlparse

    url = await handler.build_authorize_url(
        connector, "client:app", _make_resolved(connector.meta), _CALLBACK_URL
    )
    return parse_qs(urlparse(url).query)["state"][0]


async def test_state_minted_for_other_connector_is_rejected(handler: OAuthHandler) -> None:
    """State minted for 'hubspot' must not complete 'notion''s callback."""
    hubspot = _build_connector("hubspot")
    notion = _build_connector("notion")

    state = await _mint_state_for(handler, hubspot)

    with pytest.raises(ValueError, match="connector mismatch"):
        await handler.exchange_code(
            notion, "code123", state, _make_resolved(notion.meta), _CALLBACK_URL
        )


@respx.mock
async def test_same_connector_state_succeeds(handler: OAuthHandler) -> None:
    """State minted for 'hubspot' completes 'hubspot''s callback (control case)."""
    hubspot = _build_connector("hubspot")
    state = await _mint_state_for(handler, hubspot)

    respx.post("https://hubspot.com/oauth/token").mock(
        return_value=Response(200, json={"access_token": "at", "expires_in": 3600})
    )

    connection, app_key = await handler.exchange_code(
        hubspot, "code123", state, _make_resolved(hubspot.meta), _CALLBACK_URL
    )
    assert app_key == "client:app"
    assert connection.access_token == "at"


async def test_mismatch_check_does_not_consume_the_real_connectors_nonce(
    handler: OAuthHandler,
) -> None:
    """A mismatched callback must not burn the nonce — the legitimate connector
    can still complete its own flow afterwards."""
    hubspot = _build_connector("hubspot")
    notion = _build_connector("notion")
    state = await _mint_state_for(handler, hubspot)

    with pytest.raises(ValueError, match="connector mismatch"):
        await handler.exchange_code(
            notion, "code123", state, _make_resolved(notion.meta), _CALLBACK_URL
        )

    # The nonce survives the rejected attempt, so the real connector still works.
    with respx.mock:
        respx.post("https://hubspot.com/oauth/token").mock(
            return_value=Response(200, json={"access_token": "at", "expires_in": 3600})
        )
        connection, _ = await handler.exchange_code(
            hubspot, "code123", state, _make_resolved(hubspot.meta), _CALLBACK_URL
        )
    assert connection.access_token == "at"
