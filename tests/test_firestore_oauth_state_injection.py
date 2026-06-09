"""Emulator-backed test: OAuthHandler with an injected Firestore state store.

Proves the injectability seam end-to-end — an OAuthHandler constructed with a
FirestoreOutboundOAuthStateStore completes a real signed-state PKCE round-trip
(authorize → exchange), with the nonce + verifier living in Firestore rather than
the in-memory module singleton. Real signing (itsdangerous) + real Firestore;
only the outbound token POST is mocked (respx), per AGENTS.md testing rules.

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import os
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)
from httpx import Response

from broker.connectors.base import BaseConnector
from broker.connectors.registry import ConnectorRegistry
from broker.models.connector_config import (
    AppConnectorCredentials,
    ConnectorMeta,
    ResolvedOAuth,
)
from broker.services.firestore_outbound_state_store import FirestoreOutboundOAuthStateStore
from broker.services.oauth import OAuthHandler

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)

_STATE_SECRET = "test-secret-key-for-signing-16+"
_CALLBACK_URL = "http://localhost/callback"


@pytest.fixture(autouse=True)
def _clear_registry():
    ConnectorRegistry.clear()
    yield
    ConnectorRegistry.clear()


@pytest.fixture
async def state_store():
    configure_firestore_client_env()
    prefix = f"test_{os.urandom(4).hex()}_"
    store = FirestoreOutboundOAuthStateStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await store.setup()
    yield store
    await cleanup_live_collections(prefix)
    await reset_firestore_client()


def _build_connector(name: str) -> BaseConnector:
    """Define + instantiate a PKCE-enabled connector subclass for ``name``."""
    connector_meta = ConnectorMeta(
        name=name,
        display_name=name.title(),
        mcp_url=f"https://mcp.{name}.com/mcp",
        oauth_authorize_url=f"https://{name}.com/oauth/authorize",
        oauth_token_url=f"https://{name}.com/oauth/token",
        supports_pkce=True,
    )

    class _Conn(BaseConnector):
        meta = connector_meta

    instance = ConnectorRegistry.get(name)
    assert instance is not None
    return instance


def _resolved(connector: BaseConnector) -> ResolvedOAuth:
    return ResolvedOAuth(
        authorize_url=connector.meta.oauth_authorize_url,
        token_url=connector.meta.oauth_token_url,
        credentials=AppConnectorCredentials(client_id="cid", client_secret="csecret"),
    )


@respx.mock
async def test_signed_state_round_trip_with_firestore_store(
    state_store: FirestoreOutboundOAuthStateStore,
) -> None:
    """authorize stores nonce+verifier in Firestore; exchange consumes them and succeeds."""
    handler = OAuthHandler(state_secret=_STATE_SECRET, state_store=state_store)
    notion = _build_connector("notion")

    url = await handler.build_authorize_url(notion, "acme:app", _resolved(notion), _CALLBACK_URL)
    params = parse_qs(urlparse(url).query)
    state = params["state"][0]
    # PKCE challenge present means a verifier was persisted to Firestore.
    assert "code_challenge" in params

    respx.post("https://notion.com/oauth/token").mock(
        return_value=Response(200, json={"access_token": "at", "expires_in": 3600})
    )

    connection, app_key = await handler.exchange_code(
        notion, "code123", state, _resolved(notion), _CALLBACK_URL
    )
    assert app_key == "acme:app"
    assert connection.access_token == "at"

    # Single-use: replaying the same state is rejected (nonce already consumed).
    with pytest.raises(ValueError, match="already used"):
        await handler.exchange_code(notion, "code123", state, _resolved(notion), _CALLBACK_URL)
