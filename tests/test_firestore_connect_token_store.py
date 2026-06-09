"""Emulator-backed tests for FirestoreConnectTokenStore.

Exercises the real Firestore client against the emulator (no mocks), per
AGENTS.md testing rules. Skipped when no emulator is reachable.

The point of the Firestore backend is cross-instance single-use: a connect token
created on one instance must be consumable exactly once on any other instance.
These tests prove that by creating on store A and consuming on store B that share
the same collection prefix (and the same process-wide Firestore client).

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import os
import time
from unittest.mock import patch

import pytest
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)

from broker.services.api_key_store import CONNECT_TOKEN_PREFIX, CONNECT_TOKEN_TTL
from broker.services.firestore_connect_token_store import FirestoreConnectTokenStore

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)


@pytest.fixture
async def prefix():
    """Isolated collection prefix; resets the client singleton + cleans up live data."""
    configure_firestore_client_env()
    collection_prefix = f"test_{os.urandom(4).hex()}_"
    yield collection_prefix
    await cleanup_live_collections(collection_prefix)
    await reset_firestore_client()


async def _store(prefix: str) -> FirestoreConnectTokenStore:
    """Build + set up a store instance sharing the given prefix (one instance per call)."""
    store = FirestoreConnectTokenStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await store.setup()
    return store


async def test_create_on_one_instance_consume_on_another(prefix: str) -> None:
    """A token created on instance A is consumable on instance B (shared backing)."""
    instance_a = await _store(prefix)
    instance_b = await _store(prefix)

    token = await instance_a.create("acme:app1")
    assert token.startswith(CONNECT_TOKEN_PREFIX)

    assert await instance_b.consume(token) == "acme:app1"


async def test_single_use_across_instances(prefix: str) -> None:
    """Second consume (on either instance) returns None — single-use across instances."""
    instance_a = await _store(prefix)
    instance_b = await _store(prefix)

    token = await instance_a.create("acme:app1")
    assert await instance_b.consume(token) == "acme:app1"
    # Replay on the original instance also misses — the doc was deleted.
    assert await instance_a.consume(token) is None


async def test_unknown_token_returns_none(prefix: str) -> None:
    store = await _store(prefix)
    assert await store.consume("ct_does-not-exist") is None


async def test_expired_token_returns_none(prefix: str) -> None:
    """A token older than CONNECT_TOKEN_TTL is rejected (and not consumed)."""
    store = await _store(prefix)
    token = await store.create("acme:app1")

    # Fast-forward consume's clock past the TTL without sleeping.
    future = time.time() + CONNECT_TOKEN_TTL + 10
    with patch("broker.services.firestore_connect_token_store.time.time", return_value=future):
        assert await store.consume(token) is None


async def test_cleanup_reaps_expired_tokens(prefix: str) -> None:
    """cleanup_expired deletes tokens older than the TTL so the consume after misses."""
    store = await _store(prefix)
    token = await store.create("acme:app1")

    future = time.time() + CONNECT_TOKEN_TTL + 10
    with patch("broker.services.firestore_connect_token_store.time.time", return_value=future):
        await store.cleanup_expired()
        assert await store.consume(token) is None
