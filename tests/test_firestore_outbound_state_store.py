"""Emulator-backed tests for FirestoreOutboundOAuthStateStore.

Exercises the real Firestore client against the emulator (no mocks), per
AGENTS.md testing rules. Skipped when no emulator is reachable.

The Firestore backend lets the nonce + PKCE verifier minted on one instance be
consumed on another (uvicorn worker / Cloud Run replica). These tests prove the
cross-instance single-use nonce, the PKCE round-trip + removal, and cleanup.

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

from broker.services.firestore_outbound_state_store import FirestoreOutboundOAuthStateStore

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)

_NONCE_TTL = 900


@pytest.fixture
async def prefix():
    """Isolated collection prefix; resets the client singleton + cleans up live data."""
    configure_firestore_client_env()
    collection_prefix = f"test_{os.urandom(4).hex()}_"
    yield collection_prefix
    await cleanup_live_collections(collection_prefix)
    await reset_firestore_client()


async def _store(prefix: str) -> FirestoreOutboundOAuthStateStore:
    """Build + set up a store instance sharing the given prefix (one instance per call)."""
    store = FirestoreOutboundOAuthStateStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await store.setup()
    return store


async def test_nonce_consumed_once_across_instances(prefix: str) -> None:
    """A nonce stored on instance A is consumable once on instance B; replay is False."""
    instance_a = await _store(prefix)
    instance_b = await _store(prefix)

    await instance_a.store_nonce("nonce-1")
    assert await instance_b.consume_nonce("nonce-1") is True
    # Replay on the original instance finds it gone.
    assert await instance_a.consume_nonce("nonce-1") is False


async def test_consume_unknown_nonce_is_false(prefix: str) -> None:
    store = await _store(prefix)
    assert await store.consume_nonce("never-stored") is False


async def test_pkce_verifier_round_trip_and_removed(prefix: str) -> None:
    """The verifier round-trips across instances and is removed after the first get."""
    instance_a = await _store(prefix)
    instance_b = await _store(prefix)

    await instance_a.store_nonce("nonce-1")
    await instance_a.store_pkce_verifier("nonce-1", "verifier-xyz")

    assert await instance_b.get_and_remove_pkce_verifier("nonce-1") == "verifier-xyz"
    # Single-use: the verifier is cleared after the first read.
    assert await instance_a.get_and_remove_pkce_verifier("nonce-1") is None


async def test_get_verifier_when_absent_returns_none(prefix: str) -> None:
    store = await _store(prefix)
    await store.store_nonce("nonce-1")  # nonce exists, but no verifier stored
    assert await store.get_and_remove_pkce_verifier("nonce-1") is None


async def test_cleanup_expired_reaps_old_nonces(prefix: str) -> None:
    """cleanup_expired deletes nonces older than the horizon so consume then misses."""
    store = await _store(prefix)
    await store.store_nonce("nonce-1")

    # Advance the cleanup clock past the TTL without sleeping.
    future = time.time() + _NONCE_TTL + 10
    with patch("broker.services.firestore_outbound_state_store.time.time", return_value=future):
        await store.cleanup_expired(_NONCE_TTL)

    assert await store.consume_nonce("nonce-1") is False
