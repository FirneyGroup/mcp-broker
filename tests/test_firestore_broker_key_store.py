"""Emulator-backed tests for FirestoreBrokerKeyStore.

Exercises the real Firestore client against the emulator (no mocks), per
AGENTS.md testing rules. Skipped when no emulator is reachable.

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import os

import pytest
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)

from broker.services.firestore_broker_key_store import FirestoreBrokerKeyStore

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)


@pytest.fixture
async def key_store():
    configure_firestore_client_env()
    prefix = f"test_{os.urandom(4).hex()}_"
    store = FirestoreBrokerKeyStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await store.setup()
    yield store
    await cleanup_live_collections(prefix)
    await reset_firestore_client()


async def test_create_and_verify_round_trip(key_store: FirestoreBrokerKeyStore) -> None:
    raw_key = await key_store.create_key("acme:app1")
    assert raw_key.startswith("br_")
    assert await key_store.verify(raw_key) == "acme:app1"


async def test_verify_unknown_key_returns_none(key_store: FirestoreBrokerKeyStore) -> None:
    await key_store.create_key("acme:app1")
    assert await key_store.verify("br_not-a-real-key") is None
    assert await key_store.verify("") is None


async def test_create_key_twice_for_same_app_raises(key_store: FirestoreBrokerKeyStore) -> None:
    """One key per app, enforced atomically by document.create()."""
    await key_store.create_key("acme:app1")
    with pytest.raises(ValueError, match="already has a key"):
        await key_store.create_key("acme:app1")


async def test_rotate_invalidates_old_key(key_store: FirestoreBrokerKeyStore) -> None:
    old_key = await key_store.create_key("acme:app1")
    new_key = await key_store.rotate("acme:app1")
    assert new_key is not None
    assert new_key != old_key
    assert await key_store.verify(old_key) is None
    assert await key_store.verify(new_key) == "acme:app1"


async def test_rotate_missing_app_returns_none(key_store: FirestoreBrokerKeyStore) -> None:
    assert await key_store.rotate("acme:ghost") is None


async def test_has_key(key_store: FirestoreBrokerKeyStore) -> None:
    assert await key_store.has_key("acme:app1") is False
    await key_store.create_key("acme:app1")
    assert await key_store.has_key("acme:app1") is True


async def test_delete_key(key_store: FirestoreBrokerKeyStore) -> None:
    key = await key_store.create_key("acme:app1")
    assert await key_store.delete_key("acme:app1") is True
    assert await key_store.delete_key("acme:app1") is False  # already gone
    assert await key_store.verify(key) is None


async def test_list_keys_excludes_hashes(key_store: FirestoreBrokerKeyStore) -> None:
    await key_store.create_key("acme:app1")
    await key_store.create_key("acme:app2")
    listed = await key_store.list_keys()
    app_keys = {entry["app_key"] for entry in listed}
    assert app_keys == {"acme:app1", "acme:app2"}
    for entry in listed:
        assert "key_hash" not in entry
        assert "created_at" in entry
