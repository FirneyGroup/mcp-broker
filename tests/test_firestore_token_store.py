"""Emulator-backed tests for FirestoreTokenStore.

These exercise the REAL Firestore client against the local emulator (no mocks),
per AGENTS.md testing rules. They are skipped when no emulator is reachable.

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765

Covers the regressions the original mock tests missed:
  - save() must NOT delete sibling connectors (purge-on-create belonged to the
    broker-key path, not per-connection save).
  - the query methods must iterate `query.stream()` (an async generator), not
    `await` it.
  - EncryptedTokenStore round-trips ciphertext through the Firestore document.
"""

import logging
import os
import time

import pytest
from cryptography.fernet import Fernet, InvalidToken
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)

from broker.models.connection import AppConnection
from broker.services.firestore_token_store import FirestoreTokenStore
from broker.services.store import EncryptedTokenStore

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)


# === FIXTURES ===


@pytest.fixture
async def firestore_store():
    """Fresh FirestoreTokenStore (emulator or live) with an isolated prefix.

    Resets the module-level client singleton and uses a unique collection prefix
    so tests don't see each other's documents; live data is deleted on teardown.
    """
    configure_firestore_client_env()
    prefix = f"test_{os.urandom(4).hex()}_"
    store = FirestoreTokenStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await store.setup()
    yield store
    await cleanup_live_collections(prefix)
    await reset_firestore_client()


def _connection(
    connector: str, *, access: str = "tok", expires_at: int | None = None
) -> AppConnection:
    return AppConnection(
        connector_name=connector,
        access_token=access,
        refresh_token="refresh",
        expires_at=expires_at,
        scopes=["read"],
    )


# === TESTS ===


async def test_save_and_get_round_trip(firestore_store: FirestoreTokenStore) -> None:
    await firestore_store.save("acme:app1", "notion", _connection("notion", access="abc"))
    fetched = await firestore_store.get("acme:app1", "notion")
    assert fetched is not None
    assert fetched.connector_name == "notion"
    assert fetched.access_token == "abc"


async def test_get_missing_returns_none(firestore_store: FirestoreTokenStore) -> None:
    assert await firestore_store.get("acme:app1", "nope") is None


async def test_save_preserves_other_connectors(firestore_store: FirestoreTokenStore) -> None:
    """Saving one connector must NOT delete the app's other connectors (C3)."""
    await firestore_store.save("acme:app1", "notion", _connection("notion"))
    await firestore_store.save("acme:app1", "google", _connection("google"))

    assert await firestore_store.get("acme:app1", "notion") is not None
    assert await firestore_store.get("acme:app1", "google") is not None


async def test_list_for_app_returns_all_connectors(firestore_store: FirestoreTokenStore) -> None:
    """list_for_app iterates the query stream and returns every connector (C2)."""
    await firestore_store.save("acme:app1", "notion", _connection("notion"))
    await firestore_store.save("acme:app1", "google", _connection("google"))

    connections = await firestore_store.list_for_app("acme:app1")
    assert {c.connector_name for c in connections} == {"notion", "google"}


async def test_list_expiring_filters_by_window(firestore_store: FirestoreTokenStore) -> None:
    """list_expiring returns only connections expiring within the buffer (C2)."""
    now = int(time.time())
    # Different app_keys so the test is independent of per-app behavior.
    await firestore_store.save("acme:soon", "notion", _connection("notion", expires_at=now + 60))
    await firestore_store.save(
        "acme:far", "notion", _connection("notion", expires_at=now + 100_000)
    )
    await firestore_store.save("acme:none", "notion", _connection("notion", expires_at=None))

    expiring = await firestore_store.list_expiring(buffer_seconds=600)
    app_keys = {app_key for app_key, _connector, _conn in expiring}
    assert "acme:soon" in app_keys
    assert "acme:far" not in app_keys
    assert "acme:none" not in app_keys


async def test_delete_all_for_app_removes_every_connector(
    firestore_store: FirestoreTokenStore,
) -> None:
    """delete_all_for_app removes all of an app's connectors and returns the count (C2)."""
    await firestore_store.save("acme:app1", "notion", _connection("notion"))
    await firestore_store.save("acme:app1", "google", _connection("google"))

    deleted = await firestore_store.delete_all_for_app("acme:app1")
    assert deleted == 2
    assert await firestore_store.get("acme:app1", "notion") is None
    assert await firestore_store.get("acme:app1", "google") is None


async def test_delete_single_connector(firestore_store: FirestoreTokenStore) -> None:
    await firestore_store.save("acme:app1", "notion", _connection("notion"))
    await firestore_store.save("acme:app1", "google", _connection("google"))

    await firestore_store.delete("acme:app1", "notion")

    assert await firestore_store.get("acme:app1", "notion") is None
    assert await firestore_store.get("acme:app1", "google") is not None


async def test_encrypted_store_round_trips_ciphertext(
    firestore_store: FirestoreTokenStore,
) -> None:
    """EncryptedTokenStore stores ciphertext in Firestore and decrypts on read."""
    key = Fernet.generate_key().decode()
    encrypted = EncryptedTokenStore(keys=[key], delegate=firestore_store)

    await encrypted.save("acme:app1", "notion", _connection("notion", access="super-secret"))

    # Raw (unencrypted) view: the stored access_token must be ciphertext.
    raw = await firestore_store.get("acme:app1", "notion")
    assert raw is not None
    assert raw.access_token != "super-secret"

    # Decrypted view round-trips the plaintext.
    decrypted = await encrypted.get("acme:app1", "notion")
    assert decrypted is not None
    assert decrypted.access_token == "super-secret"


async def test_encrypted_store_refresh_token_is_ciphertext_at_rest(
    firestore_store: FirestoreTokenStore,
) -> None:
    """The refresh_token (not just access_token) must be encrypted in the document."""
    key = Fernet.generate_key().decode()
    encrypted = EncryptedTokenStore(keys=[key], delegate=firestore_store)
    secret_refresh = "refresh-super-secret"

    connection = AppConnection(
        connector_name="notion",
        access_token="acc",
        refresh_token=secret_refresh,
        expires_at=None,
        scopes=["read"],
    )
    await encrypted.save("acme:app1", "notion", connection)

    raw = await firestore_store.get("acme:app1", "notion")
    assert raw is not None
    assert raw.refresh_token is not None
    assert raw.refresh_token != secret_refresh

    decrypted = await encrypted.get("acme:app1", "notion")
    assert decrypted is not None
    assert decrypted.refresh_token == secret_refresh


async def test_encrypted_store_wrong_key_propagates_invalid_token(
    firestore_store: FirestoreTokenStore,
) -> None:
    """Ciphertext written with key A must not decrypt under key B — the
    cryptography InvalidToken must propagate, never silently return plaintext."""
    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()
    writer = EncryptedTokenStore(keys=[key_a], delegate=firestore_store)
    reader = EncryptedTokenStore(keys=[key_b], delegate=firestore_store)

    await writer.save("acme:app1", "notion", _connection("notion", access="super-secret"))

    with pytest.raises(InvalidToken):
        await reader.get("acme:app1", "notion")


async def test_list_for_app_skips_malformed_doc(
    firestore_store: FirestoreTokenStore, caplog: pytest.LogCaptureFixture
) -> None:
    """One doc missing connection_json must not crash list_for_app (which the
    token-refresh maintenance loop depends on) — skip it and warn instead."""
    from broker.services.firestore_client import hash_doc_id

    await firestore_store.save("acme:app1", "notion", _connection("notion"))
    # Inject a malformed sibling doc for the same app, missing connection_json.
    bad_doc_id = hash_doc_id("acme:app1:broken")
    await (
        firestore_store._db.collection(firestore_store._conn_collection)
        .document(bad_doc_id)
        .set({"app_key": "acme:app1", "connector_name": "broken"})
    )

    with caplog.at_level(logging.WARNING, logger="broker.services.firestore_token_store"):
        connections = await firestore_store.list_for_app("acme:app1")

    assert {c.connector_name for c in connections} == {"notion"}
    assert any("missing connection_json" in record.getMessage() for record in caplog.records)
