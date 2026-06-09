"""Emulator-backed tests for the Firestore client singleton.

Replaces the previous mock-only tests, which asserted on mock calls and on a log
*format string* (not the rendered message). These exercise the real client
against the emulator and assert on observable behavior, per AGENTS.md testing
rules. Skipped when no emulator is reachable.

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import logging
import os
import socket

import pytest

import broker.services.firestore_client as firestore_client

EMULATOR_HOST = os.environ.get("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8765")


def _emulator_reachable(host: str) -> bool:
    """True if a TCP connection to the emulator host:port succeeds within 1s."""
    hostname, _, port = host.partition(":")
    try:
        with socket.create_connection((hostname, int(port)), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _emulator_reachable(EMULATOR_HOST),
    reason=f"Firestore emulator not reachable at {EMULATOR_HOST}",
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the module singleton and point the client at the emulator each test."""
    os.environ["FIRESTORE_EMULATOR_HOST"] = EMULATOR_HOST
    firestore_client._client = None
    firestore_client._client_config = None
    yield
    if firestore_client._client is not None:
        firestore_client._client.close()
    firestore_client._client = None
    firestore_client._client_config = None


async def test_get_client_round_trips_against_emulator() -> None:
    """The returned client can actually read and write the emulator."""
    client = firestore_client.get_firestore_client("test-project", "(default)")
    doc_ref = client.collection("client_smoke").document("doc1")
    await doc_ref.set({"value": 42})
    snapshot = await doc_ref.get()
    assert snapshot.to_dict() == {"value": 42}


def test_singleton_returns_same_instance() -> None:
    first = firestore_client.get_firestore_client("test-project", "(default)")
    second = firestore_client.get_firestore_client("test-project", "(default)")
    assert first is second


def test_mismatched_config_raises() -> None:
    """Requesting a different project/database after init is a programming error."""
    firestore_client.get_firestore_client("test-project", "(default)")
    with pytest.raises(RuntimeError, match="already initialized"):
        firestore_client.get_firestore_client("other-project", "(default)")


async def test_close_resets_singleton() -> None:
    firestore_client.get_firestore_client("test-project", "(default)")
    assert firestore_client._client is not None
    await firestore_client.close_firestore_client()
    assert firestore_client._client is None
    assert firestore_client._client_config is None


def test_emulator_detection_logged(caplog: pytest.LogCaptureFixture) -> None:
    """When FIRESTORE_EMULATOR_HOST is set, the init log names the emulator."""
    with caplog.at_level(logging.INFO, logger="broker.services.firestore_client"):
        firestore_client.get_firestore_client("test-project", "(default)")
    assert any("emulator" in record.getMessage() for record in caplog.records)
