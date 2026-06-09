"""Shared Firestore test configuration: emulator (default) or live Firestore.

The mode is chosen from the environment so the *same* store tests run both ways:

- **Emulator** (default — CI and local): ``FIRESTORE_EMULATOR_HOST`` is set, or the
  local default is reachable. State is ephemeral, so no cleanup is needed.
- **Live**: ``FIRESTORE_TEST_PROJECT`` names a real GCP project and the emulator
  env var is absent. Tests run against real Firestore via ADC — real pessimistic
  locking, the one behaviour the emulator cannot reproduce. Each test namespaces
  its data with a random ``collection_prefix``; the fixtures delete that data on
  teardown so a live run leaves no litter in the project.

Run live (emulator must be off so the google client does not route to it):
    FIRESTORE_TEST_PROJECT=my-project uv run pytest tests/test_firestore_token_store.py \\
        tests/test_firestore_broker_key_store.py tests/test_firestore_inbound_auth_store.py
"""

import os
import socket

# === MODE RESOLUTION ===

_DEFAULT_EMULATOR_HOST = "127.0.0.1:8765"
_LIVE_PROJECT = os.environ.get("FIRESTORE_TEST_PROJECT")

# Live mode requires a real project AND no emulator override: the google client
# always routes to the emulator when FIRESTORE_EMULATOR_HOST is present, so
# "live + emulator set" is incoherent and we treat it as emulator mode.
FIRESTORE_LIVE = bool(_LIVE_PROJECT) and "FIRESTORE_EMULATOR_HOST" not in os.environ
FIRESTORE_PROJECT = _LIVE_PROJECT if FIRESTORE_LIVE else "test-project"
EMULATOR_HOST = os.environ.get("FIRESTORE_EMULATOR_HOST", _DEFAULT_EMULATOR_HOST)


def _emulator_reachable(host: str) -> bool:
    """True if a TCP connection to the emulator host:port succeeds within 1s."""
    hostname, _, port = host.partition(":")
    try:
        with socket.create_connection((hostname, int(port)), timeout=1):
            return True
    except OSError:
        return False


# The Firestore store suite runs when either backend is available.
FIRESTORE_AVAILABLE = FIRESTORE_LIVE or _emulator_reachable(EMULATOR_HOST)
FIRESTORE_SKIP_REASON = (
    "No Firestore backend reachable — start the emulator "
    f"(FIRESTORE_EMULATOR_HOST, default {_DEFAULT_EMULATOR_HOST}) "
    "or set FIRESTORE_TEST_PROJECT for live Firestore."
)


def configure_firestore_client_env() -> None:
    """Point the broker's Firestore client at the chosen backend, then reset the
    module-level singleton so the next call builds a fresh client.

    Emulator mode sets ``FIRESTORE_EMULATOR_HOST`` (the google client routes to
    the emulator when it is present). Live mode must clear it so the client uses
    ADC against the real project. Each fixture calls this before constructing a
    store, so test ordering cannot bleed one mode's client into another.
    """
    import broker.services.firestore_client as firestore_client

    if FIRESTORE_LIVE:
        os.environ.pop("FIRESTORE_EMULATOR_HOST", None)
    else:
        os.environ["FIRESTORE_EMULATOR_HOST"] = EMULATOR_HOST
    firestore_client._client = None
    firestore_client._client_config = None


async def reset_firestore_client() -> None:
    """Close the shared client and clear the singleton (fixture teardown)."""
    import broker.services.firestore_client as firestore_client

    await firestore_client.close_firestore_client()
    firestore_client._client = None
    firestore_client._client_config = None


async def cleanup_live_collections(prefix: str) -> None:
    """Delete every document under root collections named ``{prefix}*``.

    Firestore collections are implicit, so deleting their documents removes them.
    Filtering on the test's unique random prefix bounds deletion to this test's
    own data — never shared or real collections. No-op in emulator mode, where
    state is ephemeral and wiped on emulator restart.
    """
    if not FIRESTORE_LIVE:
        return
    from google.cloud import firestore

    client = firestore.AsyncClient(project=FIRESTORE_PROJECT)
    try:
        async for collection in client.collections():
            if not collection.id.startswith(prefix):
                continue
            async for document in collection.list_documents():
                await document.delete()
    finally:
        client.close()
