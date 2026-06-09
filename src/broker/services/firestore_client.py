"""Firestore AsyncClient management for the broker.

Provides a process-wide singleton AsyncClient with ADC auth, emulator support,
and per-environment database configuration.
"""

import hashlib
import logging
import os

from google.cloud.firestore_v1 import AsyncClient

logger = logging.getLogger(__name__)

# SHA-256 hex digest truncated to 32 chars (128 bits) — collision-safe as a Firestore doc ID.
_DOC_ID_HASH_CHARS = 32


def hash_doc_id(value: str) -> str:
    """SHA-256 hex digest (truncated) for use as a Firestore document ID.

    Keeps raw secrets and path-unsafe characters (e.g. '/') out of document paths.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:_DOC_ID_HASH_CHARS]


# Process-wide singleton + the (project_id, database) it was created for.
_client: AsyncClient | None = None
_client_config: tuple[str, str] | None = None


def get_firestore_client(project_id: str, database: str = "(default)") -> AsyncClient:
    """Get or create the Firestore AsyncClient.

    Uses Application Default Credentials (ADC) and respects FIRESTORE_EMULATOR_HOST
    for local development. The client is a process-wide singleton; calling this
    with a different project/database after initialization is a programming error
    and raises rather than silently returning a client for the wrong project.
    """
    global _client, _client_config

    # No lock guards this lazy init: it is only ever called during the app's
    # sequential lifespan startup (single-threaded, before request handling), so a
    # concurrent first-call race cannot occur. Do not add a lock — it would be dead.
    if _client is not None:
        if _client_config != (project_id, database):
            raise RuntimeError(
                f"Firestore client already initialized for {_client_config}; "
                f"refusing to return a client for {(project_id, database)}"
            )
        return _client

    _client = AsyncClient(project=project_id, database=database)
    _client_config = (project_id, database)

    emulator_host = os.environ.get("FIRESTORE_EMULATOR_HOST")
    log_location = f"emulator:{emulator_host}" if emulator_host else "Cloud Firestore"
    logger.info(
        "[Firestore] Initialized AsyncClient (project=%s, database=%s, location=%s)",
        project_id,
        database,
        log_location,
    )
    return _client


async def close_firestore_client() -> None:
    """Close the Firestore AsyncClient and release resources.

    Kept ``async`` to match the lifespan teardown sequence; the underlying
    ``AsyncClient.close()`` is synchronous (it closes the gRPC channel).
    """
    global _client, _client_config

    if _client is not None:
        _client.close()
        _client = None
        _client_config = None
        logger.info("[Firestore] AsyncClient closed")
