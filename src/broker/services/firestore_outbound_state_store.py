"""Firestore implementation of the outbound OAuth state store.

Backs ``OutboundOAuthStateStore`` on Firestore Native mode so the nonce + PKCE
verifier minted on one instance during ``/connect`` can be consumed on any other
instance during the callback — the property the in-memory store cannot provide
across uvicorn workers / Cloud Run replicas.

Collection structure (one collection, two doc namespaces per nonce):
  {prefix}outbound_oauth_state/{hash("nonce:" + nonce)}  → {created_at}
  {prefix}outbound_oauth_state/{hash("pkce:" + nonce)}   → {created_at, pkce_verifier}

The nonce and its PKCE verifier live in SEPARATE documents, mirroring the
in-memory store's two independent dicts: ``_validate_and_consume_state`` consumes
(deletes) the nonce BEFORE ``get_and_remove_pkce_verifier`` runs, so a single
shared document would take the verifier down with the nonce. Both docs carry
``created_at`` so ``cleanup_expired`` reaps either independently.

Document IDs are SHA-256 hashes, so neither the nonce nor the verifier appears in
a document path. PKCE verifiers are stored NOT encrypted: they are short-lived
flow secrets that live only between ``/connect`` and the callback, expire within
``_NONCE_TTL`` (the cleanup horizon), and are deleted on consume. This mirrors the
in-memory / SQLite-era model — a MultiFernet layer would buy nothing the TTL +
single-use delete don't.
"""

import logging
import time
from typing import cast

from google.cloud.firestore_v1 import AsyncClient, async_transactional
from google.cloud.firestore_v1.async_transaction import AsyncTransaction
from google.cloud.firestore_v1.base_query import FieldFilter

from broker.services.auth_store_interfaces import OutboundOAuthStateStore
from broker.services.firestore_client import get_firestore_client, hash_doc_id

logger = logging.getLogger(__name__)


class FirestoreOutboundOAuthStateStore(OutboundOAuthStateStore):
    """Outbound OAuth state store backed by Firestore (Native mode).

    ``consume_nonce`` is transactional (delete-if-present) so a nonce is
    single-use across instances, defeating replay. The PKCE verifier lives in its
    own document so it survives nonce consumption and is removed on its own get.
    """

    def __init__(self, project_id: str, database: str = "(default)", collection_prefix: str = ""):
        self._project_id = project_id
        self._database = database
        self._collection = f"{collection_prefix}outbound_oauth_state"
        self._client: AsyncClient | None = None

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info(
            "[FirestoreOutboundOAuthStateStore] Setup complete (collection=%s)", self._collection
        )

    @property
    def _db(self) -> AsyncClient:
        if self._client is None:
            raise RuntimeError("FirestoreOutboundOAuthStateStore.setup() must be called before use")
        return self._client

    @staticmethod
    def _nonce_doc_id(nonce: str) -> str:
        """Doc id for a nonce, namespaced so it never collides with its verifier doc."""
        return hash_doc_id(f"nonce:{nonce}")

    @staticmethod
    def _pkce_doc_id(nonce: str) -> str:
        """Doc id for a nonce's PKCE verifier, namespaced separately from the nonce."""
        return hash_doc_id(f"pkce:{nonce}")

    async def store_nonce(self, nonce: str) -> None:
        """Store a nonce with current timestamp."""
        await (
            self._db.collection(self._collection)
            .document(self._nonce_doc_id(nonce))
            .set({"created_at": time.time()})
        )

    async def consume_nonce(self, nonce: str) -> bool:
        """Consume (remove) a nonce. Returns True if found, else False.

        Transactional delete-if-present so a replayed nonce finds it gone and a
        concurrent consume cannot both succeed. Does NOT touch the verifier doc —
        ``get_and_remove_pkce_verifier`` runs afterwards in ``exchange_code``.
        """
        nonce_ref = self._db.collection(self._collection).document(self._nonce_doc_id(nonce))

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> bool:
            snap = await nonce_ref.get(transaction=transaction)
            if snap.to_dict() is None:
                return False
            transaction.delete(nonce_ref)
            return True

        # @async_transactional erases the wrapped return type to Coroutine[Unknown];
        # cast back so the bool return type-checks.
        return cast(bool, await _attempt(self._db.transaction()))

    async def store_pkce_verifier(self, nonce: str, verifier: str) -> None:
        """Store the PKCE verifier in its own document keyed by the nonce."""
        await (
            self._db.collection(self._collection)
            .document(self._pkce_doc_id(nonce))
            .set({"pkce_verifier": verifier, "created_at": time.time()})
        )

    async def get_and_remove_pkce_verifier(self, nonce: str) -> str | None:
        """Read and delete the PKCE verifier for a nonce. Returns the verifier or None.

        Transactional read + delete so the verifier is single-use even when two
        callbacks race; ``None`` when no verifier was stored for the nonce.
        """
        pkce_ref = self._db.collection(self._collection).document(self._pkce_doc_id(nonce))

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> str | None:
            snap = await pkce_ref.get(transaction=transaction)
            pkce_fields = snap.to_dict()
            if pkce_fields is None:
                return None
            transaction.delete(pkce_ref)
            return pkce_fields.get("pkce_verifier")

        # @async_transactional erases the wrapped return type to Coroutine[Unknown];
        # cast back so the str | None return type-checks.
        return cast(str | None, await _attempt(self._db.transaction()))

    async def cleanup_expired(self, max_age_seconds: int) -> None:
        """Delete nonce + verifier documents older than ``max_age_seconds``.

        Both doc namespaces carry ``created_at``, so a single query over the
        collection reaps stale nonces and orphaned verifiers alike.
        """
        threshold = time.time() - max_age_seconds
        query = self._db.collection(self._collection).where(
            filter=FieldFilter("created_at", "<=", threshold)
        )
        async for doc in query.stream():
            await doc.reference.delete()
