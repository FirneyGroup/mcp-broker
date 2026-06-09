"""Firestore implementation of the single-use connect token store.

Backs ``ConnectTokenStoreABC`` on Firestore Native mode so a connect token
created on one instance can be consumed (exactly once) on any other instance —
the property the in-memory store cannot provide across uvicorn workers / Cloud
Run replicas.

Collection structure:
  {prefix}connect_tokens/{doc_id}  → {app_key, created_at}

Document IDs are SHA-256 hashes of the raw token, so the token itself never
appears in a document path. Tokens are minted with the same prefix + entropy as
the in-memory store (reusing ``CONNECT_TOKEN_PREFIX`` / ``KEY_BYTES``) and expire
after ``CONNECT_TOKEN_TTL`` seconds.
"""

import logging
import secrets
import time
from typing import cast

from google.cloud.firestore_v1 import AsyncClient, async_transactional
from google.cloud.firestore_v1.async_transaction import AsyncTransaction
from google.cloud.firestore_v1.base_query import FieldFilter

from broker.services.api_key_store import (
    CONNECT_TOKEN_PREFIX,
    CONNECT_TOKEN_TTL,
    KEY_BYTES,
)
from broker.services.auth_store_interfaces import ConnectTokenStoreABC
from broker.services.firestore_client import get_firestore_client, hash_doc_id

logger = logging.getLogger(__name__)


class FirestoreConnectTokenStore(ConnectTokenStoreABC):
    """Single-use connect token store backed by Firestore (Native mode).

    ``consume`` is transactional (read → TTL-check → delete) so a token can be
    redeemed exactly once even when two instances race on the same token — the
    single-use guarantee the browser OAuth connect flow depends on.
    """

    def __init__(self, project_id: str, database: str = "(default)", collection_prefix: str = ""):
        self._project_id = project_id
        self._database = database
        self._collection = f"{collection_prefix}connect_tokens"
        self._client: AsyncClient | None = None

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info("[FirestoreConnectTokenStore] Setup complete (collection=%s)", self._collection)

    @property
    def _db(self) -> AsyncClient:
        if self._client is None:
            raise RuntimeError("FirestoreConnectTokenStore.setup() must be called before use")
        return self._client

    async def create(self, app_key: str) -> str:
        """Create a single-use connect token for an app. Returns the token."""
        token = f"{CONNECT_TOKEN_PREFIX}{secrets.token_urlsafe(KEY_BYTES)}"
        token_record = {"app_key": app_key, "created_at": time.time()}
        await self._db.collection(self._collection).document(hash_doc_id(token)).set(token_record)
        logger.info("[FirestoreConnectTokenStore] Created for app: %s", app_key)
        return token

    async def consume(self, token: str) -> str | None:
        """Validate and consume a connect token. Returns app_key or None.

        Single-use: the document is deleted inside the transaction on the first
        successful validation, so a concurrent or replayed consume finds it gone.
        Expired tokens (older than ``CONNECT_TOKEN_TTL``) return None and are left
        for ``cleanup_expired`` / native TTL to reap.
        """
        token_ref = self._db.collection(self._collection).document(hash_doc_id(token))

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> str | None:
            # The SDK re-invokes this closure on retry, so read the clock here — a
            # ``now`` captured at method entry could let an expired token pass on a
            # later attempt.
            now = time.time()
            snap = await token_ref.get(transaction=transaction)
            token_fields = snap.to_dict()
            if token_fields is None:
                return None
            if now - token_fields["created_at"] > CONNECT_TOKEN_TTL:
                return None
            transaction.delete(token_ref)
            return token_fields["app_key"]

        # @async_transactional erases the wrapped return type to Coroutine[Unknown];
        # cast back so the str | None return type-checks.
        return cast(str | None, await _attempt(self._db.transaction()))

    async def cleanup_expired(self) -> None:
        """Delete tokens older than ``CONNECT_TOKEN_TTL``.

        Native TTL on ``created_at`` could also drive this server-side; the query
        path is a backstop and keeps tests deterministic.
        """
        threshold = time.time() - CONNECT_TOKEN_TTL
        query = self._db.collection(self._collection).where(
            filter=FieldFilter("created_at", "<=", threshold)
        )
        async for doc in query.stream():
            await doc.reference.delete()
