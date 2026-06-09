"""Firestore implementation of BrokerKeyStore.

Document ID is ``hash_doc_id(app_key)`` — a deterministic hash, so creation is
still atomic (``create()`` fails if the app already has a key, matching SQLite's
PK constraint) while keeping path-unsafe characters (e.g. a ``/`` in an app_key)
out of the document path. ``key_hash`` is an indexed field, so ``verify`` is a
single strongly-consistent query.

Only the SHA-256 key hash is stored; raw keys are shown once and never persisted.
The real ``app_key`` is kept as a document field (returned by ``verify``/``list_keys``).
"""

import logging
from datetime import UTC, datetime

from google.api_core.exceptions import AlreadyExists, NotFound
from google.cloud.firestore_v1 import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from broker.services.api_key_store import BrokerKeyStore, generate_api_key, hash_api_key
from broker.services.firestore_client import get_firestore_client, hash_doc_id

logger = logging.getLogger(__name__)


class FirestoreBrokerKeyStore(BrokerKeyStore):
    """Per-app API key store backed by Firestore (Native mode)."""

    def __init__(self, project_id: str, database: str = "(default)", collection_prefix: str = ""):
        self._project_id = project_id
        self._database = database
        self._collection = f"{collection_prefix}broker_keys"
        self._client: AsyncClient | None = None

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info("[FirestoreKeyStore] Setup complete (collection=%s)", self._collection)

    async def teardown(self) -> None:
        """No-op — the client lifecycle is owned by the app lifespan."""

    @property
    def _db(self) -> AsyncClient:
        if self._client is None:
            raise RuntimeError("FirestoreBrokerKeyStore.setup() must be called before use")
        return self._client

    async def create_key(self, app_key: str) -> str:
        """Create a key for an app. Returns the raw API key (shown once)."""
        if not app_key:
            raise ValueError("app_key must not be empty")
        key = generate_api_key()
        key_record = {
            "app_key": app_key,
            "key_hash": hash_api_key(key),
            "created_at": datetime.now(UTC).isoformat(),
            "rotated_at": None,
        }
        try:
            await (
                self._db.collection(self._collection)
                .document(hash_doc_id(app_key))
                .create(key_record)
            )
        except AlreadyExists as exc:
            raise ValueError(f"App '{app_key}' already has a key") from exc
        return key

    async def verify(self, raw_key: str) -> str | None:
        """Verify a key by its hash. Returns app_key on success, None on failure.

        SHA-256 pre-image resistance makes timing attacks on the hash lookup
        infeasible, matching the SQLite store's rationale and the standard
        API-key verification pattern.
        """
        if not raw_key:
            return None
        query = (
            self._db.collection(self._collection)
            .where(filter=FieldFilter("key_hash", "==", hash_api_key(raw_key)))
            .limit(1)
        )
        async for doc in query.stream():
            key_record = doc.to_dict()
            app_key = key_record.get("app_key") if key_record else None
            if app_key is None:
                # A malformed key doc must not 500 the auth path — skip it and surface
                # the doc id (never the key hash) so an operator can investigate.
                logger.warning("[FirestoreKeyStore] Key doc %s missing app_key; skipping", doc.id)
                continue
            return app_key
        return None

    async def rotate(self, app_key: str) -> str | None:
        """Rotate the key for an app. Returns the new key, or None if not found."""
        if not app_key:
            return None
        key = generate_api_key()
        try:
            await (
                self._db.collection(self._collection)
                .document(hash_doc_id(app_key))
                .update(
                    {"key_hash": hash_api_key(key), "rotated_at": datetime.now(UTC).isoformat()}
                )
            )
        except NotFound:
            return None
        return key

    async def list_keys(self) -> list[dict]:
        """List all registered apps (no key hashes exposed)."""
        keys: list[dict] = []
        async for doc in self._db.collection(self._collection).stream():
            key_record = doc.to_dict()
            if key_record is None:
                continue
            keys.append(
                {
                    "app_key": key_record["app_key"],
                    "created_at": key_record["created_at"],
                    "rotated_at": key_record.get("rotated_at"),
                }
            )
        return keys

    async def has_key(self, app_key: str) -> bool:
        """Check if an app has a key (point read)."""
        if not app_key:
            return False
        snapshot = await self._db.collection(self._collection).document(hash_doc_id(app_key)).get()
        return snapshot.exists

    async def delete_key(self, app_key: str) -> bool:
        """Delete an app's key. Returns True if a key existed and was deleted.

        The bool is best-effort under concurrency: two simultaneous deletes of the
        same app may both observe the doc and return True (SQLite is atomic here).
        The deletion itself is idempotent.
        """
        if not app_key:
            return False
        doc_ref = self._db.collection(self._collection).document(hash_doc_id(app_key))
        snapshot = await doc_ref.get()
        if not snapshot.exists:
            return False
        await doc_ref.delete()
        return True
