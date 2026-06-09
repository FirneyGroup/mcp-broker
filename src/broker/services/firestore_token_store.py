"""Firestore token store — persists OAuth tokens and registrations.

Implements the TokenStore ABC using Firestore Native mode for multi-instance
Cloud Run deployments (strongly-consistent point reads and queries).

Collection structure:
  {prefix}connections/{doc_id}   → {app_key, connector_name, connection_json, expires_at}
  {prefix}registrations/{doc_id} → {connector_name, registration_json}

Document IDs are SHA-256 hashes so raw secrets never appear in the document path.
"""

import logging
import time

from google.cloud.firestore_v1 import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from broker.models.connection import AppConnection
from broker.models.connector_config import DynamicRegistration
from broker.services.firestore_client import get_firestore_client, hash_doc_id
from broker.services.store import TokenStore

logger = logging.getLogger(__name__)

# Firestore caps a single WriteBatch at 500 operations; chunk cascade deletes here.
_BATCH_LIMIT = 500

# Bound on the re-query-then-delete loop that closes the snapshot race in
# delete_all_for_app (a concurrent save landing after one snapshot is caught by
# the next pass). Bounded so a pathological write storm can't spin forever.
_DELETE_ALL_MAX_PASSES = 5


class FirestoreTokenStore(TokenStore):
    """Firestore-backed token store for Cloud Run deployments.

    `save` writes a single (app_key, connector_name) document and does NOT touch
    the app's other connectors. The re-provisioning cascade (deleting an app's
    connections when its broker key is deleted/recreated) lives in the broker-key
    path via `delete_all_for_app`, not here.
    """

    def __init__(self, project_id: str, database: str = "(default)", collection_prefix: str = ""):
        self._project_id = project_id
        self._database = database
        self._collection_prefix = collection_prefix
        self._client: AsyncClient | None = None
        # Collection names are derived from the prefix at construction — always str.
        self._conn_collection = f"{collection_prefix}connections"
        self._reg_collection = f"{collection_prefix}registrations"

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info(
            "[FirestoreTokenStore] Setup complete (project=%s, database=%s, "
            "conn_collection=%s, reg_collection=%s)",
            self._project_id,
            self._database,
            self._conn_collection,
            self._reg_collection,
        )

    async def teardown(self) -> None:
        """No-op — the client lifecycle is owned by the app lifespan."""

    @property
    def _db(self) -> AsyncClient:
        """Return the initialized client, or raise if `setup()` has not run."""
        if self._client is None:
            raise RuntimeError("FirestoreTokenStore.setup() must be called before use")
        return self._client

    # --- Connections ---

    async def get(self, app_key: str, connector_name: str) -> AppConnection | None:
        """Retrieve a stored connection, or None if absent."""
        doc_id = hash_doc_id(f"{app_key}:{connector_name}")
        doc = await self._db.collection(self._conn_collection).document(doc_id).get()
        conn_fields = doc.to_dict()
        if conn_fields is None:
            return None
        connection_json = conn_fields.get("connection_json")
        if connection_json is None:
            logger.warning(
                "[FirestoreTokenStore] Connection doc %s missing connection_json; skipping", doc_id
            )
            return None
        return AppConnection.model_validate_json(connection_json)

    async def save(self, app_key: str, connector_name: str, connection: AppConnection) -> None:
        """Create or replace the single (app_key, connector_name) connection document."""
        doc_id = hash_doc_id(f"{app_key}:{connector_name}")
        conn_record = {
            "app_key": app_key,
            "connector_name": connector_name,
            "connection_json": connection.model_dump_json(),
            "expires_at": connection.expires_at,  # top-level + indexed for list_expiring
            "saved_at": time.time(),
        }
        await self._db.collection(self._conn_collection).document(doc_id).set(conn_record)
        logger.info("[FirestoreTokenStore] Saved connection: %s/%s", app_key, connector_name)

    async def delete(self, app_key: str, connector_name: str) -> None:
        """Delete a specific connection."""
        doc_id = hash_doc_id(f"{app_key}:{connector_name}")
        await self._db.collection(self._conn_collection).document(doc_id).delete()
        logger.info("[FirestoreTokenStore] Deleted connection: %s/%s", app_key, connector_name)

    async def delete_all_for_app(self, app_key: str) -> int:
        """Delete every connection for an app. Returns the number deleted.

        Called from the broker-key path so re-provisioning the same app_key cannot
        inherit previously-linked OAuth tokens.
        """
        collection = self._db.collection(self._conn_collection)
        deleted_count = 0
        # Re-query-then-delete until a pass finds none: a save landing after one
        # snapshot would survive a single-pass cascade (AGENTS.md Gotcha #2,
        # multi-instance). Bounded so a write storm can't spin forever.
        for _ in range(_DELETE_ALL_MAX_PASSES):
            query = collection.where(filter=FieldFilter("app_key", "==", app_key))
            refs = [doc.reference async for doc in query.stream()]
            if not refs:
                break
            await self._batch_delete(refs)
            deleted_count += len(refs)
        if deleted_count:
            logger.info(
                "[FirestoreTokenStore] Deleted %d connections for %s", deleted_count, app_key
            )
        return deleted_count

    async def _batch_delete(self, refs: list) -> None:
        """Delete the given document references in WriteBatch chunks of _BATCH_LIMIT."""
        for start in range(0, len(refs), _BATCH_LIMIT):
            batch = self._db.batch()
            for ref in refs[start : start + _BATCH_LIMIT]:
                batch.delete(ref)
            await batch.commit()

    async def list_for_app(self, app_key: str) -> list[AppConnection]:
        """List all connections for an app."""
        query = self._db.collection(self._conn_collection).where(
            filter=FieldFilter("app_key", "==", app_key)
        )
        connections: list[AppConnection] = []
        async for doc in query.stream():
            conn_fields = doc.to_dict()
            connection_json = conn_fields.get("connection_json") if conn_fields else None
            if connection_json is None:
                # One malformed doc must not crash the maintenance loop that lists
                # an app's connections — skip it and surface the doc id (never the
                # token contents) so an operator can investigate.
                logger.warning(
                    "[FirestoreTokenStore] Skipping connection doc %s missing connection_json",
                    doc.id,
                )
                continue
            connections.append(AppConnection.model_validate_json(connection_json))
        return connections

    async def list_expiring(
        self, buffer_seconds: int = 600
    ) -> list[tuple[str, str, AppConnection]]:
        """List connections expiring within `buffer_seconds`.

        Connections with no expiry (`expires_at` None) are excluded — the `> 0`
        filter drops nulls, matching the SQLite `expires_at IS NOT NULL` guard.
        """
        threshold = int(time.time()) + buffer_seconds
        query = (
            self._db.collection(self._conn_collection)
            .where(filter=FieldFilter("expires_at", ">", 0))
            .where(filter=FieldFilter("expires_at", "<=", threshold))
        )
        results: list[tuple[str, str, AppConnection]] = []
        async for doc in query.stream():
            conn_fields = doc.to_dict() or {}
            connection_json = conn_fields.get("connection_json")
            app_key = conn_fields.get("app_key")
            connector_name = conn_fields.get("connector_name")
            if connection_json is None or app_key is None or connector_name is None:
                # A malformed doc must not crash the token-refresh maintenance loop
                # that drives list_expiring — skip it and surface the doc id only.
                logger.warning(
                    "[FirestoreTokenStore] Skipping expiring doc %s missing required fields", doc.id
                )
                continue
            connection = AppConnection.model_validate_json(connection_json)
            results.append((app_key, connector_name, connection))
        return results

    # --- Registrations ---

    async def get_registration(self, connector_name: str) -> DynamicRegistration | None:
        """Retrieve a stored dynamic registration, or None if absent."""
        doc_id = hash_doc_id(f"registration:{connector_name}")
        doc = await self._db.collection(self._reg_collection).document(doc_id).get()
        reg_fields = doc.to_dict()
        if reg_fields is None:
            return None
        registration_json = reg_fields.get("registration_json")
        if registration_json is None:
            logger.warning(
                "[FirestoreTokenStore] Registration doc %s missing registration_json; skipping",
                doc_id,
            )
            return None
        return DynamicRegistration.model_validate_json(registration_json)

    async def save_registration(
        self, connector_name: str, registration: DynamicRegistration
    ) -> None:
        """Create or replace a dynamic registration."""
        doc_id = hash_doc_id(f"registration:{connector_name}")
        reg_record = {
            "connector_name": connector_name,
            "registration_json": registration.model_dump_json(),
            "registered_at": time.time(),
        }
        await self._db.collection(self._reg_collection).document(doc_id).set(reg_record)
        logger.info("[FirestoreTokenStore] Saved registration: %s", connector_name)
