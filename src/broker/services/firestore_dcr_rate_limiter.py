"""Firestore implementation of the per-IP DCR rate limiter.

Backs ``DCRRateLimiter`` on Firestore Native mode so the per-IP cap on
``/oauth/register`` holds across instances — the in-memory limiter's cap becomes
(cap × N) under N workers / replicas, which is why the in-memory backend forces a
single worker. This limiter shares one counter per IP across all instances.

Collection structure:
  {prefix}dcr_rate_limits/{doc_id}  → {events: [timestamp, ...]}

Document IDs are ``hash_doc_id(ip)`` so a path-unsafe IP (e.g. an IPv6 literal)
can't break the document path. The IP itself is not a secret, but hashing keeps
the path-shape uniform with the other Firestore stores.
"""

import logging
import time
from typing import cast

from google.cloud.firestore_v1 import AsyncClient, async_transactional
from google.cloud.firestore_v1.async_transaction import AsyncTransaction

from broker.services.auth_store_interfaces import DCRRateLimiter
from broker.services.firestore_client import get_firestore_client, hash_doc_id

logger = logging.getLogger(__name__)


class FirestoreDCRRateLimiter(DCRRateLimiter):
    """Per-IP sliding-window rate limiter backed by Firestore (Native mode).

    Mirrors the in-memory ``_DCRRateLimiter`` window/cap semantics exactly:
    ``allow`` filters the IP's event timestamps to the window, rejects when the
    count is already at the cap, otherwise appends the new event and returns True.
    The whole read-modify-write runs in a transaction so the cap holds under
    concurrent registrations across instances.
    """

    def __init__(  # noqa: PLR0913 -- one-time wiring: window/cap params plus Firestore connection coords, not a hot path
        self,
        max_per_window: int,
        window_seconds: int,
        project_id: str,
        database: str = "(default)",
        collection_prefix: str = "",
    ):
        self._max_per_window = max_per_window
        self._window_seconds = window_seconds
        self._project_id = project_id
        self._database = database
        self._collection = f"{collection_prefix}dcr_rate_limits"
        self._client: AsyncClient | None = None

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info("[FirestoreDCRRateLimiter] Setup complete (collection=%s)", self._collection)

    @property
    def _db(self) -> AsyncClient:
        if self._client is None:
            raise RuntimeError("FirestoreDCRRateLimiter.setup() must be called before use")
        return self._client

    async def allow(self, client_ip: str) -> bool:
        """True if the IP is under the cap; records the event when True.

        Transactional read → window-filter → append-if-under-cap → write so two
        concurrent registrations from the same IP cannot both slip past the cap.
        """
        ip_ref = self._db.collection(self._collection).document(hash_doc_id(client_ip))

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> bool:
            # The SDK re-invokes this closure on retry, so read the clock here so a
            # contended re-run filters the window against the current time.
            now_ts = time.time()
            snap = await ip_ref.get(transaction=transaction)
            ip_fields = snap.to_dict() or {}
            events = [
                ts for ts in ip_fields.get("events", []) if now_ts - ts < self._window_seconds
            ]
            if len(events) >= self._max_per_window:
                # Persist the pruned window so stale timestamps don't accumulate,
                # but reject — the IP is at the cap.
                transaction.set(ip_ref, {"events": events})
                return False
            events.append(now_ts)
            transaction.set(ip_ref, {"events": events})
            return True

        # @async_transactional erases the wrapped return type to Coroutine[Unknown];
        # cast back so the bool return type-checks.
        return cast(bool, await _attempt(self._db.transaction()))

    async def cleanup_expired(self) -> None:
        """Drop per-IP documents whose newest event has aged out of the window.

        Mirrors the in-memory limiter's cleanup: an IP whose events have all aged
        past the window is reaped so the collection doesn't grow unbounded as
        one-shot IPs come and go. Filtering on a denormalized ``latest_event``
        would need a write on every allow(); instead we scan and check in code,
        matching the in-memory O(N) walk (N bounded by recently-seen IPs).
        """
        now_ts = time.time()
        async for doc in self._db.collection(self._collection).stream():
            ip_fields = doc.to_dict() or {}
            events = ip_fields.get("events", [])
            if not events or all(now_ts - ts >= self._window_seconds for ts in events):
                await doc.reference.delete()
