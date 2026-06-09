"""Firestore implementation of the inbound OAuth 2.1 auth store.

Mirrors ``SQLiteInboundAuthStore`` semantics on Firestore Native mode for
multi-instance Cloud Run. Collections (doc IDs are already hashes/ids, so they
are safe in the path):

  {prefix}oauth_clients/{client_id}
  {prefix}oauth_codes/{code_hash}
  {prefix}inbound_tokens/{token_hash}

Security-critical pieces preserved:
- Authorization codes are single-use (transactional read-check-delete).
- Refresh rotation is atomic: a Firestore transaction marks the old refresh used
  and writes the new pair together. Replay (a second rotation of an already-used
  refresh) is signalled by a sentinel RETURN from the transaction (never a raise
  inside it, which the SDK would treat as a retryable abort); the family is then
  cascade-deleted and ``InvalidGrantError`` raised OUTSIDE the transaction.
- Hashes (code/token/client-secret) are stored, never raw secrets.
- ``reap_at`` drives native TTL and the cleanup query: ``expires_at`` for access
  tokens and unused refreshes, ``used_at + replay window`` for a rotated refresh.

Shared generation helpers + ``InvalidGrantError`` are imported from the SQLite
module so both backends mint identically and raise the same exception class that
``oauth_server`` catches.
"""

import hmac
import logging
import time
from datetime import UTC, datetime
from typing import Literal, cast

from google.api_core.exceptions import Aborted
from google.cloud.firestore_v1 import AsyncClient, async_transactional
from google.cloud.firestore_v1.async_transaction import AsyncTransaction
from google.cloud.firestore_v1.base_query import FieldFilter
from pydantic import BaseModel, ConfigDict, ValidationError

from broker.models.inbound_auth import (
    InboundToken,
    OAuthClient,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RegistrationResponse,
    RotatedTokenPair,
)
from broker.services.auth_store_interfaces import InboundAuthStore
from broker.services.firestore_client import get_firestore_client
from broker.services.inbound_auth_store import (
    REPLAY_DETECTION_WINDOW_SECONDS,
    InvalidGrantError,
    RotationContendedError,
    generate_access_token,
    generate_client_id,
    generate_client_secret,
    generate_refresh_token,
)
from broker.services.inbound_oauth_helpers import (
    audit_log_oauth_event,
    hash_prefix,
    sha256_hex,
)

logger = logging.getLogger(__name__)

# Firestore transactions are optimistic on the emulator (real Standard-edition is
# pessimistic and blocks); bump the SDK's internal retry budget so a contended
# rotation's loser re-reads the winner's commit and resolves to a clean replay
# rather than exhausting retries and raising.
_ROTATE_TXN_ATTEMPTS = 10

# Firestore caps a single WriteBatch at 500 operations; we chunk family deletes
# at this size so a large family commits atomically per chunk instead of failing.
_BATCH_LIMIT = 500

# Bound on the re-query-then-delete loop that closes the snapshot race in
# delete_all_for_app (a concurrent save landing after one snapshot is caught by
# the next pass). Bounded so a pathological write storm can't spin forever.
_DELETE_ALL_MAX_PASSES = 5


# === INTERNAL ===


class _RotateOutcome(BaseModel):
    """Sentinel returned from the rotation transaction so replay/miss are handled
    OUTSIDE the transaction (raising inside would be treated as a retryable abort)."""

    kind: Literal["ok", "replay", "not_found"]
    pair: RotatedTokenPair | None = None
    family_id: str | None = None

    model_config = ConfigDict(frozen=True)


def _token_doc(token: InboundToken, reap_at: int) -> dict:
    """Serialize an InboundToken to a Firestore document with a TTL ``reap_at``."""
    return {**token.model_dump(), "reap_at": reap_at}


def _token_from_doc(token_fields: dict) -> InboundToken:
    """Rebuild an InboundToken from a document (dropping the doc-only ``reap_at``)."""
    return InboundToken.model_validate(
        {key: value for key, value in token_fields.items() if key != "reap_at"}
    )


def _mint_rotated_pair(
    family_id: str, app_key: str, req: RefreshRotationRequest, now_ts: int
) -> RotatedTokenPair:
    """Mint a fresh (access, refresh) pair in the same family. Pure — no I/O."""
    raw_access, access_hash = generate_access_token()
    raw_refresh, refresh_hash = generate_refresh_token()
    access = InboundToken(
        token_hash=access_hash,
        token_kind="access",  # noqa: S106 -- discriminator literal, not a credential
        parent_refresh_hash=refresh_hash,
        family_id=family_id,
        client_id=req.client_id,
        app_key=app_key,
        resource=req.resource,
        scope=req.scope,
        expires_at=now_ts + req.access_ttl_seconds,
        issued_at=now_ts,
    )
    refresh = InboundToken(
        token_hash=refresh_hash,
        token_kind="refresh",  # noqa: S106 -- discriminator literal, not a credential
        parent_refresh_hash=req.token_hash,
        family_id=family_id,
        client_id=req.client_id,
        app_key=app_key,
        resource=req.resource,
        scope=req.scope,
        expires_at=now_ts + req.refresh_ttl_seconds,
        issued_at=now_ts,
    )
    return RotatedTokenPair(
        access=access, refresh=refresh, raw_access_token=raw_access, raw_refresh_token=raw_refresh
    )


# === STORE ===


class FirestoreInboundAuthStore(InboundAuthStore):
    """OAuth 2.1 inbound auth store backed by Firestore (Native mode)."""

    def __init__(self, project_id: str, database: str = "(default)", collection_prefix: str = ""):
        self._project_id = project_id
        self._database = database
        self._clients_name = f"{collection_prefix}oauth_clients"
        self._codes_name = f"{collection_prefix}oauth_codes"
        self._tokens_name = f"{collection_prefix}inbound_tokens"
        self._client: AsyncClient | None = None

    async def setup(self) -> None:
        """Acquire the shared Firestore client."""
        self._client = get_firestore_client(self._project_id, self._database)
        logger.info("[FirestoreInboundAuthStore] Setup complete (prefix=%s)", self._tokens_name)

    @property
    def _db(self) -> AsyncClient:
        if self._client is None:
            raise RuntimeError("FirestoreInboundAuthStore.setup() must be called before use")
        return self._client

    # --- DCR clients ---

    async def create_client(
        self, request: RegistrationRequest, client_ip: str | None
    ) -> RegistrationResponse:
        client_id = generate_client_id()
        raw_secret, secret_hash = self._mint_secret_if_confidential(
            request.token_endpoint_auth_method
        )
        doc = {
            "client_id": client_id,
            "client_secret_hash": secret_hash,
            "token_endpoint_auth_method": request.token_endpoint_auth_method,
            "redirect_uris": list(request.redirect_uris),
            "grant_types": list(request.grant_types),
            "response_types": list(request.response_types),
            "scope": request.scope,
            "client_name": request.client_name,
            "created_at": datetime.now(UTC).isoformat(),
            "created_ip": client_ip,
        }
        await self._db.collection(self._clients_name).document(client_id).set(doc)
        audit_log_oauth_event(
            "dcr_register", client_id=client_id, redirect_uris=request.redirect_uris, ip=client_ip
        )
        return RegistrationResponse(
            client_id=client_id,
            client_id_issued_at=int(time.time()),
            client_secret=raw_secret,
            client_secret_expires_at=0,
            token_endpoint_auth_method=request.token_endpoint_auth_method,
            grant_types=request.grant_types,
            response_types=request.response_types,
            redirect_uris=request.redirect_uris,
            client_name=request.client_name,
            scope=request.scope,
        )

    @staticmethod
    def _mint_secret_if_confidential(auth_method: str) -> tuple[str | None, str | None]:
        """Public clients ('none') get no secret; everyone else gets one + its hash."""
        if auth_method == "none":
            return None, None
        return generate_client_secret()

    async def get_client(self, client_id: str) -> OAuthClient | None:
        snap = await self._db.collection(self._clients_name).document(client_id).get()
        client_fields = snap.to_dict()
        if client_fields is None:
            return None
        return OAuthClient(
            client_id=client_fields["client_id"],
            token_endpoint_auth_method=client_fields["token_endpoint_auth_method"],
            redirect_uris=client_fields["redirect_uris"],
            grant_types=client_fields["grant_types"],
            response_types=client_fields["response_types"],
            scope=client_fields["scope"],
            client_name=client_fields["client_name"],
            created_at=client_fields["created_at"],
        )

    async def verify_client_secret(self, client_id: str, supplied_secret: str) -> bool:
        if not client_id or not supplied_secret:
            return False
        snap = await self._db.collection(self._clients_name).document(client_id).get()
        client_fields = snap.to_dict()
        if client_fields is None or client_fields.get("client_secret_hash") is None:
            return False
        return hmac.compare_digest(client_fields["client_secret_hash"], sha256_hex(supplied_secret))

    # --- Authorization codes (single-use) ---

    async def create_code(self, code_hash: str, oauth_code: OAuthCode) -> None:
        await self._db.collection(self._codes_name).document(code_hash).set(oauth_code.model_dump())

    async def consume_code(self, code_hash: str, client_id: str) -> OAuthCode | None:
        code_ref = self._db.collection(self._codes_name).document(code_hash)

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> dict | None:
            # The SDK re-invokes this closure on retry, so the expiry clock must be
            # read here — a `now_ts` captured at method entry could let an expired
            # code pass on a later attempt.
            now_ts = int(time.time())
            snap = await code_ref.get(transaction=transaction)
            code_fields = snap.to_dict()
            if (
                code_fields is None
                or code_fields["expires_at"] <= now_ts
                or code_fields["client_id"] != client_id
            ):
                return None
            transaction.delete(code_ref)
            return code_fields

        # @async_transactional erases the wrapped return type to Coroutine[Unknown];
        # cast back so the OAuthCode validation below type-checks.
        code_fields = cast(dict | None, await _attempt(self._db.transaction()))
        return OAuthCode.model_validate(code_fields) if code_fields is not None else None

    # --- Tokens + rotation ---

    async def create_token_pair(self, pair: RotatedTokenPair) -> None:
        tokens = self._db.collection(self._tokens_name)
        # Atomic two-doc write so a partial failure can't orphan one token.
        batch = self._db.batch()
        batch.set(
            tokens.document(pair.access.token_hash), _token_doc(pair.access, pair.access.expires_at)
        )
        batch.set(
            tokens.document(pair.refresh.token_hash),
            _token_doc(pair.refresh, pair.refresh.expires_at),
        )
        await batch.commit()
        audit_log_oauth_event(
            "token_issue",
            client_id=pair.access.client_id,
            app_key=pair.access.app_key,
            family_id=pair.access.family_id,
            access_hash_prefix=hash_prefix(pair.access.token_hash),
            refresh_hash_prefix=hash_prefix(pair.refresh.token_hash),
        )

    async def rotate_refresh(
        self, rotation_request: RefreshRotationRequest, now_ts: int | None = None
    ) -> RotatedTokenPair:
        tokens = self._db.collection(self._tokens_name)
        refresh_ref = tokens.document(rotation_request.token_hash)

        @async_transactional
        async def _attempt(transaction: AsyncTransaction) -> _RotateOutcome:
            # The SDK re-invokes this closure on retry, so resolve the expiry clock
            # here — a `now` captured at method entry could let an expired refresh
            # pass the expiry check on a contended re-run seconds later.
            now = now_ts if now_ts is not None else int(time.time())
            snap = await refresh_ref.get(transaction=transaction)
            refresh_fields = snap.to_dict()
            # client_id scoping is a security invariant (cross-client forced-logout).
            if (
                refresh_fields is None
                or refresh_fields.get("token_kind") != "refresh"
                or refresh_fields.get("client_id") != rotation_request.client_id
            ):
                return _RotateOutcome(kind="not_found")
            # Replay is checked BEFORE expiry: a used refresh retained inside the
            # replay window (its row outlives expires_at) must surface as replay and
            # revoke the family, not fall through as "not_found" once it expires
            # (OAuth 2.1 §4.3.1, matching the SQLite backend).
            if refresh_fields.get("used_at") is not None:
                return _RotateOutcome(kind="replay", family_id=refresh_fields["family_id"])
            if refresh_fields.get("expires_at", 0) <= now:
                return _RotateOutcome(kind="not_found")
            transaction.update(
                refresh_ref,
                {"used_at": now, "reap_at": now + REPLAY_DETECTION_WINDOW_SECONDS},
            )
            pair = _mint_rotated_pair(
                refresh_fields["family_id"], refresh_fields["app_key"], rotation_request, now
            )
            transaction.set(
                tokens.document(pair.access.token_hash),
                _token_doc(pair.access, pair.access.expires_at),
            )
            transaction.set(
                tokens.document(pair.refresh.token_hash),
                _token_doc(pair.refresh, pair.refresh.expires_at),
            )
            return _RotateOutcome(kind="ok", pair=pair)

        # _classify_contention re-reads with the same clock the closure would use.
        now = now_ts if now_ts is not None else int(time.time())
        try:
            # @async_transactional erases the wrapped return type to Coroutine[Unknown];
            # cast back to the sentinel so the outcome dispatch below type-checks.
            outcome = cast(
                _RotateOutcome,
                await _attempt(self._db.transaction(max_attempts=_ROTATE_TXN_ATTEMPTS)),
            )
        except ValidationError:
            # A corrupt/partial token doc fails _mint_rotated_pair's model build with a
            # ValidationError (a ValueError subclass). Re-raise it FIRST so real data
            # corruption surfaces instead of being misclassified as storage contention
            # and looping the caller on retryable 503s forever.
            raise
        except (Aborted, ValueError):
            # Internal retries exhausted under contention — re-read (no txn) and
            # classify so a concurrent rotation surfaces as a clean replay or a
            # retryable error, never a raw 500.
            outcome = await self._classify_contention(rotation_request, now)
        return await self._resolve_outcome(outcome, rotation_request)

    async def _resolve_outcome(
        self, outcome: _RotateOutcome, rotation_request: RefreshRotationRequest
    ) -> RotatedTokenPair:
        """Audit + return on success, cascade-revoke on replay, raise otherwise."""
        if outcome.kind == "ok" and outcome.pair is not None:
            audit_log_oauth_event(
                "token_refresh_rotate",
                client_id=outcome.pair.access.client_id,
                family_id=outcome.pair.access.family_id,
                old_hash_prefix=hash_prefix(rotation_request.token_hash),
                new_hash_prefix=hash_prefix(outcome.pair.refresh.token_hash),
            )
            return outcome.pair
        if outcome.kind == "replay" and outcome.family_id is not None:
            await self._revoke_family_docs(outcome.family_id)
            audit_log_oauth_event(
                "token_refresh_replay_revoke",
                client_id=rotation_request.client_id,
                family_id=outcome.family_id,
                hash_prefix=hash_prefix(rotation_request.token_hash),
            )
            raise InvalidGrantError("refresh replay; family revoked")
        raise InvalidGrantError("refresh not found, expired, or client mismatch")

    async def _classify_contention(
        self, rotation_request: RefreshRotationRequest, now: int
    ) -> _RotateOutcome:
        """Resolve a contended rotation from a fresh (non-transactional) point read."""
        snap = (
            await self._db.collection(self._tokens_name).document(rotation_request.token_hash).get()
        )
        refresh_fields = snap.to_dict()
        if (
            refresh_fields is None
            or refresh_fields.get("token_kind") != "refresh"
            or refresh_fields.get("client_id") != rotation_request.client_id
        ):
            return _RotateOutcome(kind="not_found")
        # Replay before expiry, mirroring the transaction closure: a used refresh in
        # the replay window must revoke the family even after expires_at passes.
        if refresh_fields.get("used_at") is not None:
            return _RotateOutcome(kind="replay", family_id=refresh_fields["family_id"])
        if refresh_fields.get("expires_at", 0) <= now:
            return _RotateOutcome(kind="not_found")
        # Refresh is still live; the rotation just kept losing the race. Retryable —
        # NOT invalid_grant (which would wrongly force re-auth on a valid token).
        raise RotationContendedError("refresh rotation contended; retry")

    async def get_access(self, token_hash: str) -> InboundToken | None:
        snap = await self._db.collection(self._tokens_name).document(token_hash).get()
        token_fields = snap.to_dict()
        if token_fields is None or token_fields.get("token_kind") != "access":
            return None
        # Defense-in-depth: constant-time confirm the stored hash matches.
        if not hmac.compare_digest(token_fields["token_hash"], token_hash):
            return None
        return _token_from_doc(token_fields)

    async def get_refresh_row(self, token_hash: str) -> InboundToken | None:
        snap = await self._db.collection(self._tokens_name).document(token_hash).get()
        token_fields = snap.to_dict()
        if token_fields is None or token_fields.get("token_kind") != "refresh":
            return None
        return _token_from_doc(token_fields)

    async def revoke_token(
        self, token_hash: str, client_id: str, kind: Literal["access", "refresh"]
    ) -> bool:
        ref = self._db.collection(self._tokens_name).document(token_hash)
        snap = await ref.get()
        token_fields = snap.to_dict()
        did_delete = False
        if kind == "refresh":
            if (
                token_fields is not None
                and token_fields.get("token_kind") == "refresh"
                and token_fields.get("client_id") == client_id
            ):
                await self._revoke_family_docs(token_fields["family_id"])
                did_delete = True
        elif (
            token_fields is not None
            and token_fields.get("token_kind") == "access"
            and token_fields.get("client_id") == client_id
        ):
            await ref.delete()
            did_delete = True
        if did_delete:
            audit_log_oauth_event(
                "token_revoke", client_id=client_id, kind=kind, hash_prefix=hash_prefix(token_hash)
            )
        return did_delete

    async def revoke_family(self, family_id: str, client_id: str) -> None:
        # Query by family_id only (single-field auto-index) and scope client_id in
        # code, so no composite index is required. family_id is a 128-bit secret.
        query = self._db.collection(self._tokens_name).where(
            filter=FieldFilter("family_id", "==", family_id)
        )
        refs = [
            doc.reference
            async for doc in query.stream()
            if (token_fields := doc.to_dict()) is not None
            and token_fields.get("client_id") == client_id
        ]
        await self._batch_delete(refs)

    async def _revoke_family_docs(self, family_id: str) -> None:
        """Delete every token in a family (replay/refresh-revoke cascade).

        Batched so a mid-cascade failure can't leave live tokens in a family that
        AGENTS.md requires to be fully revoked on replay.
        """
        query = self._db.collection(self._tokens_name).where(
            filter=FieldFilter("family_id", "==", family_id)
        )
        refs = [doc.reference async for doc in query.stream()]
        await self._batch_delete(refs)

    async def _batch_delete(self, refs: list) -> None:
        """Delete the given document references in WriteBatch chunks of _BATCH_LIMIT."""
        for start in range(0, len(refs), _BATCH_LIMIT):
            batch = self._db.batch()
            for ref in refs[start : start + _BATCH_LIMIT]:
                batch.delete(ref)
            await batch.commit()

    # --- Maintenance ---

    async def cleanup_expired(self) -> None:
        """Reap expired codes and tokens. Native TTL on expires_at/reap_at also does
        this server-side; this query path is a backstop and keeps tests deterministic."""
        now_ts = int(time.time())
        codes = self._db.collection(self._codes_name).where(
            filter=FieldFilter("expires_at", "<=", now_ts)
        )
        async for doc in codes.stream():
            await doc.reference.delete()
        # reap_at: expires_at for access/unused refresh, used_at + window for a used refresh.
        tokens = self._db.collection(self._tokens_name).where(
            filter=FieldFilter("reap_at", "<=", now_ts)
        )
        async for doc in tokens.stream():
            await doc.reference.delete()

    async def delete_all_for_app(self, app_key: str) -> None:
        """Cascade-delete codes + tokens for an app_key. Leaves oauth_clients (not app-bound)."""
        if not app_key:
            return
        for name in (self._codes_name, self._tokens_name):
            await self._delete_all_matching(name, app_key)
        logger.info("[FirestoreInboundAuthStore] Cascade-deleted rows for app: %s", app_key)

    async def _delete_all_matching(self, collection_name: str, app_key: str) -> None:
        """Batch-delete every doc whose ``app_key`` matches, re-querying until a pass
        finds none. The re-query loop closes the snapshot race where a save landing
        after one stream survives the cascade (AGENTS.md Gotcha #2, multi-instance)."""
        collection = self._db.collection(collection_name)
        for _ in range(_DELETE_ALL_MAX_PASSES):
            query = collection.where(filter=FieldFilter("app_key", "==", app_key))
            refs = [doc.reference async for doc in query.stream()]
            if not refs:
                return
            await self._batch_delete(refs)
