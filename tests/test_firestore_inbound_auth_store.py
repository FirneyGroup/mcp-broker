"""Emulator-backed tests for FirestoreInboundAuthStore.

Exercises the real Firestore client against the emulator (no mocks), per AGENTS.md.
Skipped when no emulator is reachable. Start one with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import asyncio
import os
import time

import pytest
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)

from broker.models.inbound_auth import (
    InboundToken,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RotatedTokenPair,
)
from broker.services.firestore_inbound_auth_store import FirestoreInboundAuthStore
from broker.services.inbound_auth_store import (
    REPLAY_DETECTION_WINDOW_SECONDS,
    InvalidGrantError,
    RotationContendedError,
    generate_access_token,
    generate_family_id,
    generate_refresh_token,
)
from broker.services.inbound_oauth_helpers import sha256_hex

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)


@pytest.fixture
async def store():
    configure_firestore_client_env()
    prefix = f"test_{os.urandom(4).hex()}_"
    inbound = FirestoreInboundAuthStore(project_id=FIRESTORE_PROJECT, collection_prefix=prefix)
    await inbound.setup()
    yield inbound
    await cleanup_live_collections(prefix)
    await reset_firestore_client()


# === helpers ===


def _make_pair(client_id: str, app_key: str = "acme:app1") -> tuple[RotatedTokenPair, str, str]:
    family_id = generate_family_id()
    raw_a, access_hash = generate_access_token()
    raw_r, refresh_hash = generate_refresh_token()
    now = int(time.time())
    access = InboundToken(
        token_hash=access_hash,
        token_kind="access",
        parent_refresh_hash=refresh_hash,
        family_id=family_id,
        client_id=client_id,
        app_key=app_key,
        resource="https://broker/proxy/x",
        scope="read",
        expires_at=now + 3600,
        issued_at=now,
    )
    refresh = InboundToken(
        token_hash=refresh_hash,
        token_kind="refresh",
        parent_refresh_hash=None,
        family_id=family_id,
        client_id=client_id,
        app_key=app_key,
        resource="https://broker/proxy/x",
        scope="read",
        expires_at=now + 86400,
        issued_at=now,
    )
    pair = RotatedTokenPair(
        access=access, refresh=refresh, raw_access_token=raw_a, raw_refresh_token=raw_r
    )
    return pair, refresh_hash, family_id


def _rotation_request(refresh_hash: str, client_id: str) -> RefreshRotationRequest:
    return RefreshRotationRequest(
        token_hash=refresh_hash,
        client_id=client_id,
        resource="https://broker/proxy/x",
        scope="read",
        access_ttl_seconds=3600,
        refresh_ttl_seconds=86400,
    )


async def _seed(
    store: FirestoreInboundAuthStore, client_id: str, app_key: str = "acme:app1"
) -> tuple[str, str]:
    pair, refresh_hash, family_id = _make_pair(client_id, app_key)
    await store.create_token_pair(pair)
    return refresh_hash, family_id


async def _count_family(store: FirestoreInboundAuthStore, family_id: str) -> int:
    from google.cloud.firestore_v1.base_query import FieldFilter

    query = store._db.collection(store._tokens_name).where(
        filter=FieldFilter("family_id", "==", family_id)
    )
    return len([doc async for doc in query.stream()])


async def _force_refresh_state(
    store: FirestoreInboundAuthStore, refresh_hash: str, used_at: int, expires_at: int, reap_at: int
) -> None:
    """Stamp a used/expiry/reap state on an existing refresh doc.

    Mirrors the SQLite `_force_refresh_state` helper: cleanup_expired reaps by
    `reap_at`, so a used refresh inside the replay window must carry
    `reap_at = used_at + REPLAY_DETECTION_WINDOW_SECONDS` (what rotate_refresh sets).
    """
    await (
        store._db.collection(store._tokens_name)
        .document(refresh_hash)
        .update({"used_at": used_at, "expires_at": expires_at, "reap_at": reap_at})
    )


async def _read_token(store: FirestoreInboundAuthStore, token_hash: str) -> dict | None:
    snap = await store._db.collection(store._tokens_name).document(token_hash).get()
    return snap.to_dict()


# === DCR clients ===


async def test_confidential_client_round_trip(store: FirestoreInboundAuthStore) -> None:
    request = RegistrationRequest(
        client_name="acme",
        redirect_uris=["https://claude.ai/cb"],
        token_endpoint_auth_method="client_secret_basic",
    )
    response = await store.create_client(request, client_ip="1.2.3.4")
    assert response.client_secret is not None
    assert await store.verify_client_secret(response.client_id, response.client_secret) is True
    assert await store.verify_client_secret(response.client_id, "wrong") is False
    fetched = await store.get_client(response.client_id)
    assert fetched is not None
    assert fetched.client_name == "acme"


async def test_public_client_has_no_secret(store: FirestoreInboundAuthStore) -> None:
    request = RegistrationRequest(
        client_name="pub", redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none"
    )
    response = await store.create_client(request, client_ip=None)
    assert response.client_secret is None
    assert await store.verify_client_secret(response.client_id, "anything") is False


# === codes (single-use) ===


def _code(client_id: str, app_key: str = "acme:app1", ttl: int = 60) -> OAuthCode:
    return OAuthCode(
        client_id=client_id,
        app_key=app_key,
        redirect_uri="https://claude.ai/cb",
        resource="https://broker/proxy/x",
        scope="read",
        code_challenge="challenge",
        expires_at=int(time.time()) + ttl,
    )


async def test_consume_code_is_single_use(store: FirestoreInboundAuthStore) -> None:
    code_hash = sha256_hex("code-123")
    await store.create_code(code_hash, _code("cr_client"))
    first = await store.consume_code(code_hash, "cr_client")
    assert first is not None
    assert await store.consume_code(code_hash, "cr_client") is None


async def test_consume_code_wrong_client(store: FirestoreInboundAuthStore) -> None:
    code_hash = sha256_hex("code-456")
    await store.create_code(code_hash, _code("cr_owner"))
    assert await store.consume_code(code_hash, "cr_other") is None


async def test_consume_code_expired(store: FirestoreInboundAuthStore) -> None:
    code_hash = sha256_hex("code-789")
    await store.create_code(code_hash, _code("cr_client", ttl=-1))
    assert await store.consume_code(code_hash, "cr_client") is None


# === tokens + rotation ===


async def test_create_and_get_token_pair(store: FirestoreInboundAuthStore) -> None:
    pair, refresh_hash, family_id = _make_pair("cr_client")
    await store.create_token_pair(pair)
    access = await store.get_access(pair.access.token_hash)
    assert access is not None and access.family_id == family_id
    refresh = await store.get_refresh_row(refresh_hash)
    assert refresh is not None and refresh.used_at is None


async def test_rotate_happy_path(store: FirestoreInboundAuthStore) -> None:
    refresh_hash, family_id = await _seed(store, "cr_client")
    rotated = await store.rotate_refresh(_rotation_request(refresh_hash, "cr_client"))
    assert rotated.access.family_id == family_id
    assert rotated.refresh.family_id == family_id
    # old refresh persists, marked used (replay canary)
    old = await store.get_refresh_row(refresh_hash)
    assert old is not None and old.used_at is not None


async def test_rotate_replay_revokes_family(store: FirestoreInboundAuthStore) -> None:
    refresh_hash, family_id = await _seed(store, "cr_client")
    req = _rotation_request(refresh_hash, "cr_client")
    await store.rotate_refresh(req)
    assert await _count_family(store, family_id) == 4  # old access+refresh + new access+refresh
    with pytest.raises(InvalidGrantError, match="replay"):
        await store.rotate_refresh(req)
    assert await _count_family(store, family_id) == 0


async def test_rotate_concurrent_at_most_one_succeeds(store: FirestoreInboundAuthStore) -> None:
    """Two concurrent rotations of the same refresh → exactly one mints, the other
    is detected as replay and revokes the family."""
    refresh_hash, _ = await _seed(store, "cr_client")
    req = _rotation_request(refresh_hash, "cr_client")

    outcomes = await asyncio.gather(
        store.rotate_refresh(req), store.rotate_refresh(req), return_exceptions=True
    )
    successes = [o for o in outcomes if isinstance(o, RotatedTokenPair)]
    # Loser fails closed: a clean replay (InvalidGrantError, which revokes the
    # family) or a retryable RotationContendedError if it kept losing the storage
    # race. The security invariant: there is never a second mint.
    failures = [o for o in outcomes if isinstance(o, (InvalidGrantError, RotationContendedError))]
    assert len(successes) == 1, f"expected exactly one mint, got {outcomes}"
    assert len(failures) == 1, f"expected the loser to fail closed, got {outcomes}"


async def test_rotate_missing_raises(store: FirestoreInboundAuthStore) -> None:
    with pytest.raises(InvalidGrantError):
        await store.rotate_refresh(_rotation_request(sha256_hex("nope"), "cr_client"))


async def test_rotate_wrong_client_raises(store: FirestoreInboundAuthStore) -> None:
    refresh_hash, _ = await _seed(store, "cr_owner")
    with pytest.raises(InvalidGrantError):
        await store.rotate_refresh(_rotation_request(refresh_hash, "cr_attacker"))


# === revocation ===


async def test_revoke_refresh_cascades_family(store: FirestoreInboundAuthStore) -> None:
    refresh_hash, family_id = await _seed(store, "cr_client")
    assert await store.revoke_token(refresh_hash, "cr_client", "refresh") is True
    assert await _count_family(store, family_id) == 0


async def test_revoke_access_single(store: FirestoreInboundAuthStore) -> None:
    pair, refresh_hash, family_id = _make_pair("cr_client")
    await store.create_token_pair(pair)
    assert await store.revoke_token(pair.access.token_hash, "cr_client", "access") is True
    assert await store.get_access(pair.access.token_hash) is None
    # refresh survives an access revoke
    assert await store.get_refresh_row(refresh_hash) is not None


# === maintenance ===


async def test_delete_all_for_app(store: FirestoreInboundAuthStore) -> None:
    refresh_hash, _ = await _seed(store, "cr_client", app_key="acme:app1")
    await store.create_code(sha256_hex("c1"), _code("cr_client", app_key="acme:app1"))
    # a client registration must NOT be deleted (not app-bound)
    reg = await store.create_client(
        RegistrationRequest(client_name="x", redirect_uris=["https://claude.ai/cb"]), client_ip=None
    )

    await store.delete_all_for_app("acme:app1")

    assert await store.get_refresh_row(refresh_hash) is None
    assert await store.consume_code(sha256_hex("c1"), "cr_client") is None
    assert await store.get_client(reg.client_id) is not None  # DCR client preserved


async def test_cleanup_expired_preserves_used_refresh_within_replay_window(
    store: FirestoreInboundAuthStore,
) -> None:
    """A used refresh must persist past expiry inside the replay window so a replay
    triggers family revoke instead of falling through as "not found". cleanup_expired
    reaps by reap_at = used_at + window, so the row stays until the window closes."""
    refresh_hash, family_id = await _seed(store, "cr_client")
    now_ts = int(time.time())
    # Used 1 day ago, expired 1 hour ago, but reap_at is 6 days out — inside the window.
    await _force_refresh_state(
        store,
        refresh_hash,
        used_at=now_ts - 86400,
        expires_at=now_ts - 3600,
        reap_at=now_ts - 86400 + REPLAY_DETECTION_WINDOW_SECONDS,
    )
    await store.cleanup_expired()
    assert await _read_token(store, refresh_hash) is not None, "row reaped inside replay window"
    # Replay against the preserved row must now revoke the whole family.
    with pytest.raises(InvalidGrantError, match="replay"):
        await store.rotate_refresh(_rotation_request(refresh_hash, "cr_client"))
    assert await _count_family(store, family_id) == 0


async def test_cleanup_expired_purges_used_refresh_outside_replay_window(
    store: FirestoreInboundAuthStore,
) -> None:
    """Past the replay window the used refresh is reaped — table growth stays bounded."""
    refresh_hash, _ = await _seed(store, "cr_client")
    now_ts = int(time.time())
    outside = now_ts - REPLAY_DETECTION_WINDOW_SECONDS - 1
    await _force_refresh_state(
        store, refresh_hash, used_at=outside, expires_at=outside, reap_at=outside
    )
    await store.cleanup_expired()
    assert await _read_token(store, refresh_hash) is None


async def test_revoke_family_does_not_cross_clients(store: FirestoreInboundAuthStore) -> None:
    """Revoking a family scoped to client A must not delete client B's family rows.

    Defense-in-depth: the 128-bit family_id already makes guessing infeasible; this
    pins the client_id constraint on the cascade so a leaked family_id can't force
    another client's logout."""
    _, victim_family_id = await _seed(store, "victim_client")
    # A second, independent family for a different client.
    _, attacker_family_id = await _seed(store, "attacker_client")

    # Attacker calls revoke_family with the victim's family_id but their own client_id.
    await store.revoke_family(victim_family_id, "attacker_client")

    assert await _count_family(store, victim_family_id) > 0, "victim family was cross-deleted"
    # Sanity: the attacker can revoke their own family.
    await store.revoke_family(attacker_family_id, "attacker_client")
    assert await _count_family(store, attacker_family_id) == 0


async def test_rotate_replay_batch_revokes_whole_family(
    store: FirestoreInboundAuthStore,
) -> None:
    """A replay must cascade-delete EVERY token in the family (batched), leaving no
    live token behind — AGENTS.md requires the full family revoked on replay."""
    refresh_hash, family_id = await _seed(store, "cr_client")
    req = _rotation_request(refresh_hash, "cr_client")
    await store.rotate_refresh(req)  # mints a second pair → 4 docs in the family
    assert await _count_family(store, family_id) == 4
    with pytest.raises(InvalidGrantError, match="replay"):
        await store.rotate_refresh(req)
    assert await _count_family(store, family_id) == 0


async def test_rotate_corrupt_doc_surfaces_validation_error(
    store: FirestoreInboundAuthStore,
) -> None:
    """A corrupt refresh doc (missing a required field) must surface the validation
    error, NOT be misclassified as storage contention (which would loop the caller
    on retryable 503s and hide real corruption)."""
    from pydantic import ValidationError

    refresh_hash, _ = await _seed(store, "cr_client")
    # Null out a required field so _mint_rotated_pair's InboundToken build fails.
    await store._db.collection(store._tokens_name).document(refresh_hash).update({"app_key": None})

    with pytest.raises(ValidationError):
        await store.rotate_refresh(_rotation_request(refresh_hash, "cr_client"))
