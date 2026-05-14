"""Tests for SQLiteInboundAuthStore.

Real SQLite; no mocking the store itself. Concurrency tests use
`asyncio.to_thread` to drive truly parallel writes against the same database,
which is the only way to exercise the `BEGIN IMMEDIATE` serialization path.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import time
from pathlib import Path

import pytest

from broker.models.inbound_auth import (
    InboundToken,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RotatedTokenPair,
)
from broker.services.inbound_auth_store import (
    REPLAY_DETECTION_WINDOW_SECONDS,
    InvalidGrantError,
    SQLiteInboundAuthStore,
    generate_access_token,
    generate_client_id,
    generate_family_id,
    generate_refresh_token,
)

# === FIXTURES ===

GENERIC_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
GENERIC_APP_KEY = "acme:claude_ai"
GENERIC_RESOURCE = "https://broker.example.com/proxy/notion"
GENERIC_SCOPE = "mcp:proxy:notion"
GENERIC_CHALLENGE = "abcdef01234567890123456789012345678901234567"


def _sha256(value: str) -> str:
    """Mirror of the store's internal hashing — used in tests to seed rows."""
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteInboundAuthStore:
    """Fresh store backed by a temp DB. mkdir-p exercised via nested subdir."""
    db_path = tmp_path / "subdir" / "inbound_oauth.db"
    initialized = SQLiteInboundAuthStore(str(db_path))
    await initialized.setup()
    return initialized


def _registration(auth_method: str = "none") -> RegistrationRequest:
    return RegistrationRequest(
        client_name="Acme Claude",
        redirect_uris=[GENERIC_REDIRECT_URI],
        token_endpoint_auth_method=auth_method,  # type: ignore[arg-type] -- Literal narrowed at runtime
    )


def _oauth_code(client_id: str, expires_at: int | None = None) -> OAuthCode:
    return OAuthCode(
        client_id=client_id,
        app_key=GENERIC_APP_KEY,
        redirect_uri=GENERIC_REDIRECT_URI,
        resource=GENERIC_RESOURCE,
        scope=GENERIC_SCOPE,
        code_challenge=GENERIC_CHALLENGE,
        expires_at=expires_at if expires_at is not None else int(time.time()) + 60,
    )


async def _seed_refresh_pair(
    store: SQLiteInboundAuthStore,
    client_id: str,
    *,
    refresh_expires_in: int = 2592000,
    app_key: str = GENERIC_APP_KEY,
) -> tuple[str, str, str]:
    """Insert a synthetic (access, refresh) pair and return their hashes + family_id."""
    family_id = generate_family_id()
    _, access_hash = generate_access_token()
    _, refresh_hash = generate_refresh_token()
    now_ts = int(time.time())
    access_token_row = InboundToken(
        token_hash=access_hash,
        token_kind="access",
        family_id=family_id,
        client_id=client_id,
        app_key=app_key,
        resource=GENERIC_RESOURCE,
        scope=GENERIC_SCOPE,
        expires_at=now_ts + 3600,
        issued_at=now_ts,
    )
    refresh_token_row = InboundToken(
        token_hash=refresh_hash,
        token_kind="refresh",
        family_id=family_id,
        client_id=client_id,
        app_key=app_key,
        resource=GENERIC_RESOURCE,
        scope=GENERIC_SCOPE,
        expires_at=now_ts + refresh_expires_in,
        issued_at=now_ts,
    )
    pair = RotatedTokenPair(
        access=access_token_row,
        refresh=refresh_token_row,
        raw_access_token="placeholder-not-stored",
        raw_refresh_token="placeholder-not-stored",
    )
    await store.create_token_pair(pair)
    return access_hash, refresh_hash, family_id


def _rotation_request(
    token_hash: str,
    client_id: str,
    *,
    access_ttl: int = 3600,
    refresh_ttl: int = 2592000,
    resource: str = GENERIC_RESOURCE,
    scope: str = GENERIC_SCOPE,
) -> RefreshRotationRequest:
    """Build a RefreshRotationRequest with sane defaults for the common case."""
    return RefreshRotationRequest(
        token_hash=token_hash,
        client_id=client_id,
        resource=resource,
        scope=scope,
        access_ttl_seconds=access_ttl,
        refresh_ttl_seconds=refresh_ttl,
    )


def _count_family_rows(db_path: str, family_id: str) -> int:
    """Count surviving rows for a family. Bypasses the store — read-only verification."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM inbound_tokens WHERE family_id = ?", (family_id,)
        )
        return cursor.fetchone()[0]
    finally:
        conn.close()


# =============================================================================
# SETUP
# =============================================================================


async def test_setup_creates_parent_directory(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "inbound_oauth.db"
    nested_store = SQLiteInboundAuthStore(str(db_path))
    await nested_store.setup()
    assert db_path.parent.exists()
    assert db_path.exists()


async def test_setup_is_idempotent(store: SQLiteInboundAuthStore) -> None:
    """Second setup() must not raise on existing tables."""
    await store.setup()
    await store.setup()


# =============================================================================
# CLIENT REGISTRATION
# =============================================================================


async def test_create_client_public_no_secret(store: SQLiteInboundAuthStore) -> None:
    response = await store.create_client(_registration(), client_ip="1.2.3.4")
    assert response.client_id.startswith("mcp_client_")
    assert response.client_secret is None
    assert response.client_name == "Acme Claude"


async def test_create_client_confidential_returns_secret_once(
    store: SQLiteInboundAuthStore,
) -> None:
    response = await store.create_client(
        _registration(auth_method="client_secret_basic"), client_ip=None
    )
    assert response.client_secret is not None
    # Hash on disk; raw never re-readable.
    fetched = await store.get_client(response.client_id)
    assert fetched is not None
    assert fetched.token_endpoint_auth_method == "client_secret_basic"


async def test_get_client_round_trip(store: SQLiteInboundAuthStore) -> None:
    registration = _registration()
    response = await store.create_client(registration, client_ip="1.2.3.4")
    fetched = await store.get_client(response.client_id)
    assert fetched is not None
    assert fetched.client_id == response.client_id
    assert fetched.client_name == "Acme Claude"
    assert fetched.redirect_uris == [GENERIC_REDIRECT_URI]


async def test_get_client_unknown_returns_none(store: SQLiteInboundAuthStore) -> None:
    assert await store.get_client("mcp_client_does_not_exist") is None


# =============================================================================
# AUTHORIZATION CODES
# =============================================================================


async def test_create_and_consume_code_happy_path(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    raw_code = "the-raw-auth-code-value"
    code_hash = _sha256(raw_code)
    await store.create_code(code_hash, _oauth_code(client_id))
    consumed = await store.consume_code(code_hash, client_id)
    assert consumed is not None
    assert consumed.client_id == client_id
    assert consumed.resource == GENERIC_RESOURCE


async def test_consume_code_is_single_use(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    code_hash = _sha256("single-use-code")
    await store.create_code(code_hash, _oauth_code(client_id))
    first = await store.consume_code(code_hash, client_id)
    second = await store.consume_code(code_hash, client_id)
    assert first is not None
    assert second is None


async def test_consume_code_mismatched_client_returns_none(
    store: SQLiteInboundAuthStore,
) -> None:
    issued_client_id = generate_client_id()
    other_client_id = generate_client_id()
    code_hash = _sha256("client-mismatch-code")
    await store.create_code(code_hash, _oauth_code(issued_client_id))
    consumed = await store.consume_code(code_hash, other_client_id)
    assert consumed is None
    # Code must NOT be deleted on client mismatch — leave it for the rightful owner.
    rightful = await store.consume_code(code_hash, issued_client_id)
    assert rightful is not None


async def test_consume_code_expired_returns_none(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    code_hash = _sha256("expired-code")
    past_expiry = int(time.time()) - 10
    await store.create_code(code_hash, _oauth_code(client_id, expires_at=past_expiry))
    assert await store.consume_code(code_hash, client_id) is None


# =============================================================================
# TOKEN PAIR + ACCESS LOOKUP
# =============================================================================


async def test_create_token_pair_and_get_access(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    access_hash, _, family_id = await _seed_refresh_pair(store, client_id)
    fetched_access = await store.get_access(access_hash)
    assert fetched_access is not None
    assert fetched_access.family_id == family_id
    assert fetched_access.client_id == client_id


async def test_get_access_unknown_returns_none(store: SQLiteInboundAuthStore) -> None:
    assert await store.get_access("no-such-hash") is None


async def test_get_access_does_not_return_refresh_rows(
    store: SQLiteInboundAuthStore,
) -> None:
    """get_access must filter by token_kind='access' so refresh hashes can't validate."""
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)
    assert await store.get_access(refresh_hash) is None


# =============================================================================
# REFRESH ROTATION — atomic guarantees
# =============================================================================


async def test_rotate_refresh_happy_path(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    _, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    rotation_request = _rotation_request(refresh_hash, client_id)
    rotated = await store.rotate_refresh(rotation_request)
    assert rotated.access.family_id == family_id
    assert rotated.refresh.family_id == family_id
    assert rotated.refresh.parent_refresh_hash == refresh_hash
    # Old refresh row persists with used_at set (replay detection canary).
    persisted_refresh = _read_token(store, refresh_hash)
    assert persisted_refresh is not None
    assert persisted_refresh["used_at"] is not None


async def test_rotate_refresh_replay_revokes_family(
    store: SQLiteInboundAuthStore,
) -> None:
    """Replaying an already-used refresh wipes the entire family."""
    client_id = generate_client_id()
    _, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    rotation_request = _rotation_request(refresh_hash, client_id)
    await store.rotate_refresh(rotation_request)
    # Family now has: old access + old refresh (used_at set) + new access + new refresh.
    assert _count_family_rows(store._db_path, family_id) == 4
    with pytest.raises(InvalidGrantError, match="replay"):
        await store.rotate_refresh(rotation_request)
    # Replay must cascade — every row in the family deleted.
    assert _count_family_rows(store._db_path, family_id) == 0


async def test_rotate_refresh_concurrent_at_most_one_succeeds(
    store: SQLiteInboundAuthStore,
) -> None:
    """asyncio.gather + asyncio.to_thread → real concurrency against SQLite.

    The `BEGIN IMMEDIATE` serialization means exactly one caller mints a new
    pair; the loser sees `used_at NOT NULL` on its conditional UPDATE and
    raises InvalidGrantError after revoking the family.
    """
    client_id = generate_client_id()
    _, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    rotation_request = _rotation_request(refresh_hash, client_id)

    async def rotate_in_thread() -> RotatedTokenPair:
        # Wrap the (sync-under-the-hood) async method in a thread so the two
        # callers actually contend on SQLite's reserved lock.
        return await asyncio.to_thread(asyncio.run, store.rotate_refresh(rotation_request))

    outcomes = await asyncio.gather(rotate_in_thread(), rotate_in_thread(), return_exceptions=True)
    successes = [out for out in outcomes if isinstance(out, RotatedTokenPair)]
    failures = [out for out in outcomes if isinstance(out, InvalidGrantError)]
    assert len(successes) == 1, f"Expected exactly one success, got {len(successes)}"
    assert len(failures) == 1
    assert "replay" in str(failures[0])
    # Loser triggered family revoke → entire family gone.
    assert _count_family_rows(store._db_path, family_id) == 0


async def test_rotate_refresh_missing_returns_invalid_grant(
    store: SQLiteInboundAuthStore,
) -> None:
    rotation_request = _rotation_request("hash-of-nonexistent-token", generate_client_id())
    with pytest.raises(InvalidGrantError, match="not found"):
        await store.rotate_refresh(rotation_request)


async def test_rotate_refresh_expired_returns_invalid_grant(
    store: SQLiteInboundAuthStore,
) -> None:
    client_id = generate_client_id()
    # Seed with a refresh that's already expired (negative TTL).
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id, refresh_expires_in=-10)
    rotation_request = _rotation_request(refresh_hash, client_id)
    with pytest.raises(InvalidGrantError):
        await store.rotate_refresh(rotation_request)


async def test_rotate_refresh_wrong_client_returns_invalid_grant(
    store: SQLiteInboundAuthStore,
) -> None:
    """Refresh token belonging to client A cannot be rotated by client B."""
    issued_client_id = generate_client_id()
    other_client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, issued_client_id)
    rotation_request = _rotation_request(refresh_hash, other_client_id)
    with pytest.raises(InvalidGrantError):
        await store.rotate_refresh(rotation_request)


async def test_rotate_refresh_rolls_back_on_mint_failure(
    store: SQLiteInboundAuthStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Crash mid-rotation: monkeypatch _mint_replacement_pair to raise.

    The transaction must roll back so `used_at` stays NULL and a retry works.
    """
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("simulated crash after UPDATE used_at")

    monkeypatch.setattr(SQLiteInboundAuthStore, "_mint_replacement_pair", staticmethod(boom))
    rotation_request = _rotation_request(refresh_hash, client_id)
    with pytest.raises(RuntimeError, match="simulated crash"):
        await store.rotate_refresh(rotation_request)
    # Rollback must have restored used_at to NULL.
    persisted = _read_token(store, refresh_hash)
    assert persisted is not None
    assert persisted["used_at"] is None
    # Sanity: retry without the monkeypatch succeeds.
    monkeypatch.undo()
    rotated = await store.rotate_refresh(rotation_request)
    assert rotated.access.client_id == client_id


# =============================================================================
# REVOKE — RFC 7009
# =============================================================================


async def test_revoke_token_access_deletes_only_that_row(
    store: SQLiteInboundAuthStore,
) -> None:
    client_id = generate_client_id()
    access_hash, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    await store.revoke_token(access_hash, client_id, kind="access")
    assert await store.get_access(access_hash) is None
    # Refresh and family intact.
    assert _count_family_rows(store._db_path, family_id) == 1
    persisted_refresh = _read_token(store, refresh_hash)
    assert persisted_refresh is not None


async def test_revoke_token_refresh_cascades_to_family(
    store: SQLiteInboundAuthStore,
) -> None:
    client_id = generate_client_id()
    _, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    assert _count_family_rows(store._db_path, family_id) == 2
    await store.revoke_token(refresh_hash, client_id, kind="refresh")
    assert _count_family_rows(store._db_path, family_id) == 0


async def test_revoke_token_silent_on_unknown(store: SQLiteInboundAuthStore) -> None:
    """RFC 7009 §2.2: revoke MUST silently succeed regardless of existence."""
    await store.revoke_token("hash-of-nonexistent", generate_client_id(), kind="access")
    await store.revoke_token("hash-of-nonexistent", generate_client_id(), kind="refresh")


async def test_revoke_token_silent_on_wrong_client(store: SQLiteInboundAuthStore) -> None:
    """Wrong client_id silently no-ops — but the rightful owner's token survives."""
    client_id = generate_client_id()
    other_client_id = generate_client_id()
    access_hash, _, _ = await _seed_refresh_pair(store, client_id)
    await store.revoke_token(access_hash, other_client_id, kind="access")
    assert await store.get_access(access_hash) is not None


async def test_revoke_family_cascades(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    _, _, family_id = await _seed_refresh_pair(store, client_id)
    await store.revoke_family(family_id)
    assert _count_family_rows(store._db_path, family_id) == 0


# =============================================================================
# CASCADE DELETE (AGENTS.md Known Gotcha #2)
# =============================================================================


async def test_delete_all_for_app_scoped_to_target_app(
    store: SQLiteInboundAuthStore,
) -> None:
    """Cascade only deletes the target app's rows; other apps untouched."""
    # App A: client + code + token pair.
    client_a = await store.create_client(_registration(), client_ip=None)
    code_hash_a = _sha256("code-app-a")
    await store.create_code(code_hash_a, _oauth_code(client_a.client_id))
    _, _, family_a = await _seed_refresh_pair(store, client_a.client_id)
    # App B uses a different app_key — manually wire a token pair.
    other_app_key = "acme:web"
    _, _, family_b = await _seed_refresh_pair(store, generate_client_id(), app_key=other_app_key)
    other_code_hash = _sha256("code-app-b")
    other_code = OAuthCode(
        client_id=client_a.client_id,  # client itself isn't app-bound; this is fine
        app_key=other_app_key,
        redirect_uri=GENERIC_REDIRECT_URI,
        resource=GENERIC_RESOURCE,
        scope=GENERIC_SCOPE,
        code_challenge=GENERIC_CHALLENGE,
        expires_at=int(time.time()) + 60,
    )
    await store.create_code(other_code_hash, other_code)
    # Cascade for App A.
    await store.delete_all_for_app(GENERIC_APP_KEY)
    # App A's tokens + code gone.
    assert _count_family_rows(store._db_path, family_a) == 0
    assert await store.consume_code(code_hash_a, client_a.client_id) is None
    # App B's tokens + code untouched.
    assert _count_family_rows(store._db_path, family_b) == 2
    other_consumed = await store.consume_code(other_code_hash, client_a.client_id)
    assert other_consumed is not None
    # Client row also untouched — clients aren't app-bound in v1.
    assert await store.get_client(client_a.client_id) is not None


async def test_delete_all_for_app_empty_string_is_noop(
    store: SQLiteInboundAuthStore,
) -> None:
    """Defensive: empty app_key must not nuke the whole table."""
    client_id = generate_client_id()
    _, _, family_id = await _seed_refresh_pair(store, client_id)
    await store.delete_all_for_app("")
    assert _count_family_rows(store._db_path, family_id) == 2


# =============================================================================
# CLEANUP
# =============================================================================


async def test_cleanup_expired_deletes_expired_codes_only(
    store: SQLiteInboundAuthStore,
) -> None:
    client_id = generate_client_id()
    fresh_code_hash = _sha256("fresh-code")
    expired_code_hash = _sha256("expired-code")
    await store.create_code(fresh_code_hash, _oauth_code(client_id))
    await store.create_code(
        expired_code_hash, _oauth_code(client_id, expires_at=int(time.time()) - 100)
    )
    await store.cleanup_expired()
    # Fresh code survives.
    consumed_fresh = await store.consume_code(fresh_code_hash, client_id)
    assert consumed_fresh is not None
    # Expired code already gone before consume even runs.
    assert await store.consume_code(expired_code_hash, client_id) is None


async def test_cleanup_expired_deletes_expired_tokens_only(
    store: SQLiteInboundAuthStore,
) -> None:
    client_id = generate_client_id()
    fresh_access, _, _ = await _seed_refresh_pair(store, client_id)
    expired_access, _, _ = await _seed_refresh_pair(store, client_id, refresh_expires_in=-100)
    # Manually expire the second access row (helper expiry only touches refresh).
    conn = sqlite3.connect(store._db_path)
    try:
        conn.execute(
            "UPDATE inbound_tokens SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()) - 50, expired_access),
        )
        conn.commit()
    finally:
        conn.close()
    await store.cleanup_expired()
    assert await store.get_access(fresh_access) is not None
    assert await store.get_access(expired_access) is None


async def test_cleanup_expired_preserves_used_refresh_within_replay_window(
    store: SQLiteInboundAuthStore,
) -> None:
    """Used refresh rows must persist past expiry inside the replay window so
    replay attempts trigger family revoke instead of falling through as
    "not found". Without this carve-out, an attacker who waits past the row's
    natural expiry can hide the replay."""
    client_id = generate_client_id()
    _, refresh_hash, family_id = await _seed_refresh_pair(store, client_id)
    now_ts = int(time.time())
    # Mark used 1 day ago; expire 1 hour ago — squarely inside the 7-day window.
    _force_refresh_state(store, refresh_hash, used_at=now_ts - 86400, expires_at=now_ts - 3600)
    await store.cleanup_expired()
    persisted = _read_token(store, refresh_hash)
    assert persisted is not None, "used refresh row was reaped inside replay window"
    # Replay attempt against the preserved row must now revoke the family.
    rotation_request = _rotation_request(refresh_hash, client_id)
    with pytest.raises(InvalidGrantError, match="replay"):
        await store.rotate_refresh(rotation_request)
    assert _count_family_rows(store._db_path, family_id) == 0


async def test_cleanup_expired_purges_used_refresh_outside_replay_window(
    store: SQLiteInboundAuthStore,
) -> None:
    """Past the 7-day replay window the row is reaped — operators get table
    growth bounded, and the replay-detection coverage only extends so far."""
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)
    now_ts = int(time.time())
    outside_window = now_ts - REPLAY_DETECTION_WINDOW_SECONDS - 1
    _force_refresh_state(store, refresh_hash, used_at=outside_window, expires_at=outside_window)
    await store.cleanup_expired()
    assert _read_token(store, refresh_hash) is None


async def test_rotate_refresh_uses_provided_ttls(store: SQLiteInboundAuthStore) -> None:
    """TTLs come from the rotation request — never hardcoded. Operator config
    must propagate to every rotation, not just the initial issue."""
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)
    custom_access_ttl = 600
    custom_refresh_ttl = 86400 * 14
    # Fix `now` so we can assert on expires_at without flakiness.
    fixed_now = int(time.time())
    rotation_request = _rotation_request(
        refresh_hash,
        client_id,
        access_ttl=custom_access_ttl,
        refresh_ttl=custom_refresh_ttl,
    )
    rotated = await store.rotate_refresh(rotation_request, now_ts=fixed_now)
    assert rotated.access.expires_at == fixed_now + custom_access_ttl
    assert rotated.refresh.expires_at == fixed_now + custom_refresh_ttl


# =============================================================================
# verify_client_secret
# =============================================================================


async def test_verify_client_secret_happy_path(store: SQLiteInboundAuthStore) -> None:
    registration = await store.create_client(
        _registration(auth_method="client_secret_basic"), client_ip=None
    )
    assert registration.client_secret is not None
    assert await store.verify_client_secret(registration.client_id, registration.client_secret)


async def test_verify_client_secret_wrong_secret(store: SQLiteInboundAuthStore) -> None:
    registration = await store.create_client(
        _registration(auth_method="client_secret_basic"), client_ip=None
    )
    assert not await store.verify_client_secret(registration.client_id, "not-the-real-secret")


async def test_verify_client_secret_public_client_returns_false(
    store: SQLiteInboundAuthStore,
) -> None:
    """Public clients (auth_method='none') have no secret_hash — any supplied secret fails."""
    registration = await store.create_client(_registration(), client_ip=None)
    assert not await store.verify_client_secret(registration.client_id, "any-string")


async def test_verify_client_secret_unknown_client_returns_false(
    store: SQLiteInboundAuthStore,
) -> None:
    assert not await store.verify_client_secret("mcp_client_does_not_exist", "any-secret")


async def test_verify_client_secret_empty_inputs_return_false(
    store: SQLiteInboundAuthStore,
) -> None:
    """Empty inputs short-circuit before the DB lookup."""
    assert not await store.verify_client_secret("", "anything")
    assert not await store.verify_client_secret("mcp_client_xyz", "")


# =============================================================================
# get_refresh_row
# =============================================================================


async def test_get_refresh_row_returns_unused(store: SQLiteInboundAuthStore) -> None:
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)
    fetched = await store.get_refresh_row(refresh_hash)
    assert fetched is not None
    assert fetched.token_kind == "refresh"
    assert fetched.used_at is None


async def test_get_refresh_row_returns_used(store: SQLiteInboundAuthStore) -> None:
    """Used refresh rows must remain readable — the /token endpoint needs them
    to detect replay attempts at the precondition layer."""
    client_id = generate_client_id()
    _, refresh_hash, _ = await _seed_refresh_pair(store, client_id)
    await store.rotate_refresh(_rotation_request(refresh_hash, client_id))
    fetched = await store.get_refresh_row(refresh_hash)
    assert fetched is not None
    assert fetched.used_at is not None


async def test_get_refresh_row_unknown_returns_none(store: SQLiteInboundAuthStore) -> None:
    assert await store.get_refresh_row("hash-of-nonexistent") is None


async def test_get_refresh_row_does_not_return_access_rows(
    store: SQLiteInboundAuthStore,
) -> None:
    """The query must filter by token_kind='refresh' to prevent access-token hashes
    from validating as refresh rows."""
    client_id = generate_client_id()
    access_hash, _, _ = await _seed_refresh_pair(store, client_id)
    assert await store.get_refresh_row(access_hash) is None


# =============================================================================
# HELPERS used only inside tests
# =============================================================================


def _read_token(store: SQLiteInboundAuthStore, token_hash: str) -> dict[str, object] | None:
    """Read a token row directly. Returns dict or None. Used for state assertions
    that bypass the store API (verifying rollback, used_at, etc.)."""
    conn = sqlite3.connect(store._db_path)
    try:
        row = conn.execute(
            "SELECT token_hash, token_kind, used_at, family_id, expires_at "
            "FROM inbound_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "token_hash": row[0],
        "token_kind": row[1],
        "used_at": row[2],
        "family_id": row[3],
        "expires_at": row[4],
    }


def _force_refresh_state(
    store: SQLiteInboundAuthStore,
    token_hash: str,
    *,
    used_at: int,
    expires_at: int,
) -> None:
    """Bypass the store to set `used_at` and `expires_at` directly for cleanup tests."""
    conn = sqlite3.connect(store._db_path)
    try:
        conn.execute(
            "UPDATE inbound_tokens SET used_at = ?, expires_at = ? WHERE token_hash = ?",
            (used_at, expires_at, token_hash),
        )
        conn.commit()
    finally:
        conn.close()
