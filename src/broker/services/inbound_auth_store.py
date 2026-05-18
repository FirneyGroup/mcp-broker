"""SQLite implementation of the inbound OAuth auth store.

Uses synchronous sqlite3 with open-per-call connections, matching the broker's
existing TokenStore + SQLiteBrokerKeyStore patterns. Methods are async (for
interface symmetry with other stores) but the underlying SQLite calls are
synchronous.

v1.0 ships a single concrete class — no abstraction layer. If/when a second
backend is needed (Firestore, Postgres), an `InboundAuthStore` interface gets
extracted at that time (YAGNI).

WARNING: Single-process only. Multi-worker uvicorn deployments need either
sticky-session routing or a shared backing store.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from broker.models.inbound_auth import (
    InboundToken,
    OAuthClient,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RegistrationResponse,
    RotatedTokenPair,
)
from broker.services.inbound_oauth_helpers import (
    ACCESS_TOKEN_PREFIX,
    CLIENT_ID_PREFIX,
    REFRESH_TOKEN_PREFIX,
    audit_log_oauth_event,
    hash_prefix,
    sha256_hex,
)

logger = logging.getLogger(__name__)

# === CONSTANTS ===

CLIENT_SECRET_BYTES = 32
ACCESS_TOKEN_BYTES = 32
REFRESH_TOKEN_BYTES = 32
CLIENT_ID_BYTES = 32
FAMILY_ID_BYTES = 16

# Window after a refresh row's `expires_at` during which we retain rows with
# `used_at NOT NULL` so replay attempts past natural expiry still surface as
# OAuth 2.1 §4.3.1 replay (family revoke) rather than fall through as "not
# found". 7 days balances replay-window coverage against table growth.
REPLAY_DETECTION_WINDOW_SECONDS = 7 * 24 * 3600

# === INTERNAL ARG BUNDLES ===


class _ClientInsertContext(BaseModel):
    """Per-call constants for `_persist_client_row`. Internal — not a public model."""

    client_id: str
    secret_hash: str | None
    now_iso: str
    client_ip: str | None

    model_config = ConfigDict(extra="forbid", frozen=True)


class _NewPairContext(BaseModel):
    """Family + app + freshly-minted hashes shared by `_build_access_row` and
    `_build_refresh_row`. Internal — not a public model."""

    family_id: str
    app_key: str
    access_hash: str
    refresh_hash: str

    model_config = ConfigDict(extra="forbid", frozen=True)


# === EXCEPTIONS ===


class InvalidGrantError(RuntimeError):
    """Refresh token rotation rejected — replay, expiry, or missing token.

    Per OAuth 2.1 §4.3.1, on detected refresh replay the caller must cascade
    family revocation (which `rotate_refresh` handles before raising).
    """


# === TOKEN GENERATION HELPERS ===


def generate_client_id() -> str:
    """RFC 7591 client_id — prefixed for traceability in logs and ad-hoc SQL."""
    return f"{CLIENT_ID_PREFIX}{secrets.token_urlsafe(CLIENT_ID_BYTES)}"


def generate_client_secret() -> tuple[str, str]:
    """Returns (raw_secret, sha256_hash). Raw shown once at registration."""
    raw_secret = secrets.token_urlsafe(CLIENT_SECRET_BYTES)
    return raw_secret, sha256_hex(raw_secret)


def generate_access_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Raw given to client; hash stored."""
    raw_token = f"{ACCESS_TOKEN_PREFIX}{secrets.token_urlsafe(ACCESS_TOKEN_BYTES)}"
    return raw_token, sha256_hex(raw_token)


def generate_refresh_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Raw given to client; hash stored."""
    raw_token = f"{REFRESH_TOKEN_PREFIX}{secrets.token_urlsafe(REFRESH_TOKEN_BYTES)}"
    return raw_token, sha256_hex(raw_token)


def generate_family_id() -> str:
    """Unique id binding a refresh token to its rotation lineage."""
    return secrets.token_urlsafe(FAMILY_ID_BYTES)


# === STORE ===


class SQLiteInboundAuthStore:
    """OAuth 2.1 inbound auth store backed by SQLite.

    Three tables: `oauth_clients` (DCR), `oauth_codes` (authorization codes,
    single-use, 60s TTL), `inbound_tokens` (access + refresh, hashed).

    Atomic refresh rotation uses `BEGIN IMMEDIATE` + conditional UPDATE; see
    `rotate_refresh` for the proof obligation.
    """

    def __init__(self, db_path: str = "./data/inbound_oauth.db") -> None:
        """Construct a store rooted at `db_path` (created on first `setup()`)."""
        self._db_path = db_path

    # === CONNECTION HELPER ===

    @contextmanager
    def _db_conn(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Yield a connection; close on exit.

        `immediate=True` switches to autocommit mode (`isolation_level=None`)
        for callers that issue explicit `BEGIN IMMEDIATE` — namely
        `consume_code` and `_rotate_under_lock`. All other callers use the
        sqlite3 default (deferred) so writes wrap implicitly.
        """
        conn = sqlite3.connect(self._db_path, isolation_level=None if immediate else "DEFERRED")
        try:
            yield conn
        finally:
            conn.close()

    # === LIFECYCLE ===

    async def setup(self) -> None:
        """Create tables and indexes if missing. Idempotent."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._db_conn() as conn:
            self._create_schema(conn)
            conn.commit()
            logger.info("[InboundAuthStore] Initialized: %s", self._db_path)

    @staticmethod
    def _create_schema(conn: sqlite3.Connection) -> None:
        """DDL for oauth_clients, oauth_codes, inbound_tokens + indexes."""
        conn.execute(
            "CREATE TABLE IF NOT EXISTS oauth_clients ("
            "client_id TEXT PRIMARY KEY,"
            "client_secret_hash TEXT,"
            "token_endpoint_auth_method TEXT NOT NULL,"
            "redirect_uris TEXT NOT NULL,"
            "grant_types TEXT NOT NULL,"
            "response_types TEXT NOT NULL,"
            "scope TEXT,"
            "client_name TEXT NOT NULL,"
            "created_at TEXT NOT NULL,"
            "created_ip TEXT"
            ")"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_clients_ip_time "
            "ON oauth_clients(created_ip, created_at)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS oauth_codes ("
            "code_hash TEXT PRIMARY KEY,"
            "client_id TEXT NOT NULL,"
            "app_key TEXT NOT NULL,"
            "redirect_uri TEXT NOT NULL,"
            "resource TEXT NOT NULL,"
            "scope TEXT NOT NULL,"
            "code_challenge TEXT NOT NULL,"
            "expires_at INTEGER NOT NULL"
            ")"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS inbound_tokens ("
            "token_hash TEXT PRIMARY KEY,"
            "token_kind TEXT NOT NULL,"
            "parent_refresh_hash TEXT,"
            "family_id TEXT NOT NULL,"
            "client_id TEXT NOT NULL,"
            "app_key TEXT NOT NULL,"
            "resource TEXT NOT NULL,"
            "scope TEXT NOT NULL,"
            "expires_at INTEGER NOT NULL,"
            "issued_at INTEGER NOT NULL,"
            "used_at INTEGER"
            ")"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_inbound_tokens_family ON inbound_tokens(family_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_inbound_tokens_app_key ON inbound_tokens(app_key)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_inbound_tokens_expires ON inbound_tokens(expires_at)"
        )

    # === ROW → MODEL HELPERS ===

    @staticmethod
    def _row_to_inbound_token(row: tuple) -> InboundToken:
        """Unpack the 11-column `inbound_tokens` SELECT into the model."""
        return InboundToken(
            token_hash=row[0],
            token_kind=row[1],
            parent_refresh_hash=row[2],
            family_id=row[3],
            client_id=row[4],
            app_key=row[5],
            resource=row[6],
            scope=row[7],
            expires_at=row[8],
            issued_at=row[9],
            used_at=row[10],
        )

    @staticmethod
    def _row_to_oauth_code(row: tuple) -> OAuthCode:
        """Unpack the 7-column `oauth_codes` SELECT into the model."""
        return OAuthCode(
            client_id=row[0],
            app_key=row[1],
            redirect_uri=row[2],
            resource=row[3],
            scope=row[4],
            code_challenge=row[5],
            expires_at=row[6],
        )

    @staticmethod
    def _row_to_oauth_client(row: tuple) -> OAuthClient:
        """Unpack the 8-column `oauth_clients` SELECT into the model."""
        return OAuthClient(
            client_id=row[0],
            token_endpoint_auth_method=row[1],
            redirect_uris=json.loads(row[2]),
            grant_types=json.loads(row[3]),
            response_types=json.loads(row[4]),
            scope=row[5],
            client_name=row[6],
            created_at=row[7],
        )

    # === CLIENTS (DCR) ===

    async def create_client(
        self, request: RegistrationRequest, client_ip: str | None
    ) -> RegistrationResponse:
        """RFC 7591 dynamic client registration. Confidential clients receive a
        one-shot `client_secret`; only the hash is persisted."""
        client_id = generate_client_id()
        raw_secret, secret_hash = self._mint_secret_if_confidential(
            request.token_endpoint_auth_method
        )
        insert_context = _ClientInsertContext(
            client_id=client_id,
            secret_hash=secret_hash,
            now_iso=datetime.now(UTC).isoformat(),
            client_ip=client_ip,
        )
        with self._db_conn() as conn:
            self._persist_client_row(conn, request, insert_context)
            conn.commit()
        audit_log_oauth_event(
            "dcr_register",
            client_id=client_id,
            redirect_uris=request.redirect_uris,
            ip=client_ip,
        )
        return self._build_registration_response(client_id, raw_secret, int(time.time()), request)

    @staticmethod
    def _build_registration_response(
        client_id: str,
        raw_secret: str | None,
        issued_at: int,
        request: RegistrationRequest,
    ) -> RegistrationResponse:
        """Assemble the RFC 7591 §3.2.1 response. Echoes back the registration
        metadata so the client can confirm what was persisted."""
        return RegistrationResponse(
            client_id=client_id,
            client_id_issued_at=issued_at,
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
    def _persist_client_row(
        conn: sqlite3.Connection,
        request: RegistrationRequest,
        insert_context: _ClientInsertContext,
    ) -> None:
        """Single-row insert for `oauth_clients`. JSON-encodes list columns."""
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_secret_hash, "
            "token_endpoint_auth_method, redirect_uris, grant_types, response_types, "
            "scope, client_name, created_at, created_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                insert_context.client_id,
                insert_context.secret_hash,
                request.token_endpoint_auth_method,
                json.dumps(request.redirect_uris),
                json.dumps(request.grant_types),
                json.dumps(request.response_types),
                request.scope,
                request.client_name,
                insert_context.now_iso,
                insert_context.client_ip,
            ),
        )

    @staticmethod
    def _mint_secret_if_confidential(auth_method: str) -> tuple[str | None, str | None]:
        """Public clients (`none`) get no secret; everyone else gets one + its hash."""
        if auth_method == "none":
            return None, None
        return generate_client_secret()

    async def get_client(self, client_id: str) -> OAuthClient | None:
        """Lookup a DCR'd client by id. None on miss."""
        with self._db_conn() as conn:
            row = conn.execute(
                "SELECT client_id, token_endpoint_auth_method, redirect_uris, "
                "grant_types, response_types, scope, client_name, created_at "
                "FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_oauth_client(row)

    async def verify_client_secret(self, client_id: str, supplied_secret: str) -> bool:
        """Constant-time verify a confidential client's secret.

        Returns False on unknown client_id, public client (no secret_hash), or
        mismatch. Keeps the sqlite path inside the store rather than leaking
        `_db_path` to callers that need to authenticate clients.
        """
        if not client_id or not supplied_secret:
            return False
        with self._db_conn() as conn:
            row = conn.execute(
                "SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if not row or row[0] is None:
            return False
        return hmac.compare_digest(row[0], sha256_hex(supplied_secret))

    # === AUTHORIZATION CODES ===

    async def create_code(self, code_hash: str, oauth_code: OAuthCode) -> None:
        """Persist a freshly-minted auth code. PRIMARY KEY collision raises IntegrityError."""
        with self._db_conn() as conn:
            conn.execute(
                "INSERT INTO oauth_codes (code_hash, client_id, app_key, redirect_uri, "
                "resource, scope, code_challenge, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    code_hash,
                    oauth_code.client_id,
                    oauth_code.app_key,
                    oauth_code.redirect_uri,
                    oauth_code.resource,
                    oauth_code.scope,
                    oauth_code.code_challenge,
                    oauth_code.expires_at,
                ),
            )
            conn.commit()

    async def consume_code(self, code_hash: str, client_id: str) -> OAuthCode | None:
        """Atomic SELECT-then-DELETE under BEGIN IMMEDIATE. Single-use.

        Returns None on miss, expiry, or client_id mismatch — every failure mode
        maps to the same RFC 6749 §4.1.3 `invalid_grant` response, so the caller
        cannot leak whether the code existed.
        """
        now_ts = int(time.time())
        with self._db_conn(immediate=True) as conn:
            row = self._consume_code_under_lock(conn, code_hash, client_id, now_ts)
        return self._row_to_oauth_code(row) if row else None

    @staticmethod
    def _consume_code_under_lock(
        conn: sqlite3.Connection,
        code_hash: str,
        client_id: str,
        now_ts: int,
    ) -> tuple | None:
        """SELECT-then-DELETE wrapped in BEGIN IMMEDIATE. Returns row or None."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT client_id, app_key, redirect_uri, resource, scope, "
                "code_challenge, expires_at FROM oauth_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if not row or row[6] <= now_ts or row[0] != client_id:
                conn.execute("COMMIT")
                return None
            conn.execute("DELETE FROM oauth_codes WHERE code_hash = ?", (code_hash,))
            conn.execute("COMMIT")
            return row
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # === TOKENS ===

    async def create_token_pair(self, pair: RotatedTokenPair) -> None:
        """Persist the access + refresh rows for a newly-issued token pair.

        Caller provides the already-hashed `InboundToken` rows + their raw
        values; this method only writes the rows. The raw token strings on
        `pair` are intentionally NOT persisted — they exist on the model so
        the caller can return them to the client.
        """
        with self._db_conn() as conn:
            self._insert_token_row(conn, pair.access)
            self._insert_token_row(conn, pair.refresh)
            conn.commit()
        audit_log_oauth_event(
            "token_issue",
            client_id=pair.access.client_id,
            app_key=pair.access.app_key,
            family_id=pair.access.family_id,
            access_hash_prefix=hash_prefix(pair.access.token_hash),
            refresh_hash_prefix=hash_prefix(pair.refresh.token_hash),
        )

    @staticmethod
    def _insert_token_row(conn: sqlite3.Connection, token: InboundToken) -> None:
        """Single-row insert helper for `inbound_tokens`."""
        conn.execute(
            "INSERT INTO inbound_tokens (token_hash, token_kind, parent_refresh_hash, "
            "family_id, client_id, app_key, resource, scope, expires_at, issued_at, used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                token.token_hash,
                token.token_kind,
                token.parent_refresh_hash,
                token.family_id,
                token.client_id,
                token.app_key,
                token.resource,
                token.scope,
                token.expires_at,
                token.issued_at,
                token.used_at,
            ),
        )

    async def rotate_refresh(
        self,
        rotation_request: RefreshRotationRequest,
        now_ts: int | None = None,
    ) -> RotatedTokenPair:
        """Atomic refresh-token rotation per OAuth 2.1 §4.3.1.

        See `_rotate_under_lock` for the BEGIN-IMMEDIATE proof obligation and
        `cleanup_expired` for why the consumed refresh row is NOT deleted on
        success (replay detection requires it to persist).
        """
        effective_now = now_ts if now_ts is not None else int(time.time())
        with self._db_conn(immediate=True) as conn:
            rotated_pair = self._rotate_under_lock(conn, rotation_request, effective_now)
        audit_log_oauth_event(
            "token_refresh_rotate",
            client_id=rotated_pair.access.client_id,
            family_id=rotated_pair.access.family_id,
            old_hash_prefix=hash_prefix(rotation_request.token_hash),
            new_hash_prefix=hash_prefix(rotated_pair.refresh.token_hash),
        )
        return rotated_pair

    @staticmethod
    def _rotate_under_lock(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
        now_ts: int,
    ) -> RotatedTokenPair:
        """BEGIN IMMEDIATE + mark-or-replay + mint. On replay the inner branch
        commits its family-revoke DELETE before raising, so the outer
        rollback-on-exception cannot un-revoke it."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            SQLiteInboundAuthStore._mark_refresh_used_or_replay(conn, rotation_request, now_ts)
            rotated_pair = SQLiteInboundAuthStore._mint_replacement_pair(
                conn, rotation_request, now_ts
            )
            conn.execute("COMMIT")
            return rotated_pair
        except Exception:
            # Best-effort rollback. Replay branch already committed; sqlite
            # raises OperationalError if no transaction is open. We suppress
            # the broader ``sqlite3.Error`` so any other unexpected sqlite
            # failure during the rollback (DatabaseError, etc.) still lets
            # the ORIGINAL exception (InvalidGrantError on the replay path)
            # propagate to the caller — otherwise the outer handler would
            # see a sqlite exception instead and surface 500.
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _mark_refresh_used_or_replay(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
        now_ts: int,
    ) -> None:
        """Conditional UPDATE marks the refresh row used; rowcount=0 → replay or miss.

        Both the UPDATE here and the follow-up SELECT in `_classify_refresh_miss`
        scope by `client_id` — see that helper for the cross-client attack vector.
        """
        cursor = conn.execute(
            "UPDATE inbound_tokens SET used_at = ? "
            "WHERE token_hash = ? AND token_kind = 'refresh' "
            "AND client_id = ? AND used_at IS NULL AND expires_at > ?",
            (now_ts, rotation_request.token_hash, rotation_request.client_id, now_ts),
        )
        if cursor.rowcount == 1:
            return
        SQLiteInboundAuthStore._classify_refresh_miss(conn, rotation_request)

    @staticmethod
    def _classify_refresh_miss(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
    ) -> None:
        """Disambiguate a rowcount=0 UPDATE: replay (used_at set) → family revoke; else not found.

        The SELECT MUST filter by `client_id`. Without it, a hash match owned by a
        *different* client whose row already has `used_at != NULL` would trigger
        `_revoke_family_on_replay` against the wrong family — a forced-logout
        attack from any DCR client that ever obtained another client's prior-
        generation refresh token (e.g. via intercepted response logs).
        """
        token_row = conn.execute(
            "SELECT family_id, used_at "
            "FROM inbound_tokens WHERE token_hash = ? AND token_kind = 'refresh' "
            "AND client_id = ?",
            (rotation_request.token_hash, rotation_request.client_id),
        ).fetchone()
        if token_row and token_row[1] is not None:
            SQLiteInboundAuthStore._revoke_family_on_replay(conn, token_row[0], rotation_request)
            raise InvalidGrantError("refresh replay; family revoked")
        raise InvalidGrantError("refresh not found, expired, or client mismatch")

    @staticmethod
    def _revoke_family_on_replay(
        conn: sqlite3.Connection,
        family_id: str,
        rotation_request: RefreshRotationRequest,
    ) -> None:
        """Cascade-delete the family and COMMIT so revoke is durable.

        Per OAuth 2.1 §4.3.1 replay detection must be durable — committing
        here ensures the outer rollback (on the raised `InvalidGrantError`)
        cannot resurrect the revoked family.
        """
        conn.execute("DELETE FROM inbound_tokens WHERE family_id = ?", (family_id,))
        conn.execute("COMMIT")
        audit_log_oauth_event(
            "token_refresh_replay_revoke",
            client_id=rotation_request.client_id,
            family_id=family_id,
            hash_prefix=hash_prefix(rotation_request.token_hash),
        )

    @staticmethod
    def _mint_replacement_pair(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
        now_ts: int,
    ) -> RotatedTokenPair:
        """Mint and insert a fresh (access, refresh) pair in the same family."""
        raw_access, raw_refresh, pair_context = SQLiteInboundAuthStore._prepare_pair_context(
            conn, rotation_request.token_hash, rotation_request.client_id
        )
        access_row = SQLiteInboundAuthStore._build_access_row(
            rotation_request, pair_context, now_ts
        )
        refresh_row = SQLiteInboundAuthStore._build_refresh_row(
            rotation_request, pair_context, now_ts
        )
        SQLiteInboundAuthStore._insert_token_row(conn, access_row)
        SQLiteInboundAuthStore._insert_token_row(conn, refresh_row)
        return RotatedTokenPair(
            access=access_row,
            refresh=refresh_row,
            raw_access_token=raw_access,
            raw_refresh_token=raw_refresh,
        )

    @staticmethod
    def _prepare_pair_context(
        conn: sqlite3.Connection, parent_token_hash: str, client_id: str
    ) -> tuple[str, str, _NewPairContext]:
        """Inherit family + app from the consumed refresh, mint new hashes, return both raws.

        The SELECT filters by ``client_id`` as well as ``token_hash`` even
        though both reads happen inside the same ``BEGIN IMMEDIATE``
        transaction. Currently the prior UPDATE already guarantees the row
        belongs to this client; the redundant filter pins the invariant in
        the SQL so a future refactor that splits the rotation into separate
        transactions cannot silently introduce a cross-client family
        inheritance bug.
        """
        existing_row = conn.execute(
            "SELECT family_id, app_key FROM inbound_tokens WHERE token_hash = ? AND client_id = ?",
            (parent_token_hash, client_id),
        ).fetchone()
        if not existing_row:  # defensive — _mark_refresh_used_or_replay returned ok
            raise InvalidGrantError("refresh disappeared mid-rotation")
        raw_access, access_hash = generate_access_token()
        raw_refresh, refresh_hash = generate_refresh_token()
        pair_context = _NewPairContext(
            family_id=existing_row[0],
            app_key=existing_row[1],
            access_hash=access_hash,
            refresh_hash=refresh_hash,
        )
        return raw_access, raw_refresh, pair_context

    @staticmethod
    def _build_access_row(
        rotation_request: RefreshRotationRequest,
        pair_context: _NewPairContext,
        now_ts: int,
    ) -> InboundToken:
        """Construct the new access-token row. TTL comes from the request."""
        return InboundToken(
            token_hash=pair_context.access_hash,
            token_kind="access",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=pair_context.refresh_hash,
            family_id=pair_context.family_id,
            client_id=rotation_request.client_id,
            app_key=pair_context.app_key,
            resource=rotation_request.resource,
            scope=rotation_request.scope,
            expires_at=now_ts + rotation_request.access_ttl_seconds,
            issued_at=now_ts,
        )

    @staticmethod
    def _build_refresh_row(
        rotation_request: RefreshRotationRequest,
        pair_context: _NewPairContext,
        now_ts: int,
    ) -> InboundToken:
        """Construct the new refresh-token row. TTL comes from the request."""
        return InboundToken(
            token_hash=pair_context.refresh_hash,
            token_kind="refresh",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=rotation_request.token_hash,
            family_id=pair_context.family_id,
            client_id=rotation_request.client_id,
            app_key=pair_context.app_key,
            resource=rotation_request.resource,
            scope=rotation_request.scope,
            expires_at=now_ts + rotation_request.refresh_ttl_seconds,
            issued_at=now_ts,
        )

    async def get_access(self, token_hash: str) -> InboundToken | None:
        """Lookup an access token by hash. None on miss; caller checks expiry."""
        with self._db_conn() as conn:
            row = conn.execute(
                "SELECT token_hash, token_kind, parent_refresh_hash, family_id, "
                "client_id, app_key, resource, scope, expires_at, issued_at, used_at "
                "FROM inbound_tokens WHERE token_kind = 'access' AND token_hash = ?",
                (token_hash,),
            ).fetchone()
        if not row:
            return None
        # Defense-in-depth: the SQL lookup is already a hash-equality check,
        # but we re-verify with constant-time compare in case a caller ever
        # wires up a code path that compares hashes in Python.
        if not hmac.compare_digest(row[0], token_hash):
            return None
        return self._row_to_inbound_token(row)

    async def get_refresh_row(self, token_hash: str) -> InboundToken | None:
        """Read a refresh-token row by hash, regardless of used_at state.

        Used by the /token endpoint for the scope-check phase before rotation.
        The rotate path itself does NOT use this — it goes through
        `_mark_refresh_used_or_replay` under BEGIN IMMEDIATE. Returning rows
        with `used_at NOT NULL` is intentional: filtering them out would mask
        replay attempts at the precondition layer.
        """
        with self._db_conn() as conn:
            row = conn.execute(
                "SELECT token_hash, token_kind, parent_refresh_hash, family_id, "
                "client_id, app_key, resource, scope, expires_at, issued_at, used_at "
                "FROM inbound_tokens WHERE token_hash = ? AND token_kind = 'refresh'",
                (token_hash,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_inbound_token(row)

    async def revoke_token(
        self,
        token_hash: str,
        client_id: str,
        kind: Literal["access", "refresh"],
    ) -> bool:
        """RFC 7009 §2.2 — silently succeed regardless of existence.

        Refresh revoke cascades to the whole family (a stolen refresh cannot
        leave live access tokens behind). Access revoke deletes only the row.
        `client_id` scopes the delete to its issuee.

        Returns True iff a row was actually deleted. Callers iterating
        ``_kinds_from_hint`` use this to short-circuit after a hit and to gate
        audit-log emission — a hash that misses must NOT produce a spurious
        ``token_revoke`` event for monitoring.
        """
        with self._db_conn() as conn:
            if kind == "refresh":
                did_delete = self._revoke_refresh_family(conn, token_hash, client_id)
            else:
                did_delete = self._revoke_access_token(conn, token_hash, client_id)
            conn.commit()
        if did_delete:
            audit_log_oauth_event(
                "token_revoke",
                client_id=client_id,
                kind=kind,
                hash_prefix=hash_prefix(token_hash),
            )
        return did_delete

    @staticmethod
    def _revoke_refresh_family(
        conn: sqlite3.Connection,
        token_hash: str,
        client_id: str,
    ) -> bool:
        """Resolve the family from the refresh row, then cascade-delete it.

        Returns True iff a family was found and deleted.
        """
        family_row = conn.execute(
            "SELECT family_id FROM inbound_tokens "
            "WHERE token_hash = ? AND token_kind = 'refresh' AND client_id = ?",
            (token_hash, client_id),
        ).fetchone()
        if not family_row:
            return False
        conn.execute("DELETE FROM inbound_tokens WHERE family_id = ?", (family_row[0],))
        return True

    @staticmethod
    def _revoke_access_token(
        conn: sqlite3.Connection,
        token_hash: str,
        client_id: str,
    ) -> bool:
        """Delete a single access-token row, scoped to the supplied client.

        Returns True iff a row was actually deleted.
        """
        cursor = conn.execute(
            "DELETE FROM inbound_tokens "
            "WHERE token_hash = ? AND token_kind = 'access' AND client_id = ?",
            (token_hash, client_id),
        )
        return cursor.rowcount > 0

    async def revoke_family(self, family_id: str, client_id: str) -> None:
        """Cascade-delete every token in the family (admin-side revoke path).

        Scoped to ``client_id`` so that even if a caller is tricked into
        passing an attacker-supplied ``family_id``, they cannot force-logout
        sessions belonging to a different client. ``family_id`` is a 128-bit
        random secret so guessing is infeasible — this is defense-in-depth
        for the case where it might leak through a logging or replay channel.
        """
        with self._db_conn() as conn:
            conn.execute(
                "DELETE FROM inbound_tokens WHERE family_id = ? AND client_id = ?",
                (family_id, client_id),
            )
            conn.commit()

    # === MAINTENANCE ===

    async def cleanup_expired(self) -> None:
        """Reap expired auth codes and tokens. Idempotent.

        Preserves used refresh rows (`used_at NOT NULL`) for
        ``REPLAY_DETECTION_WINDOW_SECONDS`` past their ``used_at`` timestamp
        (NOT past ``expires_at``). Without this carve-out, an attacker who
        steals a refresh and waits for the row to age out would see "not
        found" on replay instead of triggering family revoke — violating
        OAuth 2.1 §4.3.1.

        Note: the retention window is measured from rotation time, not from
        natural expiry. In practice tokens are rotated near their expiry so
        the two are close, but for a refresh rotated early in its lifetime
        the row can age out of the replay window while the family is still
        live. The legitimate user is unaffected (a replayed old refresh hits
        "not found" rather than triggering revoke).
        """
        now_ts = int(time.time())
        replay_cutoff = now_ts - REPLAY_DETECTION_WINDOW_SECONDS
        with self._db_conn() as conn:
            conn.execute("DELETE FROM oauth_codes WHERE expires_at <= ?", (now_ts,))
            conn.execute(
                "DELETE FROM inbound_tokens "
                "WHERE expires_at <= ? "
                "AND NOT (token_kind = 'refresh' AND used_at IS NOT NULL AND used_at > ?)",
                (now_ts, replay_cutoff),
            )
            conn.commit()

    async def delete_all_for_app(self, app_key: str) -> None:
        """Cascade delete when a broker key is revoked (AGENTS.md Known Gotcha #2).

        Removes rows from `oauth_codes` and `inbound_tokens` scoped to the
        target app. Does NOT touch `oauth_clients` — DCR'd clients are not
        bound to an `app_key` in v1 (the app the bearer grants access to is
        chosen at /oauth/authorize time, not at registration time).

        Wiring lives at the admin endpoint (T04), not in `BrokerKeyStore` —
        keeps the two stores decoupled.
        """
        if not app_key:
            return
        with self._db_conn() as conn:
            conn.execute("DELETE FROM oauth_codes WHERE app_key = ?", (app_key,))
            conn.execute("DELETE FROM inbound_tokens WHERE app_key = ?", (app_key,))
            conn.commit()
        logger.info("[InboundAuthStore] Cascade-deleted rows for app: %s", app_key)
