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
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

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
)

logger = logging.getLogger(__name__)

# === CONSTANTS ===

CLIENT_SECRET_BYTES = 32
ACCESS_TOKEN_BYTES = 32
REFRESH_TOKEN_BYTES = 32
CLIENT_ID_BYTES = 32
FAMILY_ID_BYTES = 16


# === EXCEPTIONS ===


class InvalidGrantError(RuntimeError):
    """Refresh token rotation rejected — replay, expiry, or missing token.

    Per OAuth 2.1 §4.3.1, on detected refresh replay the caller must cascade
    family revocation (which `rotate_refresh` handles before raising).
    """


# === TOKEN GENERATION HELPERS ===


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest. Used for every inbound token hash on disk."""
    return hashlib.sha256(value.encode()).hexdigest()


def generate_client_id() -> str:
    """RFC 7591 client_id — prefixed for traceability in logs and ad-hoc SQL."""
    return f"{CLIENT_ID_PREFIX}{secrets.token_urlsafe(CLIENT_ID_BYTES)}"


def generate_client_secret() -> tuple[str, str]:
    """Returns (raw_secret, sha256_hash). Raw shown once at registration."""
    raw_secret = secrets.token_urlsafe(CLIENT_SECRET_BYTES)
    return raw_secret, _sha256_hex(raw_secret)


def generate_access_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Raw given to client; hash stored."""
    raw_token = f"{ACCESS_TOKEN_PREFIX}{secrets.token_urlsafe(ACCESS_TOKEN_BYTES)}"
    return raw_token, _sha256_hex(raw_token)


def generate_refresh_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Raw given to client; hash stored."""
    raw_token = f"{REFRESH_TOKEN_PREFIX}{secrets.token_urlsafe(REFRESH_TOKEN_BYTES)}"
    return raw_token, _sha256_hex(raw_token)


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
        self._db_path = db_path

    # === LIFECYCLE ===

    async def setup(self) -> None:
        """Create tables and indexes if missing. Idempotent."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        try:
            self._create_schema(conn)
            conn.commit()
            logger.info("[InboundAuthStore] Initialized: %s", self._db_path)
        finally:
            conn.close()

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

    # === CLIENTS (DCR) ===

    async def create_client(
        self, request: RegistrationRequest, client_ip: str | None
    ) -> RegistrationResponse:
        """RFC 7591 dynamic client registration.

        Confidential clients (auth method != "none") receive a one-shot
        client_secret — only the hash is persisted.
        """
        client_id = generate_client_id()
        raw_secret, secret_hash = self._mint_secret_if_confidential(
            request.token_endpoint_auth_method
        )
        now_iso = datetime.now(UTC).isoformat()
        issued_at = int(time.time())
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute(
                "INSERT INTO oauth_clients (client_id, client_secret_hash, "
                "token_endpoint_auth_method, redirect_uris, grant_types, response_types, "
                "scope, client_name, created_at, created_ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    client_id,
                    secret_hash,
                    request.token_endpoint_auth_method,
                    json.dumps(request.redirect_uris),
                    json.dumps(request.grant_types),
                    json.dumps(request.response_types),
                    request.scope,
                    request.client_name,
                    now_iso,
                    client_ip,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        audit_log_oauth_event(
            "dcr_register",
            client_id=client_id,
            redirect_uris=request.redirect_uris,
            ip=client_ip,
        )
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
    def _mint_secret_if_confidential(auth_method: str) -> tuple[str | None, str | None]:
        """Public clients (`none`) get no secret; everyone else gets one + its hash."""
        if auth_method == "none":
            return None, None
        return generate_client_secret()

    async def get_client(self, client_id: str) -> OAuthClient | None:
        """Lookup a DCR'd client by id. None on miss."""
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute(
                "SELECT client_id, token_endpoint_auth_method, redirect_uris, "
                "grant_types, response_types, scope, client_name, created_at "
                "FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            )
            row = cursor.fetchone()
        finally:
            conn.close()
        if not row:
            return None
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

    # === AUTHORIZATION CODES ===

    async def create_code(self, code_hash: str, oauth_code: OAuthCode) -> None:
        """Persist a freshly-minted auth code. PRIMARY KEY collision raises IntegrityError."""
        conn = sqlite3.connect(self._db_path)
        try:
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
        finally:
            conn.close()

    async def consume_code(self, code_hash: str, client_id: str) -> OAuthCode | None:
        """Atomic SELECT-then-DELETE under BEGIN IMMEDIATE. Single-use.

        Returns None on miss, expiry, or client_id mismatch — every failure mode
        maps to the same RFC 6749 §4.1.3 `invalid_grant` response, so the caller
        cannot leak whether the code existed.
        """
        now_ts = int(time.time())
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT client_id, app_key, redirect_uri, resource, scope, "
                    "code_challenge, expires_at FROM oauth_codes WHERE code_hash = ?",
                    (code_hash,),
                ).fetchone()
                if not row or row[6] < now_ts or row[0] != client_id:
                    conn.execute("COMMIT")
                    return None
                conn.execute("DELETE FROM oauth_codes WHERE code_hash = ?", (code_hash,))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()
        return OAuthCode(
            client_id=row[0],
            app_key=row[1],
            redirect_uri=row[2],
            resource=row[3],
            scope=row[4],
            code_challenge=row[5],
            expires_at=row[6],
        )

    # === TOKENS ===

    async def create_token_pair(self, pair: RotatedTokenPair) -> None:
        """Persist the access + refresh rows for a newly-issued token pair.

        Caller provides the already-hashed `InboundToken` rows + their raw
        values; this method only writes the rows. The raw token strings on
        `pair` are intentionally NOT persisted — they exist on the model so
        the caller can return them to the client.
        """
        conn = sqlite3.connect(self._db_path)
        try:
            self._insert_token_row(conn, pair.access)
            self._insert_token_row(conn, pair.refresh)
            conn.commit()
        finally:
            conn.close()
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

        Concurrency guarantee: under `BEGIN IMMEDIATE`, at most one concurrent
        caller succeeds in flipping `used_at` from NULL → not-NULL. Losing
        callers see `used_at NOT NULL` and trigger family revoke (the DELETE +
        COMMIT happens inside `_mark_refresh_used_or_replay` itself, so the
        revoke is durable even though the caller still raises).

        Deviation from the plan's pseudocode: we do NOT delete the consumed
        refresh row on success. Replay detection requires that row to persist
        (with `used_at` set) until `cleanup_expired` reaps it at its original
        expiry — otherwise the second caller's UPDATE sees an empty row and
        falls into the "not found" branch instead of the replay branch.
        """
        effective_now = now_ts if now_ts is not None else int(time.time())
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        try:
            rotated_pair = self._rotate_under_lock(conn, rotation_request, effective_now)
        finally:
            conn.close()
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
        """BEGIN IMMEDIATE + mark-or-replay + mint, with ROLLBACK only on the
        happy-path branch. The replay branch commits its own DELETE before
        raising — see `_mark_refresh_used_or_replay`."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            SQLiteInboundAuthStore._mark_refresh_used_or_replay(conn, rotation_request, now_ts)
            rotated_pair = SQLiteInboundAuthStore._mint_replacement_pair(
                conn, rotation_request, now_ts
            )
            conn.execute("COMMIT")
            return rotated_pair
        except Exception:
            # Best-effort rollback. The replay branch has already committed
            # its family-revoke DELETE; sqlite raises OperationalError if no
            # transaction is open — suppress so we propagate the original error.
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _mark_refresh_used_or_replay(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
        now_ts: int,
    ) -> None:
        """Conditional UPDATE marks the refresh row used. Loss → replay-or-miss.

        On replay we COMMIT the family-revoke DELETE before raising so the
        outer ROLLBACK on the exception path cannot un-revoke the family.
        Per OAuth 2.1 §4.3.1, replay detection must be durable.
        """
        cursor = conn.execute(
            "UPDATE inbound_tokens SET used_at = ? "
            "WHERE token_hash = ? AND token_kind = 'refresh' "
            "AND client_id = ? AND used_at IS NULL AND expires_at > ?",
            (now_ts, rotation_request.token_hash, rotation_request.client_id, now_ts),
        )
        if cursor.rowcount == 1:
            return
        token_row = conn.execute(
            "SELECT family_id, used_at, expires_at, client_id "
            "FROM inbound_tokens WHERE token_hash = ? AND token_kind = 'refresh'",
            (rotation_request.token_hash,),
        ).fetchone()
        if token_row and token_row[1] is not None:
            family_id = token_row[0]
            conn.execute("DELETE FROM inbound_tokens WHERE family_id = ?", (family_id,))
            conn.execute("COMMIT")
            audit_log_oauth_event(
                "token_refresh_replay_revoke",
                client_id=rotation_request.client_id,
                family_id=family_id,
                hash_prefix=hash_prefix(rotation_request.token_hash),
            )
            raise InvalidGrantError("refresh replay; family revoked")
        raise InvalidGrantError("refresh not found, expired, or client mismatch")

    @staticmethod
    def _mint_replacement_pair(
        conn: sqlite3.Connection,
        rotation_request: RefreshRotationRequest,
        now_ts: int,
    ) -> RotatedTokenPair:
        """Mint and insert a fresh (access, refresh) pair in the same family."""
        # Inherit family_id from the consumed refresh so cascade revoke covers both.
        existing_row = conn.execute(
            "SELECT family_id, app_key FROM inbound_tokens WHERE token_hash = ?",
            (rotation_request.token_hash,),
        ).fetchone()
        if not existing_row:  # defensive — _mark_refresh_used_or_replay returned ok
            raise InvalidGrantError("refresh disappeared mid-rotation")
        family_id, app_key = existing_row[0], existing_row[1]
        raw_access, access_hash = generate_access_token()
        raw_refresh, refresh_hash = generate_refresh_token()
        access_row = InboundToken(
            token_hash=access_hash,
            token_kind="access",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=refresh_hash,
            family_id=family_id,
            client_id=rotation_request.client_id,
            app_key=app_key,
            resource=rotation_request.resource,
            scope=rotation_request.scope,
            expires_at=now_ts + 3600,
            issued_at=now_ts,
        )
        refresh_row = InboundToken(
            token_hash=refresh_hash,
            token_kind="refresh",  # noqa: S106 -- discriminator literal, not a credential
            parent_refresh_hash=rotation_request.token_hash,
            family_id=family_id,
            client_id=rotation_request.client_id,
            app_key=app_key,
            resource=rotation_request.resource,
            scope=rotation_request.scope,
            expires_at=now_ts + 2592000,
            issued_at=now_ts,
        )
        SQLiteInboundAuthStore._insert_token_row(conn, access_row)
        SQLiteInboundAuthStore._insert_token_row(conn, refresh_row)
        return RotatedTokenPair(
            access=access_row,
            refresh=refresh_row,
            raw_access_token=raw_access,
            raw_refresh_token=raw_refresh,
        )

    async def get_access(self, token_hash: str) -> InboundToken | None:
        """Lookup an access token by hash. None on miss; caller checks expiry."""
        conn = sqlite3.connect(self._db_path)
        try:
            row = conn.execute(
                "SELECT token_hash, token_kind, parent_refresh_hash, family_id, "
                "client_id, app_key, resource, scope, expires_at, issued_at, used_at "
                "FROM inbound_tokens WHERE token_kind = 'access' AND token_hash = ?",
                (token_hash,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        # Defense-in-depth: the SQL lookup is already a hash-equality check, but
        # we re-verify with constant-time compare in case a caller ever wires up
        # a code path that compares hashes in Python.
        if not hmac.compare_digest(row[0], token_hash):
            return None
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

    async def revoke_token(
        self,
        token_hash: str,
        client_id: str,
        kind: Literal["access", "refresh"],
    ) -> None:
        """RFC 7009 §2.2 — silently succeed regardless of existence.

        For `kind="refresh"`, cascade-delete every access token sharing the
        same `family_id`, so a stolen refresh cannot leave live access tokens.
        For `kind="access"`, delete only that row. `client_id` scopes the
        delete: a token revealed to a client can only be revoked by that
        client.
        """
        conn = sqlite3.connect(self._db_path)
        try:
            if kind == "refresh":
                family_row = conn.execute(
                    "SELECT family_id FROM inbound_tokens "
                    "WHERE token_hash = ? AND token_kind = 'refresh' AND client_id = ?",
                    (token_hash, client_id),
                ).fetchone()
                if family_row:
                    conn.execute("DELETE FROM inbound_tokens WHERE family_id = ?", (family_row[0],))
            else:
                conn.execute(
                    "DELETE FROM inbound_tokens "
                    "WHERE token_hash = ? AND token_kind = 'access' AND client_id = ?",
                    (token_hash, client_id),
                )
            conn.commit()
        finally:
            conn.close()
        audit_log_oauth_event(
            "token_revoke",
            client_id=client_id,
            kind=kind,
            hash_prefix=hash_prefix(token_hash),
        )

    async def revoke_family(self, family_id: str) -> None:
        """Cascade-delete every token in the family (admin-side revoke path)."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("DELETE FROM inbound_tokens WHERE family_id = ?", (family_id,))
            conn.commit()
        finally:
            conn.close()

    # === MAINTENANCE ===

    async def cleanup_expired(self) -> None:
        """Reap expired auth codes and tokens. Idempotent."""
        now_ts = int(time.time())
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?", (now_ts,))
            conn.execute("DELETE FROM inbound_tokens WHERE expires_at < ?", (now_ts,))
            conn.commit()
        finally:
            conn.close()

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
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("DELETE FROM oauth_codes WHERE app_key = ?", (app_key,))
            conn.execute("DELETE FROM inbound_tokens WHERE app_key = ?", (app_key,))
            conn.commit()
        finally:
            conn.close()
        logger.info("[InboundAuthStore] Cascade-deleted rows for app: %s", app_key)
