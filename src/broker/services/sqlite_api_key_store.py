"""SQLite implementation of BrokerKeyStore.

Uses synchronous sqlite3 with open-per-call connections, matching the broker's
existing TokenStore pattern in store.py. Methods are async (matching the ABC)
but the underlying SQLite calls are synchronous.
"""

import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from broker.services.api_key_store import (
    BrokerKeyStore,
    generate_api_key,
    hash_api_key,
)

logger = logging.getLogger(__name__)


class SQLiteBrokerKeyStore(BrokerKeyStore):
    """Per-app API key store backed by SQLite."""

    def __init__(self, db_path: str = "./data/broker_keys.db") -> None:
        self._db_path = db_path

    # --- Lifecycle ---

    async def setup(self) -> None:
        """Create tables and indexes."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS broker_keys (
                    app_key TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    rotated_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_broker_key_hash ON broker_keys (key_hash)")
            conn.commit()
            logger.info("[KeyStore] Initialized: %s", self._db_path)
        finally:
            conn.close()

    async def teardown(self) -> None:
        """No persistent connections to close (open-per-call pattern)."""

    # --- Key operations ---

    async def create_key(self, app_key: str) -> str:
        """Create a key for an app. Returns the raw API key (shown once)."""
        if not app_key:
            raise ValueError("app_key must not be empty")
        key = generate_api_key()
        now = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute(
                "INSERT INTO broker_keys (app_key, key_hash, created_at) VALUES (?, ?, ?)",
                (app_key, hash_api_key(key), now),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"App '{app_key}' already has a key") from exc
        finally:
            conn.close()
        return key

    async def verify(self, raw_key: str) -> str | None:
        """Verify a key. Returns app_key on success, None on failure.

        Uses SQL hash lookup (not hmac.compare_digest) because the keys are
        256-bit random tokens — SHA-256 pre-image resistance makes timing
        attacks on the hash comparison infeasible. This matches the standard
        API key verification pattern (GitHub, Stripe, etc.).
        """
        if not raw_key:
            return None
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute(
                "SELECT app_key FROM broker_keys WHERE key_hash = ?",
                (hash_api_key(raw_key),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return row[0]
        finally:
            conn.close()

    async def rotate(self, app_key: str) -> str | None:
        """Rotate key for an app. Returns new key, or None if not found."""
        if not app_key:
            return None
        key = generate_api_key()
        now = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute(
                "UPDATE broker_keys SET key_hash = ?, rotated_at = ? WHERE app_key = ?",
                (hash_api_key(key), now, app_key),
            )
            conn.commit()
            if cursor.rowcount == 0:
                return None
            return key
        finally:
            conn.close()

    async def list_keys(self) -> list[dict]:
        """List all registered apps (no key hashes exposed)."""
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute(
                "SELECT app_key, created_at, rotated_at FROM broker_keys ORDER BY created_at"
            )
            return [
                {"app_key": r[0], "created_at": r[1], "rotated_at": r[2]} for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    async def has_key(self, app_key: str) -> bool:
        """Check if an app has a key."""
        if not app_key:
            return False
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute("SELECT 1 FROM broker_keys WHERE app_key = ? LIMIT 1", (app_key,))
            return cursor.fetchone() is not None
        finally:
            conn.close()

    async def delete_key(self, app_key: str) -> bool:
        """Delete an app's key. Returns True if deleted."""
        if not app_key:
            return False
        conn = sqlite3.connect(self._db_path)
        try:
            cursor = conn.execute("DELETE FROM broker_keys WHERE app_key = ?", (app_key,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
