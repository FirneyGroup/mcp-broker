"""
Token Store — persists OAuth tokens and dynamic registrations.

TokenStore: Abstract interface.
SQLiteTokenStore: SQLite for development.
EncryptedTokenStore: Decorator wrapping any TokenStore with MultiFernet encryption at rest.
"""

import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.fernet import Fernet, MultiFernet

from broker.config import StoreConfig
from broker.models.connection import AppConnection
from broker.models.connector_config import DynamicRegistration

logger = logging.getLogger(__name__)


# =============================================================================
# ABSTRACT BASE
# =============================================================================


class TokenStore(ABC):
    """Abstract token storage."""

    # --- Connections (per app + connector) ---

    @abstractmethod
    async def get(self, app_key: str, connector_name: str) -> AppConnection | None:
        """Get stored connection. Returns None if not found."""

    @abstractmethod
    async def save(self, app_key: str, connector_name: str, connection: AppConnection) -> None:
        """Save or update a connection."""

    @abstractmethod
    async def delete(self, app_key: str, connector_name: str) -> None:
        """Delete a connection."""

    @abstractmethod
    async def delete_all_for_app(self, app_key: str) -> int:
        """Delete every connection for an app. Returns number of rows deleted.

        Called when an app's broker key is deleted so that re-provisioning
        a key for the same app_key cannot silently regain access to
        previously-linked OAuth tokens.
        """

    @abstractmethod
    async def list_for_app(self, app_key: str) -> list[AppConnection]:
        """List all connections for an app."""

    @abstractmethod
    async def list_expiring(
        self, buffer_seconds: int = 600
    ) -> list[tuple[str, str, AppConnection]]:
        """List connections expiring within buffer_seconds.

        Returns list of (app_key, connector_name, connection) tuples.
        Skips connections with no expiry (expires_at is None).
        """

    # --- Registrations (per connector, shared across apps) ---

    @abstractmethod
    async def get_registration(self, connector_name: str) -> DynamicRegistration | None:
        """Get stored dynamic registration. Returns None if not found."""

    @abstractmethod
    async def save_registration(
        self, connector_name: str, registration: DynamicRegistration
    ) -> None:
        """Save or update a dynamic registration."""


# =============================================================================
# SQLITE IMPLEMENTATION
# =============================================================================


class SQLiteTokenStore(TokenStore):
    """SQLite token store for development.

    app_key format: 'client_id:app_id' (e.g. 'my_company:app1').
    Stores AppConnection and DynamicRegistration as JSON blobs.
    """

    def __init__(self, db_path: str = "./data/tokens.db") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if not exist."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    app_key TEXT NOT NULL,
                    connector_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    PRIMARY KEY (app_key, connector_name)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registrations (
                    connector_name TEXT NOT NULL PRIMARY KEY,
                    data TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    # --- Connections ---

    async def get(self, app_key: str, connector_name: str) -> AppConnection | None:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT data FROM connections WHERE app_key = ? AND connector_name = ?",
                (app_key, connector_name),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return AppConnection.model_validate_json(row[0])
        finally:
            conn.close()

    async def save(self, app_key: str, connector_name: str, connection: AppConnection) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO connections (app_key, connector_name, data)
                   VALUES (?, ?, ?)
                   ON CONFLICT(app_key, connector_name)
                   DO UPDATE SET data = excluded.data""",
                (app_key, connector_name, connection.model_dump_json()),
            )
            conn.commit()
            logger.info("[TokenStore] Saved connection: %s/%s", app_key, connector_name)
        finally:
            conn.close()

    async def delete(self, app_key: str, connector_name: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "DELETE FROM connections WHERE app_key = ? AND connector_name = ?",
                (app_key, connector_name),
            )
            conn.commit()
            logger.info("[TokenStore] Deleted connection: %s/%s", app_key, connector_name)
        finally:
            conn.close()

    async def delete_all_for_app(self, app_key: str) -> int:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM connections WHERE app_key = ?",
                (app_key,),
            )
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("[TokenStore] Cascade-deleted %d connections for %s", deleted, app_key)
            return deleted
        finally:
            conn.close()

    async def list_for_app(self, app_key: str) -> list[AppConnection]:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT data FROM connections WHERE app_key = ?",
                (app_key,),
            )
            return [AppConnection.model_validate_json(row[0]) for row in cursor.fetchall()]
        finally:
            conn.close()

    async def list_expiring(
        self, buffer_seconds: int = 600
    ) -> list[tuple[str, str, AppConnection]]:
        threshold = int(time.time()) + buffer_seconds
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """SELECT app_key, connector_name, data FROM connections
                   WHERE json_extract(data, '$.expires_at') IS NOT NULL
                   AND json_extract(data, '$.expires_at') <= ?""",
                (threshold,),
            )
            return [
                (row[0], row[1], AppConnection.model_validate_json(row[2]))
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    # --- Registrations ---

    async def get_registration(self, connector_name: str) -> DynamicRegistration | None:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT data FROM registrations WHERE connector_name = ?",
                (connector_name,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return DynamicRegistration.model_validate_json(row[0])
        finally:
            conn.close()

    async def save_registration(
        self, connector_name: str, registration: DynamicRegistration
    ) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO registrations (connector_name, data)
                   VALUES (?, ?)
                   ON CONFLICT(connector_name)
                   DO UPDATE SET data = excluded.data""",
                (connector_name, registration.model_dump_json()),
            )
            conn.commit()
            logger.info("[TokenStore] Saved registration: %s", connector_name)
        finally:
            conn.close()


# =============================================================================
# ENCRYPTION WRAPPER
# =============================================================================


class EncryptedTokenStore(TokenStore):
    """Decorator that encrypts secrets before delegating to another store.

    Uses MultiFernet for key rotation:
    - First key is active (for encryption)
    - Older keys can still decrypt (for rotation)

    Encrypts: access_token, refresh_token (connections), client_secret (registrations).
    """

    def __init__(self, keys: list[str], delegate: TokenStore) -> None:
        if not keys:
            raise ValueError("At least one encryption key is required")
        self._fernet = MultiFernet([Fernet(k) for k in keys])
        self._delegate = delegate

    def _encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        """Decrypt a string value."""
        return self._fernet.decrypt(value.encode()).decode()

    # --- Connection encryption ---

    def _encrypt_connection(self, connection: AppConnection) -> AppConnection:
        """Encrypt sensitive fields of a connection."""
        updates = {"access_token": self._encrypt(connection.access_token)}
        if connection.refresh_token:
            updates["refresh_token"] = self._encrypt(connection.refresh_token)
        return connection.model_copy(update=updates)

    def _decrypt_connection(self, connection: AppConnection) -> AppConnection:
        """Decrypt sensitive fields of a connection."""
        updates = {"access_token": self._decrypt(connection.access_token)}
        if connection.refresh_token:
            updates["refresh_token"] = self._decrypt(connection.refresh_token)
        return connection.model_copy(update=updates)

    # --- Registration encryption ---

    def _encrypt_registration(self, registration: DynamicRegistration) -> DynamicRegistration:
        """Encrypt client_secret in a registration."""
        return registration.model_copy(
            update={"client_secret": self._encrypt(registration.client_secret)}
        )

    def _decrypt_registration(self, registration: DynamicRegistration) -> DynamicRegistration:
        """Decrypt client_secret in a registration."""
        return registration.model_copy(
            update={"client_secret": self._decrypt(registration.client_secret)}
        )

    # --- Connection methods ---

    async def get(self, app_key: str, connector_name: str) -> AppConnection | None:
        connection = await self._delegate.get(app_key, connector_name)
        if connection is None:
            return None
        return self._decrypt_connection(connection)

    async def save(self, app_key: str, connector_name: str, connection: AppConnection) -> None:
        encrypted = self._encrypt_connection(connection)
        await self._delegate.save(app_key, connector_name, encrypted)

    async def delete(self, app_key: str, connector_name: str) -> None:
        await self._delegate.delete(app_key, connector_name)

    async def delete_all_for_app(self, app_key: str) -> int:
        return await self._delegate.delete_all_for_app(app_key)

    async def list_for_app(self, app_key: str) -> list[AppConnection]:
        connections = await self._delegate.list_for_app(app_key)
        return [self._decrypt_connection(c) for c in connections]

    async def list_expiring(
        self, buffer_seconds: int = 600
    ) -> list[tuple[str, str, AppConnection]]:
        rows = await self._delegate.list_expiring(buffer_seconds)
        return [(app_key, name, self._decrypt_connection(conn)) for app_key, name, conn in rows]

    # --- Registration methods ---

    async def get_registration(self, connector_name: str) -> DynamicRegistration | None:
        registration = await self._delegate.get_registration(connector_name)
        if registration is None:
            return None
        return self._decrypt_registration(registration)

    async def save_registration(
        self, connector_name: str, registration: DynamicRegistration
    ) -> None:
        encrypted = self._encrypt_registration(registration)
        await self._delegate.save_registration(connector_name, encrypted)


# =============================================================================
# FACTORY
# =============================================================================


def create_token_store(store_config: StoreConfig, encryption_keys: list[str]) -> TokenStore:
    """Create token store from settings.

    Args:
        store_config: StoreConfig from settings.
        encryption_keys: MultiFernet keys from broker config.

    Returns:
        TokenStore wrapped with encryption.
    """
    if store_config.backend == "sqlite":
        delegate = SQLiteTokenStore(db_path=store_config.sqlite.db_path)
    else:
        raise ValueError(f"Unknown store backend: {store_config.backend}")

    return EncryptedTokenStore(keys=encryption_keys, delegate=delegate)
