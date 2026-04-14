"""
API Key Store — abstract interface for per-app key management.

verify() returns the app_key string directly. Scopes and connector access rules
come from the ClientRegistry (YAML config), not the key store.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from broker.config import DEFAULT_SCOPES

logger = logging.getLogger(__name__)

KEY_PREFIX = "br_"
KEY_BYTES = 32

CONNECT_TOKEN_PREFIX = "ct_"  # noqa: S105 — not a password, token type prefix
CONNECT_TOKEN_TTL = 300  # 5 minutes


def generate_api_key() -> str:
    """Generate a prefixed API key."""
    return f"{KEY_PREFIX}{secrets.token_urlsafe(KEY_BYTES)}"


def hash_api_key(key: str) -> str:
    """SHA-256 hash a key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


# =============================================================================
# IDENTITY MODEL
# =============================================================================


class BrokerAppIdentity(BaseModel):
    """Resolved identity from a verified API key + client registry lookup."""

    app_key: str
    scopes: list[str] = Field(default_factory=lambda: list(DEFAULT_SCOPES))
    allowed_connectors: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)

    def has_scope(self, scope: str) -> bool:
        """Check if this identity has a specific scope."""
        return scope in self.scopes

    def can_access_connector(self, connector_name: str) -> bool:
        """Check if this identity can access a specific connector.

        Empty allowed_connectors means all connectors are accessible.
        """
        if not self.allowed_connectors:
            return True
        return connector_name in self.allowed_connectors


# =============================================================================
# ABSTRACT KEY STORE
# =============================================================================


class BrokerKeyStore(ABC):
    """Abstract per-app API key store.

    Methods are async to match the existing TokenStore pattern, even though
    the SQLite implementation uses synchronous sqlite3 underneath.
    """

    @abstractmethod
    async def setup(self) -> None: ...

    @abstractmethod
    async def teardown(self) -> None: ...

    @abstractmethod
    async def create_key(self, app_key: str) -> str:
        """Create a key for an app. Returns the raw API key (shown once)."""
        ...

    @abstractmethod
    async def verify(self, raw_key: str) -> str | None:
        """Verify a key. Returns app_key on success, None on failure."""
        ...

    @abstractmethod
    async def rotate(self, app_key: str) -> str | None:
        """Rotate key for an app. Returns new key, or None if not found."""
        ...

    @abstractmethod
    async def list_keys(self) -> list[dict]:
        """List all registered apps (no key hashes exposed)."""
        ...

    @abstractmethod
    async def has_key(self, app_key: str) -> bool:
        """Check if an app has a key. More efficient than list_keys() for existence checks."""
        ...

    @abstractmethod
    async def delete_key(self, app_key: str) -> bool:
        """Delete an app's key. Returns True if deleted."""
        ...


# =============================================================================
# CONNECT TOKEN STORE (in-memory, single-use, TTL)
# =============================================================================


class ConnectTokenStore:
    """Single-use, time-limited tokens for browser-initiated OAuth connect.

    Replaces raw broker_key in URL query params. Tokens are consumed on first
    use and expire after CONNECT_TOKEN_TTL seconds.

    WARNING: Single-process only. Tokens are stored in-memory — with multiple
    uvicorn workers, a token created in worker A is invisible to worker B.
    Multi-worker deployments need a shared backing store (Redis, SQLite) or
    sticky-session routing.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, tuple[str, float]] = {}  # token → (app_key, created_at)

    def create(self, app_key: str) -> str:
        """Create a single-use connect token for an app. Returns the token."""
        self._cleanup()
        token = f"{CONNECT_TOKEN_PREFIX}{secrets.token_urlsafe(KEY_BYTES)}"
        self._tokens[token] = (app_key, time.time())
        logger.info("[ConnectToken] Created for app: %s", app_key)
        return token

    def consume(self, token: str) -> str | None:
        """Validate and consume a connect token. Returns app_key or None.

        Single-use: token is deleted after first successful validation.
        """
        self._cleanup()
        entry = self._tokens.pop(token, None)
        if not entry:
            return None
        app_key, created_at = entry
        if time.time() - created_at > CONNECT_TOKEN_TTL:
            return None
        return app_key

    def _cleanup(self) -> None:
        """Remove expired tokens."""
        now = time.time()
        expired = [
            tok
            for tok, (_, created_at) in self._tokens.items()
            if now - created_at > CONNECT_TOKEN_TTL
        ]
        for tok in expired:
            del self._tokens[tok]
