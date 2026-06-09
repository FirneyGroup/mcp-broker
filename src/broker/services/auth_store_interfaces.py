"""Abstract interfaces for auth/state/rate-limit stores.

These ABCs are the swap points between the SQLite/in-memory backends and the
Firestore backends. Each mirrors the concrete reference implementation exactly,
so a Firestore implementation can be dropped in without changing callers:

- InboundAuthStore       — OAuth 2.1 server state (DCR clients, codes, tokens)
- ConnectTokenStoreABC   — single-use connect tokens for browser OAuth
- OutboundOAuthStateStore — nonces + PKCE verifiers across authorize/callback
- DCRRateLimiter         — per-IP rate limiting for dynamic client registration
"""

from __future__ import annotations

from abc import ABC, abstractmethod
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

# =============================================================================
# INBOUND OAUTH AUTH STORE
# =============================================================================


class InboundAuthStore(ABC):
    """Abstract OAuth 2.1 inbound auth store (DCR clients, codes, access/refresh tokens).

    The contract mirrors the concrete SQLite store; a Firestore implementation
    MUST preserve the same security semantics — single-use authorization codes,
    atomic refresh rotation with replay detection + family revoke, and
    hash-at-rest for codes/tokens/client secrets.
    """

    @abstractmethod
    async def setup(self) -> None:
        """Initialize backing storage (schema / collections)."""

    # --- DCR clients ---

    @abstractmethod
    async def create_client(
        self, request: RegistrationRequest, client_ip: str | None
    ) -> RegistrationResponse:
        """RFC 7591 dynamic client registration. Confidential clients get a one-shot secret."""

    @abstractmethod
    async def get_client(self, client_id: str) -> OAuthClient | None:
        """Look up a registered client by id. None on miss."""

    @abstractmethod
    async def verify_client_secret(self, client_id: str, supplied_secret: str) -> bool:
        """Constant-time verify a confidential client's secret."""

    # --- Authorization codes (single-use) ---

    @abstractmethod
    async def create_code(self, code_hash: str, oauth_code: OAuthCode) -> None:
        """Persist a freshly-minted authorization code, keyed by its hash."""

    @abstractmethod
    async def consume_code(self, code_hash: str, client_id: str) -> OAuthCode | None:
        """Atomically validate-and-delete an authorization code. Single-use; None on miss."""

    # --- Tokens + rotation ---

    @abstractmethod
    async def create_token_pair(self, pair: RotatedTokenPair) -> None:
        """Persist a freshly-issued (access, refresh) token pair."""

    @abstractmethod
    async def rotate_refresh(
        self, rotation_request: RefreshRotationRequest, now_ts: int | None = None
    ) -> RotatedTokenPair:
        """Atomic refresh rotation (OAuth 2.1 §4.3.1). On replay, cascade-revoke the family and raise."""

    @abstractmethod
    async def get_access(self, token_hash: str) -> InboundToken | None:
        """Look up an access token by hash. None on miss."""

    @abstractmethod
    async def get_refresh_row(self, token_hash: str) -> InboundToken | None:
        """Read a refresh-token row by hash regardless of used_at (precondition checks)."""

    @abstractmethod
    async def revoke_token(
        self, token_hash: str, client_id: str, kind: Literal["access", "refresh"]
    ) -> bool:
        """RFC 7009 revocation. Refresh revoke cascades to the family. True iff a row was deleted."""

    @abstractmethod
    async def revoke_family(self, family_id: str, client_id: str) -> None:
        """Cascade-delete every token in a family (admin path), scoped to client_id."""

    # --- Maintenance ---

    @abstractmethod
    async def cleanup_expired(self) -> None:
        """Reap expired codes and tokens (retaining used refresh rows in the replay window)."""

    @abstractmethod
    async def delete_all_for_app(self, app_key: str) -> None:
        """Cascade-delete codes + tokens for an app_key (broker-key revocation)."""


# =============================================================================
# CONNECT TOKEN STORE
# =============================================================================


class ConnectTokenStoreABC(ABC):
    """Abstract single-use connect token store.

    Tokens are created for browser-initiated OAuth connects and consumed
    (once) during the callback. Methods are async so a Firestore-backed
    implementation can perform its (transactional) single-use I/O; the
    in-memory default satisfies the contract without awaiting.
    """

    @abstractmethod
    async def create(self, app_key: str) -> str:
        """Create a single-use connect token. Returns the token."""
        ...

    @abstractmethod
    async def consume(self, token: str) -> str | None:
        """Validate and consume a token. Returns app_key or None."""
        ...


# =============================================================================
# OUTBOUND OAUTH STATE STORE
# =============================================================================


class OutboundOAuthStateStore(ABC):
    """Abstract store for outbound OAuth flow state.

    Manages nonces and PKCE verifiers across the authorization and callback.
    Methods are async so a Firestore-backed implementation can share state
    across instances; the in-memory default satisfies the contract without
    awaiting.
    """

    @abstractmethod
    async def store_nonce(self, nonce: str) -> None:
        """Store a nonce with current timestamp."""
        ...

    @abstractmethod
    async def consume_nonce(self, nonce: str) -> bool:
        """Consume (remove) a nonce. Returns True if found."""
        ...

    @abstractmethod
    async def store_pkce_verifier(self, nonce: str, verifier: str) -> None:
        """Store PKCE verifier associated with a nonce."""
        ...

    @abstractmethod
    async def get_and_remove_pkce_verifier(self, nonce: str) -> str | None:
        """Get and remove PKCE verifier for a nonce."""
        ...

    @abstractmethod
    async def cleanup_expired(self, max_age_seconds: int) -> None:
        """Remove expired nonces and associated PKCE verifiers."""
        ...


# =============================================================================
# DCR RATE LIMITER
# =============================================================================


class DCRRateLimiter(ABC):
    """Abstract per-IP rate limiter for Dynamic Client Registration.

    Methods are async so a Firestore-backed implementation can enforce the cap
    across instances (transactional read-modify-write per IP); the in-memory
    default satisfies the contract without awaiting.
    """

    @abstractmethod
    async def allow(self, client_ip: str) -> bool:
        """Return True if the IP is under the cap; record the event when True."""
        ...

    @abstractmethod
    async def cleanup_expired(self) -> None:
        """Drop per-IP entries whose events have all aged out of the window."""
        ...
