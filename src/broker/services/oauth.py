"""
OAuth 2.1 Flow Handler

Handles authorization URL generation, code exchange, and token refresh.
Uses PKCE (S256) for all flows. State parameter signed with itsdangerous.
"""

import hashlib
import logging
import secrets
import time
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from broker.connectors.base import BaseConnector, filter_token_response
from broker.models.connection import AppConnection
from broker.models.connector_config import ResolvedOAuth
from broker.services.auth_store_interfaces import OutboundOAuthStateStore

logger = logging.getLogger(__name__)

# === CONSTANTS ===

# Nonce TTL — 15 minutes (generous for OAuth flows).
# This is only a cleanup horizon for the in-memory store, NOT the replay bound:
# the ≤10-minute single-use replay window is enforced by _STATE_MAX_AGE (the
# itsdangerous signature max_age), so the TTL is intentionally longer.
_NONCE_TTL = 900

# State token expiry — decode_state uses shorter window to ensure
# the full validation in exchange_code still has headroom
_STATE_MAX_AGE = 600
_STATE_PEEK_MAX_AGE = 590

# Replay protection requires nonces to outlive state tokens
assert _NONCE_TTL >= _STATE_MAX_AGE, (  # noqa: S101
    f"_NONCE_TTL ({_NONCE_TTL}) must be >= _STATE_MAX_AGE ({_STATE_MAX_AGE}) "
    "or replay protection is silently defeated"
)

# Max characters of error response body to log (prevents credential leakage from verbose providers)
_MAX_ERROR_LOG_LENGTH = 200

# Buffer (seconds) before expiry to trigger refresh — shared with proxy.py
TOKEN_REFRESH_BUFFER = 60

_HTTP_OK = 200


# Single-use nonces to prevent replay attacks.
# WARNING: In-memory only — lost on process restart. Any OAuth flow in progress
# during restart will fail ("PKCE verifier not found"), which also blocks replay.
# Acceptable for single-instance deployment. Multi-instance requires shared store.
class _InMemoryOutboundOAuthStateStore(OutboundOAuthStateStore):
    """In-memory implementation of outbound OAuth state store.

    WARNING: Single-process only. With multiple uvicorn workers, a nonce
    created in worker A is invisible to worker B. Multi-worker deployments
    need a shared backing store (Redis) or sticky-session routing.
    """

    def __init__(self):
        self._nonce_timestamps: dict[str, float] = {}
        self._pkce_verifiers: dict[str, str] = {}

    async def setup(self) -> None:
        """No-op — in-memory state needs no initialization."""

    async def store_nonce(self, nonce: str) -> None:
        """Store a nonce with current timestamp."""
        self._nonce_timestamps[nonce] = time.time()

    async def consume_nonce(self, nonce: str) -> bool:
        """Consume (remove) a nonce. Returns True if found, False on replay.

        ``_nonce_timestamps`` is the single source of truth: consuming removes
        the nonce, so a replay's ``consume_nonce`` returns False. (A separate
        consumed-set would be defeated by ``cleanup_expired`` — see git history.)
        """
        if nonce in self._nonce_timestamps:
            del self._nonce_timestamps[nonce]
            return True
        return False

    async def store_pkce_verifier(self, nonce: str, verifier: str) -> None:
        """Store PKCE verifier associated with a nonce."""
        self._pkce_verifiers[nonce] = verifier

    async def get_and_remove_pkce_verifier(self, nonce: str) -> str | None:
        """Get and remove PKCE verifier for a nonce."""
        return self._pkce_verifiers.pop(nonce, None)

    async def cleanup_expired(self, max_age_seconds: int = _NONCE_TTL) -> None:
        """Remove expired nonces and associated PKCE verifiers."""
        now = time.time()
        expired_nonces = [
            nonce
            for nonce, timestamp in self._nonce_timestamps.items()
            if now - timestamp > max_age_seconds
        ]
        for nonce in expired_nonces:
            del self._nonce_timestamps[nonce]
            self._pkce_verifiers.pop(nonce, None)


# Global singleton instance
_outbound_state_store = _InMemoryOutboundOAuthStateStore()


class OAuthHandler:
    """OAuth 2.1 flow handler with PKCE and signed state."""

    def __init__(
        self, state_secret: str, state_store: OutboundOAuthStateStore | None = None
    ) -> None:
        self._serializer = URLSafeTimedSerializer(state_secret)
        # Default to the process-local in-memory store so the single-instance
        # behaviour is unchanged; the lifespan injects a Firestore-backed store
        # when ``store.backend == "firestore"`` for multi-instance deployments.
        self._state_store = state_store or _outbound_state_store

    # --- Public API ---

    async def build_authorize_url(
        self,
        connector: BaseConnector,
        app_key: str,
        resolved: ResolvedOAuth,
        callback_url: str,
    ) -> str:
        """Build OAuth authorization URL with PKCE + signed state."""
        await self._state_store.cleanup_expired(_NONCE_TTL)

        nonce = secrets.token_urlsafe(32)
        state = self._sign_oauth_state(app_key, connector.meta.name, nonce)
        await self._state_store.store_nonce(nonce)

        code_challenge = None
        if connector.meta.supports_pkce:
            code_verifier, code_challenge = _generate_pkce_pair()
            await self._state_store.store_pkce_verifier(nonce, code_verifier)

        params = self._build_authorize_params(
            connector,
            resolved,
            callback_url,
            state,
            code_challenge,
        )

        url = f"{resolved.authorize_url}?{urlencode(params)}"
        logger.info("[OAuth] Built authorize URL for %s/%s", app_key, connector.meta.name)
        return url

    async def exchange_code(  # noqa: PLR0913 — OAuth flow requires all 5 params
        self,
        connector: BaseConnector,
        code: str,
        state: str,
        resolved: ResolvedOAuth,
        callback_url: str,
    ) -> tuple[AppConnection, str]:
        """Validate state, exchange authorization code for tokens.

        Raises:
            ValueError: If state is invalid, expired, or replayed.
        """
        decoded_state = await self._validate_and_consume_state(state, connector.meta.name)
        app_key = decoded_state["app_key"]

        auth_headers, body_credentials = connector.build_token_request_auth(resolved.credentials)
        token_request_body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            **body_credentials,
        }
        if connector.meta.supports_pkce:
            code_verifier = await self._state_store.get_and_remove_pkce_verifier(
                decoded_state["nonce"]
            )
            if not code_verifier:
                raise ValueError("PKCE verifier not found for this OAuth flow")
            token_request_body["code_verifier"] = code_verifier

        token_response = await self._post_token_request(
            connector, resolved.token_url, token_request_body, "exchange", auth_headers
        )
        connection = _build_connection_from_token(connector, token_response)

        logger.info("[OAuth] Token exchange successful for %s/%s", app_key, connector.meta.name)
        return connection, app_key

    async def refresh_if_expired(
        self,
        connector: BaseConnector,
        connection: AppConnection,
        resolved: ResolvedOAuth,
    ) -> AppConnection:
        """Refresh token if expired. Returns connection unchanged if not needed.

        Caller (proxy.get_valid_token) holds per-app-per-connector lock,
        so refresh is serialized at the app+connector level.
        """
        if connection.expires_at is None or connection.refresh_token is None:
            return connection

        # Not expired yet (with buffer)
        if connection.expires_at > time.time() + TOKEN_REFRESH_BUFFER:
            return connection

        return await self._do_refresh(connector, connection, resolved)

    async def _do_refresh(
        self,
        connector: BaseConnector,
        connection: AppConnection,
        resolved: ResolvedOAuth,
    ) -> AppConnection:
        """Execute the token refresh POST. Called under lock."""
        logger.info("[OAuth] Refreshing token for %s", connector.meta.name)

        auth_headers, body_credentials = connector.build_token_request_auth(resolved.credentials)
        token_request_body = {
            "grant_type": "refresh_token",
            "refresh_token": connection.refresh_token,
            **body_credentials,
        }

        token_response = await self._post_token_request(
            connector, resolved.token_url, token_request_body, "refresh", auth_headers
        )
        refreshed = _apply_refreshed_token(connection, token_response)

        logger.info("[OAuth] Token refreshed for %s", connector.meta.name)
        return refreshed

    def decode_state(self, state: str, max_age: int = _STATE_PEEK_MAX_AGE) -> dict:
        """Decode signed OAuth state without consuming the nonce.

        Used by callback to peek at app_key for credential lookup before
        calling exchange_code (which does the full validation + nonce consumption).

        Raises:
            ValueError: If state is expired or has an invalid signature.
        """
        try:
            return self._serializer.loads(state, max_age=max_age)
        # noqa justification (B904): the itsdangerous exception can embed the signed
        # state payload in its repr; chaining it would leak that payload into
        # tracebacks and logs, so the chain is deliberately dropped.
        except SignatureExpired:
            raise ValueError("OAuth state expired")  # noqa: B904 — drop chain to avoid leaking signed state payload
        except BadSignature:
            raise ValueError("Invalid OAuth state signature")  # noqa: B904 — drop chain to avoid leaking signed state payload

    # --- Internal ---

    def _sign_oauth_state(self, app_key: str, connector_name: str, nonce: str) -> str:
        """Sign state payload with itsdangerous serializer."""
        decoded_state = {"app_key": app_key, "connector": connector_name, "nonce": nonce}
        return self._serializer.dumps(decoded_state)

    async def _validate_and_consume_state(self, state: str, connector_name: str) -> dict:
        """Validate signature, check nonce + connector binding, consume nonce.

        ``connector_name`` is the connector actually handling the callback. The
        signed state carries the connector it was minted for; binding them here
        stops a state minted for connector A from completing connector B's flow.

        Raises:
            ValueError: If state is expired, invalid, replayed, or was minted
                for a different connector.
        """
        try:
            decoded_state = self._serializer.loads(state, max_age=_STATE_MAX_AGE)
        # noqa justification (B904): the itsdangerous exception can embed the signed
        # state payload in its repr; chaining it would leak that payload into
        # tracebacks and logs, so the chain is deliberately dropped.
        except SignatureExpired:
            raise ValueError("OAuth state expired")  # noqa: B904 — drop chain to avoid leaking signed state payload
        except BadSignature:
            raise ValueError("Invalid OAuth state signature")  # noqa: B904 — drop chain to avoid leaking signed state payload

        # Bind the signed connector to the one handling this callback. Checked
        # after signature validation so an attacker can't probe this on forged state.
        if decoded_state.get("connector") != connector_name:
            raise ValueError("OAuth state connector mismatch")

        nonce = decoded_state["nonce"]

        await self._state_store.cleanup_expired(_NONCE_TTL)
        # Single-use: consume_nonce removes the nonce, so a replay finds it gone.
        if not await self._state_store.consume_nonce(nonce):
            raise ValueError("OAuth state already used (replay) or expired")

        return decoded_state

    def _build_authorize_params(  # noqa: PLR0913 — all params needed for OAuth authorize
        self,
        connector: BaseConnector,
        resolved: ResolvedOAuth,
        callback_url: str,
        state: str,
        code_challenge: str | None,
    ) -> dict[str, str]:
        """Build OAuth authorize query parameters."""
        params: dict[str, str] = {
            "client_id": resolved.credentials.client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        if connector.meta.scopes:
            params["scope"] = " ".join(connector.meta.scopes)

        return connector.customize_authorize_params(params)

    async def _post_token_request(  # noqa: PLR0913 — OAuth token exchange requires all params
        self,
        connector: BaseConnector,
        token_url: str,
        token_request_body: dict,
        operation: str,
        extra_headers: dict | None = None,
    ) -> dict:
        """POST to OAuth token endpoint, parse response via connector hook.

        Args:
            token_url: Token endpoint URL (from ResolvedOAuth.token_url).
            extra_headers: Auth headers from connector.build_token_request_auth()
                (e.g. Basic Auth for Notion).

        Raises:
            ValueError: If the token endpoint returns non-200.
        """
        headers = {"Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=token_request_body,
                headers=headers,
            )

        if response.status_code != _HTTP_OK:
            truncated_body = response.text[:_MAX_ERROR_LOG_LENGTH]
            logger.error(
                "[OAuth] Token %s failed for %s: %s %s",
                operation,
                connector.meta.name,
                response.status_code,
                truncated_body,
            )
            raise ValueError(f"Token {operation} failed: {response.status_code}")

        try:
            response_body = response.json()
        except Exception as exc:
            raise ValueError(
                f"Token {operation} returned non-JSON response for {connector.meta.name}"
            ) from exc

        parsed = connector.parse_token_response(response_body)
        return filter_token_response(parsed)


# === Module-Level Helpers ===


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return code_verifier, code_challenge


def _compute_expires_at(token_response: dict) -> int | None:
    """Compute absolute expiry timestamp from token response's expires_in."""
    expires_in = token_response.get("expires_in")
    if expires_in is None:
        return None
    try:
        return int(time.time()) + int(expires_in)
    except (ValueError, TypeError):
        logger.warning("[OAuth] Non-numeric expires_in: %s", expires_in)
        return None


def _apply_refreshed_token(
    connection: AppConnection,
    token_response: dict,
) -> AppConnection:
    """Apply refreshed token data to an existing connection."""
    return connection.model_copy(
        update={
            "access_token": token_response["access_token"],
            "refresh_token": token_response.get("refresh_token", connection.refresh_token),
            "expires_at": _compute_expires_at(token_response),
        }
    )


def _build_connection_from_token(
    connector: BaseConnector,
    token_response: dict,
) -> AppConnection:
    """Build AppConnection from parsed token response."""
    return AppConnection(
        connector_name=connector.meta.name,
        access_token=token_response["access_token"],
        refresh_token=token_response.get("refresh_token"),
        expires_at=_compute_expires_at(token_response),
        scopes=(
            token_response.get("scope", "").split()
            if token_response.get("scope")
            # meta.scopes is a tuple (frozen, immutable); AppConnection.scopes is list.
            else list(connector.meta.scopes)
        ),
    )
