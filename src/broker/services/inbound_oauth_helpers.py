"""Pure helpers for the inbound OAuth 2.1 AS.

No I/O — these functions are deterministic given their inputs. Stateful concerns
(rate limiting, audit logging) belong elsewhere; this module is for crypto +
validation + URL normalization.

WARNING: Some callers (rate limiter, in-memory state) are single-process only.
Multi-worker uvicorn deployments will need a shared backing store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import Collection, Iterable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# === CONSTANTS ===

ACCESS_TOKEN_PREFIX = "mcp_at_"  # noqa: S105 -- token prefix, not a credential
REFRESH_TOKEN_PREFIX = "mcp_rt_"  # noqa: S105 -- token prefix, not a credential
CLIENT_ID_PREFIX = "mcp_client_"

CODE_VERIFIER_MIN_LEN = 43
CODE_VERIFIER_MAX_LEN = 128

# RFC 7636 §4.1 — code_verifier = high-entropy 43-128 chars from this set.
PKCE_VERIFIER_CHARSET = re.compile(r"^[A-Za-z0-9\-._~]+$")

HASH_PREFIX_LEN = 8  # how many chars of a token hash to include in audit logs


# === HASHING ===


def sha256_hex(value: str) -> str:
    """SHA-256 hex digest of `value`. Used to fingerprint tokens, codes, and client
    secrets before they touch the database — raw values never persist."""
    return hashlib.sha256(value.encode()).hexdigest()


# === PKCE ===


def pkce_challenge_s256(verifier: str) -> str:
    """RFC 7636 §4.2 — challenge = base64url(sha256(verifier)) with padding stripped."""
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """RFC 7636 §4.6 — challenge = base64url(sha256(verifier)) with padding stripped.

    Enforces RFC 7636 §4.1 character set so non-conforming verifiers are rejected
    before any cryptographic work is done.
    """
    if not (CODE_VERIFIER_MIN_LEN <= len(code_verifier) <= CODE_VERIFIER_MAX_LEN):
        return False
    if not PKCE_VERIFIER_CHARSET.fullmatch(code_verifier):
        return False
    return hmac.compare_digest(pkce_challenge_s256(code_verifier), code_challenge)


# === RESOURCE NORMALIZATION ===


def normalize_resource(raw: str) -> str:
    """Normalize a `resource` URL for COMPARISON only. Storage keeps the raw client-sent string.

    Lowercases scheme + host + path; strips trailing slash. The path-lowercase is a
    deliberate RFC 3986 §6.2.2.1 deviation justified by MCP-spec convention and
    claude.ai's WHATWG normalization quirks (claude-code#52871). Symmetric lowercase
    on both sides of every compare is the only reliable strategy.

    Per RFC 8707 §2 only https URLs may name a resource. Raises ValueError on
    fragment, non-https scheme, or empty host.
    """
    parsed = urlparse(raw)
    if parsed.fragment:
        raise ValueError("resource MUST NOT contain a fragment")
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if scheme != "https":
        raise ValueError("resource scheme must be https")
    if not netloc:
        raise ValueError("resource host must not be empty")
    path = parsed.path.rstrip("/").lower()
    return f"{scheme}://{netloc}{path}"


def resource_matches_connector(resource_norm: str, public_url: str, connector_name: str) -> bool:
    """Audience boundary: a token issued for one connector cannot be used on another.

    Inputs MUST already be normalized via normalize_resource() — this function does
    not lowercase to enforce that contract.
    """
    expected_prefix = f"{public_url.rstrip('/')}/proxy/{connector_name}".lower()
    return resource_norm == expected_prefix or resource_norm.startswith(expected_prefix + "/")


def connector_from_resource(
    resource_norm: str,
    public_url: str,
    connector_names: Collection[str],
) -> str | None:
    """Extract the connector name from a normalized resource URL.

    `connector_names` is `Collection[str]` (not `Iterable[str]`) so callers cannot
    accidentally pass a one-shot generator that would silently exhaust mid-check.

    Returns None if the resource doesn't match `{public_url}/proxy/{name}` or the
    extracted name isn't in `connector_names`.
    """
    prefix = f"{public_url.rstrip('/')}/proxy/".lower()
    if not resource_norm.startswith(prefix):
        return None
    rest = resource_norm[len(prefix) :]
    extracted_name = rest.split("/", 1)[0]
    return extracted_name if extracted_name in connector_names else None


def connector_from_request_path(
    request_path: str,
    connector_names: Collection[str],
) -> str | None:
    """Extract the connector name from a live `/proxy/{connector}/...` request path.

    `connector_names` is `Collection[str]` (not `Iterable[str]`) so callers cannot
    accidentally pass a one-shot generator that would silently exhaust mid-check.

    Tolerates deep paths (`/proxy/notion/mcp/messages/abc123`) and missing-suffix
    shapes (`/proxy/notion`, `/proxy/notion/`).
    """
    if not request_path.startswith("/proxy/"):
        return None
    rest = request_path[len("/proxy/") :]
    extracted_name = rest.split("/", 1)[0]
    return extracted_name if extracted_name and extracted_name in connector_names else None


# === REDIRECT URI VALIDATION ===


def is_acceptable_redirect_uri(uri: str, allowlist: Iterable[str]) -> bool:
    """Exact-match check against the operator-configured allowlist.

    With no identity layer at ``/oauth/authorize`` the allowlist is the security
    boundary — a stolen DCR registration with an attacker-controlled callback
    would otherwise exfiltrate codes. Operators declare which MCP clients they
    trust via ``broker.oauth.allowed_redirect_uris`` in ``settings.yaml``.
    """
    return uri in allowlist


# === BASIC AUTH PARSING ===


def parse_basic_auth(header_value: str | None) -> tuple[str, str] | None:
    """Parse `Authorization: Basic <base64(client_id:client_secret)>`. None on malformed."""
    if not header_value or not header_value.lower().startswith("basic "):
        return None
    encoded = header_value[len("basic ") :].strip()
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    client_id, secret = decoded.split(":", 1)
    return client_id, secret


# === WWW-AUTHENTICATE CHALLENGE ===


def _escape_quoted_string(value: str) -> str:
    """RFC 6750 §3 quoted-string escape: backslash before ``"`` and ``\\``.

    Defense-in-depth — current callers pass operator-controlled constants or
    enum values, but interpolating any caller-supplied string into a quoted
    HTTP header without escaping is a header-injection waiting to happen.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_bearer_challenge(
    resource_metadata_url: str,
    scope: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> str:
    """Build a spec-compliant WWW-Authenticate Bearer challenge string.

    NOTE: callers must place this in a `WWW-Authenticate` header (capital case).
    HTTP/2 lowercases header names on the wire; claude.ai bug #219 does
    case-sensitive lookup. CF Tunnel users must force HTTP/1.1 origin.
    """
    parts = [f'resource_metadata="{_escape_quoted_string(resource_metadata_url)}"']
    if error:
        parts.append(f'error="{_escape_quoted_string(error)}"')
    if error_description:
        parts.append(f'error_description="{_escape_quoted_string(error_description)}"')
    if scope:
        parts.append(f'scope="{_escape_quoted_string(scope)}"')
    return "Bearer " + ", ".join(parts)


# === AUDIT LOGGING ===


def hash_prefix(token_hash: str) -> str:
    """First N chars of a hash, for traceability in logs (never log full hash or raw token)."""
    return token_hash[:HASH_PREFIX_LEN]


# Field names that almost certainly contain a raw credential. Audit logs MUST
# carry hash prefixes (e.g. `hash_prefix`, `access_hash_prefix`) — never the
# raw value. Enforced here rather than trusting every caller (AGENTS.md
# Security Invariant: "Log statements MUST NOT include tokens, keys,
# secrets, or decrypted credentials — even at DEBUG level").
_AUDIT_LOG_BANNED_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "code",
        "code_verifier",
        "raw_token",
        "secret",
        "password",
        "api_key",
    }
)


def audit_log_oauth_event(event_type: str, **fields: object) -> None:
    """Structured audit log for OAuth lifecycle events.

    Raises ``ValueError`` if any field name matches a known credential key —
    callers MUST pass hash prefixes (``hash_prefix``, ``access_hash_prefix``,
    etc.). The denylist is conservative: anything that LOOKS like a token by
    name gets blocked even if the value happens to be safe, so a single
    misnaming can't silently leak a secret into the log aggregator.
    """
    banned_keys_supplied = _AUDIT_LOG_BANNED_KEYS & fields.keys()
    if banned_keys_supplied:
        raise ValueError(
            f"audit_log_oauth_event refuses banned key(s): {sorted(banned_keys_supplied)}. "
            "Pass a hash prefix (e.g. hash_prefix=hash_prefix(token_hash)) instead."
        )
    payload = {"event": event_type, "ts": int(time.time()), **fields}
    logger.info("[OAuthAudit] %s", json.dumps(payload, sort_keys=True, default=str))
