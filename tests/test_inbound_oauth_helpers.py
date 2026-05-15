"""Tests for inbound OAuth pure helpers (no I/O, no FastAPI)."""

from __future__ import annotations

import base64
import json
import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from broker.services.inbound_oauth_helpers import (
    CODE_VERIFIER_MAX_LEN,
    CODE_VERIFIER_MIN_LEN,
    audit_log_oauth_event,
    build_bearer_challenge,
    connector_from_request_path,
    connector_from_resource,
    hash_prefix,
    is_acceptable_redirect_uri,
    normalize_resource,
    parse_basic_auth,
    pkce_challenge_s256,
    resource_matches_connector,
    sha256_hex,
    verify_pkce_s256,
)

# === CONSTANTS ===

PUBLIC_URL = "https://broker.example.com"
NOTION_RESOURCE = "https://broker.example.com/proxy/notion"


# === verify_pkce_s256 ===


def test_pkce_round_trip_known_good():
    code_verifier = "a" * 64
    challenge = pkce_challenge_s256(code_verifier)
    assert verify_pkce_s256(code_verifier, challenge) is True


def test_pkce_rejects_short_verifier():
    too_short = "a" * (CODE_VERIFIER_MIN_LEN - 1)
    challenge = pkce_challenge_s256(too_short)
    assert verify_pkce_s256(too_short, challenge) is False


def test_pkce_rejects_long_verifier():
    too_long = "a" * (CODE_VERIFIER_MAX_LEN + 1)
    challenge = pkce_challenge_s256(too_long)
    assert verify_pkce_s256(too_long, challenge) is False


def test_pkce_rejects_mismatched_challenge():
    code_verifier = "a" * 64
    bogus_challenge = pkce_challenge_s256("b" * 64)
    assert verify_pkce_s256(code_verifier, bogus_challenge) is False


def test_pkce_min_and_max_lengths_accepted():
    min_verifier = "a" * CODE_VERIFIER_MIN_LEN
    max_verifier = "a" * CODE_VERIFIER_MAX_LEN
    assert verify_pkce_s256(min_verifier, pkce_challenge_s256(min_verifier)) is True
    assert verify_pkce_s256(max_verifier, pkce_challenge_s256(max_verifier)) is True


@pytest.mark.parametrize(
    "verifier",
    [
        "a" * 32 + " " * 11,  # space — outside RFC 7636 §4.1 charset
        "a" * 32 + "\x00" * 11,  # NUL byte
        "a" * 32 + "αβγδεζηθικλ",  # Greek letters
        "a" * 32 + "++++++++++/",  # base64 chars outside the unreserved set
    ],
)
def test_pkce_rejects_invalid_characters(verifier: str):
    """RFC 7636 §4.1 — verifier must use only unreserved characters."""
    # Build a valid-shape challenge so the only failure mode is the charset check.
    challenge = pkce_challenge_s256(verifier)
    assert verify_pkce_s256(verifier, challenge) is False


# === sha256_hex ===


def test_sha256_hex_known_vector():
    """NIST FIPS 180-4 known answer for the empty string."""
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex("") == expected


def test_sha256_hex_deterministic():
    first = sha256_hex("hello world")
    second = sha256_hex("hello world")
    assert first == second
    assert len(first) == 64  # 256 bits == 64 hex chars


# === normalize_resource ===


def test_normalize_resource_strips_trailing_slash():
    assert normalize_resource(NOTION_RESOURCE + "/") == normalize_resource(NOTION_RESOURCE)


def test_normalize_resource_lowercases_scheme_host_path():
    upper = normalize_resource("HTTPS://Broker.Example.COM/Proxy/Notion")
    lower = normalize_resource(NOTION_RESOURCE)
    assert upper == lower


def test_normalize_resource_rejects_fragment():
    with pytest.raises(ValueError, match="MUST NOT contain a fragment"):
        normalize_resource(NOTION_RESOURCE + "#section")


def test_normalize_resource_tolerates_query_string():
    """RFC 8707 §2 says SHOULD NOT include queries, but we accept for robustness."""
    normalized = normalize_resource(NOTION_RESOURCE + "?foo=bar")
    assert normalized == NOTION_RESOURCE


def test_normalize_resource_idempotent():
    once = normalize_resource(NOTION_RESOURCE + "/")
    twice = normalize_resource(once)
    assert once == twice


def test_normalize_resource_handles_root_path():
    normalized = normalize_resource(PUBLIC_URL + "/")
    assert normalized == PUBLIC_URL


def test_normalize_resource_handles_deep_path():
    deep = NOTION_RESOURCE + "/mcp/messages/abc"
    assert normalize_resource(deep) == deep


@pytest.mark.parametrize(
    "raw",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/plain,hello",
        "http://broker.example.com/proxy/notion",
        "ftp://broker.example.com/",
    ],
)
def test_normalize_resource_rejects_non_https_scheme(raw: str):
    """RFC 8707 §2 — resource indicators MUST use https."""
    with pytest.raises(ValueError, match="scheme must be https"):
        normalize_resource(raw)


def test_normalize_resource_rejects_empty_scheme():
    with pytest.raises(ValueError, match="scheme must be https"):
        normalize_resource("//broker.example.com/proxy/notion")


def test_normalize_resource_rejects_empty_netloc():
    with pytest.raises(ValueError, match="host must not be empty"):
        normalize_resource("https:///proxy/notion")


# === resource_matches_connector ===


@pytest.mark.parametrize(
    "resource_norm, public_url, connector_name, expected",
    [
        # Exact match
        (NOTION_RESOURCE, PUBLIC_URL, "notion", True),
        # Subpath under the connector
        (NOTION_RESOURCE + "/mcp", PUBLIC_URL, "notion", True),
        # Different connector name
        ("https://broker.example.com/proxy/hubspot", PUBLIC_URL, "notion", False),
        # public_url with trailing slash — right-stripped, still matches
        (NOTION_RESOURCE, PUBLIC_URL + "/", "notion", True),
        # Prefix overlap must not match — boundary is `/`
        ("https://broker.example.com/proxy/notion-staging", PUBLIC_URL, "notion", False),
    ],
)
def test_resource_matches_connector(
    resource_norm: str, public_url: str, connector_name: str, expected: bool
):
    assert resource_matches_connector(resource_norm, public_url, connector_name) is expected


# === connector_from_resource ===


@pytest.mark.parametrize(
    "resource_norm, connector_names, expected",
    [
        # Happy path — extracts connector when name is known
        (NOTION_RESOURCE + "/mcp", ["notion", "hubspot"], "notion"),
        # Connector not in known set
        ("https://broker.example.com/proxy/unknown", ["notion"], None),
        # Non-proxy path
        ("https://broker.example.com/oauth/token", ["notion"], None),
        # Bare `/proxy/` with no connector segment
        ("https://broker.example.com/proxy/", ["notion"], None),
    ],
)
def test_connector_from_resource(
    resource_norm: str, connector_names: list[str], expected: str | None
):
    assert connector_from_resource(resource_norm, PUBLIC_URL, connector_names) == expected


def test_connector_from_resource_rejects_generator():
    """Iterable[str] would silently exhaust a generator; Collection[str] forces a sized container.

    Pyright catches this at type-check time. At runtime the call still works because the
    generator is iterable, but the type contract is what protects callers from the bug.
    """
    names = (name for name in ["notion"])
    # Cast away the type error to exercise runtime behaviour: it still returns the right value.
    extracted = connector_from_resource(
        NOTION_RESOURCE,
        PUBLIC_URL,
        names,  # type: ignore[arg-type] -- intentionally probing the contract
    )
    assert extracted == "notion"


# === connector_from_request_path ===


@pytest.mark.parametrize(
    "request_path, connector_names, expected",
    [
        # Bare connector path
        ("/proxy/notion", ["notion"], "notion"),
        # Trailing slash variant
        ("/proxy/notion/", ["notion"], "notion"),
        # Deep path under connector
        ("/proxy/notion/mcp/messages/abc123", ["notion"], "notion"),
        # Non-proxy path
        ("/oauth/token", ["notion"], None),
        # Unknown connector
        ("/proxy/unknown/mcp", ["notion"], None),
        # Bare prefix
        ("/proxy/", ["notion"], None),
    ],
)
def test_connector_from_request_path(
    request_path: str, connector_names: list[str], expected: str | None
):
    assert connector_from_request_path(request_path, connector_names) == expected


# === is_acceptable_redirect_uri ===

_TEST_ALLOWLIST = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


def test_is_acceptable_redirect_uri_exact_match():
    assert (
        is_acceptable_redirect_uri("https://claude.ai/api/mcp/auth_callback", _TEST_ALLOWLIST)
        is True
    )
    assert (
        is_acceptable_redirect_uri("https://claude.com/api/mcp/auth_callback", _TEST_ALLOWLIST)
        is True
    )


def test_is_acceptable_redirect_uri_off_allowlist_rejected():
    """Empty allowlist + arbitrary URI both reject — the function is exact-match only."""
    assert is_acceptable_redirect_uri("https://evil.example.com/callback", _TEST_ALLOWLIST) is False
    assert is_acceptable_redirect_uri("https://anything.test/cb", ()) is False


def test_is_acceptable_redirect_uri_subdomain_rejected():
    """Allowlist is exact — subdomains do not match."""
    assert (
        is_acceptable_redirect_uri(
            "https://staging.claude.ai/api/mcp/auth_callback", _TEST_ALLOWLIST
        )
        is False
    )


# === parse_basic_auth ===


def test_parse_basic_auth_well_formed():
    encoded = base64.b64encode(b"alice:s3cret").decode()
    parsed = parse_basic_auth(f"Basic {encoded}")
    assert parsed == ("alice", "s3cret")


def test_parse_basic_auth_lowercase_scheme():
    encoded = base64.b64encode(b"alice:s3cret").decode()
    parsed = parse_basic_auth(f"basic {encoded}")
    assert parsed == ("alice", "s3cret")


def test_parse_basic_auth_missing_prefix():
    encoded = base64.b64encode(b"alice:s3cret").decode()
    assert parse_basic_auth(f"Bearer {encoded}") is None


def test_parse_basic_auth_non_base64():
    assert parse_basic_auth("Basic !!!not-base64!!!") is None


def test_parse_basic_auth_missing_colon():
    encoded = base64.b64encode(b"no-colon-here").decode()
    assert parse_basic_auth(f"Basic {encoded}") is None


def test_parse_basic_auth_password_with_colon():
    """Password may contain colons — split must be on first colon only."""
    encoded = base64.b64encode(b"alice:pass:with:colons").decode()
    parsed = parse_basic_auth(f"Basic {encoded}")
    assert parsed == ("alice", "pass:with:colons")


def test_parse_basic_auth_handles_none():
    """`request.headers.get('authorization')` returns None when the header is absent —
    the parser must treat that as 'no credentials supplied', not crash."""
    assert parse_basic_auth(None) is None


def test_parse_basic_auth_handles_empty_string():
    assert parse_basic_auth("") is None


# === build_bearer_challenge ===


def test_build_bearer_challenge_minimal():
    challenge = build_bearer_challenge(PUBLIC_URL + "/.well-known/resource")
    assert challenge.startswith("Bearer ")
    assert 'resource_metadata="https://broker.example.com/.well-known/resource"' in challenge


def test_build_bearer_challenge_with_all_parts():
    challenge = build_bearer_challenge(
        PUBLIC_URL + "/.well-known/resource",
        scope="mcp:read",
        error="invalid_token",
        error_description="The token expired",
    )
    assert 'resource_metadata="https://broker.example.com/.well-known/resource"' in challenge
    assert 'error="invalid_token"' in challenge
    assert 'error_description="The token expired"' in challenge
    assert 'scope="mcp:read"' in challenge


def test_build_bearer_challenge_omits_none_values():
    challenge = build_bearer_challenge(
        PUBLIC_URL + "/.well-known/resource",
        scope=None,
        error=None,
        error_description=None,
    )
    assert "error=" not in challenge
    assert "scope=" not in challenge


# === hash_prefix ===


def test_hash_prefix_first_eight_chars():
    full_hash = "abcdef1234567890"
    assert hash_prefix(full_hash) == "abcdef12"


def test_hash_prefix_short_hash():
    """Hashes shorter than HASH_PREFIX_LEN return the whole string (slice never raises)."""
    assert hash_prefix("abc") == "abc"


# === audit_log_oauth_event ===


def test_audit_log_emits_json_at_info(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger="broker.services.inbound_oauth_helpers")
    audit_log_oauth_event(
        "token_issued",
        client_id="mcp_client_acme",
        token_hash_prefix="abcdef12",
    )
    audit_records = [r for r in caplog.records if r.name == "broker.services.inbound_oauth_helpers"]
    assert len(audit_records) == 1
    assert "[OAuthAudit]" in audit_records[0].getMessage()
    payload = json.loads(audit_records[0].getMessage().split(" ", 1)[1])
    assert payload["event"] == "token_issued"
    assert payload["client_id"] == "mcp_client_acme"
    assert payload["token_hash_prefix"] == "abcdef12"
    assert "ts" in payload


# === PROPERTY TESTS (hypothesis) ===


@given(
    code_verifier=st.text(
        # RFC 7636 §4.1 — `[A-Za-z0-9\-._~]`. ASCII-only so we don't generate Unicode
        # letters that the charset check now rejects.
        alphabet=st.sampled_from(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        ),
        min_size=CODE_VERIFIER_MIN_LEN,
        max_size=CODE_VERIFIER_MAX_LEN,
    )
)
def test_property_pkce_round_trip(code_verifier: str):
    """Any RFC 7636-compliant verifier of valid length verifies against its derived challenge."""
    challenge = pkce_challenge_s256(code_verifier)
    assert verify_pkce_s256(code_verifier, challenge) is True


@given(
    host=st.from_regex(r"[a-zA-Z][a-zA-Z0-9.-]{1,30}\.[a-zA-Z]{2,}", fullmatch=True),
    path=st.from_regex(r"(/[a-zA-Z0-9_.-]{1,20}){0,5}/?", fullmatch=True),
)
def test_property_normalize_resource_idempotent(host: str, path: str):
    """normalize_resource is idempotent — applying it twice equals applying it once.

    Scheme is fixed to `https` because the helper now rejects other schemes (RFC 8707 §2).
    """
    candidate_url = f"https://{host}{path}"
    once = normalize_resource(candidate_url)
    twice = normalize_resource(once)
    assert once == twice
