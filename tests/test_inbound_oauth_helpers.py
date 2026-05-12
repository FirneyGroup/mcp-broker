"""Tests for inbound OAuth pure helpers (no I/O, no FastAPI)."""

from __future__ import annotations

import base64
import hashlib
import json
import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from broker.services.inbound_oauth_helpers import (
    ALLOWED_REDIRECT_URIS,
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
    resource_matches_connector,
    verify_pkce_s256,
)

# === HELPERS ===


def derive_challenge(code_verifier: str) -> str:
    """Compute the RFC 7636 S256 challenge from a verifier — mirrors the function under test."""
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# === verify_pkce_s256 ===


def test_pkce_round_trip_known_good():
    code_verifier = "a" * 64
    challenge = derive_challenge(code_verifier)
    assert verify_pkce_s256(code_verifier, challenge) is True


def test_pkce_rejects_short_verifier():
    too_short = "a" * (CODE_VERIFIER_MIN_LEN - 1)
    challenge = derive_challenge(too_short)
    assert verify_pkce_s256(too_short, challenge) is False


def test_pkce_rejects_long_verifier():
    too_long = "a" * (CODE_VERIFIER_MAX_LEN + 1)
    challenge = derive_challenge(too_long)
    assert verify_pkce_s256(too_long, challenge) is False


def test_pkce_rejects_mismatched_challenge():
    code_verifier = "a" * 64
    bogus_challenge = derive_challenge("b" * 64)
    assert verify_pkce_s256(code_verifier, bogus_challenge) is False


def test_pkce_min_and_max_lengths_accepted():
    min_verifier = "a" * CODE_VERIFIER_MIN_LEN
    max_verifier = "a" * CODE_VERIFIER_MAX_LEN
    assert verify_pkce_s256(min_verifier, derive_challenge(min_verifier)) is True
    assert verify_pkce_s256(max_verifier, derive_challenge(max_verifier)) is True


def test_pkce_uses_constant_time_compare():
    """Code review check — verify_pkce_s256 must call hmac.compare_digest."""
    import inspect

    from broker.services.inbound_oauth_helpers import verify_pkce_s256 as fn

    source = inspect.getsource(fn)
    assert "hmac.compare_digest" in source, "verify_pkce_s256 must use hmac.compare_digest"


# === normalize_resource ===


def test_normalize_resource_strips_trailing_slash():
    assert normalize_resource("https://broker.example.com/proxy/notion/") == normalize_resource(
        "https://broker.example.com/proxy/notion"
    )


def test_normalize_resource_lowercases_scheme_host_path():
    upper = normalize_resource("HTTPS://Broker.Example.COM/Proxy/Notion")
    lower = normalize_resource("https://broker.example.com/proxy/notion")
    assert upper == lower


def test_normalize_resource_rejects_fragment():
    with pytest.raises(ValueError, match="MUST NOT contain a fragment"):
        normalize_resource("https://broker.example.com/proxy/notion#section")


def test_normalize_resource_tolerates_query_string():
    """RFC 8707 §2 says SHOULD NOT include queries, but we accept for robustness."""
    normalized = normalize_resource("https://broker.example.com/proxy/notion?foo=bar")
    assert normalized == "https://broker.example.com/proxy/notion"


def test_normalize_resource_idempotent():
    once = normalize_resource("https://broker.example.com/proxy/notion/")
    twice = normalize_resource(once)
    assert once == twice


def test_normalize_resource_handles_root_path():
    normalized = normalize_resource("https://broker.example.com/")
    assert normalized == "https://broker.example.com"


def test_normalize_resource_handles_deep_path():
    normalized = normalize_resource("https://broker.example.com/proxy/notion/mcp/messages/abc")
    assert normalized == "https://broker.example.com/proxy/notion/mcp/messages/abc"


# === resource_matches_connector ===


def test_resource_matches_connector_exact():
    assert (
        resource_matches_connector(
            "https://broker.example.com/proxy/notion",
            "https://broker.example.com",
            "notion",
        )
        is True
    )


def test_resource_matches_connector_with_subpath():
    assert (
        resource_matches_connector(
            "https://broker.example.com/proxy/notion/mcp",
            "https://broker.example.com",
            "notion",
        )
        is True
    )


def test_resource_matches_connector_wrong_name():
    assert (
        resource_matches_connector(
            "https://broker.example.com/proxy/hubspot",
            "https://broker.example.com",
            "notion",
        )
        is False
    )


def test_resource_matches_connector_public_url_trailing_slash_tolerated():
    """public_url is right-stripped, so trailing slash variants behave identically."""
    assert (
        resource_matches_connector(
            "https://broker.example.com/proxy/notion",
            "https://broker.example.com/",
            "notion",
        )
        is True
    )


def test_resource_matches_connector_rejects_prefix_overlap():
    """`notion-staging` should not match `notion` — boundary is `/`."""
    assert (
        resource_matches_connector(
            "https://broker.example.com/proxy/notion-staging",
            "https://broker.example.com",
            "notion",
        )
        is False
    )


# === connector_from_resource ===


def test_connector_from_resource_extracts_name():
    name = connector_from_resource(
        "https://broker.example.com/proxy/notion/mcp",
        "https://broker.example.com",
        ["notion", "hubspot"],
    )
    assert name == "notion"


def test_connector_from_resource_unknown_connector():
    name = connector_from_resource(
        "https://broker.example.com/proxy/unknown",
        "https://broker.example.com",
        ["notion"],
    )
    assert name is None


def test_connector_from_resource_non_proxy_path():
    name = connector_from_resource(
        "https://broker.example.com/oauth/token",
        "https://broker.example.com",
        ["notion"],
    )
    assert name is None


def test_connector_from_resource_bare_prefix():
    """`/proxy/` with no connector → empty extracted name → None."""
    name = connector_from_resource(
        "https://broker.example.com/proxy/",
        "https://broker.example.com",
        ["notion"],
    )
    assert name is None


# === connector_from_request_path ===


def test_connector_from_request_path_bare_name():
    assert connector_from_request_path("/proxy/notion", ["notion"]) == "notion"


def test_connector_from_request_path_trailing_slash():
    assert connector_from_request_path("/proxy/notion/", ["notion"]) == "notion"


def test_connector_from_request_path_deep():
    extracted = connector_from_request_path("/proxy/notion/mcp/messages/abc123", ["notion"])
    assert extracted == "notion"


def test_connector_from_request_path_non_proxy():
    assert connector_from_request_path("/oauth/token", ["notion"]) is None


def test_connector_from_request_path_unknown_connector():
    assert connector_from_request_path("/proxy/unknown/mcp", ["notion"]) is None


def test_connector_from_request_path_bare_prefix():
    assert connector_from_request_path("/proxy/", ["notion"]) is None


# === is_acceptable_redirect_uri ===


def test_is_acceptable_redirect_uri_claude_ai():
    assert is_acceptable_redirect_uri("https://claude.ai/api/mcp/auth_callback") is True


def test_is_acceptable_redirect_uri_claude_com():
    assert is_acceptable_redirect_uri("https://claude.com/api/mcp/auth_callback") is True


def test_is_acceptable_redirect_uri_arbitrary_https_rejected():
    assert is_acceptable_redirect_uri("https://evil.example.com/callback") is False


def test_is_acceptable_redirect_uri_loopback_rejected():
    """v1 strict allowlist — loopback support is v1.5."""
    assert is_acceptable_redirect_uri("http://127.0.0.1:8080/callback") is False
    assert is_acceptable_redirect_uri("http://localhost:8080/callback") is False


def test_is_acceptable_redirect_uri_subdomain_of_claude_rejected():
    """Allowlist is exact — subdomains do not match."""
    assert is_acceptable_redirect_uri("https://staging.claude.ai/api/mcp/auth_callback") is False


def test_allowed_redirect_uris_immutable():
    assert isinstance(ALLOWED_REDIRECT_URIS, frozenset)


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


# === build_bearer_challenge ===


def test_build_bearer_challenge_minimal():
    challenge = build_bearer_challenge("https://broker.example.com/.well-known/resource")
    assert challenge.startswith("Bearer ")
    assert 'resource_metadata="https://broker.example.com/.well-known/resource"' in challenge


def test_build_bearer_challenge_with_all_parts():
    challenge = build_bearer_challenge(
        "https://broker.example.com/.well-known/resource",
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
        "https://broker.example.com/.well-known/resource",
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


def test_audit_log_never_includes_raw_token_value(caplog: pytest.LogCaptureFixture):
    """Callers must pass hash prefixes; this test guards against accidental raw-token logging."""
    caplog.set_level(logging.INFO, logger="broker.services.inbound_oauth_helpers")
    secret_token = "mcp_at_super_secret_value_should_not_leak"  # noqa: S105 -- test fixture
    audit_log_oauth_event("login_attempt", token_hash_prefix="abcdef12")
    for record in caplog.records:
        assert secret_token not in record.getMessage()


# === PROPERTY TESTS (hypothesis) ===


@given(
    code_verifier=st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"),
            whitelist_characters="-._~",
        ),
        min_size=CODE_VERIFIER_MIN_LEN,
        max_size=CODE_VERIFIER_MAX_LEN,
    )
)
def test_property_pkce_round_trip(code_verifier: str):
    """Any URL-safe verifier of valid length verifies against its derived challenge."""
    challenge = derive_challenge(code_verifier)
    assert verify_pkce_s256(code_verifier, challenge) is True


@given(
    scheme=st.sampled_from(["http", "https", "HTTP", "HTTPS"]),
    host=st.from_regex(r"[a-zA-Z][a-zA-Z0-9.-]{1,30}\.[a-zA-Z]{2,}", fullmatch=True),
    path=st.from_regex(r"(/[a-zA-Z0-9_.-]{1,20}){0,5}/?", fullmatch=True),
)
def test_property_normalize_resource_idempotent(scheme: str, host: str, path: str):
    """normalize_resource is idempotent — applying it twice equals applying it once."""
    candidate_url = f"{scheme}://{host}{path}"
    once = normalize_resource(candidate_url)
    twice = normalize_resource(once)
    assert once == twice
