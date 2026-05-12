"""Tests for inbound OAuth Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from broker.models.inbound_auth import (
    InboundToken,
    OAuthClient,
    OAuthCode,
    RefreshRotationRequest,
    RegistrationRequest,
    RegistrationResponse,
    RotatedTokenPair,
    TokenResponse,
)

# === RegistrationRequest ===


def test_registration_request_minimal_valid():
    request = RegistrationRequest(
        client_name="Acme Claude",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )
    assert request.client_name == "Acme Claude"
    assert request.grant_types == ["authorization_code", "refresh_token"]
    assert request.response_types == ["code"]
    assert request.token_endpoint_auth_method == "none"


def test_registration_request_requires_redirect_uris():
    with pytest.raises(ValidationError, match="redirect_uris"):
        RegistrationRequest(client_name="Acme Claude", redirect_uris=[])


def test_registration_request_requires_client_name():
    with pytest.raises(ValidationError, match="client_name"):
        RegistrationRequest.model_validate(
            {"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}
        )


def test_registration_request_ignores_unknown_fields():
    """RFC 7591 §2 — registration metadata may contain unknown fields."""
    request = RegistrationRequest.model_validate(
        {
            "client_name": "Acme Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "logo_uri": "https://claude.ai/logo.png",
            "tos_uri": "https://anthropic.com/tos",
        }
    )
    assert request.client_name == "Acme Claude"
    assert not hasattr(request, "logo_uri")


def test_registration_request_token_endpoint_auth_method_literal():
    with pytest.raises(ValidationError):
        RegistrationRequest(
            client_name="Acme Claude",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
            token_endpoint_auth_method="bogus",  # type: ignore[arg-type] -- intentionally invalid
        )


# === RegistrationResponse ===


def test_registration_response_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        RegistrationResponse.model_validate(
            {
                "client_id": "mcp_client_acme",
                "client_id_issued_at": 1700000000,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "client_name": "Acme Claude",
                "extra_field": "rejected",
            }
        )


def test_registration_response_is_frozen():
    response = RegistrationResponse(
        client_id="mcp_client_acme",
        client_id_issued_at=1700000000,
        token_endpoint_auth_method="none",
        grant_types=["authorization_code"],
        response_types=["code"],
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        client_name="Acme Claude",
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        response.client_id = "mcp_client_other"  # type: ignore[misc] -- frozen check


# === OAuthClient ===


def test_oauth_client_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        OAuthClient.model_validate(
            {
                "client_id": "mcp_client_acme",
                "token_endpoint_auth_method": "none",
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": None,
                "client_name": "Acme Claude",
                "created_at": "2026-01-01T00:00:00Z",
                "rogue": "field",
            }
        )


def test_oauth_client_is_frozen():
    client = OAuthClient(
        client_id="mcp_client_acme",
        token_endpoint_auth_method="none",
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
        scope=None,
        client_name="Acme Claude",
        created_at="2026-01-01T00:00:00Z",
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        client.client_id = "mcp_client_other"  # type: ignore[misc] -- frozen check


# === OAuthCode ===


def test_oauth_code_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        OAuthCode.model_validate(
            {
                "client_id": "mcp_client_acme",
                "app_key": "acme:claude_ai",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "resource": "https://broker.example.com/proxy/notion",
                "scope": "mcp:read",
                "code_challenge": "abc123",
                "expires_at": 1700000600,
                "unexpected": True,
            }
        )


def test_oauth_code_is_frozen():
    code = OAuthCode(
        client_id="mcp_client_acme",
        app_key="acme:claude_ai",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        resource="https://broker.example.com/proxy/notion",
        scope="mcp:read",
        code_challenge="abc123",
        expires_at=1700000600,
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        code.scope = "mcp:write"  # type: ignore[misc] -- frozen check


# === InboundToken ===


def _make_inbound_token(**overrides: object) -> InboundToken:
    fields: dict[str, object] = {
        "token_hash": "hash_value_here",
        "token_kind": "access",
        "family_id": "fam_123",
        "client_id": "mcp_client_acme",
        "app_key": "acme:claude_ai",
        "resource": "https://broker.example.com/proxy/notion",
        "scope": "mcp:read",
        "expires_at": 1700003600,
        "issued_at": 1700000000,
    }
    fields.update(overrides)
    return InboundToken.model_validate(fields)


def test_inbound_token_minimal_valid():
    token = _make_inbound_token()
    assert token.token_kind == "access"
    assert token.parent_refresh_hash is None
    assert token.used_at is None


def test_inbound_token_refresh_kind():
    token = _make_inbound_token(token_kind="refresh")
    assert token.token_kind == "refresh"


def test_inbound_token_kind_literal_rejects_other_values():
    with pytest.raises(ValidationError, match="token_kind"):
        _make_inbound_token(token_kind="bearer")


def test_inbound_token_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        _make_inbound_token(rogue="field")


def test_inbound_token_is_frozen():
    token = _make_inbound_token()
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        token.scope = "mcp:write"  # type: ignore[misc] -- frozen check


# === TokenResponse ===


def test_token_response_defaults_to_bearer():
    response = TokenResponse(
        access_token="mcp_at_xyz",
        expires_in=3600,
        scope="mcp:read",
    )
    assert response.token_type == "Bearer"
    assert response.refresh_token is None


def test_token_response_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        TokenResponse.model_validate(
            {
                "access_token": "mcp_at_xyz",
                "expires_in": 3600,
                "scope": "mcp:read",
                "id_token": "should-be-rejected",
            }
        )


def test_token_response_is_frozen():
    response = TokenResponse(
        access_token="mcp_at_xyz",
        expires_in=3600,
        scope="mcp:read",
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        response.expires_in = 7200  # type: ignore[misc] -- frozen check


# === RefreshRotationRequest ===


def test_refresh_rotation_request_valid():
    request = RefreshRotationRequest(
        token_hash="hash_value_here",
        client_id="mcp_client_acme",
        resource="https://broker.example.com/proxy/notion",
        scope="mcp:read",
    )
    assert request.client_id == "mcp_client_acme"


def test_refresh_rotation_request_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        RefreshRotationRequest.model_validate(
            {
                "token_hash": "hash_value_here",
                "client_id": "mcp_client_acme",
                "resource": "https://broker.example.com/proxy/notion",
                "scope": "mcp:read",
                "extra": "field",
            }
        )


def test_refresh_rotation_request_is_frozen():
    request = RefreshRotationRequest(
        token_hash="hash_value_here",
        client_id="mcp_client_acme",
        resource="https://broker.example.com/proxy/notion",
        scope="mcp:read",
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        request.scope = "mcp:write"  # type: ignore[misc] -- frozen check


# === RotatedTokenPair ===


def test_rotated_token_pair_is_frozen():
    access_token = _make_inbound_token()
    refresh_token = _make_inbound_token(token_kind="refresh")
    pair = RotatedTokenPair(
        access=access_token,
        refresh=refresh_token,
        raw_access_token="mcp_at_raw",
        raw_refresh_token="mcp_rt_raw",
    )
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        pair.raw_access_token = "mcp_at_other"  # type: ignore[misc] -- frozen check


def test_rotated_token_pair_forbids_unknown_fields():
    access_token = _make_inbound_token()
    refresh_token = _make_inbound_token(token_kind="refresh")
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        RotatedTokenPair.model_validate(
            {
                "access": access_token.model_dump(),
                "refresh": refresh_token.model_dump(),
                "raw_access_token": "mcp_at_raw",
                "raw_refresh_token": "mcp_rt_raw",
                "id_token": "rejected",
            }
        )
