"""Tests for inbound OAuth Pydantic models."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

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

# === CONSTANTS ===

TEST_CLIENT_ID = "mcp_client_acme"
TEST_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
TEST_RESOURCE_URL = "https://broker.example.com/proxy/notion"
TEST_APP_KEY = "acme:claude_ai"
TEST_CLIENT_NAME = "Acme Claude"


# === FIXTURE BUILDERS ===


def _make_inbound_token(**overrides: object) -> InboundToken:
    fields: dict[str, object] = {
        "token_hash": "hash_value_here",
        "token_kind": "access",
        "family_id": "fam_123",
        "client_id": TEST_CLIENT_ID,
        "app_key": TEST_APP_KEY,
        "resource": TEST_RESOURCE_URL,
        "scope": "mcp:read",
        "expires_at": 1700003600,
        "issued_at": 1700000000,
    }
    fields.update(overrides)
    return InboundToken.model_validate(fields)


def _valid_kwargs_for(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Minimum valid construction kwargs for each model, used by parametrized tests."""
    if model_cls is RegistrationResponse:
        return {
            "client_id": TEST_CLIENT_ID,
            "client_id_issued_at": 1700000000,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "redirect_uris": [TEST_REDIRECT_URI],
            "client_name": TEST_CLIENT_NAME,
        }
    if model_cls is OAuthClient:
        return {
            "client_id": TEST_CLIENT_ID,
            "token_endpoint_auth_method": "none",
            "redirect_uris": [TEST_REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": None,
            "client_name": TEST_CLIENT_NAME,
            "created_at": "2026-01-01T00:00:00Z",
        }
    if model_cls is OAuthCode:
        return {
            "client_id": TEST_CLIENT_ID,
            "app_key": TEST_APP_KEY,
            "redirect_uri": TEST_REDIRECT_URI,
            "resource": TEST_RESOURCE_URL,
            "scope": "mcp:read",
            "code_challenge": "abc123",
            "expires_at": 1700000600,
        }
    if model_cls is InboundToken:
        return {
            "token_hash": "hash_value_here",
            "token_kind": "access",
            "family_id": "fam_123",
            "client_id": TEST_CLIENT_ID,
            "app_key": TEST_APP_KEY,
            "resource": TEST_RESOURCE_URL,
            "scope": "mcp:read",
            "expires_at": 1700003600,
            "issued_at": 1700000000,
        }
    if model_cls is TokenResponse:
        return {
            "access_token": "mcp_at_xyz",
            "expires_in": 3600,
            "scope": "mcp:read",
        }
    if model_cls is RefreshRotationRequest:
        return {
            "token_hash": "hash_value_here",
            "client_id": TEST_CLIENT_ID,
            "resource": TEST_RESOURCE_URL,
            "scope": "mcp:read",
            "access_ttl_seconds": 3600,
            "refresh_ttl_seconds": 2592000,
        }
    if model_cls is RotatedTokenPair:
        access = _make_inbound_token()
        refresh = _make_inbound_token(token_kind="refresh")
        return {
            "access": access.model_dump(),
            "refresh": refresh.model_dump(),
            "raw_access_token": "mcp_at_raw",
            "raw_refresh_token": "mcp_rt_raw",
        }
    raise AssertionError(f"no valid kwargs registered for {model_cls!r}")


# Every frozen + extra="forbid" model gets the same two invariants checked.
# RegistrationRequest is intentionally excluded — it uses extra="ignore" (RFC 7591 §2)
# and isn't frozen because callers mutate before persistence.
INVARIANT_MODELS: list[type[BaseModel]] = [
    RegistrationResponse,
    OAuthClient,
    OAuthCode,
    InboundToken,
    TokenResponse,
    RefreshRotationRequest,
    RotatedTokenPair,
]


# === Shared invariants (frozen + extra=forbid) ===


@pytest.mark.parametrize("model_cls", INVARIANT_MODELS)
def test_model_forbids_unknown_fields(model_cls: type[BaseModel]):
    payload = {**_valid_kwargs_for(model_cls), "rogue_field": "rejected"}
    with pytest.raises(ValidationError, match="extra_inputs|Extra inputs"):
        model_cls.model_validate(payload)


@pytest.mark.parametrize("model_cls", INVARIANT_MODELS)
def test_model_is_frozen(model_cls: type[BaseModel]):
    instance = model_cls.model_validate(_valid_kwargs_for(model_cls))
    # First mutable field across the seven models — kept identical so we exercise
    # frozen behaviour, not a specific field.
    target_field = next(iter(model_cls.model_fields))
    with pytest.raises(ValidationError, match="frozen|Instance is frozen"):
        setattr(instance, target_field, "anything")


# === RegistrationRequest ===


def test_registration_request_minimal_valid():
    request = RegistrationRequest(
        client_name=TEST_CLIENT_NAME,
        redirect_uris=[TEST_REDIRECT_URI],
    )
    assert request.client_name == TEST_CLIENT_NAME
    assert request.grant_types == ["authorization_code", "refresh_token"]
    assert request.response_types == ["code"]
    assert request.token_endpoint_auth_method == "none"


def test_registration_request_requires_redirect_uris():
    with pytest.raises(ValidationError, match="redirect_uris"):
        RegistrationRequest(client_name=TEST_CLIENT_NAME, redirect_uris=[])


def test_registration_request_requires_client_name():
    with pytest.raises(ValidationError, match="client_name"):
        RegistrationRequest.model_validate({"redirect_uris": [TEST_REDIRECT_URI]})


def test_registration_request_ignores_unknown_fields():
    """RFC 7591 §2 — registration metadata may contain unknown fields."""
    request = RegistrationRequest.model_validate(
        {
            "client_name": TEST_CLIENT_NAME,
            "redirect_uris": [TEST_REDIRECT_URI],
            "logo_uri": "https://claude.ai/logo.png",
            "tos_uri": "https://anthropic.com/tos",
        }
    )
    assert request.client_name == TEST_CLIENT_NAME
    assert not hasattr(request, "logo_uri")


def test_registration_request_token_endpoint_auth_method_literal():
    with pytest.raises(ValidationError):
        RegistrationRequest(
            client_name=TEST_CLIENT_NAME,
            redirect_uris=[TEST_REDIRECT_URI],
            token_endpoint_auth_method="bogus",  # type: ignore[arg-type] -- intentionally invalid Literal
        )


# === New constraint regression tests ===


def test_client_name_max_length():
    overlong = "a" * 256
    with pytest.raises(ValidationError, match="client_name"):
        RegistrationRequest(client_name=overlong, redirect_uris=[TEST_REDIRECT_URI])


def test_scope_max_length():
    overlong_scope = "a" * 2049
    with pytest.raises(ValidationError, match="scope"):
        RegistrationRequest(
            client_name=TEST_CLIENT_NAME,
            redirect_uris=[TEST_REDIRECT_URI],
            scope=overlong_scope,
        )


def test_redirect_uri_list_max_length():
    too_many = [TEST_REDIRECT_URI] * 11
    with pytest.raises(ValidationError, match="redirect_uris"):
        RegistrationRequest(client_name=TEST_CLIENT_NAME, redirect_uris=too_many)


def test_redirect_uri_element_max_length():
    overlong_uri = "https://example.com/" + ("a" * 2048)
    with pytest.raises(ValidationError, match="redirect_uri exceeds"):
        RegistrationRequest(client_name=TEST_CLIENT_NAME, redirect_uris=[overlong_uri])


def test_grant_types_literal_rejects_unknown():
    with pytest.raises(ValidationError, match="grant_types"):
        RegistrationRequest(
            client_name=TEST_CLIENT_NAME,
            redirect_uris=[TEST_REDIRECT_URI],
            grant_types=["password"],  # type: ignore[list-item] -- intentionally invalid Literal
        )


def test_response_types_literal_rejects_unknown():
    with pytest.raises(ValidationError, match="response_types"):
        RegistrationRequest(
            client_name=TEST_CLIENT_NAME,
            redirect_uris=[TEST_REDIRECT_URI],
            response_types=["token"],  # type: ignore[list-item] -- intentionally invalid Literal
        )


def test_oauth_client_auth_method_literal_rejects_unknown():
    payload = _valid_kwargs_for(OAuthClient)
    payload["token_endpoint_auth_method"] = "private_key_jwt"
    with pytest.raises(ValidationError, match="token_endpoint_auth_method"):
        OAuthClient.model_validate(payload)


@pytest.mark.parametrize(
    "model_cls, field",
    [
        (OAuthCode, "expires_at"),
        (InboundToken, "expires_at"),
        (InboundToken, "issued_at"),
    ],
)
def test_expires_at_must_be_positive(model_cls: type[BaseModel], field: str):
    payload = {**_valid_kwargs_for(model_cls), field: 0}
    with pytest.raises(ValidationError, match=field):
        model_cls.model_validate(payload)
    payload[field] = -1
    with pytest.raises(ValidationError, match=field):
        model_cls.model_validate(payload)


# === InboundToken (kind-specific) ===


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


# === TokenResponse defaults ===


def test_token_response_defaults_to_bearer():
    response = TokenResponse(
        access_token="mcp_at_xyz",
        expires_in=3600,
        scope="mcp:read",
    )
    assert response.token_type == "Bearer"
    assert response.refresh_token is None


# === RefreshRotationRequest happy path ===


def test_refresh_rotation_request_valid():
    request = RefreshRotationRequest(
        token_hash="hash_value_here",
        client_id=TEST_CLIENT_ID,
        resource=TEST_RESOURCE_URL,
        scope="mcp:read",
        access_ttl_seconds=3600,
        refresh_ttl_seconds=2592000,
    )
    assert request.client_id == TEST_CLIENT_ID
