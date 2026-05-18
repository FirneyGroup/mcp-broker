"""Pydantic models for inbound OAuth 2.1 AS (claude.ai integration)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# === CONSTANTS ===

REDIRECT_URI_MAX_LEN = 2048
SCOPE_MAX_LEN = 2048
CLIENT_NAME_MAX_LEN = 255
REDIRECT_URIS_LIST_MAX_LEN = 10


# === Registration ===


class RegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration request. extra='ignore' per RFC 7591 §2 —
    registration metadata may contain unknown fields that we accept-and-discard."""

    client_name: str = Field(..., min_length=1, max_length=CLIENT_NAME_MAX_LEN)
    redirect_uris: list[str] = Field(..., min_length=1, max_length=REDIRECT_URIS_LIST_MAX_LEN)
    token_endpoint_auth_method: Literal["none", "client_secret_basic", "client_secret_post"] = (
        "none"  # noqa: S105 -- RFC 7591 auth method enum value, not a credential
    )
    grant_types: list[Literal["authorization_code", "refresh_token"]] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"],
        min_length=1,
        description=(
            "Grant types the client wants to use. Each value is checked at /token "
            "before dispatch — registering ['authorization_code'] only means the "
            "client can NOT later refresh, and no refresh_token will be issued. "
            "Empty list rejected at registration time."
        ),
    )
    response_types: list[Literal["code"]] = Field(default_factory=lambda: ["code"])
    scope: str | None = Field(default=None, max_length=SCOPE_MAX_LEN)

    @field_validator("redirect_uris")
    @classmethod
    def _validate_redirect_uri_lengths(cls, uris: list[str]) -> list[str]:
        # Per-element max length; the list-level max_length is on the Field.
        for uri in uris:
            if len(uri) > REDIRECT_URI_MAX_LEN:
                raise ValueError(f"redirect_uri exceeds {REDIRECT_URI_MAX_LEN} chars")
        return uris

    model_config = ConfigDict(extra="ignore")


class RegistrationResponse(BaseModel):
    client_id: str
    client_id_issued_at: int
    client_secret: str | None = None
    client_secret_expires_at: int = 0
    token_endpoint_auth_method: Literal["none", "client_secret_basic", "client_secret_post"]  # noqa: S105 -- RFC 7591 auth method enum value, not a credential
    grant_types: list[Literal["authorization_code", "refresh_token"]]
    response_types: list[Literal["code"]]
    redirect_uris: list[str]
    client_name: str
    scope: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


# === Persistent Records ===


class OAuthClient(BaseModel):
    client_id: str
    token_endpoint_auth_method: Literal[  # noqa: S105 -- RFC 7591 auth method enum value, not a credential
        "none", "client_secret_basic", "client_secret_post"
    ]
    redirect_uris: list[str]
    grant_types: list[Literal["authorization_code", "refresh_token"]]
    response_types: list[Literal["code"]]
    scope: str | None
    client_name: str
    created_at: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class OAuthCode(BaseModel):
    client_id: str
    app_key: str
    redirect_uri: str
    resource: str
    scope: str = Field(..., max_length=SCOPE_MAX_LEN)
    code_challenge: str
    expires_at: int = Field(..., gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class InboundToken(BaseModel):
    token_hash: str
    token_kind: Literal["access", "refresh"]
    parent_refresh_hash: str | None = None
    family_id: str
    client_id: str
    app_key: str
    resource: str
    scope: str = Field(..., max_length=SCOPE_MAX_LEN)
    expires_at: int = Field(..., gt=0)
    issued_at: int = Field(..., gt=0)
    used_at: int | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


# === Token Issuance & Rotation ===


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 -- OAuth 2.0 §5.1 token_type field name, not a credential
    expires_in: int
    refresh_token: str | None = None
    scope: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class RefreshRotationRequest(BaseModel):
    """Bundles refresh rotation params to satisfy ruff PLR0913 (max 4 args).

    TTLs are supplied per call (sourced from `OAuthInboundConfig`) so the store
    never hardcodes lifetimes — operator config remains authoritative across
    every rotation, not just the initial token issue.
    """

    token_hash: str
    client_id: str
    resource: str
    scope: str = Field(..., max_length=SCOPE_MAX_LEN)
    access_ttl_seconds: int = Field(..., gt=0)
    refresh_ttl_seconds: int = Field(..., gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class RotatedTokenPair(BaseModel):
    access: InboundToken
    refresh: InboundToken
    raw_access_token: str
    raw_refresh_token: str

    model_config = ConfigDict(extra="forbid", frozen=True)
