"""Pydantic models for inbound OAuth 2.1 AS (claude.ai integration)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration request. extra='ignore' per RFC 7591 §2 —
    registration metadata may contain unknown fields that we accept-and-discard."""

    client_name: str
    redirect_uris: list[str] = Field(..., min_length=1)
    token_endpoint_auth_method: Literal["none", "client_secret_basic", "client_secret_post"] = (
        "none"  # noqa: S105 -- RFC 7591 auth method enum value, not a credential
    )
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    scope: str | None = None

    model_config = ConfigDict(extra="ignore")


class RegistrationResponse(BaseModel):
    client_id: str
    client_id_issued_at: int
    client_secret: str | None = None
    client_secret_expires_at: int = 0
    token_endpoint_auth_method: str
    grant_types: list[str]
    response_types: list[str]
    redirect_uris: list[str]
    client_name: str
    scope: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class OAuthClient(BaseModel):
    client_id: str
    token_endpoint_auth_method: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    scope: str | None
    client_name: str
    created_at: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class OAuthCode(BaseModel):
    client_id: str
    app_key: str
    redirect_uri: str
    resource: str
    scope: str
    code_challenge: str
    expires_at: int

    model_config = ConfigDict(extra="forbid", frozen=True)


class InboundToken(BaseModel):
    token_hash: str
    token_kind: Literal["access", "refresh"]
    parent_refresh_hash: str | None = None
    family_id: str
    client_id: str
    app_key: str
    resource: str
    scope: str
    expires_at: int
    issued_at: int
    used_at: int | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 -- OAuth 2.0 §5.1 token_type field name, not a credential
    expires_in: int
    refresh_token: str | None = None
    scope: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class RefreshRotationRequest(BaseModel):
    """Bundles refresh rotation params to satisfy ruff PLR0913 (max 4 args)."""

    token_hash: str
    client_id: str
    resource: str
    scope: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class RotatedTokenPair(BaseModel):
    access: InboundToken
    refresh: InboundToken
    raw_access_token: str
    raw_refresh_token: str

    model_config = ConfigDict(extra="forbid", frozen=True)
