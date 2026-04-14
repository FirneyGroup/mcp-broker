"""
Connection model — represents a stored OAuth token for an app + connector pair.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class AppConnection(BaseModel):
    """Per-app OAuth token (stored in DB)."""

    connector_name: str
    access_token: str
    refresh_token: str | None = None
    expires_at: int | None = Field(
        default=None, description="Unix timestamp when access_token expires"
    )
    scopes: list[str] = Field(default_factory=list)
    connected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    connected_by: str | None = None

    model_config = ConfigDict(frozen=True)
