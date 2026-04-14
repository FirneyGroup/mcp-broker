"""
MCP Broker Configuration

Loads settings from YAML with ${VAR} interpolation from environment.
Four sections: broker (service settings), store (token storage),
apps (per-app OAuth credentials), clients (per-app auth + scopes).
"""

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

_ENV_VAR_PATTERN = re.compile(r"^\$\{([^}]+)\}$")
_PARTIAL_ENV_VAR_PATTERN = re.compile(r"\$\{[^}]+\}")


# =============================================================================
# CONFIG MODELS
# =============================================================================


DEFAULT_SCOPES = ["proxy", "status"]


class BrokerAppConfig(BaseModel):
    """Per-app auth configuration from YAML clients section."""

    scopes: list[str] = Field(default_factory=lambda: list(DEFAULT_SCOPES))
    allowed_connectors: list[str] = Field(
        default_factory=list,
        description="Connectors this app can access (empty = all)",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class BrokerConfig(BaseModel):
    """Service-level settings."""

    host: str = "0.0.0.0"  # noqa: S104 — container bind address
    port: int = 8002
    log_level: str = "INFO"
    connectors: list[str] = Field(
        default_factory=list,
        description="Connector modules to load at startup (e.g. ['hubspot', 'notion', 'workspace_mcp'])",
    )
    admin_key: str = Field(..., min_length=16, description="Separate secret for admin endpoints")
    encryption_keys: list[str] = Field(
        ..., min_length=1, description="MultiFernet keys — first is active"
    )
    state_secret: str = Field(
        ..., min_length=16, description="HMAC secret for OAuth state signing (min 16 chars)"
    )
    success_redirect_url: str | None = Field(
        default=None,
        description="Where to redirect users after successful OAuth connection (None = show built-in success page)",
    )
    public_url: str = Field(
        default="http://localhost:8002/",
        description="Publicly accessible base URL for OAuth callbacks (must include trailing slash)",
    )

    @field_validator("public_url")
    @classmethod
    def _normalize_trailing_slash(cls, url: str) -> str:
        return url if url.endswith("/") else url + "/"

    token_refresh_enabled: bool = Field(
        default=True, description="Enable background token refresh loop"
    )
    token_refresh_interval_seconds: int = Field(
        default=300,
        ge=60,
        le=600,
        description="How often to scan for expiring tokens (max 600s to stay within buffer)",
    )
    # extra="ignore" for backwards compat with deployed settings.yaml
    # (e.g. renamed frontend_url → success_redirect_url)
    model_config = ConfigDict(frozen=True, extra="ignore")


class SQLiteStoreConfig(BaseModel):
    db_path: str = "./data/tokens.db"
    key_db_path: str = "./data/broker_keys.db"
    model_config = ConfigDict(frozen=True, extra="forbid")


class StoreConfig(BaseModel):
    backend: str = "sqlite"
    sqlite: SQLiteStoreConfig = SQLiteStoreConfig()
    model_config = ConfigDict(frozen=True, extra="forbid")


class BrokerSettings(BaseModel):
    """Root settings — 4 sections: broker, store, apps, clients."""

    broker: BrokerConfig
    store: StoreConfig = StoreConfig()
    apps: dict[str, dict[str, dict[str, dict[str, str]]]] = Field(
        default_factory=dict,
        description="Per-app OAuth credentials: apps.{client_id}.{app_id}.{connector_name}.{field}",
    )
    clients: dict[str, dict[str, BrokerAppConfig]] = Field(
        default_factory=dict,
        description="Per-app auth config: clients.{client_id}.{app_id}.{scopes, allowed_connectors}",
    )
    model_config = ConfigDict(frozen=True, extra="forbid")

    def get_app_credentials(self, app_key: str, connector_name: str) -> dict[str, str]:
        """Look up OAuth credentials for an app + connector.
        app_key format: 'client_id:app_id' (e.g. 'my_company:app1').
        Returns dict with client_id and client_secret.
        Raises KeyError if not found.
        """
        if ":" not in app_key:
            raise KeyError(f"Invalid app_key format: '{app_key}' (expected 'client_id:app_id')")
        client_id, app_id = app_key.split(":", 1)
        try:
            return self.apps[client_id][app_id][connector_name]
        except KeyError:
            raise KeyError(
                f"No credentials for connector '{connector_name}' in app '{app_key}'"
            ) from None


# =============================================================================
# ENV VAR RESOLUTION
# =============================================================================


def _resolve_env_var_references(config_value: Any) -> Any:
    """Recursively resolve ${VAR_NAME} references from environment."""
    if isinstance(config_value, dict):
        return {k: _resolve_env_var_references(v) for k, v in config_value.items()}
    if isinstance(config_value, list):
        return [_resolve_env_var_references(entry) for entry in config_value]
    if isinstance(config_value, str):
        match = _ENV_VAR_PATTERN.match(config_value)
        if match:
            var_name = match.group(1)
            value = os.environ.get(var_name)
            if value is None:
                raise KeyError(
                    f"Environment variable '{var_name}' not set (required by settings.yaml)"
                )
            return value
        if _PARTIAL_ENV_VAR_PATTERN.search(config_value):
            raise ValueError(
                f"Embedded ${{VAR}} references are not supported: '{config_value}'. "
                f"Use a standalone ${{VAR}} or set the full value directly."
            )
    return config_value


# =============================================================================
# SETTINGS LOADER
# =============================================================================


def load_settings(path: str | None = None) -> BrokerSettings:
    """Load and validate settings from YAML + environment."""
    load_dotenv()
    yaml_path = Path(path or os.environ.get("BROKER_SETTINGS_PATH", "./settings.yaml"))

    if not yaml_path.exists():
        raise FileNotFoundError(
            f"Settings file not found: {yaml_path}. "
            f"Copy settings.example.yaml to settings.yaml and configure."
        )

    with open(yaml_path) as f:
        raw = yaml.safe_load(f) or {}

    resolved = _resolve_env_var_references(raw)
    settings = BrokerSettings(**resolved)

    logger.info(
        "[Config] Loaded settings: broker=%s:%s, store=%s, apps=%s clients",
        settings.broker.host,
        settings.broker.port,
        settings.store.backend,
        len(settings.apps),
    )
    return settings
