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


class SettingsError(Exception):
    """Settings cannot be loaded — missing env vars or malformed settings.yaml.

    Startup catches this and emits a clean banner instead of a Python traceback.
    """


def _resolve_env_var_references(config_value: Any) -> Any:
    """Resolve ${VAR_NAME} references. Collects ALL misses and reports them together."""
    missing: list[tuple[str, tuple[str, ...]]] = []
    resolved = _resolve_recursive(config_value, path=(), missing=missing)
    if missing:
        raise SettingsError(_format_missing_vars(missing))
    return resolved


def _resolve_recursive(
    config_value: Any,
    *,
    path: tuple[str, ...],
    missing: list[tuple[str, tuple[str, ...]]],
) -> Any:
    """Walk the settings tree, substitute ${VAR} values, append misses to `missing`."""
    if isinstance(config_value, dict):
        return {
            key: _resolve_recursive(value, path=(*path, key), missing=missing)
            for key, value in config_value.items()
        }
    if isinstance(config_value, list):
        return [
            _resolve_recursive(entry, path=(*path, f"[{i}]"), missing=missing)
            for i, entry in enumerate(config_value)
        ]
    if isinstance(config_value, str):
        return _resolve_string_value(config_value, path=path, missing=missing)
    return config_value


def _resolve_string_value(
    config_value: str,
    *,
    path: tuple[str, ...],
    missing: list[tuple[str, tuple[str, ...]]],
) -> str:
    """Substitute a single ${VAR} string, or raise on embedded references."""
    match = _ENV_VAR_PATTERN.match(config_value)
    if match:
        var_name = match.group(1)
        value = os.environ.get(var_name)
        if value is None:
            missing.append((var_name, path))
            return ""  # placeholder; caller raises SettingsError before this is used
        return value
    if _PARTIAL_ENV_VAR_PATTERN.search(config_value):
        raise SettingsError(
            f"Embedded ${{VAR}} references are not supported: '{config_value}'. "
            f"Use a standalone ${{VAR}} or set the full value directly."
        )
    return config_value


def _format_missing_vars(missing: list[tuple[str, tuple[str, ...]]]) -> str:
    """Human-readable error listing every missing env var + its settings.yaml path."""
    # Group by env var name — one var may be referenced in multiple places.
    by_var: dict[str, list[tuple[str, ...]]] = {}
    for var_name, path in missing:
        by_var.setdefault(var_name, []).append(path)
    body = [
        line
        for var_name in sorted(by_var)
        for line in _format_var_block(var_name, by_var[var_name])
    ]
    return "\n".join(
        [
            "",
            "Broker cannot start — required environment variables not set:",
            "",
            *body,
            "",
            "Fix: add the variable(s) to .env, or remove the referencing block",
            "     from settings.yaml if the integration isn't needed.",
            "",
        ]
    )


def _format_var_block(var_name: str, paths: list[tuple[str, ...]]) -> list[str]:
    """Render one missing-var entry: the var name followed by each yaml path it occurs at."""
    lines = [f"  {var_name}"]
    for path in paths:
        yaml_path = ".".join(path) if path else "(root)"
        lines.append(f"      settings.yaml: {yaml_path}")
    return lines


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
