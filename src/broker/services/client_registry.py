"""Client registry — resolves compound app_keys to BrokerAppConfig from YAML."""

import logging
from typing import Any

from broker.config import BrokerAppConfig

logger = logging.getLogger(__name__)


class BrokerClientRegistry:
    """Resolves compound app_keys (client_id:app_id) to BrokerAppConfig."""

    def __init__(self, clients: dict[str, dict[str, BrokerAppConfig]]) -> None:
        self._apps: dict[str, BrokerAppConfig] = {}
        for client_name, apps in clients.items():
            if ":" in client_name:
                raise ValueError(f"Client name '{client_name}' must not contain ':'")
            for app_name, config in apps.items():
                if ":" in app_name:
                    raise ValueError(f"App name '{app_name}' must not contain ':'")
                self._apps[f"{client_name}:{app_name}"] = config
        logger.info("[ClientRegistry] Loaded %d app(s)", len(self._apps))

    def get(self, app_key: str) -> BrokerAppConfig | None:
        """Look up app_key → BrokerAppConfig, or None."""
        return self._apps.get(app_key)

    def list_apps(self) -> list[dict[str, Any]]:
        """List all defined apps with compound IDs and scopes."""
        return [
            {
                "app_key": app_key,
                "scopes": config.scopes,
                "allowed_connectors": config.allowed_connectors,
            }
            for app_key, config in self._apps.items()
        ]
