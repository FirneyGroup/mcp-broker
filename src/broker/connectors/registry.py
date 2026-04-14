"""
ConnectorRegistry — global registry mapping connector names to instances.

Stores instances (not classes) since connectors are stateless singletons.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from broker.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class ConnectorRegistry:
    """Global registry of connector instances."""

    _connectors: dict[str, BaseConnector] = {}

    @classmethod
    def auto_register(cls, connector_cls: type) -> None:
        """Called by BaseConnector.__init_subclass__. Creates instance and registers.

        Raises ValueError for invalid connector names.
        Logs warning (but does not suppress) on overwrite — startup will see it.
        """
        name = connector_cls.meta.name
        if not name or not name.strip():
            raise ValueError(f"Connector name must not be empty: {connector_cls.__name__}")
        if name in cls._connectors:
            logger.warning("[ConnectorRegistry] Overwriting: %s", name)
        instance = connector_cls()
        cls._connectors[name] = instance
        logger.info("[ConnectorRegistry] Registered: %s", name)

    @classmethod
    def get(cls, name: str) -> BaseConnector | None:
        """Get connector instance by name. Returns None if not found."""
        return cls._connectors.get(name)

    @classmethod
    def list_all(cls) -> list[BaseConnector]:
        """List all registered connector instances."""
        return list(cls._connectors.values())

    @classmethod
    def clear(cls) -> None:
        """Clear all registered connectors (for testing)."""
        cls._connectors.clear()

    @classmethod
    def get_stats(cls) -> dict[str, int]:
        """Get registry statistics."""
        return {"total_connectors": len(cls._connectors)}
