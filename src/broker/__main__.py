"""
Broker process entrypoint.

Validates settings synchronously before starting uvicorn. Running validation
outside the async lifespan means SettingsError terminates the process via
Python's normal SystemExit pathway — no starlette wrapping, no traceback
gymnastics, and no need for os._exit inside async code.

Invoked by ``./start start`` as ``python -m broker``.
"""

from __future__ import annotations

import logging
import os

import uvicorn

from broker.config import SettingsError, load_settings

logger = logging.getLogger("broker.startup")


def main() -> None:
    """Validate settings, then launch uvicorn."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    try:
        settings = load_settings()
    except SettingsError as error:
        logger.critical("%s", error)
        raise SystemExit(1) from None

    host = os.environ.get("BROKER_HOST", settings.broker.host)
    port = int(os.environ.get("BROKER_PORT", str(settings.broker.port)))

    uvicorn.run(
        "broker.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=["src"],
    )


if __name__ == "__main__":
    main()
