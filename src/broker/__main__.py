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

    _abort_if_multiworker_with_oauth(settings.broker.oauth.enabled)

    host = os.environ.get("BROKER_HOST", settings.broker.host)
    port = int(os.environ.get("BROKER_PORT", str(settings.broker.port)))

    uvicorn.run(
        "broker.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=["src"],
    )


def _abort_if_multiworker_with_oauth(oauth_enabled: bool) -> None:
    """Refuse to start under multi-worker uvicorn when inbound OAuth is on.

    Reason: the DCR rate limiter and outbound nonce/PKCE state are in-memory and
    per-process. With ``WEB_CONCURRENCY > 1`` the limiter cap becomes (cap × N)
    and per-flow state can land on a different worker than the one that
    issued the state. Fix is to deploy with a single worker, or to disable
    inbound OAuth.
    """
    if not oauth_enabled:
        return
    workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
    if workers > 1:
        raise SystemExit(
            "broker.oauth.enabled=true is incompatible with WEB_CONCURRENCY="
            f"{workers}. The in-memory DCR rate limiter is per-process; multi-"
            "worker would degrade it. Either set WEB_CONCURRENCY=1 or disable "
            "broker.oauth in settings.yaml."
        )


if __name__ == "__main__":
    main()
