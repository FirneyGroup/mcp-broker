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


def _int_env(name: str, default: int) -> int:
    """Read an integer env var, exiting cleanly on a non-numeric value.

    A bare ``int(os.environ[...])`` raises ValueError with a stack trace, which
    contradicts this module's job of turning startup misconfiguration into a
    clean SystemExit instead of an alarming traceback.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


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

    _abort_if_multiworker_with_oauth(settings.broker.oauth.enabled, settings.store.backend)

    host = os.environ.get("BROKER_HOST", settings.broker.host)
    port = _int_env("BROKER_PORT", settings.broker.port)

    uvicorn.run(
        "broker.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=["src"],
    )


def _abort_if_multiworker_with_oauth(oauth_enabled: bool, store_backend: str = "sqlite") -> None:
    """Refuse to start under multi-worker uvicorn when inbound OAuth is on AND
    the store backend keeps OAuth state process-local.

    Reason: on the default (sqlite / in-memory) backend the DCR rate limiter and
    outbound nonce/PKCE state are per-process. With ``WEB_CONCURRENCY > 1`` the
    limiter cap becomes (cap × N) and per-flow state can land on a different
    worker than the one that issued it. With ``store.backend == "firestore"``
    that state is shared across instances, so multi-worker is legal. Fix is to
    deploy with a single worker, switch the store backend to firestore, or
    disable inbound OAuth.
    """
    if not oauth_enabled or store_backend == "firestore":
        return
    workers = _int_env("WEB_CONCURRENCY", 1)
    if workers > 1:
        raise SystemExit(
            "broker.oauth.enabled=true is incompatible with WEB_CONCURRENCY="
            f"{workers} on the '{store_backend}' store backend. The DCR rate "
            "limiter and outbound OAuth state are per-process. Set "
            "WEB_CONCURRENCY=1, switch store.backend to 'firestore' for "
            "multi-worker, or disable broker.oauth in settings.yaml."
        )


if __name__ == "__main__":
    main()
