"""Emulator-backed tests for FirestoreDCRRateLimiter.

Exercises the real Firestore client against the emulator (no mocks), per
AGENTS.md testing rules. Skipped when no emulator is reachable.

The Firestore backend shares the per-IP DCR cap across instances — the property
that makes multi-worker inbound OAuth legal. These tests prove the cap holds
across two limiter instances sharing a prefix, and that window expiry restores
allowance (timestamps are manipulated rather than sleeping).

Start an emulator with:
    gcloud emulators firestore start --host-port=127.0.0.1:8765
"""

import os
import time
from unittest.mock import patch

import pytest
from firestore_backend import (
    FIRESTORE_AVAILABLE,
    FIRESTORE_PROJECT,
    FIRESTORE_SKIP_REASON,
    cleanup_live_collections,
    configure_firestore_client_env,
    reset_firestore_client,
)

from broker.services.firestore_dcr_rate_limiter import FirestoreDCRRateLimiter

pytestmark = pytest.mark.skipif(not FIRESTORE_AVAILABLE, reason=FIRESTORE_SKIP_REASON)


@pytest.fixture
async def prefix():
    """Isolated collection prefix; resets the client singleton + cleans up live data."""
    configure_firestore_client_env()
    collection_prefix = f"test_{os.urandom(4).hex()}_"
    yield collection_prefix
    await cleanup_live_collections(collection_prefix)
    await reset_firestore_client()


async def _limiter(prefix: str, *, cap: int, window: int) -> FirestoreDCRRateLimiter:
    """Build + set up a limiter sharing the given prefix (one instance per call)."""
    limiter = FirestoreDCRRateLimiter(
        max_per_window=cap,
        window_seconds=window,
        project_id=FIRESTORE_PROJECT,
        collection_prefix=prefix,
    )
    await limiter.setup()
    return limiter


async def test_cap_enforced_across_instances(prefix: str) -> None:
    """Two limiter instances sharing the prefix enforce ONE cap, not cap-per-instance."""
    instance_a = await _limiter(prefix, cap=3, window=60)
    instance_b = await _limiter(prefix, cap=3, window=60)

    # Three allowed across the two instances combined; the fourth is rejected.
    assert await instance_a.allow("1.2.3.4") is True
    assert await instance_b.allow("1.2.3.4") is True
    assert await instance_a.allow("1.2.3.4") is True
    assert await instance_b.allow("1.2.3.4") is False


async def test_separate_ips_independent(prefix: str) -> None:
    limiter = await _limiter(prefix, cap=1, window=60)
    assert await limiter.allow("1.1.1.1") is True
    assert await limiter.allow("2.2.2.2") is True
    assert await limiter.allow("1.1.1.1") is False


async def test_window_expiry_restores_allowance(prefix: str) -> None:
    """Once the IP's events age out of the window, the IP is allowed again."""
    limiter = await _limiter(prefix, cap=1, window=10)
    assert await limiter.allow("1.2.3.4") is True
    assert await limiter.allow("1.2.3.4") is False

    # Advance allow()'s clock past the window — the prior event ages out.
    future = time.time() + 20
    with patch("broker.services.firestore_dcr_rate_limiter.time.time", return_value=future):
        assert await limiter.allow("1.2.3.4") is True


async def test_cleanup_reaps_stale_ip(prefix: str) -> None:
    """cleanup_expired drops an IP whose events have all aged out of the window."""
    limiter = await _limiter(prefix, cap=5, window=10)
    await limiter.allow("one-shot-ip")

    future = time.time() + 20
    with patch("broker.services.firestore_dcr_rate_limiter.time.time", return_value=future):
        await limiter.cleanup_expired()
        # The stale doc is gone; a fresh allow starts the window from scratch.
        assert await limiter.allow("one-shot-ip") is True
