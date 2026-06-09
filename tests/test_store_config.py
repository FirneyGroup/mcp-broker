"""Tests for StoreConfig backend validation (fails fast at load time)."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from broker.config import FirestoreStoreConfig, SettingsError, StoreConfig, load_settings


def test_sqlite_backend_is_default_and_valid() -> None:
    config = StoreConfig()
    assert config.backend == "sqlite"
    assert config.firestore is None


def test_firestore_backend_requires_firestore_config() -> None:
    """Selecting the firestore backend without a [store.firestore] section must
    fail at config-load time, not deep in the async lifespan."""
    with pytest.raises(ValidationError, match="firestore"):
        StoreConfig(backend="firestore")


def test_firestore_backend_with_config_is_valid() -> None:
    config = StoreConfig(
        backend="firestore",
        firestore=FirestoreStoreConfig(project_id="my-project"),
    )
    assert config.firestore is not None
    assert config.firestore.project_id == "my-project"


def test_unknown_backend_rejected() -> None:
    with pytest.raises(ValidationError):
        StoreConfig(backend="postgres")


def test_load_settings_validation_error_does_not_leak_secret(tmp_path: Path) -> None:
    """A constraint-violating secret in settings.yaml must surface as a
    SettingsError whose message lists only the offending field path, never the
    secret value. Without the ValidationError wrapper in load_settings, Pydantic's
    str() embeds ``input_value='<secret>'`` in the crash traceback."""
    # admin_key has min_length=16; this short value violates the constraint and
    # would be echoed verbatim by a raw ValidationError.
    leaked_secret = "topsecret-admin"  # noqa: S105 — test fixture, deliberately short to trip min_length
    settings_yaml = {
        "broker": {
            "admin_key": leaked_secret,
            "encryption_keys": ["dGVzdC1rZXktMzItYnl0ZXMtZm9yLWZlcm5ldC1vaw=="],
            "state_secret": "state-secret-at-least-16-chars",
        }
    }
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(yaml.safe_dump(settings_yaml))

    with pytest.raises(SettingsError) as exc_info:
        load_settings(path=str(settings_path))

    message = str(exc_info.value)
    assert leaked_secret not in message
    assert "admin_key" in message
