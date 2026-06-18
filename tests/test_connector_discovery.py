"""Connector discovery — entry-point resolution, in-tree fallback, collision guard.

`_load_connectors` resolves each name in `settings.broker.connectors` either from an
externally-installed package registered under the ``mcp_broker.connectors`` entry-point
group, or from the in-tree ``connectors.{name}.adapter`` convention. A name resolvable
both ways is a hard error so an external package cannot silently shadow a reviewed
in-tree connector.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from broker import main as broker_main


@dataclass
class _FakeEntryPoint:
    name: str
    value: str


@pytest.fixture
def record_imports(monkeypatch):
    """Replace import_module with a recorder so no connector is actually imported.

    find_spec uses the builtin __import__ internally, not importlib.import_module, so
    patching import_module here does not interfere with the in-tree collision check.
    """
    imported: list[str] = []
    monkeypatch.setattr(broker_main.importlib, "import_module", imported.append)
    return imported


def _patch_entry_points(monkeypatch, entry_points):
    monkeypatch.setattr(broker_main, "entry_points", lambda group: list(entry_points))


def test_external_entry_point_takes_precedence(monkeypatch, record_imports):
    _patch_entry_points(monkeypatch, [_FakeEntryPoint(name="acme", value="acme_pkg.adapter")])
    broker_main._load_connectors(["acme"])
    assert record_imports == ["acme_pkg.adapter"]


def test_in_tree_fallback_when_no_entry_point(monkeypatch, record_imports):
    _patch_entry_points(monkeypatch, [])
    broker_main._load_connectors(["notion"])
    assert record_imports == ["connectors.notion.adapter"]


def test_collision_between_in_tree_and_entry_point_is_hard_error(monkeypatch, record_imports):
    # 'notion' exists in-tree; an entry point also claiming it must abort, not shadow it.
    _patch_entry_points(monkeypatch, [_FakeEntryPoint(name="notion", value="evil_pkg.adapter")])
    with pytest.raises(ValueError, match="both in-tree"):
        broker_main._load_connectors(["notion"])
    assert record_imports == []  # guard fires before any import


def test_invalid_connector_name_rejected(monkeypatch, record_imports):
    _patch_entry_points(monkeypatch, [])
    with pytest.raises(ValueError, match="Invalid connector name"):
        broker_main._load_connectors(["bad-name"])
    assert record_imports == []
