"""Every file under a packaged source root is inventoried or declared repository-only.

A canonical vector that is committed but absent from the reviewed inventory silently misses the
wheel while ``--check`` stays green (``publish-action-notices-1.1.0.case.json`` did). The script's
source-coverage gate closes that gap for the routine ripple check, not only the packaging suite.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def script() -> ModuleType:
    path = _REPO_ROOT / "scripts" / "verify_resource_manifest.py"
    spec = importlib.util.spec_from_file_location("_verify_resource_manifest_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_checkout_has_no_uninventoried_source(script: ModuleType) -> None:
    inventory = script.load_inventory_config()
    assert script.uninventoried_sources(inventory, repo_root=_REPO_ROOT) == ()


def test_every_committed_canonical_vector_is_inventoried(script: ModuleType) -> None:
    inventory = script.load_inventory_config()
    names = {entry.source_path for entry in inventory.entries}
    on_disk = {
        f"fixtures/canonical/{path.name}"
        for path in (_REPO_ROOT / "fixtures" / "canonical").iterdir()
        if path.is_file()
    }
    assert "fixtures/canonical/publish-action-notices-1.1.0.case.json" in names
    assert on_disk <= names


def test_an_uninventoried_source_fails_closed_while_declared_corpora_pass(
    script: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "fixtures" / "canonical").mkdir(parents=True)
    (tmp_path / "fixtures" / "replay").mkdir(parents=True)
    (tmp_path / "guidance").mkdir()
    (tmp_path / "fixtures" / "canonical" / "new-vector.case.json").write_bytes(b"{}\n")
    (tmp_path / "fixtures" / "replay" / "corpus.case.json").write_bytes(b"{}\n")
    (tmp_path / "fixtures" / "manifest.json").write_bytes(b"{}\n")
    (tmp_path / "guidance" / ".DS_Store").write_bytes(b"")
    (tmp_path / "guidance" / "new-page.md").write_bytes(b"# new\n")
    inventory = script.ResourceInventory(package="yoetz", resource_set_version="0", entries=())

    assert script.uninventoried_sources(inventory, repo_root=tmp_path) == (
        "fixtures/canonical/new-vector.case.json",
        "guidance/new-page.md",
    )
    with pytest.raises(script.ResourceManifestError) as refused:
        script.verify_source_coverage(inventory, repo_root=tmp_path)
    assert refused.value.reason == "source_unpackaged"
    assert "fixtures/canonical/new-vector.case.json" in refused.value.detail
