"""The packaged-resource owning command converges, checks, and fails before partial writes."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Final, cast

import pytest

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RIPPLE_SCRIPT = _REPO_ROOT / "scripts" / "sync_resource_ripple.py"

# Every tree the inventory reads from or writes into, so a copied checkout can run the real ripple.
_CHECKOUT_TREES: Final = (
    ".agents/plugins/finishup",
    ".agents/skills/finishup",
    "fixtures/agent-plugins",
    "fixtures/canonical",
    "fixtures/privacy",
    "fixtures/replay",
    "fixtures/receipts",
    "guidance",
    "migrations",
    "schemas",
    "scripts",
    "skills",
    "src/finishup",
    "support",
)


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _copy_checkout(destination: Path) -> None:
    """Copy the working-tree source and generated trees the ripple reads and writes."""

    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_REPO_ROOT / "pyproject.toml", destination / "pyproject.toml")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for relative in _CHECKOUT_TREES:
        shutil.copytree(_REPO_ROOT / relative, destination / relative, ignore=ignore)
    shutil.copy2(_REPO_ROOT / "fixtures/manifest.json", destination / "fixtures/manifest.json")


def _synthetic_checkout(root: Path, *, inventory_count: int, reviewed_count: int) -> None:
    _write(root, "src/finishup/__init__.py", "")
    _write(root, "src/finishup/protocol/__init__.py", "")
    _write(
        root, "src/finishup/protocol/schemas.py", "def load_schema_catalog():\n    return None\n"
    )
    _write(
        root,
        "src/finishup/version.py",
        f"REVIEWED_RESOURCE_COUNT = {reviewed_count}\n"
        "\n"
        "def build_version_manifest():\n"
        "    return {}\n"
        "\n"
        "def version_manifest_json(manifest, *, include_resources=False):\n"
        "    return b'{}'\n",
    )
    _write(root, "schemas/version/version-manifest-2.3.0.schema.json", '{"type":"object"}')
    _write(
        root,
        "scripts/verify_resource_manifest.py",
        "class _Inventory:\n"
        f"    entries = tuple(range({inventory_count}))\n"
        "\n"
        "def load_inventory_config():\n"
        "    return _Inventory()\n",
    )
    _write(
        root,
        "scripts/generate_schemas.py",
        "from pathlib import Path\n"
        "import sys\n"
        "root = Path(__file__).resolve().parent.parent\n"
        "state = root / 'schemas/state.txt'\n"
        "if '--write' in sys.argv:\n"
        "    state.write_text('stable\\n', encoding='utf-8')\n"
        "elif state.read_text(encoding='utf-8') != 'stable\\n':\n"
        "    raise SystemExit(1)\n",
    )
    _write(root, "scripts/sync_service_status_schema.py", "")
    _write(root, "scripts/sync_semantic_capacity_schemas.py", "")
    _write(root, "scripts/sync_repository_authority_schemas.py", "")
    _write(root, "scripts/sync_committed_agent_trees.py", "")
    _write(root, "scripts/sync_mcp_descriptor_digests.py", "")
    _write(root, "scripts/generate_advice_egress_fixture.py", "")
    _write(root, "scripts/generate_project_policy_fixture.py", "")
    _write(root, "scripts/generate_check_conclusion_fixture.py", "")
    _write(root, "scripts/generate_check_totals_fixture.py", "")
    _write(root, "scripts/generate_check_observations_awaited_fixture.py", "")
    _write(root, "scripts/generate_review_dialogue_fixture.py", "")
    _write(root, "scripts/generate_task_statement_fixture.py", "")
    _write(root, "scripts/generate_publish_action_notices_fixture.py", "")
    _write(root, "scripts/generate_check_inspection_fixture.py", "")
    _write(root, "schemas/state.txt", "stale\n")
    _write(root, "src/finishup/resources/manifest.json", "{}\n")
    _write(root, "skills/codex/finishup/manifest.json", "{}\n")
    _write(root, "support/runtime-support.json", "{}\n")


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_RIPPLE_SCRIPT), *arguments],
        cwd=_REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=600,
    )


def _run_resource_manifest(*arguments: str, repo_root: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    source_root = str(repo_root / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing else os.pathsep.join((source_root, existing))
    )
    return subprocess.run(
        [
            sys.executable,
            str(_REPO_ROOT / "scripts/verify_resource_manifest.py"),
            *arguments,
            "--repo-root",
            str(repo_root),
        ],
        cwd=repo_root,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )


def _load_resource_manifest_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_finishup_test_verify_resource_manifest",
        _REPO_ROOT / "scripts/verify_resource_manifest.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load verify_resource_manifest.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_checkout_passes_the_single_ci_entrypoint() -> None:
    completed = _run("--check")

    assert completed.returncode == 0, completed.stderr
    assert "generated artifacts are at a fixed point" in completed.stdout


@pytest.mark.slow
def test_shared_invalid_schema_member_identity_cannot_pass_the_ripple(tmp_path: Path) -> None:
    """Source/mirror parity cannot conceal an invalid hand-maintained schema inventory."""

    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    manifest_path = checkout / "schemas/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    member = next(
        item for item in manifest["members"] if item["path"] == "consent/status-6.0.0.schema.json"
    )
    # The owning ripple refreshes digest/size bindings from source bytes. Media type remains
    # part of the hand-maintained identity and cannot be repaired by refreshing those bindings.
    member["media_type"] = "text/plain"
    manifest_path.write_bytes(canonical_encode(manifest))

    # The command owns all mirror and runtime digest changes, so the final failure can only be
    # seen by loading the schema catalog, not by comparing a stale package mirror with a source.
    completed = _run("--write", "--repo-root", str(checkout))
    assert completed.returncode != 0
    assert "schema_manifest_member_mismatch" in completed.stderr


def test_write_repeats_until_the_owned_bytes_are_stable(tmp_path: Path) -> None:
    _synthetic_checkout(tmp_path, inventory_count=1, reviewed_count=1)

    completed = _run("--write", "--repo-root", str(tmp_path))

    assert completed.returncode == 0, completed.stderr
    assert "fixed point after 2 pass(es)" in completed.stdout
    assert (tmp_path / "schemas/state.txt").read_text(encoding="utf-8") == "stable\n"


def test_sync_retires_prior_inventory_file_before_manifest_publish_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted retirement leaves an old manifest that a retry can converge."""

    resource_manifest = _load_resource_manifest_module()

    resource_root = tmp_path / "src/finishup/resources"
    stale_relative = "fixtures/replay/retired.case.json"
    stale_path = resource_root / stale_relative
    stale_path.parent.mkdir(parents=True)
    stale_path.write_bytes(b"retired")
    manifest_path = resource_root / "manifest.json"
    old_manifest = canonical_encode({"entries": [{"package_path": stale_relative}]}) + b"\n"
    manifest_path.write_bytes(old_manifest)

    current_relative = "fixtures/canonical/current.case.json"
    current_data = b"{}"
    current = resource_manifest.CollectedResource(
        resource_manifest.ResourceInventoryEntry(
            logical_name=current_relative,
            source_path=current_relative,
            package_path=current_relative,
            kind="canonical_vector",
            media_type="application/json",
            size_cap=100,
            text=True,
        ),
        len(current_data),
        f"sha256:{hashlib.sha256(current_data).hexdigest()}",
        current_data,
    )
    new_manifest = canonical_encode({"entries": []}) + b"\n"
    real_replace = resource_manifest.os.replace
    interrupted = False

    def interrupt_manifest_publish(source: Path, destination: Path) -> None:
        nonlocal interrupted
        if Path(destination) == manifest_path and not interrupted:
            interrupted = True
            raise OSError("simulated_manifest_publish_interruption")
        real_replace(source, destination)

    monkeypatch.setattr(resource_manifest.os, "replace", interrupt_manifest_publish)
    with pytest.raises(OSError, match="simulated_manifest_publish_interruption"):
        resource_manifest.sync_resource_tree((current,), new_manifest, repo_root=tmp_path)

    assert not stale_path.exists()
    assert manifest_path.read_bytes() == old_manifest

    monkeypatch.setattr(resource_manifest.os, "replace", real_replace)
    resource_manifest.sync_resource_tree((current,), new_manifest, repo_root=tmp_path)
    assert not stale_path.exists()
    assert (resource_root / current_relative).read_bytes() == current_data
    assert manifest_path.read_bytes() == new_manifest


def test_real_sync_retires_stale_package_resource_and_keeps_source_fixture(
    tmp_path: Path,
) -> None:
    """Inventory retirement removes only the generated mirror and keeps the source corpus."""

    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    relative = "fixtures/replay/lineage-event-families.case.json"
    source = checkout / relative
    package = checkout / "src/finishup/resources" / relative
    package.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, package)

    manifest_path = checkout / "src/finishup/resources/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["entries"].append(
        {
            "kind": "canonical_vector",
            "logical_name": relative,
            "media_type": "application/vnd.yoetz.fixture-case+json",
            "package_path": relative,
            "sha256": f"sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}",
            "size": source.stat().st_size,
            "source_path": relative,
        }
    )
    manifest_path.write_bytes(canonical_encode(manifest) + b"\n")

    completed = _run_resource_manifest("--sync", repo_root=checkout)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert source.is_file()
    assert not package.exists()


@pytest.mark.parametrize(
    "layout", ("package_root", "package_parent", "package_extra", "source_parent")
)
def test_resource_scans_reject_symlinked_roots_ancestors_and_extras(
    tmp_path: Path, layout: str
) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    resources = checkout / "src/finishup/resources"

    if layout == "package_root":
        target = checkout / "package-resource-target"
        shutil.move(str(resources), str(target))
        resources.symlink_to(target, target_is_directory=True)
    elif layout == "package_parent":
        parent = resources / "fixtures"
        target = checkout / "package-fixtures-target"
        shutil.move(str(parent), str(target))
        parent.symlink_to(target, target_is_directory=True)
    elif layout == "package_extra":
        target = checkout / "unowned-resource.json"
        target.write_text("{}\n", encoding="utf-8")
        (resources / "unowned-resource.json").symlink_to(target)
    else:
        parent = checkout / "fixtures/canonical"
        target = checkout / "source-canonical-target"
        shutil.move(str(parent), str(target))
        parent.symlink_to(target, target_is_directory=True)

    for mode in ("--check", "--sync"):
        completed = _run_resource_manifest(mode, repo_root=checkout)
        assert completed.returncode == 1
        assert "symlink_forbidden" in completed.stderr


@pytest.mark.slow
def test_write_converges_a_reviewed_source_byte_change_in_a_real_checkout(tmp_path: Path) -> None:
    """A guidance byte change ripples through every dependent digest in one command."""

    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    guidance = checkout / "guidance/workflow.md"
    guidance.write_bytes(guidance.read_bytes() + b"\n<!-- ripple probe -->\n")
    marker = checkout / ".agents/skills/finishup/.yoetz-install.json"
    previous_marker = marker.read_bytes()

    written = _run("--write", "--repo-root", str(checkout))
    assert written.returncode == 0, written.stderr + written.stdout

    assert (checkout / "src/finishup/resources/guidance/workflow.md").read_bytes() == (
        guidance.read_bytes()
    )
    support = json.loads((checkout / "support/runtime-support.json").read_bytes())
    package_manifest = json.loads((checkout / "src/finishup/resources/manifest.json").read_bytes())
    assert support["resource_set_digest"] == package_manifest["resource_set_digest"]
    for relative in (
        ".agents/plugins/finishup/skills/finishup/references/workflow.md",
        ".agents/skills/finishup/references/workflow.md",
    ):
        assert (checkout / relative).read_bytes() == guidance.read_bytes()
    assert marker.read_bytes() != previous_marker

    checked = _run("--check", "--repo-root", str(checkout))
    assert checked.returncode == 0, checked.stderr + checked.stdout

    before_second_write = {
        path.relative_to(checkout).as_posix(): path.read_bytes()
        for root in (".agents", "src/finishup/resources", "schemas", "skills", "support")
        for path in (checkout / root).rglob("*")
        if path.is_file()
    }
    repeated = _run("--write", "--repo-root", str(checkout))
    assert repeated.returncode == 0, repeated.stderr + repeated.stdout
    assert before_second_write == {
        path.relative_to(checkout).as_posix(): path.read_bytes()
        for root in (".agents", "src/finishup/resources", "schemas", "skills", "support")
        for path in (checkout / root).rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "relative",
    [
        ".agents/plugins/finishup/skills/finishup/SKILL.md",
        ".agents/skills/finishup/.yoetz-install.json",
    ],
)
def test_agent_only_drift_is_checked_and_repaired_by_the_owning_command(
    tmp_path: Path, relative: str
) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    target = checkout / relative
    original = target.read_bytes()
    target.write_bytes(b"stale generated bytes\n")

    checked = _run("--check", "--repo-root", str(checkout))
    assert checked.returncode == 1
    assert "agent_tree_drift" in checked.stderr
    assert "canonical owners: guidance/, skills/codex/finishup/" in checked.stderr
    assert "uv run python scripts/sync_resource_ripple.py --write" in checked.stderr
    assert target.read_bytes() == b"stale generated bytes\n"

    written = _run("--write", "--repo-root", str(checkout))
    assert written.returncode == 0, written.stderr + written.stdout
    assert target.read_bytes() == original


def test_linked_agent_parent_fails_before_resource_writes(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    outside = tmp_path / "foreign-install"
    shutil.move(checkout / ".agents/skills", outside)
    (checkout / ".agents/skills").symlink_to(outside, target_is_directory=True)
    marker = (outside / "finishup/.yoetz-install.json").read_bytes()
    packaged = checkout / "src/finishup/resources/guidance/workflow.md"
    original = packaged.read_bytes()
    (checkout / "guidance/workflow.md").write_bytes(original + b"\n<!-- change -->\n")

    written = _run("--write", "--repo-root", str(checkout))
    assert written.returncode == 1
    assert "unsafe_agent_tree" in written.stderr
    assert packaged.read_bytes() == original
    assert (outside / "finishup/.yoetz-install.json").read_bytes() == marker


@pytest.mark.parametrize("tree", [".agents/skills/finishup", ".agents/plugins/finishup"])
def test_foreign_agent_file_fails_before_resource_writes(tmp_path: Path, tree: str) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    foreign = checkout / tree / "foreign.txt"
    foreign.write_bytes(b"keep this file\n")
    guidance = checkout / "guidance/workflow.md"
    guidance.write_bytes(guidance.read_bytes() + b"\n<!-- pending source change -->\n")
    before = {
        path.relative_to(checkout): path.read_bytes()
        for root in (".agents", "src/finishup/resources", "schemas", "skills", "support")
        for path in (checkout / root).rglob("*")
        if path.is_file()
    }
    written = _run("--write", "--repo-root", str(checkout))
    assert written.returncode == 1
    assert "foreign_agent_files" in written.stderr
    assert foreign.read_bytes() == b"keep this file\n"
    assert before == {
        path.relative_to(checkout): path.read_bytes()
        for root in (".agents", "src/finishup/resources", "schemas", "skills", "support")
        for path in (checkout / root).rglob("*")
        if path.is_file()
    }


def test_obsolete_generated_member_requires_its_old_marker_binding(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    root = checkout / ".agents/skills/finishup"
    relative = "references/obsolete.md"
    data = b"obsolete generated reference\n"
    (root / relative).write_bytes(data)
    marker_path = root / ".yoetz-install.json"
    marker = json.loads(marker_path.read_bytes())
    marker.pop("marker_digest")
    marker["managed_files"].append(
        {
            "relative_path": relative,
            "size": len(data),
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
    )
    marker["marker_digest"] = canonical_digest(cast(JsonValue, marker))
    marker_path.write_bytes(canonical_encode(cast(JsonValue, marker)) + b"\n")

    written = _run("--write", "--repo-root", str(checkout))
    assert written.returncode == 0, written.stderr + written.stdout
    assert not (root / relative).exists()


@pytest.mark.slow
def test_write_regenerates_current_builder_owned_schema_without_changing_frozen_history(
    tmp_path: Path,
) -> None:
    """One owning command repairs a stale current schema and all of its dependent bytes."""

    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    frozen_path = checkout / "schemas/operations/status-result-1.3.0.schema.json"
    frozen = frozen_path.read_bytes()
    current_path = checkout / "schemas/operations/status-result-1.4.0.schema.json"
    expected = current_path.read_bytes()
    current = json.loads(expected)
    current["$defs"]["history_item"]["properties"]["summary_code"]["enum"].remove("child_accepted")
    current_path.write_bytes(canonical_encode(current))

    written = _run("--write", "--repo-root", str(checkout))

    assert written.returncode == 0, written.stderr + written.stdout
    assert current_path.read_bytes() == expected
    assert frozen_path.read_bytes() == frozen
    assert (
        checkout / "src/finishup/resources/schemas/operations/status-result-1.4.0.schema.json"
    ).read_bytes() == expected
    checked = _run("--check", "--repo-root", str(checkout))
    assert checked.returncode == 0, checked.stderr + checked.stdout


@pytest.mark.slow
def test_check_rejects_a_self_consistent_but_stale_cardinality_constant(tmp_path: Path) -> None:
    """Byte-parity alone cannot see a wrong generated cardinality; the owning check must."""

    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    schema_path = checkout / "schemas/version/version-manifest-2.3.0.schema.json"
    document = cast(dict[str, Any], json.loads(schema_path.read_bytes()))
    counts = document["$defs"]["resource_counts"]["properties"]
    counts["migrations"]["const"] = str(int(counts["migrations"]["const"]) - 1)
    counts["schema_resources"]["const"] = str(int(counts["schema_resources"]["const"]) + 1)
    schema_path.write_bytes(canonical_encode(cast(JsonValue, document)))

    # Re-mirror so every byte-parity comparison in the ripple is satisfied by the stale artifact.
    mirrored = subprocess.run(
        [sys.executable, str(checkout / "scripts/verify_resource_manifest.py"), "--sync"],
        cwd=checkout,
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        timeout=120,
    )
    assert mirrored.returncode == 0, mirrored.stderr

    checked = _run("--check", "--repo-root", str(checkout))

    assert checked.returncode == 1
    assert "sync_resource_ripple: FAIL (drift_detected)" in checked.stderr


def test_reviewed_count_mismatch_fails_before_any_generator_runs(tmp_path: Path) -> None:
    _synthetic_checkout(tmp_path, inventory_count=2, reviewed_count=1)
    sentinel = tmp_path / "schemas/state.txt"

    completed = _run("--write", "--repo-root", str(tmp_path))

    assert completed.returncode == 1
    assert "reviewed_resource_count_mismatch" in completed.stderr
    assert sentinel.read_text(encoding="utf-8") == "stale\n"


@pytest.mark.slow
def test_write_bootstraps_new_version_manifest_without_rewriting_released_schema(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    _copy_checkout(checkout)
    released = checkout / "schemas/version/version-manifest-2.2.0.schema.json"
    original = released.read_bytes()
    current = checkout / "schemas/version/version-manifest-2.3.0.schema.json"
    expected = current.read_bytes()
    current.unlink()

    written = _run("--write", "--repo-root", str(checkout))

    assert written.returncode == 0, written.stderr + written.stdout
    assert released.read_bytes() == original
    assert current.read_bytes() == expected
    checked = _run("--check", "--repo-root", str(checkout))
    assert checked.returncode == 0, checked.stderr + checked.stdout
