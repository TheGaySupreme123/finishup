"""Reviewed/source/embedded/installed resource byte equality.

Proves each manifest-declared runtime resource is the exact reviewed byte set in the
root canonical source tree, the ``src/finishup/resources`` package tree, the built wheel, and a clean
offline install; that the canonical fixtures are the only ``fixtures/`` corpus shipped; and
that corruption/missing/extra resource drift is detected before decode/use, both at the source
level (``scripts/verify_resource_manifest.py --check``) and at the installed-package level
(``finishup.version.read_verified_resource``).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import pytest

from finishup.version import REVIEWED_RESOURCE_COUNT

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_VERIFY_SCRIPT: Final = _REPO_ROOT / "scripts" / "verify_resource_manifest.py"
_BUILD_TIMEOUT: Final = 120


def _load_manifest() -> Any:  # raw JSON document, deliberately untyped
    manifest_path = _REPO_ROOT / "src" / "finishup" / "resources" / "manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _export_clean_source(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(_REPO_ROOT), "archive", "--format=tar", "HEAD"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    tar_path = dest.parent / f".{dest.name}-export.tar"
    tar_path.write_bytes(archive.stdout)
    try:
        with tarfile.open(tar_path) as archive_file:
            archive_file.extractall(dest, filter="data")
    finally:
        tar_path.unlink(missing_ok=True)

    # Start from ``git archive HEAD`` so unrelated untracked files cannot enter the baseline, then
    # overlay the current generated manifest's complete reviewed source/package set. Deriving this
    # list from the manifest avoids creating another inventory that must be updated by hand.
    manifest = _load_manifest()
    overlays = {"src/finishup/resources/manifest.json"}
    for entry in manifest["entries"]:
        overlays.add(entry["source_path"])
        overlays.add(f"src/finishup/resources/{entry['package_path']}")
    for relative in sorted(overlays, key=str.encode):
        source = _REPO_ROOT / relative
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def test_manifest_matches_the_single_reviewed_count_and_closed_kind_set() -> None:
    manifest = _load_manifest()
    entries = manifest["entries"]
    assert len(entries) == REVIEWED_RESOURCE_COUNT

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1
    assert set(counts) == {
        "canonical_vector",
        "compatibility_manifest",
        "guidance",
        "json_schema",
        "migration",
        "runtime_config",
        "runtime_support",
        "skill",
    }


def test_source_tree_and_package_tree_are_byte_identical_in_the_real_checkout() -> None:
    """This is the same gate ``scripts/verify_resource_manifest.py --check`` already enforces; it
    recomputes source digests, the manifest, and package-tree parity in one pass.
    """

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [sys.executable, str(_VERIFY_SCRIPT), "--check"],
        cwd=_REPO_ROOT,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_nested_codex_skill_member_metadata_detects_changed_owned_bytes(
    synthetic_repo_root: Path,
) -> None:
    skill = synthetic_repo_root / "skills/codex/finishup/SKILL.md"
    skill.write_bytes(skill.read_bytes() + b"\n")
    completed = subprocess.run(  # noqa: S603 - fixed local verifier argv, no shell
        [
            sys.executable,
            str(_VERIFY_SCRIPT),
            "--check",
            "--repo-root",
            str(synthetic_repo_root),
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert b"codex_skill_manifest_stale" in completed.stderr


def test_every_manifest_entry_source_path_matches_its_recorded_digest_and_size() -> None:
    manifest = _load_manifest()
    for entry in manifest["entries"]:
        source_path = _REPO_ROOT / entry["source_path"]
        data = source_path.read_bytes()
        assert len(data) == entry["size"], entry["logical_name"]
        assert _sha256(data) == entry["sha256"], entry["logical_name"]


def test_all_canonical_fixtures_are_referenced_by_the_manifest() -> None:
    manifest = _load_manifest()
    canonical_entries = [
        entry for entry in manifest["entries"] if entry["kind"] == "canonical_vector"
    ]
    for entry in canonical_entries:
        assert entry["logical_name"].startswith("fixtures/canonical/")

    on_disk = sorted((_REPO_ROOT / "fixtures" / "canonical").glob("*.case.json"))
    referenced = {entry["logical_name"] for entry in canonical_entries}
    assert referenced == {f"fixtures/canonical/{path.name}" for path in on_disk}


def test_adversarial_and_replay_corpora_are_not_referenced_by_the_manifest() -> None:
    manifest = _load_manifest()
    referenced_names = {entry["logical_name"] for entry in manifest["entries"]}
    for corpus in ("adversarial", "replay", "imports", "receipts", "privacy", "backward-read"):
        corpus_dir = _REPO_ROOT / "fixtures" / corpus
        if not corpus_dir.is_dir():
            continue
        for candidate in corpus_dir.rglob("*"):
            if candidate.is_file():
                relative = f"fixtures/{corpus}/{candidate.relative_to(corpus_dir).as_posix()}"
                assert relative not in referenced_names


# --------------------------------------------------------------------------
# Wheel and installed parity
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BuiltWheel:
    path: Path


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> BuiltWheel:
    out_dir = tmp_path_factory.mktemp("resource-parity-build")
    environment = dict(os.environ)
    environment["TZ"] = "UTC"
    environment["SOURCE_DATE_EPOCH"] = "1700000000"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        [
            "uv",
            "build",
            "--wheel",
            "--no-sources",
            "--offline",
            "--no-create-gitignore",
            "-o",
            str(out_dir),
        ],
        cwd=_REPO_ROOT,
        env=environment,
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    wheels = [entry for entry in out_dir.iterdir() if entry.name.endswith(".whl")]
    assert len(wheels) == 1
    return BuiltWheel(path=wheels[0])


def test_wheel_resource_bytes_match_the_package_tree_for_every_manifest_entry(
    built_wheel: BuiltWheel,
) -> None:
    manifest = _load_manifest()
    with zipfile.ZipFile(built_wheel.path) as archive:
        for entry in manifest["entries"]:
            member = f"finishup/resources/{entry['package_path']}"
            wheel_data = archive.read(member)
            source_data = (
                _REPO_ROOT / "src" / "finishup" / "resources" / entry["package_path"]
            ).read_bytes()
            assert wheel_data == source_data, entry["logical_name"]
            assert _sha256(wheel_data) == entry["sha256"], entry["logical_name"]


@pytest.fixture(scope="module")
def installed_python(built_wheel: BuiltWheel, tmp_path_factory: pytest.TempPathFactory) -> Path:
    venv_dir = tmp_path_factory.mktemp("resource-parity-venv") / "venv"
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["uv", "venv", "--python", "3.14", str(venv_dir)],
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    python = venv_dir / "bin" / "python"
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["uv", "pip", "install", "--python", str(python), "--offline", str(built_wheel.path)],
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    return python


def test_installed_package_resource_bytes_match_the_reviewed_source_for_every_entry(
    installed_python: Path,
) -> None:
    manifest = _load_manifest()
    probe_script = (
        "import importlib.resources as r, json, sys\n"
        "names = json.loads(sys.argv[1])\n"
        "root = r.files('finishup.resources')\n"
        "digests = {}\n"
        "for name in names:\n"
        "    node = root\n"
        "    for part in name.split('/'):\n"
        "        node = node.joinpath(part)\n"
        "    digests[name] = node.read_bytes().hex()\n"
        "print(json.dumps(digests))\n"
    )
    package_paths = [entry["package_path"] for entry in manifest["entries"]]
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [str(installed_python), "-c", probe_script, json.dumps(package_paths)],
        capture_output=True,
        check=True,
        timeout=30,
    )
    installed_hex = json.loads(completed.stdout)

    for entry in manifest["entries"]:
        installed_bytes = bytes.fromhex(installed_hex[entry["package_path"]])
        source_bytes = (_REPO_ROOT / entry["source_path"]).read_bytes()
        assert installed_bytes == source_bytes, entry["logical_name"]
        assert _sha256(installed_bytes) == entry["sha256"], entry["logical_name"]


def test_installed_resource_manifest_digest_matches_the_source_manifest(
    installed_python: Path,
) -> None:
    manifest = _load_manifest()
    probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(installed_python),
            "-c",
            "from finishup.version import build_version_manifest; "
            "print(build_version_manifest().resource_manifest_digest)",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    assert probe.stdout.decode("utf-8").strip() == manifest["resource_set_digest"]


def test_verification_precedes_use_a_corrupted_installed_resource_fails_closed(
    installed_python: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Corrupt one installed (not source) resource byte and prove ``read_verified_resource``
    refuses to hand back the bytes rather than silently serving stale/wrong content.
    """

    locate = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(installed_python),
            "-c",
            "import importlib.resources as r; "
            "print(r.files('finishup.resources').joinpath("
            "'schemas/common/actor-assertion-1.0.0.schema.json'))",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    installed_path = Path(locate.stdout.decode("utf-8").strip())
    original = installed_path.read_bytes()
    mutated = bytearray(original)
    mutated[0] ^= 0xFF
    installed_path.write_bytes(bytes(mutated))
    try:
        probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
            [
                str(installed_python),
                "-c",
                "from finishup.version import read_verified_resource; "
                "read_verified_resource('schemas/common/actor-assertion-1.0.0.schema.json')",
            ],
            capture_output=True,
            timeout=30,
        )
        assert probe.returncode != 0
        assert b"ResourceIntegrityError" in probe.stderr or b"resource" in probe.stderr.lower()
    finally:
        installed_path.write_bytes(original)


def test_verification_precedes_use_a_deleted_installed_resource_fails_closed(
    installed_python: Path,
) -> None:
    locate = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(installed_python),
            "-c",
            "import importlib.resources as r; "
            "print(r.files('finishup.resources').joinpath('guidance/workflow.md'))",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    installed_path = Path(locate.stdout.decode("utf-8").strip())
    original = installed_path.read_bytes()
    installed_path.unlink()
    try:
        probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
            [
                str(installed_python),
                "-c",
                "from finishup.version import read_verified_resource; "
                "read_verified_resource('guidance/workflow.md')",
            ],
            capture_output=True,
            timeout=30,
        )
        assert probe.returncode != 0
    finally:
        installed_path.write_bytes(original)


# --------------------------------------------------------------------------
# Source-level mutation matrix, via the script's own ``--repo-root`` test seam
# --------------------------------------------------------------------------


def _run_verify(repo_root: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [sys.executable, str(_VERIFY_SCRIPT), "--check", "--repo-root", str(repo_root)],
        capture_output=True,
        timeout=60,
    )


@pytest.fixture()
def synthetic_repo_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("resource-parity-synthetic")
    _export_clean_source(root)
    return root


def test_synthetic_clean_export_passes_verification(synthetic_repo_root: Path) -> None:
    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_a_one_byte_changed_package_resource_is_detected(synthetic_repo_root: Path) -> None:
    target = (
        synthetic_repo_root
        / "src"
        / "finishup"
        / "resources"
        / "guidance"
        / "agent-instructions.md"
    )
    data = bytearray(target.read_bytes())
    data[0] ^= 0xFF
    target.write_bytes(bytes(data))

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"changed guidance/agent-instructions.md" in completed.stderr


def test_a_missing_package_resource_is_detected(synthetic_repo_root: Path) -> None:
    target = (
        synthetic_repo_root
        / "src"
        / "finishup"
        / "resources"
        / "guidance"
        / "agent-instructions.md"
    )
    target.unlink()

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"missing guidance/agent-instructions.md" in completed.stderr


def test_an_extra_untracked_package_resource_is_detected(synthetic_repo_root: Path) -> None:
    stray = synthetic_repo_root / "src" / "finishup" / "resources" / "guidance" / "stray.md"
    stray.write_text("not a reviewed resource\n", encoding="utf-8")

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"extra guidance/stray.md" in completed.stderr


def test_a_manifest_json_byte_drift_is_detected(synthetic_repo_root: Path) -> None:
    manifest_path = synthetic_repo_root / "src" / "finishup" / "resources" / "manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes()[:-1] + b" \n")

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"manifest.json" in completed.stderr


def test_a_crlf_line_ending_in_a_text_resource_is_rejected(synthetic_repo_root: Path) -> None:
    # The text-policy check runs on the reviewed *source* bytes (collect_source_entries), not the
    # package-tree destination copy.
    target = synthetic_repo_root / "guidance" / "agent-instructions.md"
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"crlf_forbidden" in completed.stderr


def test_a_byte_order_mark_in_a_text_resource_is_rejected(synthetic_repo_root: Path) -> None:
    target = synthetic_repo_root / "guidance" / "agent-instructions.md"
    target.write_bytes(b"\xef\xbb\xbf" + target.read_bytes())

    completed = _run_verify(synthetic_repo_root)
    assert completed.returncode == 1
    assert b"byte_order_mark_forbidden" in completed.stderr
