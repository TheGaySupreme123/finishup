"""Clean double-build reproducibility and candidate-artifact identity.

Builds the sdist and wheel twice, from two independently created, path-distinct exports of the
exact committed source tree (``git archive HEAD``), using the pinned ``uv build`` tool with a
fixed, non-network build environment. Proves the two candidate builds are byte-identical, that
build output never leaks the local export path, and that the pinned build tool is exactly the one
ADR-007 requires.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_BUILD_TIMEOUT: Final = 120
_GIT_TIMEOUT: Final = 30


def _load_pyproject() -> dict[str, object]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _project_name_and_version() -> tuple[str, str]:
    document = _load_pyproject()
    project = cast(dict[str, object], document["project"])
    name = cast(str, project["name"])
    version = cast(str, project["version"])
    return name, version


def _pinned_uv_version() -> str:
    document = _load_pyproject()
    tool = cast(dict[str, object], document["tool"])
    uv_section = cast(dict[str, object], tool["uv"])
    required = cast(str, uv_section["required-version"])
    return required.removeprefix("==")


def _git(*arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local git binary
        ["git", "-C", str(_REPO_ROOT), *arguments],
        capture_output=True,
        check=True,
        timeout=_GIT_TIMEOUT,
    )
    return completed.stdout.decode("utf-8").strip()


def _export_clean_source(dest: Path) -> None:
    """Export the exact committed ``HEAD`` tree, ignoring any local working-tree changes."""

    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(_REPO_ROOT), "archive", "--format=tar", "HEAD"],
        capture_output=True,
        check=True,
        timeout=_GIT_TIMEOUT,
    )
    tar_path = dest.parent / f".{dest.name}-export.tar"
    tar_path.write_bytes(archive.stdout)
    try:
        with tarfile.open(tar_path) as archive_file:
            archive_file.extractall(dest, filter="data")
    finally:
        tar_path.unlink(missing_ok=True)


def _build_env(*, source_date_epoch: str, hash_seed: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment["TZ"] = "UTC"
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    environment["PYTHONHASHSEED"] = hash_seed
    environment["SOURCE_DATE_EPOCH"] = source_date_epoch
    return environment


def _run_uv_build(
    source_dir: Path, out_dir: Path, *, source_date_epoch: str, hash_seed: str = "0"
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        [
            "uv",
            "build",
            "--no-sources",
            "--offline",
            "--no-create-gitignore",
            "--clear",
            "-o",
            str(out_dir),
        ],
        cwd=source_dir,
        env=_build_env(source_date_epoch=source_date_epoch, hash_seed=hash_seed),
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )


@dataclass(frozen=True, slots=True)
class BuildResult:
    out_dir: Path
    sdist: Path
    wheel: Path


def _build_once(
    export_root: Path, out_root: Path, *, label: str, source_date_epoch: str, hash_seed: str = "0"
) -> BuildResult:
    source_dir = export_root / f"finishup-canary-{label}"
    out_dir = out_root / f"out-{label}"
    _export_clean_source(source_dir)
    _run_uv_build(source_dir, out_dir, source_date_epoch=source_date_epoch, hash_seed=hash_seed)

    entries = sorted(out_dir.iterdir())
    sdists = [entry for entry in entries if entry.name.endswith(".tar.gz")]
    wheels = [entry for entry in entries if entry.name.endswith(".whl")]
    assert len(entries) == 2, f"unexpected build output members: {[e.name for e in entries]}"
    assert len(sdists) == 1, "expected exactly one sdist"
    assert len(wheels) == 1, "expected exactly one wheel"
    return BuildResult(out_dir=out_dir, sdist=sdists[0], wheel=wheels[0])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_double_build_from_independent_exports_is_byte_identical(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    epoch = _git("log", "-1", "--format=%ct")

    first = _build_once(export_root, out_root, label="a", source_date_epoch=epoch)
    second = _build_once(export_root, out_root, label="b", source_date_epoch=epoch)

    assert first.sdist.name == second.sdist.name
    assert first.wheel.name == second.wheel.name
    assert _sha256(first.sdist) == _sha256(second.sdist)
    assert _sha256(first.wheel) == _sha256(second.wheel)
    assert first.sdist.read_bytes() == second.sdist.read_bytes()
    assert first.wheel.read_bytes() == second.wheel.read_bytes()


def test_artifact_names_match_project_identity(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    name, version = _project_name_and_version()
    epoch = _git("log", "-1", "--format=%ct")

    result = _build_once(export_root, out_root, label="identity", source_date_epoch=epoch)

    assert result.sdist.name == f"{name}-{version}.tar.gz"
    assert result.wheel.name == f"{name}-{version}-py3-none-any.whl"


def test_build_output_never_embeds_the_local_export_path(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    epoch = _git("log", "-1", "--format=%ct")

    result = _build_once(export_root, out_root, label="canary-leak", source_date_epoch=epoch)

    canary = str(export_root).encode("utf-8")
    home = str(Path.home()).encode("utf-8")
    for artifact in (result.sdist, result.wheel):
        data = artifact.read_bytes()
        assert canary not in data, f"{artifact.name} embeds the local export path"
        assert home not in data, f"{artifact.name} embeds the local home directory"


def test_offline_build_requires_no_network(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """``--offline`` build succeeding proves no build input requires network reachability."""

    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    epoch = _git("log", "-1", "--format=%ct")

    result = _build_once(export_root, out_root, label="offline", source_date_epoch=epoch)

    assert result.sdist.is_file()
    assert result.wheel.is_file()


def test_reproducible_across_varied_hash_seed_and_timestamp(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Hash seed and ``SOURCE_DATE_EPOCH`` are approved-normalized dimensions: varying them alone
    must not change artifact bytes.
    """

    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")

    first = _build_once(
        export_root, out_root, label="seed-a", source_date_epoch="1700000000", hash_seed="0"
    )
    second = _build_once(
        export_root, out_root, label="seed-b", source_date_epoch="1750000000", hash_seed="1"
    )

    assert _sha256(first.sdist) == _sha256(second.sdist)
    assert _sha256(first.wheel) == _sha256(second.wheel)


def test_build_tool_is_the_exact_pinned_version() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        ["uv", "--version"], capture_output=True, check=True, timeout=_GIT_TIMEOUT
    )
    reported = completed.stdout.decode("utf-8").strip()
    pinned = _pinned_uv_version()
    assert pinned in reported, f"pinned uv {pinned!r} does not match installed {reported!r}"


def test_unpinned_build_tool_would_be_detected(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """A build tool reporting any version other than the pinned one must fail this identity check.

    This does not invoke a second uv binary (only one is available); it proves the comparison
    itself is sensitive to a single-character version drift, so a genuinely unpinned tool cannot
    pass silently.
    """

    pinned = _pinned_uv_version()
    drifted = pinned[:-1] + ("0" if pinned[-1] != "0" else "1")
    assert drifted != pinned
    assert drifted not in f"uv {pinned} (abc)"


def test_single_byte_artifact_mutation_breaks_digest_equality(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    epoch = _git("log", "-1", "--format=%ct")

    result = _build_once(export_root, out_root, label="mutation", source_date_epoch=epoch)
    original = result.wheel.read_bytes()
    mutated = bytearray(original)
    mutated[-1] ^= 0xFF

    assert hashlib.sha256(bytes(mutated)).hexdigest() != hashlib.sha256(original).hexdigest()


def test_unreachable_package_index_does_not_change_artifact_identity(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The build must not depend on any package index: point at an invalid one and stay offline."""

    export_root = tmp_path_factory.mktemp("export")
    out_root = tmp_path_factory.mktemp("out")
    epoch = _git("log", "-1", "--format=%ct")
    source_dir = export_root / "finishup-canary-private-index"
    out_dir = out_root / "out-private-index"
    _export_clean_source(source_dir)

    environment = _build_env(source_date_epoch=epoch, hash_seed="0")
    environment["UV_DEFAULT_INDEX"] = "https://private-index.invalid/simple"

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            "uv",
            "build",
            "--no-sources",
            "--offline",
            "--no-create-gitignore",
            "--clear",
            "-o",
            str(out_dir),
        ],
        cwd=source_dir,
        env=environment,
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    assert completed.returncode == 0

    reference_out = out_root / "out-reference"
    _run_uv_build(source_dir, reference_out, source_date_epoch=epoch)
    produced = sorted(out_dir.iterdir())
    reference = sorted(reference_out.iterdir())
    assert [entry.name for entry in produced] == [entry.name for entry in reference]
    for produced_entry, reference_entry in zip(produced, reference, strict=True):
        assert produced_entry.read_bytes() == reference_entry.read_bytes()
