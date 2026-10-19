"""Transitional ``yoetz`` distributions stay exact same-version forwarders (ADR-048)."""

from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

import finishup

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_transitional_yoetz.py"
_SHIM_SOURCE = _ROOT / "release" / "transitional-yoetz" / "python" / "src"
_SHIM_MODULES = (
    "yoetz/__init__.py",
    "yoetz/__main__.py",
    "yoetz/adapters/__init__.py",
    "yoetz/adapters/release_runtime.py",
    "yoetz/cli/__init__.py",
    "yoetz/cli/entry.py",
)


def _checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_transitional_yoetz", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def _copy_sources(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in (
        "pyproject.toml",
        "LICENSE",
        "support/npm-launcher/package.json",
        "src/finishup/adapters/package_upgrade.py",
    ):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / relative, root / relative)
    shutil.copytree(
        _ROOT / "release/transitional-yoetz",
        root / "release/transitional-yoetz",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return root


def test_repository_sources_are_in_lockstep(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _checker(monkeypatch).check_sources(_ROOT) == []


@pytest.mark.parametrize(
    ("relative", "old", "new", "error"),
    [
        (
            "release/transitional-yoetz/python/pyproject.toml",
            'version = "0.3.0"',
            'version = "0.3.1"',
            "transitional_version_drift",
        ),
        (
            "release/transitional-yoetz/python/pyproject.toml",
            'dependencies = ["finishup==0.3.0"]',
            'dependencies = ["finishup>=0.3.0"]',
            "transitional_dependency_pin_drift",
        ),
        (
            "release/transitional-yoetz/python/pyproject.toml",
            'yoetz = "finishup.cli.entry:main"',
            'yoetz = "finishup.cli.entry:main"\nfinishup = "finishup.cli.entry:main"',
            "transitional_scripts_not_exactly_yoetz",
        ),
        (
            "release/transitional-yoetz/python/pyproject.toml",
            'semantic-openai = ["finishup[semantic-openai]==0.3.0"]\n',
            "",
            "transitional_extras_drift",
        ),
        (
            "src/finishup/adapters/package_upgrade.py",
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})',
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai"})',
            "upgrade_extras_drift",
        ),
        (
            "src/finishup/adapters/package_upgrade.py",
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})',
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery", "dev"})',
            "upgrade_extras_drift",
        ),
        (
            "pyproject.toml",
            'portable-recovery = ["argon2-cffi==25.1.0"]\n',
            "",
            "upgrade_extras_drift",
        ),
        (
            "src/finishup/adapters/package_upgrade.py",
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})',
            "PACKAGE_EXTRAS: Final = frozenset(_EXTRAS)",
            "upgrade_extras_unreadable",
        ),
        (
            "src/finishup/adapters/package_upgrade.py",
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})',
            'PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})\n'
            "PACKAGE_EXTRAS = frozenset()",
            "upgrade_extras_unreadable",
        ),
        (
            "pyproject.toml",
            'finishup = "finishup.cli.entry:main"',
            'finishup = "finishup.cli.entry:main"\nyoetz = "finishup.cli.entry:main"',
            "root_scripts_not_exactly_finishup",
        ),
        (
            "release/transitional-yoetz/npm/package.json",
            '"version": "0.3.0"',
            '"version": "0.2.5"',
            "transitional_npm_version_drift",
        ),
        (
            "release/transitional-yoetz/npm/bin/yoetz.js",
            '"--managed-python", `yoetz==${version}`]',
            '"--managed-python", "--force", `yoetz==${version}`]',
            "transitional_npm_delegation_unexpected",
        ),
    ],
)
def test_drift_is_named(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    old: str,
    new: str,
    error: str,
) -> None:
    root = _copy_sources(tmp_path)
    path = root / relative
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

    assert error in _checker(monkeypatch).check_sources(root)


def test_an_extra_shim_module_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _copy_sources(tmp_path)
    (root / "release/transitional-yoetz/python/src/yoetz/service.py").write_text("x = 1\n")

    assert "transitional_shim_members_unexpected" in _checker(monkeypatch).check_sources(root)


def _wheel(dist: Path, version: str, *, scripts: str, modules: tuple[str, ...]) -> None:
    info = f"yoetz-{version}.dist-info"
    with zipfile.ZipFile(dist / f"yoetz-{version}-py3-none-any.whl", "w") as archive:
        for module in modules:
            archive.writestr(module, "")
        archive.writestr(f"{info}/entry_points.txt", scripts)
        archive.writestr(
            f"{info}/METADATA",
            f"Metadata-Version: 2.4\nName: yoetz\nVersion: {version}\n"
            f"Requires-Dist: finishup=={version}\n",
        )
        archive.writestr(f"{info}/RECORD", "")


def _sdist(dist: Path, version: str) -> None:
    prefix = f"yoetz-{version}/"
    names = ["PKG-INFO", "LICENSE", "README.md", "pyproject.toml"]
    names += [f"src/{module}" for module in _SHIM_MODULES]
    with tarfile.open(dist / f"yoetz-{version}.tar.gz", "w:gz") as archive:
        for name in names:
            member = tarfile.TarInfo(prefix + name)
            archive.addfile(member, io.BytesIO(b""))


def test_built_distribution_inspection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checker = _checker(monkeypatch)
    version = finishup.__version__
    good = tmp_path / "good"
    good.mkdir()
    _wheel(
        good,
        version,
        scripts="[console_scripts]\nyoetz = finishup.cli.entry:main\n",
        modules=_SHIM_MODULES,
    )
    _sdist(good, version)
    assert checker.check_dist(good, version) == []

    both = tmp_path / "both"
    both.mkdir()
    _wheel(
        both,
        version,
        scripts=(
            "[console_scripts]\nfinishup = finishup.cli.entry:main\n"
            "yoetz = finishup.cli.entry:main\n"
        ),
        modules=(*_SHIM_MODULES, "yoetz/extra.py"),
    )
    _sdist(both, version)
    assert checker.check_dist(both, version) == [
        "transitional_wheel_members_unexpected",
        "transitional_wheel_scripts_not_exactly_yoetz",
    ]
    assert checker.check_dist(tmp_path / "good", "9.9.9") == [
        "transitional_wheel_missing_or_ambiguous"
    ]


def test_shim_forwards_every_recorded_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    """Console script, release-runtime bootstrap and package version all resolve to FinishUP."""

    # Import from the source tree without leaving bytecode beside the shim sources.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    monkeypatch.syspath_prepend(str(_SHIM_SOURCE))  # pyright: ignore[reportUnknownMemberType]
    for name in [name for name in sys.modules if name == "yoetz" or name.startswith("yoetz.")]:
        monkeypatch.delitem(sys.modules, name)
    try:
        legacy_entry = importlib.import_module("yoetz.cli.entry")
        legacy_runtime = importlib.import_module("yoetz.adapters.release_runtime")
        legacy = importlib.import_module("yoetz")
        from finishup.adapters.release_runtime import adopt_release_lease
        from finishup.cli.entry import main

        assert legacy_entry.main is main
        assert legacy_runtime.adopt_release_lease is adopt_release_lease
        assert legacy.__version__ == finishup.__version__
    finally:
        for name in [name for name in sys.modules if name == "yoetz" or name.startswith("yoetz.")]:
            del sys.modules[name]


def test_python_m_yoetz_version_prints_the_bare_version() -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("FINISHUP_", "YOETZ_"))
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(_SHIM_SOURCE), *filter(None, [environment.get("PYTHONPATH")])]
    )
    completed = subprocess.run(
        (sys.executable, "-m", "yoetz", "--version"),
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout.decode() == finishup.__version__ + "\n"
    assert completed.stderr == b""


def test_npm_transitional_package_is_delegation_only() -> None:
    package = json.loads(
        (_ROOT / "release/transitional-yoetz/npm/package.json").read_text(encoding="utf-8")
    )
    assert package["name"] == "yoetz"
    assert package["version"] == finishup.__version__
    assert package["bin"] == {"yoetz": "./bin/yoetz.js"}
    script = _ROOT / "release/transitional-yoetz/npm/bin/yoetz.js"
    assert os.access(script, os.X_OK)
    source = script.read_text(encoding="utf-8")
    assert source.splitlines()[0] == "#!/usr/bin/env node"
    assert '"--force"' not in source
    for forbidden in ("isTTY", "readline", "prompt(", "createInterface", "pip install"):
        assert forbidden not in source, forbidden
    assert 'stdio: "inherit"' in source


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_npm_transitional_launcher_updates_the_yoetz_tool_in_place(tmp_path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    shims = tmp_path / "shims"
    shims.mkdir()
    uv_record = tmp_path / "uv.txt"
    uvx_record = tmp_path / "uvx.txt"
    (shims / "uv").write_text(f'#!/bin/sh\necho "$@" >> {uv_record}\nexit 0\n')
    (shims / "uvx").write_text(f'#!/bin/sh\necho "$@" > {uvx_record}\nexit 5\n')
    (shims / "uv").chmod(0o755)
    (shims / "uvx").chmod(0o755)

    completed = subprocess.run(
        (node, str(_ROOT / "release/transitional-yoetz/npm/bin/yoetz.js"), "status", "--json"),
        env={**os.environ, "PATH": str(shims)},
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 5
    assert uv_record.read_text().splitlines() == [
        "--version",
        f"tool install --quiet --managed-python yoetz=={finishup.__version__}",
    ]
    assert uvx_record.read_text().strip() == "yoetz status --json"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_npm_transitional_launcher_reports_a_refused_install_without_forcing(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    assert node is not None
    shims = tmp_path / "shims"
    shims.mkdir()
    uv_record = tmp_path / "uv.txt"
    ran = tmp_path / "ran"
    (shims / "uv").write_text(
        f'#!/bin/sh\necho "$@" >> {uv_record}\ncase "$1" in --version) exit 0;; esac\n'
        "echo 'error: Executables already exist: yoetz' >&2\nexit 2\n"
    )
    (shims / "uvx").write_text(f"#!/bin/sh\ntouch {ran}\nexit 0\n")
    (shims / "uv").chmod(0o755)
    (shims / "uvx").chmod(0o755)

    completed = subprocess.run(
        (node, str(_ROOT / "release/transitional-yoetz/npm/bin/yoetz.js"), "version"),
        env={**os.environ, "PATH": str(shims)},
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 1
    stderr = completed.stderr.decode()
    assert "Executables already exist" in stderr
    assert "Nothing was replaced or removed" in stderr
    assert "upgrading-from-yoetz" in stderr
    assert not ran.exists()
    assert all("--force" not in line for line in uv_record.read_text().splitlines())


def _heading_slugs(document: Path) -> set[str]:
    slugs: set[str] = set()
    for line in document.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            title = line.lstrip("#").strip().lower()
            slugs.add(re.sub(r"[^\w\- ]", "", title).replace(" ", "-"))
    return slugs


def test_migration_links_resolve_to_a_docs_heading() -> None:
    """The alias notice and the transitional READMEs point at a section that exists."""

    sources = [_ROOT / "src" / "finishup" / "cli" / "entry.py"]
    sources += sorted(
        path for path in (_ROOT / "release" / "transitional-yoetz").rglob("*") if path.is_file()
    )
    link = re.compile(r"/blob/main/(docs/usage/[\w.-]+\.md)#([\w-]+)")
    found = [
        (source, match.group(1), match.group(2))
        for source in sources
        if source.suffix in {".py", ".md", ".js"}
        for match in link.finditer(source.read_text(encoding="utf-8"))
    ]

    assert {(path, anchor) for _source, path, anchor in found} >= {
        ("docs/usage/upgrading.md", "upgrading-from-yoetz")
    }
    for source, path, anchor in found:
        assert anchor in _heading_slugs(_ROOT / path), (source.name, path, anchor)
