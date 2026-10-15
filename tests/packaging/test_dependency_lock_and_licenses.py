"""Locked dependency and legal inventory gate.

Proves the declared (``pyproject.toml``), locked (``uv.lock``), built (wheel metadata), and
installed (isolated venv) dependency sets agree for the base target and every optional extra, that
every resolved Python dependency comes from the public registry (never editable/path/git/private-
index), and that every installed distribution's license normalizes to a reviewed allowlist entry.
Also checks the Node dev-only toolchain lock never enters the runtime artifact.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_BUILD_TIMEOUT: Final = 120
_PUBLIC_REGISTRY: Final = "https://pypi.org/simple"


def _uv_env() -> dict[str, str]:
    """Environment for ``uv export`` runs that select their lock mode by flag.

    CI exports ``UV_LOCKED=1`` for the ambient ``uv run --locked`` steps, and uv rejects that
    together with the ``--frozen`` these exports pass, exiting 2 before doing any work. The lock
    mode belongs to the command, so drop the inherited variable rather than let the surrounding
    workflow decide it.
    """

    env = dict(os.environ)
    env.pop("UV_LOCKED", None)
    env.pop("UV_FROZEN", None)
    return env


def _run_checked(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run a tool and fail with its own stderr instead of a bare ``CalledProcessError``.

    ``check=True`` with captured output reports only an exit status, so a uv failure here shows
    the argv and nothing about the cause. That turned two separate CI breakages into guesswork.
    """

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local binary
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed with exit status {completed.returncode}: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout.decode('utf-8', errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed


# APSW's own PyPI metadata reports the vague classic marker "any-OSI"; the reviewed disposition is
# recorded here rather than trusting an uninformative upstream field. APSW itself is zlib-licensed
# and bundles the public-domain SQLite amalgamation (see ADR-007).
_LICENSE_OVERRIDES: Final = {"apsw": "Zlib"}

_CLASSIFIER_LICENSE_MAP: Final = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
}

_CLASSIC_LICENSE_MAP: Final = {
    "Apache License, Version 2.0": "Apache-2.0",
    "ISC License": "ISC",
}

_ALLOWED_LICENSE_IDENTIFIERS: Final = frozenset(
    {
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "Apache-2.0 OR BSD-2-Clause",
        "Apache-2.0 OR BSD-3-Clause",
        "MIT OR Apache-2.0",
        "MPL-2.0",
        "MPL-2.0 AND MIT",
        "ISC",
        "PSF-2.0",
        "Zlib",
    }
)

_DEV_ONLY_TOOL_NAMES: Final = frozenset({"pytest", "pytest-timeout", "ruff", "hypothesis"})


def _load_pyproject() -> dict[str, object]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _load_uv_lock() -> dict[str, object]:
    with (_REPO_ROOT / "uv.lock").open("rb") as handle:
        return tomllib.load(handle)


def _normalize(name: str) -> str:
    """PEP 503 name normalization: collapse runs of ``-``/``_``/``.`` to a single lowercase ``-``."""

    return re.sub(r"[-_.]+", "-", name).lower()


def _uv_lock_packages() -> dict[str, dict[str, object]]:
    lock = _load_uv_lock()
    packages = cast(list[dict[str, object]], lock["package"])
    result: dict[str, dict[str, object]] = {}
    for entry in packages:
        result[_normalize(str(entry["name"]))] = entry
    return result


def _direct_dependency_pins() -> dict[str, str]:
    project = cast(dict[str, object], _load_pyproject()["project"])
    pins: dict[str, str] = {}
    for spec in cast(list[str], project["dependencies"]):
        name, _, version = spec.partition("==")
        pins[_normalize(name)] = version
    return pins


def _extra_dependency_pins() -> dict[str, dict[str, str]]:
    project = cast(dict[str, object], _load_pyproject()["project"])
    optional = cast(dict[str, list[str]], project.get("optional-dependencies", {}))
    result: dict[str, dict[str, str]] = {}
    for extra_name, specs in optional.items():
        pins: dict[str, str] = {}
        for spec in specs:
            name, _, version = spec.partition("==")
            pins[_normalize(name)] = version
        result[extra_name] = pins
    return result


# --------------------------------------------------------------------------
# Lock freshness and source purity
# --------------------------------------------------------------------------


def test_uv_lock_is_up_to_date_with_pyproject() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        ["uv", "lock", "--check", "--offline"],
        cwd=_REPO_ROOT,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_every_locked_dependency_comes_from_the_public_registry() -> None:
    packages = _uv_lock_packages()
    for normalized_name, entry in packages.items():
        if normalized_name == "finishup":
            continue  # the workspace root itself is legitimately editable
        source = cast(dict[str, object], entry.get("source", {}))
        assert set(source) == {"registry"}, f"{normalized_name} has non-registry source: {source}"
        assert source["registry"] == _PUBLIC_REGISTRY, normalized_name


def test_direct_dependencies_resolve_to_their_exact_pinned_lock_version() -> None:
    packages = _uv_lock_packages()
    for normalized_name, expected_version in _direct_dependency_pins().items():
        assert normalized_name in packages, f"{normalized_name} missing from uv.lock"
        assert str(packages[normalized_name]["version"]) == expected_version


@pytest.mark.parametrize("extra_name", ["semantic-openai", "portable-recovery"])
def test_optional_extra_dependencies_resolve_to_their_exact_pinned_lock_version(
    extra_name: str,
) -> None:
    packages = _uv_lock_packages()
    pins = _extra_dependency_pins()[extra_name]
    for normalized_name, expected_version in pins.items():
        assert normalized_name in packages, f"{normalized_name} missing from uv.lock"
        assert str(packages[normalized_name]["version"]) == expected_version


def test_native_component_identities_are_pinned_exactly() -> None:
    packages = _uv_lock_packages()
    assert str(packages["apsw"]["version"]) == "3.53.3.1"
    assert str(packages["cryptography"]["version"]) == "50.0.0"


# --------------------------------------------------------------------------
# Built/installed inventory reconciliation
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BuiltWheel:
    path: Path


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> BuiltWheel:
    out_dir = tmp_path_factory.mktemp("dependency-lock-build")
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


def _install_isolated(
    tmp_path_factory: pytest.TempPathFactory, wheel: Path, *, extras: tuple[str, ...] = ()
) -> Path:
    """Install the wheel into a fresh venv strictly from ``uv.lock``, never a fresh resolution.

    ``uv pip install <wheel>`` alone would re-resolve transitive dependencies against whatever the
    offline cache currently holds, which can silently drift from the committed lock (observed with
    ``sse-starlette``). Exporting the lock to a hashed requirements file and installing that first,
    then the wheel itself with ``--no-deps``, is what actually pins the installed set to the lock.
    """

    venv_dir = tmp_path_factory.mktemp("dependency-lock-venv") / "venv"
    _run_checked(
        ["uv", "venv", "--python", "3.14", str(venv_dir)],
        timeout=_BUILD_TIMEOUT,
    )
    python = venv_dir / "bin" / "python"

    requirements_path = tmp_path_factory.mktemp("dependency-lock-reqs") / "requirements.txt"
    export_command = [
        "uv",
        "export",
        "--format",
        "requirements.txt",
        "--no-emit-project",
        "--no-dev",
        "--offline",
        "--frozen",
        "-o",
        str(requirements_path),
    ]
    for extra in extras:
        export_command += ["--extra", extra]
    _run_checked(
        export_command,
        cwd=_REPO_ROOT,
        env=_uv_env(),
        timeout=60,
    )
    # No --offline here. The pin comes from the hashed requirements file, not from the network
    # flag: every version and artifact hash is already fixed by the export above, so a resolution
    # that drifts from the lock cannot succeed. Installing offline additionally requires each
    # artifact to be hash-checkable in the local uv cache, which a cache populated only by
    # `uv sync` is not on a clean machine — the packages install fine but leave nothing this
    # install can verify, so every run on a fresh CI cache failed on the first entry
    # (`annotated-doc`). True offline behavior is covered separately by test_offline_reinstall.
    _run_checked(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "-r",
            str(requirements_path),
        ],
        timeout=_BUILD_TIMEOUT,
    )
    # The wheel itself is a local file installed with --no-deps, so it needs no index at all.
    _run_checked(
        ["uv", "pip", "install", "--python", str(python), "--offline", "--no-deps", str(wheel)],
        timeout=_BUILD_TIMEOUT,
    )
    return python


def _installed_distributions(python: Path) -> dict[str, str]:
    probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(python),
            "-c",
            "import importlib.metadata as m, json; "
            "print(json.dumps({d.name: d.version for d in m.distributions()}))",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    raw = json.loads(probe.stdout)
    return {_normalize(name): version for name, version in raw.items()}


def test_base_install_matches_locked_direct_dependencies_with_no_unlocked_package(
    built_wheel: BuiltWheel, tmp_path_factory: pytest.TempPathFactory
) -> None:
    python = _install_isolated(tmp_path_factory, built_wheel.path)
    installed = _installed_distributions(python)
    packages = _uv_lock_packages()

    for normalized_name, expected_version in _direct_dependency_pins().items():
        assert installed.get(normalized_name) == expected_version

    for normalized_name, version in installed.items():
        if normalized_name == "finishup":
            continue
        assert normalized_name in packages, f"{normalized_name} is not in uv.lock at all"
        assert packages[normalized_name]["version"] == version, (
            f"{normalized_name} installed {version} but locked {packages[normalized_name]['version']}"
        )


@pytest.mark.parametrize("extra_name", ["semantic-openai", "portable-recovery"])
def test_extra_install_matches_locked_extra_dependencies(
    built_wheel: BuiltWheel, tmp_path_factory: pytest.TempPathFactory, extra_name: str
) -> None:
    python = _install_isolated(tmp_path_factory, built_wheel.path, extras=(extra_name,))
    installed = _installed_distributions(python)
    for normalized_name, expected_version in _extra_dependency_pins()[extra_name].items():
        assert installed.get(normalized_name) == expected_version


def test_dev_only_tooling_never_appears_in_wheel_metadata_dependencies(
    built_wheel: BuiltWheel,
) -> None:
    import zipfile
    from email.parser import BytesParser
    from email.policy import compat32

    with zipfile.ZipFile(built_wheel.path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_name))

    requires_dist = " ".join(metadata.get_all("Requires-Dist") or [])
    for tool_name in _DEV_ONLY_TOOL_NAMES:
        assert tool_name not in requires_dist.lower()


# --------------------------------------------------------------------------
# License inventory
# --------------------------------------------------------------------------


def test_every_installed_distribution_license_is_on_the_reviewed_allowlist(
    built_wheel: BuiltWheel, tmp_path_factory: pytest.TempPathFactory
) -> None:
    python = _install_isolated(
        tmp_path_factory, built_wheel.path, extras=("semantic-openai", "portable-recovery")
    )
    probe_script = (
        "import importlib.metadata as m, json\n"
        "result = []\n"
        "for dist in m.distributions():\n"
        "    meta = dist.metadata\n"
        "    result.append({\n"
        "        'name': dist.name,\n"
        "        'license_expression': meta.get('License-Expression'),\n"
        "        'license_classic': meta.get('License'),\n"
        "        'classifiers': [c for c in (meta.get_all('Classifier') or []) "
        "if c.startswith('License')],\n"
        "    })\n"
        "print(json.dumps(result))\n"
    )
    probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [str(python), "-c", probe_script],
        capture_output=True,
        check=True,
        timeout=30,
    )
    entries = json.loads(probe.stdout)

    unknown: list[str] = []
    for entry in entries:
        override = _LICENSE_OVERRIDES.get(_normalize(entry["name"]))
        if override is not None:
            normalized = override
        elif entry["license_expression"]:
            normalized = entry["license_expression"]
        elif entry["license_classic"]:
            normalized = _CLASSIC_LICENSE_MAP.get(
                entry["license_classic"], entry["license_classic"]
            )
        else:
            mapped = None
            for classifier in entry["classifiers"]:
                mapped = _CLASSIFIER_LICENSE_MAP.get(classifier, mapped)
            normalized = mapped or "UNKNOWN"

        if normalized not in _ALLOWED_LICENSE_IDENTIFIERS:
            unknown.append(f"{entry['name']}: {normalized!r}")

    assert not unknown, f"unreviewed/unknown license disposition: {unknown}"


def test_project_license_itself_is_apache_2_0() -> None:
    project = _load_pyproject()["project"]
    assert isinstance(project, dict)
    assert project["license"] == "Apache-2.0"
    assert "Apache-2.0" in _ALLOWED_LICENSE_IDENTIFIERS


# --------------------------------------------------------------------------
# Node dev-only toolchain
# --------------------------------------------------------------------------


def _node_package_json() -> dict[str, object]:
    return json.loads((_REPO_ROOT / "package.json").read_text(encoding="utf-8"))


# Every Node package this repository may declare, each exactly pinned and each dev-only. This is
# an allowlist, not a cap: adding a tool means adding a reviewed line here, in the same change that
# adds it to package.json. Ranges are rejected below so a review cannot be silently re-resolved.
_ALLOWED_NODE_DEV_PACKAGES: Final = {
    # Typechecker invoked by the `typecheck` script and by CI.
    "pyright": "1.1.411",
    # Review tooling run against working copies. Apache-2.0, never imported by shipped code.
    "@openai/codex-security": "0.1.4",
}
# An exact version: no caret, tilde, range, tag, URL, or git specifier.
_EXACT_NODE_PIN = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", re.ASCII)
_RUNTIME_DEPENDENCY_KEYS: Final = (
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundleDependencies",
    "bundledDependencies",
)


def test_node_dev_toolchain_is_pinned_and_dev_only() -> None:
    package = _node_package_json()
    assert package["engines"] == {"node": "26.5.0", "npm": "12.0.1"}
    assert package["devDependencies"] == _ALLOWED_NODE_DEV_PACKAGES
    assert package["private"] is True
    assert package["scripts"] == {"typecheck": "pyright"}


def test_no_node_package_is_declared_as_a_runtime_requirement() -> None:
    """Nothing here may be a runtime dependency, whatever it is used for.

    This manifest exists to pin local tooling; the shipped artifact is the Python package and
    carries no Node runtime. The dev-only allowlist above is the reviewed surface, so a tool
    recorded under `dependencies` would both misdeclare itself and land outside that review. Guard
    the runtime keys directly rather than inferring their absence from the dev list.
    """

    package = _node_package_json()
    declared = [key for key in _RUNTIME_DEPENDENCY_KEYS if package.get(key)]
    assert declared == [], f"node packages declared as runtime requirements: {declared}"


def test_every_node_dev_package_is_an_exact_version() -> None:
    """A range would let the reviewed toolchain drift without a diff to review."""

    package = _node_package_json()
    dev_dependencies = package["devDependencies"]
    assert isinstance(dev_dependencies, dict)
    unpinned = sorted(
        f"{name}@{spec}"
        for name, spec in cast(dict[str, str], dev_dependencies).items()
        if _EXACT_NODE_PIN.fullmatch(spec) is None
    )
    assert unpinned == [], f"node dev packages are not exactly pinned: {unpinned}"


def test_node_lockfile_is_present_and_self_consistent() -> None:
    lock_path = _REPO_ROOT / "package-lock.json"
    assert lock_path.is_file()
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    package = _node_package_json()
    assert lock["name"] == package["name"]


def test_npm_ci_ignore_scripts_reproduces_the_pinned_toolchain_when_available(
    tmp_path: Path,
) -> None:
    node_probe = subprocess.run(["node", "--version"], capture_output=True, timeout=10, check=False)
    npm_probe = subprocess.run(["npm", "--version"], capture_output=True, timeout=10, check=False)
    if node_probe.returncode != 0 or npm_probe.returncode != 0:
        pytest.skip("node/npm are not available in this environment")

    engines = cast(dict[str, object], _node_package_json()["engines"])
    pinned_node_major = str(engines["node"]).split(".")[0]
    pinned_npm_major = str(engines["npm"]).split(".")[0]
    actual_node_major = node_probe.stdout.decode("utf-8").strip().lstrip("v").split(".")[0]
    actual_npm_major = npm_probe.stdout.decode("utf-8").strip().split(".")[0]
    if actual_node_major != pinned_node_major or actual_npm_major != pinned_npm_major:
        pytest.skip(
            "contributor toolchain mismatch: "
            f"have node {actual_node_major}.x/npm {actual_npm_major}.x, "
            f"pinned node {pinned_node_major}.x/npm {pinned_npm_major}.x"
        )

    staging = tmp_path / "npm-ci-check"
    staging.mkdir()
    (staging / "package.json").write_text(
        (_REPO_ROOT / "package.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (staging / "package-lock.json").write_text(
        (_REPO_ROOT / "package-lock.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local npm binary
        ["npm", "ci", "--ignore-scripts"],
        cwd=staging,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
