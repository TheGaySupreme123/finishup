"""Lockstep gate for the transitional ``yoetz`` distributions (ADR-048).

FinishUP shipped as Yoetz through 0.2.5. ``release/transitional-yoetz/`` builds a PyPI ``yoetz``
distribution and an npm ``yoetz`` launcher that keep earlier installations working for one
deprecation release. Released 0.2.x ``yoetz upgrade`` code runs ``uv tool upgrade yoetz`` and
retains exact pins; those need an explicit requirement replacement. Pre-rename 0.3 development
builds instead install a lower bound and parse ``<tool>/bin/yoetz --version``. Both paths must
reach an exact, same-version forwarder to ``finishup``:

- its version equals the repository-root version, and it depends on ``finishup==<version>``;
- every root extra is re-exported as ``finishup[<extra>]==<version>`` (uv tool receipts record
  ``yoetz[<extra>]``), and ``PACKAGE_EXTRAS`` in ``src/finishup/adapters/package_upgrade.py``,
  the one set ``upgrade`` carries over from a receipt, names exactly the root extras;
- it declares exactly one console script, ``yoetz = finishup.cli.entry:main``. Declaring
  ``finishup`` there too would make ``uv tool install finishup`` fail beside a ``yoetz`` tool;
- the npm launchers carry the same version, and the transitional one delegates to ``yoetz``.

``--dist`` additionally inspects a built wheel and sdist without extracting them. The gate reads
only repository files and the named directory; it performs no network or package-manager call.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import Final, cast

_ROOT: Final = Path(__file__).resolve().parents[1]
_TRANSITIONAL: Final = Path("release/transitional-yoetz")
# Frozen legacy identifier (ADR-048): the distribution, launcher and import name released
# installations upgrade and run through.
_LEGACY_NAME: Final = "yoetz"
_PACKAGE_NAME: Final = "finishup"
_ENTRY_POINT: Final = "finishup.cli.entry:main"
# The extras ``upgrade`` carries over from a uv tool receipt, read statically (never imported).
_EXTRAS_SOURCE: Final = Path("src/finishup/adapters/package_upgrade.py")
_EXTRAS_CONSTANT: Final = "PACKAGE_EXTRAS"
_SHIM_MODULES: Final = frozenset(
    {
        "yoetz/__init__.py",
        "yoetz/__main__.py",
        "yoetz/adapters/__init__.py",
        "yoetz/adapters/release_runtime.py",
        "yoetz/cli/__init__.py",
        "yoetz/cli/entry.py",
    }
)
_NPM_FORBIDDEN_FIELDS: Final = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "scripts",
)


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def _load_json(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("not_an_object")
    return cast(dict[str, object], value)


def _project(document: Mapping[str, object]) -> dict[str, object]:
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError("project_table_missing")
    return cast(dict[str, object], project)


def _upgrade_extras(path: Path) -> frozenset[str] | None:
    """Return the literal ``PACKAGE_EXTRAS = frozenset({...})`` set, or None when not literal."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[ast.expr] = []
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == _EXTRAS_CONSTANT and node.value is not None:
                found.append(node.value)
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == _EXTRAS_CONSTANT for t in node.targets):
                found.append(node.value)
        elif isinstance(node, ast.AugAssign):
            # A later in-place rebinding (``PACKAGE_EXTRAS |= ...``) makes the value non-literal.
            if isinstance(node.target, ast.Name) and node.target.id == _EXTRAS_CONSTANT:
                return None
    if len(found) != 1:
        return None
    value = found[0]
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and len(value.args) == 1
        and not value.keywords
    ):
        return None
    try:
        members: object = ast.literal_eval(value.args[0])
    except ValueError, TypeError, MemoryError, RecursionError:
        return None
    if not isinstance(members, (set, tuple, list)):
        return None
    listed = cast(set[object] | tuple[object, ...] | list[object], members)
    if not all(isinstance(member, str) for member in listed):
        return None
    return frozenset(cast(set[str] | tuple[str, ...] | list[str], listed))


def check_sources(root: Path = _ROOT) -> list[str]:
    """Return every lockstep violation between the root project and the transitional sources."""

    errors: list[str] = []
    try:
        primary = _project(_load_toml(root / "pyproject.toml"))
        transitional = _project(_load_toml(root / _TRANSITIONAL / "python/pyproject.toml"))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        return [f"pyproject_unreadable: {type(error).__name__}"]
    version = primary.get("version")
    if not isinstance(version, str) or not version:
        return ["root_version_missing"]
    if primary.get("name") != _PACKAGE_NAME:
        errors.append("root_name_mismatch")
    if transitional.get("name") != _LEGACY_NAME:
        errors.append("transitional_name_mismatch")
    if transitional.get("version") != version:
        errors.append("transitional_version_drift")
    if transitional.get("requires-python") != primary.get("requires-python"):
        errors.append("transitional_requires_python_drift")
    if transitional.get("dependencies") != [f"{_PACKAGE_NAME}=={version}"]:
        errors.append("transitional_dependency_pin_drift")
    root_extras = primary.get("optional-dependencies")
    extras = transitional.get("optional-dependencies")
    expected_extras = {
        extra: [f"{_PACKAGE_NAME}[{extra}]=={version}"]
        for extra in (cast(dict[str, object], root_extras) if isinstance(root_extras, dict) else {})
    }
    if extras != expected_extras:
        errors.append("transitional_extras_drift")
    try:
        upgrade_extras = _upgrade_extras(root / _EXTRAS_SOURCE)
    except OSError, SyntaxError, ValueError:
        upgrade_extras = None
    if upgrade_extras is None:
        errors.append("upgrade_extras_unreadable")
    elif upgrade_extras != frozenset(expected_extras):
        errors.append("upgrade_extras_drift")
    if primary.get("scripts") != {_PACKAGE_NAME: _ENTRY_POINT}:
        errors.append("root_scripts_not_exactly_finishup")
    if transitional.get("scripts") != {_LEGACY_NAME: _ENTRY_POINT}:
        errors.append("transitional_scripts_not_exactly_yoetz")
    try:
        if (root / "LICENSE").read_bytes() != (
            root / _TRANSITIONAL / "python/LICENSE"
        ).read_bytes():
            errors.append("transitional_license_drift")
    except OSError:
        errors.append("transitional_license_missing")
    source = root / _TRANSITIONAL / "python/src"
    present = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if frozenset(present) != _SHIM_MODULES:
        errors.append("transitional_shim_members_unexpected")
    errors.extend(_check_npm(root, version))
    return errors


def _check_npm(root: Path, version: str) -> list[str]:
    errors: list[str] = []
    try:
        primary = _load_json(root / "support/npm-launcher/package.json")
        transitional = _load_json(root / _TRANSITIONAL / "npm/package.json")
        launcher = (root / _TRANSITIONAL / "npm/bin/yoetz.js").read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        return [f"npm_package_unreadable: {type(error).__name__}"]
    if primary.get("version") != version:
        errors.append("npm_version_drift")
    if transitional.get("name") != _LEGACY_NAME:
        errors.append("transitional_npm_name_mismatch")
    if transitional.get("version") != version:
        errors.append("transitional_npm_version_drift")
    if transitional.get("bin") != {_LEGACY_NAME: "./bin/yoetz.js"}:
        errors.append("transitional_npm_bin_mismatch")
    if transitional.get("private") is not False:
        errors.append("transitional_npm_not_public")
    if transitional.get("repository") != primary.get("repository"):
        errors.append("transitional_npm_repository_drift")
    if any(field in transitional for field in _NPM_FORBIDDEN_FIELDS):
        errors.append("transitional_npm_not_delegation_only")
    if "yoetz==${version}" not in launcher or '"--force"' in launcher:
        errors.append("transitional_npm_delegation_unexpected")
    return errors


def _entry_point_sections(text: str) -> dict[str, dict[str, str]]:
    """Parse ``entry_points.txt`` strictly: sections of ``name = object`` lines only."""

    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = sections.setdefault(stripped[1:-1], {})
            continue
        name, separator, value = stripped.partition("=")
        if current is None or not separator:
            raise ValueError("entry_points_malformed")
        current[name.strip()] = value.strip()
    return sections


def check_dist(dist: Path, version: str) -> list[str]:
    """Inspect one built transitional wheel and sdist without extracting either."""

    wheels = sorted(dist.glob(f"{_LEGACY_NAME}-*.whl"))
    sdists = sorted(dist.glob(f"{_LEGACY_NAME}-*.tar.gz"))
    if [path.name for path in wheels] != [f"{_LEGACY_NAME}-{version}-py3-none-any.whl"]:
        return ["transitional_wheel_missing_or_ambiguous"]
    if [path.name for path in sdists] != [f"{_LEGACY_NAME}-{version}.tar.gz"]:
        return ["transitional_sdist_missing_or_ambiguous"]
    errors: list[str] = []
    dist_info = f"{_LEGACY_NAME}-{version}.dist-info/"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = {name for name in archive.namelist() if not name.endswith("/")}
        modules = {name for name in names if not name.startswith(dist_info)}
        if frozenset(modules) != _SHIM_MODULES:
            errors.append("transitional_wheel_members_unexpected")
        try:
            entry_points = archive.read(f"{dist_info}entry_points.txt").decode("utf-8")
            metadata = archive.read(f"{dist_info}METADATA")
        except KeyError:
            return [*errors, "transitional_wheel_metadata_missing"]
    if _entry_point_sections(entry_points) != {"console_scripts": {_LEGACY_NAME: _ENTRY_POINT}}:
        errors.append("transitional_wheel_scripts_not_exactly_yoetz")
    message = BytesParser(policy=compat32).parsebytes(metadata)
    if message.get("Name") != _LEGACY_NAME or message.get("Version") != version:
        errors.append("transitional_wheel_identity_mismatch")
    requirements = message.get_all("Requires-Dist") or []
    if f"{_PACKAGE_NAME}=={version}" not in requirements:
        errors.append("transitional_wheel_dependency_pin_missing")
    with tarfile.open(sdists[0], mode="r:gz") as archive:
        prefix = f"{_LEGACY_NAME}-{version}/"
        members = {member.name for member in archive.getmembers() if member.isfile()}
    expected = {
        f"{prefix}{name}" for name in ("PKG-INFO", "LICENSE", "README.md", "pyproject.toml")
    } | {f"{prefix}src/{name}" for name in _SHIM_MODULES}
    if members != expected:
        errors.append("transitional_sdist_members_unexpected")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the transitional yoetz distributions stay in lockstep (ADR-048)."
    )
    parser.add_argument(
        "--dist", type=Path, help="Directory holding the built transitional wheel and sdist."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = check_sources()
    if not errors and args.dist is not None:
        version = cast(str, _project(_load_toml(_ROOT / "pyproject.toml"))["version"])
        try:
            errors = check_dist(cast(Path, args.dist), version)
        except OSError, zipfile.BadZipFile, tarfile.TarError:
            errors = ["transitional_dist_unreadable"]
    if errors:
        for error in errors:
            print(f"check_transitional_yoetz: FAIL ({error})", file=sys.stderr)
        return 1
    print("check_transitional_yoetz: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
