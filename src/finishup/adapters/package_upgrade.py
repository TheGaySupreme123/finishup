"""Bounded uv package-manager boundary for explicit upgrades."""

from __future__ import annotations

import os
import stat
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from packaging.version import InvalidVersion, Version

from finishup import __version__
from finishup.adapters.release_runtime import installation_prefix, release_update_lock
from finishup.legacy_names import LAUNCHER_NAME, LEGACY_LAUNCHER_NAME

# An explicit lower bound replaces an old exact installation pin and forbids downgrade.
PACKAGE_UPGRADE_ARGV: Final = ("uv", "tool", "install", "--upgrade", f"finishup>={__version__}")
# The uv tools this boundary upgrades in place: each tool directory, its receipt requirement and
# its console script share one name. ``yoetz`` is a tool installed before the rename; it upgrades
# through the transitional ``yoetz`` distribution, which installs the same-version ``finishup``
# and keeps the ``yoetz`` command its hosts run (ADR-048). The tool is never renamed here.
_UV_TOOL_NAMES: Final = frozenset({LAUNCHER_NAME, LEGACY_LAUNCHER_NAME})
# The optional extras the ``finishup`` distribution declares; the transitional ``yoetz``
# distribution re-exports the same set (ADR-048). A receipt naming only these carries them over,
# both on an in-place upgrade and in the move to the new name. The one definition:
# scripts/check_transitional_yoetz.py asserts it equals the repository-root pyproject extras.
PACKAGE_EXTRAS: Final = frozenset({"semantic-openai", "portable-recovery"})
# uv tool receipts are a few hundred bytes; anything larger is not one this boundary trusts.
UV_RECEIPT_MAX_BYTES: Final = 64 * 1024
# ``[tool]`` keys a plain receipt records, and the resolution keys accepted only when empty.
_PLAIN_TOOL_KEYS: Final = frozenset({"requirements", "python", "entrypoints"})
_RESOLUTION_KEYS: Final = frozenset(
    {"options", "constraints", "overrides", "build-constraint-dependencies"}
)


@dataclass(frozen=True)
class PlainToolReceipt:
    """The choices a plain uv tool receipt records: sorted known extras and the Python request."""

    extras: tuple[str, ...]
    python: str | None


def read_uv_receipt(prefix: Path) -> str:
    """Read ``<prefix>/uv-receipt.toml`` as one bounded regular file.

    Never follows a final symlink, never blocks on a FIFO or device, and never reads more than
    ``UV_RECEIPT_MAX_BYTES + 1`` bytes. Raises OSError or ValueError (including
    UnicodeDecodeError) when the receipt is missing, not a regular file, oversized or not UTF-8.
    """

    fd = os.open(
        prefix / "uv-receipt.toml",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > UV_RECEIPT_MAX_BYTES:
            raise ValueError("uv_receipt_unsafe")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(UV_RECEIPT_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > UV_RECEIPT_MAX_BYTES:
        raise ValueError("uv_receipt_unsafe")
    return raw.decode("utf-8")


def plain_uv_tool_receipt(receipt: str, name: str) -> PlainToolReceipt | None:
    """Parse a uv tool receipt that records nothing beyond ``name``, known extras and Python.

    None unless the ``[tool]`` table holds only requirements, python and entrypoints (resolution
    keys such as options, constraints, overrides or build constraints only when empty), with
    exactly one ``name`` requirement carrying only a specifier and extras from
    ``PACKAGE_EXTRAS``. Any other recorded choice would be lost by a command rebuilt from this
    receipt, so callers refuse or ask the user instead of guessing.
    """

    try:
        document = tomllib.loads(receipt)
    except tomllib.TOMLDecodeError, RecursionError:
        return None
    tool = document.get("tool")
    if type(tool) is not dict:
        return None
    table = cast(dict[str, object], tool)
    if set(table) - _PLAIN_TOOL_KEYS - _RESOLUTION_KEYS:
        return None
    if any(table.get(key) for key in _RESOLUTION_KEYS):
        return None
    requirements = table.get("requirements")
    if type(requirements) is not list:
        return None
    listed = cast(list[object], requirements)
    if len(listed) != 1 or type(listed[0]) is not dict:
        return None
    requirement = cast(dict[str, object], listed[0])
    if requirement.get("name") != name or set(requirement) - {"name", "specifier", "extras"}:
        return None
    extras = requirement.get("extras", [])
    if type(extras) is not list:
        return None
    selected = cast(list[object], extras)
    if any(type(value) is not str or value not in PACKAGE_EXTRAS for value in selected):
        return None
    interpreter = table.get("python")
    if interpreter is not None and (
        type(interpreter) is not str
        or not interpreter
        or interpreter.startswith("-")
        or len(interpreter) > 4096
        or any(ord(character) < 32 for character in interpreter)
    ):
        return None
    return PlainToolReceipt(
        extras=tuple(sorted(set(cast(list[str], selected)))),
        python=interpreter,
    )


def _upgrade_command(prefix: Path, name: str = LAUNCHER_NAME) -> tuple[str, ...] | None:
    """Preserve supported extras; refuse custom resolution instead of silently losing it."""

    try:
        receipt = plain_uv_tool_receipt(read_uv_receipt(prefix), name)
    except OSError, ValueError:
        return None
    if receipt is None:
        return None
    selected = f"[{','.join(receipt.extras)}]" if receipt.extras else ""
    python_arguments = () if receipt.python is None else ("--python", receipt.python)
    return (*PACKAGE_UPGRADE_ARGV[:-1], *python_arguments, f"{name}{selected}>={__version__}")


def execute_package_upgrade() -> str:
    """Upgrade this ambient uv installation; never a source or pinned test installation."""
    from finishup.config.paths import isolated_root

    if isolated_root() is not None:
        return "refused_isolated_runtime"
    try:
        prefix = installation_prefix()
        probe = subprocess.run(  # noqa: S603 - fixed local uv metadata command
            ("uv", "tool", "dir"),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if probe.returncode != 0 or len(probe.stdout) > 4096:
            return "package_manager_unavailable"
        tool_root = Path(os.fsdecode(probe.stdout).strip())
        if not tool_root.is_absolute():
            return "refused_non_uv_tool_runtime"
        tool = next(
            (
                name
                for name in sorted(_UV_TOOL_NAMES)
                if prefix.resolve() == (tool_root / name).resolve()
            ),
            None,
        )
        if tool is None:
            return "refused_non_uv_tool_runtime"
        with release_update_lock(prefix):
            command = _upgrade_command(prefix, tool)
            if command is None:
                return "refused_custom_uv_installation"
            # Never capture arbitrary package-manager output or copy it to structural errors.
            result = subprocess.run(  # noqa: S603 - closed argv, same supported carrier
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if result.returncode != 0:
                return "package_command_failed"
            verified = subprocess.run(  # noqa: S603 - invoking installation's exact launcher
                (str(prefix / "bin" / tool), "--version"),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            if verified.returncode != 0 or len(verified.stdout) > 256:
                return "package_version_unverified"
            try:
                text = verified.stdout.decode("ascii", errors="strict").strip()
                installed = Version(text)
            except UnicodeError, InvalidVersion:
                return "package_version_unverified"
            previous = Version(__version__)
            if installed < previous:
                return "package_version_unverified"
            return (
                "package_already_current" if installed == previous else "package_command_succeeded"
            )
    except subprocess.TimeoutExpired:
        return "outcome_unknown"
    except OSError, ValueError, InvalidVersion:
        return "package_manager_unavailable"
