"""Bounded uv package-manager boundary for explicit upgrades."""

from __future__ import annotations

import os
import subprocess
import tomllib
from pathlib import Path
from typing import Final, cast

from packaging.version import InvalidVersion, Version

from yoetz import __version__
from yoetz.adapters.release_runtime import (
    hash_bytecode_environment,
    installation_prefix,
    release_update_lock,
)

# An explicit lower bound replaces an old exact installation pin and forbids downgrade.
# --compile-bytecode, run with SOURCE_DATE_EPOCH in the child's environment: uv then writes
# checked-hash bytecode, which the release runtime verifies and reuses for its sealed copy, so
# the first serving start after an upgrade does not compile the whole package (ADR-007).
PACKAGE_UPGRADE_ARGV: Final = (
    "uv",
    "tool",
    "install",
    "--upgrade",
    "--compile-bytecode",
    f"yoetz>={__version__}",
)


def _upgrade_command(prefix: Path) -> tuple[str, ...] | None:
    """Preserve supported extras; refuse custom resolution instead of silently losing it."""

    try:
        tool = tomllib.loads((prefix / "uv-receipt.toml").read_text())["tool"]
        requirements = tool["requirements"]
        options: object = tool.get("options") or {}
        # uv records `--compile-bytecode` (which the documented install and this upgrade use)
        # as an option; any other recorded option is a custom resolution to keep, not drop.
        if (
            not isinstance(options, dict)
            or set(cast(dict[str, object], options)) - {"compile-bytecode"}
            or type(cast(dict[str, object], options).get("compile-bytecode", True)) is not bool
            or len(requirements) != 1
        ):
            return None
        requirement = requirements[0]
        if requirement.get("name") != "yoetz" or set(requirement) - {"name", "specifier", "extras"}:
            return None
        extras = requirement.get("extras", [])
        if not isinstance(extras, list):
            return None
        selected_extras = cast(list[object], extras)
        if any(
            type(value) is not str or value not in {"semantic-openai", "portable-recovery"}
            for value in selected_extras
        ):
            return None
    except OSError, ValueError, KeyError, TypeError:
        return None
    selected = f"[{','.join(sorted(set(cast(list[str], selected_extras))))}]" if extras else ""
    interpreter = tool.get("python")
    if interpreter is not None and (
        type(interpreter) is not str
        or not interpreter
        or interpreter.startswith("-")
        or len(interpreter) > 4096
        or any(ord(character) < 32 for character in interpreter)
    ):
        return None
    python_arguments = () if interpreter is None else ("--python", interpreter)
    return (*PACKAGE_UPGRADE_ARGV[:-1], *python_arguments, f"yoetz{selected}>={__version__}")


def execute_package_upgrade() -> str:
    """Upgrade this ambient uv installation; never a source or pinned test installation."""
    from yoetz.config.paths import isolated_root

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
        if not tool_root.is_absolute() or prefix.resolve() != (tool_root / "yoetz").resolve():
            return "refused_non_uv_tool_runtime"
        with release_update_lock(prefix):
            command = _upgrade_command(prefix)
            if command is None:
                return "refused_custom_uv_installation"
            # Never capture arbitrary package-manager output or copy it to structural errors.
            # umask 022: the replacement must not be writable by anyone but its owner, whatever
            # the invoking shell's umask (Ubuntu and Fedora default to 0002).
            result = subprocess.run(  # noqa: S603 - closed argv, same supported carrier
                command,
                check=False,
                env=hash_bytecode_environment(os.environ),
                umask=0o022,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if result.returncode != 0:
                return "package_command_failed"
            verified = subprocess.run(  # noqa: S603 - invoking installation's exact launcher
                (str(prefix / "bin" / "yoetz"), "--version"),
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
