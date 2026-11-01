"""Executable-backed setup discovery; configuration directories alone prove nothing."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from finishup.adapters.integrations.codex_discovery import (
    default_codex_home,
    discover_codex_binaries,
)

type SetupHost = Literal["codex", "claude", "cursor-ide", "cursor-cli"]


@dataclass(frozen=True, slots=True)
class HostInstallation:
    host: SetupHost
    executable: Path
    version: str | None
    config_root: Path
    label: str
    support: str = "untested"


def probe_version(executable: Path) -> str | None:
    try:
        completed = subprocess.run(
            (str(executable), "--version"),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode:
        return None
    text = completed.stdout[:4096].decode("utf-8", errors="replace").strip()
    # Cursor Agent CLI uses date-based versions; the IDE and Claude use SemVer.
    match = re.search(r"(?<!\w)(\d+\.\d+\.\d+(?:[-+][\w.-]+)?|\d{4}\.\d{2}\.\d{2}[\w.-]*)", text)
    return None if match is None else match.group(1)


def host_config_root(
    host: SetupHost, *, home: Path | None = None, environ: Mapping[str, str] | None = None
) -> Path:
    environment = os.environ if environ is None else environ
    base = Path.home() if home is None else home
    if host == "codex":
        for key in ("CODEX_HOME", "CODEX_TESTING_HOME"):
            value = environment.get(key)
            if value and value.strip():
                return Path(value).expanduser().absolute()
        return base / ".codex"
    if host == "claude":
        value = environment.get("CLAUDE_CONFIG_DIR")
        return Path(value).expanduser().absolute() if value else base / ".claude"
    if host == "cursor-cli":
        value = environment.get("CURSOR_CONFIG_DIR")
        if value:
            return Path(value).expanduser().absolute()
        xdg = environment.get("XDG_CONFIG_HOME")
        if sys.platform.startswith(("linux", "freebsd")) and xdg:
            return Path(xdg).expanduser().absolute() / "cursor"
    return base / ".cursor"


def discover_hosts(
    *,
    version_probe: Callable[[Path], str | None] = probe_version,
    which: Callable[[str], str | None] = shutil.which,
    home: Path | None = None,
) -> tuple[HostInstallation, ...]:
    rows = [
        HostInstallation(
            "codex",
            Path(binary.executable_path),
            binary.reported_version,
            default_codex_home() or host_config_root("codex", home=home),
            "Codex",
            binary.compatibility,
        )
        for binary in discover_codex_binaries()
        if "testing" not in binary.executable_path.lower()
    ]
    candidates: list[tuple[SetupHost, str | None, str]] = [
        ("claude", which("claude"), "Claude Code"),
        ("cursor-ide", which("cursor"), "Cursor IDE"),
        ("cursor-cli", which("cursor-agent") or which("agent"), "Cursor Agent CLI"),
    ]
    if sys.platform == "darwin" and not candidates[1][1]:
        candidates[1] = (
            "cursor-ide",
            "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
            "Cursor IDE",
        )
    for host, raw, label in candidates:
        if raw is None:
            continue
        path = Path(raw).expanduser()
        # The generic executable name belongs to Cursor only when its resolved installation
        # identifies Cursor Agent. Never label an unrelated `agent --version` as Cursor.
        if (
            host == "cursor-cli"
            and path.name == "agent"
            and "cursor" not in str(path.resolve()).lower()
        ):
            continue
        if not path.is_file() or not os.access(path, os.X_OK):
            continue
        version = version_probe(path)
        if version is None:
            continue
        rows.append(
            HostInstallation(
                host, path.resolve(), version, host_config_root(host, home=home), label
            )
        )
    return tuple(rows)
