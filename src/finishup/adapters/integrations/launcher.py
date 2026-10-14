"""Exact FinishUP launcher resolution shared by native host carriers.

A rendered host artifact (Cursor hooks, Claude Code hooks and plugin-owned MCP) must name the
installation that rendered it. Launching a bare ``finishup`` from the host's PATH lets the bridge,
the hook process, and the long-running service come from different installations on one
machine; the 2026-08-27 Claude dogfood hit exactly that split-brain. Every native renderer
therefore binds an absolute executable (plus fixed arguments for the ``python -m finishup`` entry
point) and records it in its managed marker.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import finishup

__all__ = ["invoking_launcher", "resolve_finishup_launcher", "valid_launcher"]


def valid_launcher(launcher: object) -> bool:
    """Validate one rendered launcher: an absolute executable plus fixed arguments."""

    if type(launcher) is not tuple or not launcher:
        return False
    parts = cast(tuple[object, ...], launcher)
    if any(
        type(part) is not str
        or not part
        or any(ord(char) < 32 or ord(char) == 127 for char in part)
        for part in parts
    ):
        return False
    return Path(cast(str, parts[0])).is_absolute()


def resolve_finishup_launcher(
    candidate: Path | str | Sequence[str] | None = None,
) -> tuple[str, ...]:
    """Resolve the exact launcher command used by rendered native host hooks and MCP entries.

    A plain path or name resolves to the console-script executable. A sequence
    preserves an explicit invocation such as the documented ``python -m finishup``
    module entrypoint (ADR-007): its first element is resolved as the
    executable and the remaining arguments are kept verbatim.
    """

    arguments: tuple[str, ...] = ()
    if isinstance(candidate, Sequence) and not isinstance(candidate, str):
        if not candidate or any(type(part) is not str for part in candidate):
            raise ValueError("finishup_executable_unavailable")
        arguments = tuple(candidate[1:])
        candidate = candidate[0]
    if candidate is None:
        discovered = shutil.which("finishup")
    else:
        candidate_text = os.fspath(candidate)
        raw = Path(candidate_text).expanduser()
        separators = (os.sep,) if os.altsep is None else (os.sep, os.altsep)
        explicit_path = isinstance(candidate, Path) or any(
            separator in candidate_text for separator in separators
        )
        discovered = str(raw) if explicit_path else shutil.which(candidate_text)
    if discovered is None:
        raise ValueError("finishup_executable_unavailable")
    try:
        resolved = Path(discovered).resolve(strict=True)
    except OSError as exc:
        raise ValueError("finishup_executable_unavailable") from exc
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or not resolved.is_absolute()
        or any(ord(char) < 32 or ord(char) == 127 for char in str(resolved))
    ):
        raise ValueError("finishup_executable_unavailable")
    launcher = (str(resolved), *arguments)
    if not valid_launcher(launcher):
        raise ValueError("finishup_executable_unavailable")
    return launcher


def invoking_launcher() -> str | tuple[str, ...] | None:
    """Preserve the exact invocation that produced this process.

    A console-script invocation binds hooks to that executable, and the
    documented ``python -m finishup`` entrypoint (ADR-007) binds an equivalent
    module invocation of the same interpreter rather than falling back to an
    ambient PATH lookup that may name an unrelated installation.
    """

    argv0 = Path(sys.argv[0])
    if argv0.name == "finishup":
        return sys.argv[0]
    try:
        package_main = (Path(finishup.__file__).parent / "__main__.py").resolve()
        module_invoked = argv0.resolve() == package_main
    except OSError:
        module_invoked = False
    if module_invoked:
        return (sys.executable, "-m", "finishup")
    return None
