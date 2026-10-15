"""Exact FinishUP launcher resolution shared by native host carriers.

A rendered host artifact (Cursor hooks, Claude Code hooks and plugin-owned MCP) must name the
installation that rendered it. Launching a bare ``finishup`` from the host's PATH lets the bridge,
the hook process, and the long-running service come from different installations on one
machine; the 2026-08-27 Claude dogfood hit exactly that split-brain. Every native renderer
therefore binds an absolute executable (plus fixed arguments for the ``python -m finishup`` entry
point) and records it in its managed marker.

Installations from before the rename (ADR-048) run the deprecated ``yoetz`` alias, installed by the
transitional ``yoetz`` distribution beside the ``finishup`` console script, or ``python -m yoetz``.
Both are recognized as the invoking launcher, and a newly rendered artifact binds the FinishUP
spelling of the same installation whenever that installation provides it.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast

import finishup
from finishup.legacy_names import LAUNCHER_NAME, LEGACY_LAUNCHER_NAME

__all__ = [
    "LEGACY_MODULE_NAME",
    "invoked_through_legacy_alias",
    "invoking_launcher",
    "resolve_finishup_launcher",
    "valid_launcher",
]

# Frozen legacy identifier (ADR-048): the import package of the transitional ``yoetz``
# distribution, which ``python -m yoetz`` host registrations from before the rename run.
LEGACY_MODULE_NAME: Final = "yoetz"


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
        discovered = shutil.which(LAUNCHER_NAME)
        if discovered is None:
            # Only the deprecated alias is on PATH (an upgraded ``yoetz`` tool, ADR-048). It binds
            # the FinishUP console script of this runtime only when it is provably this runtime's
            # own alias; a pre-rename ``yoetz`` or an unrelated program stays unbound.
            legacy = shutil.which(LEGACY_LAUNCHER_NAME)
            discovered = None if legacy is None else _runtime_alias_sibling(Path(legacy))
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


def _alias_sibling(alias: Path) -> str | None:
    """Return the ``finishup`` console script installed beside a deprecated ``yoetz`` alias.

    The transitional ``yoetz`` distribution depends on ``finishup`` in the same environment, so
    the alias's resolved scripts directory also holds ``finishup``. Anything else stays unbound.
    """

    try:
        sibling = alias.resolve(strict=True).with_name(LAUNCHER_NAME)
        if sibling.is_file() and os.access(sibling, os.X_OK):
            return str(sibling)
    except OSError:
        return None
    return None


def _runtime_alias_sibling(alias: Path) -> str | None:
    """Return this runtime's ``finishup`` script for a PATH ``yoetz`` proven to be its alias.

    A ``yoetz`` found on PATH binds only when its resolved path is this interpreter's ``yoetz``
    script, proven by the transitional ``yoetz`` distribution's RECORD, and the ``finishup``
    script beside it is proven by this package's RECORD (ADR-048). A ``yoetz`` from a release
    before the rename, from another environment, or from an unrelated program never binds, so a
    host artifact can never name a different installation (#604).
    """

    from finishup.adapters.integrations import codex_launcher

    alias_proof = codex_launcher.installed_launcher(LEGACY_LAUNCHER_NAME)
    launcher_proof = codex_launcher.installed_launcher(LAUNCHER_NAME)
    if alias_proof is None or launcher_proof is None:
        return None
    try:
        proven_alias = Path(alias_proof[0]).resolve(strict=True)
        proven_launcher = Path(launcher_proof[0]).resolve(strict=True)
        if alias.resolve(strict=True) != proven_alias:
            return None
    except OSError:
        return None
    if proven_launcher != proven_alias.with_name(LAUNCHER_NAME):
        return None
    return str(proven_launcher)


def _legacy_module_spelling(argv0: Path) -> bool:
    return argv0.name == "__main__.py" and argv0.parent.name == LEGACY_MODULE_NAME


def _legacy_module_main(argv0: Path) -> bool:
    """Whether argv0 is the transitional ``yoetz/__main__.py`` installed beside this package."""

    if not _legacy_module_spelling(argv0):
        return False
    try:
        site = Path(finishup.__file__).resolve().parent.parent
        return argv0.resolve().parent.parent == site
    except OSError:
        return False


def invoked_through_legacy_alias(argv0: str | None = None) -> bool:
    """Whether this process was started through a deprecated ``yoetz`` spelling (ADR-048).

    Recognizes the alias console script and ``python -m yoetz`` by spelling alone. It selects the
    deprecation notice and legacy-launcher reporting; it never changes what a command does.
    """

    path = Path(sys.argv[0] if argv0 is None else argv0)
    return path.name == LEGACY_LAUNCHER_NAME or _legacy_module_spelling(path)


def invoking_launcher() -> str | tuple[str, ...] | None:
    """Preserve the exact invocation that produced this process.

    A console-script invocation binds hooks to that executable, and the
    documented ``python -m finishup`` entrypoint (ADR-007) binds an equivalent
    module invocation of the same interpreter rather than falling back to an
    ambient PATH lookup that may name an unrelated installation.

    The deprecated ``yoetz`` alias (ADR-048) binds the ``finishup`` console script of the same
    installation when present, else the alias itself; ``python -m yoetz`` binds
    ``python -m finishup`` of the same interpreter, which imports this package.
    """

    argv0 = Path(sys.argv[0])
    if argv0.name == LAUNCHER_NAME:
        return sys.argv[0]
    if argv0.name == LEGACY_LAUNCHER_NAME:
        return _alias_sibling(argv0) or sys.argv[0]
    try:
        package_main = (Path(finishup.__file__).parent / "__main__.py").resolve()
        module_invoked = argv0.resolve() == package_main or _legacy_module_main(argv0)
    except OSError:
        module_invoked = False
    if module_invoked:
        return (sys.executable, "-m", LAUNCHER_NAME)
    return None
