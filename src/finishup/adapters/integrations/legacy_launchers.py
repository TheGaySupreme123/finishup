"""Launcher spellings a pre-rename host registration may name (ADR-048).

Yoetz 0.1-0.2 rendered host hooks and MCP entries that launch the ``yoetz`` console script (or
``python -m yoetz``). FinishUP ships that script as a deprecated alias beside ``finishup`` in the
same scripts directory, so an entry naming either spelling of this installation's launcher still
launches it. An entry naming another installation's launcher is FinishUP's only when a managed
marker recorded that exact launcher under its frozen ``yoetz_launcher`` key; ``recorded_launcher``
accepts such a marker value only when it names a FinishUP launcher under either spelling.

This module never resolves a path or reads the filesystem: it compares launcher tuples only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, cast

from finishup.adapters.integrations.launcher import valid_launcher
from finishup.legacy_names import LAUNCHER_NAME, LAUNCHER_NAMES, LEGACY_LAUNCHER_NAME

__all__ = ["launcher_aliases", "recorded_launcher"]

_ALIASES: Final = {LAUNCHER_NAME: LEGACY_LAUNCHER_NAME, LEGACY_LAUNCHER_NAME: LAUNCHER_NAME}


def launcher_aliases(launcher: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Return ``launcher`` followed by the other spelling of the same installation, if any.

    A console script ``<dir>/finishup`` pairs with ``<dir>/yoetz`` (and the reverse); the module
    entrypoint ``<python> -m finishup`` pairs with ``<python> -m yoetz``. Any other launcher has
    no alias. ``launcher`` must already be a valid rendered launcher.
    """

    executable = Path(launcher[0])
    if len(launcher) == 1 and executable.name in _ALIASES:
        return launcher, (str(executable.with_name(_ALIASES[executable.name])),)
    if len(launcher) == 3 and launcher[1] == "-m" and launcher[2] in _ALIASES:
        return launcher, (launcher[0], "-m", _ALIASES[launcher[2]])
    return (launcher,)


def recorded_launcher(value: object) -> tuple[str, ...] | None:
    """Accept one marker-recorded launcher that names a FinishUP launcher, else ``None``.

    ``value`` is the JSON list a self-consistent managed marker holds under ``yoetz_launcher``.
    The executable's name (or the module after ``-m``) must be ``finishup`` or ``yoetz``.
    """

    if type(value) is not list:
        return None
    launcher = tuple(cast(list[object], value))
    if not valid_launcher(launcher):
        return None
    parts = cast(tuple[str, ...], launcher)
    if len(parts) == 1 and Path(parts[0]).name in LAUNCHER_NAMES:
        return parts
    if len(parts) == 3 and parts[1] == "-m" and parts[2] in LAUNCHER_NAMES:
        return parts
    return None
