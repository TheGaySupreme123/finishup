"""The FinishUP full-screen terminal UI and its availability gate.

The gate is the important part of this module. A terminal UI is only ever
allowed to open for a human sitting at a real terminal: stdin and stdout must
both be TTYs, the caller must have asked for an interactive entry point, and no
CI marker may be present. Everything else — pipes, redirects, ``--help``, JSON
output, named protocol operations, the MCP server, and test fixtures — keeps its
existing byte-for-byte behaviour and never sees this code.

``run_tui`` degrades rather than fails: if the optional rendering dependency is
missing for any reason, the caller falls back to the ADR-013 prompt-loop menu,
which is still a complete interface over the same operations.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Final

__all__ = ["TUI_UNAVAILABLE", "tui_available", "tui_supported", "run_tui"]

TUI_UNAVAILABLE: Final = -1
"""Returned by :func:`run_tui` when the interface could not be started at all."""

# Set by any of the usual hosted runners. A CI job that happens to allocate a
# TTY still wants the deterministic output, not a full-screen application.
_CI_MARKERS: Final[tuple[str, ...]] = (
    "CI",
    "CONTINUOUS_INTEGRATION",
    "BUILD_NUMBER",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TEAMCITY_VERSION",
)


def _real_terminal() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except OSError, ValueError:
        return False


def tui_available(environment: Mapping[str, str] | None = None) -> bool:
    """True only for an interactive human terminal that has not opted out.

    ``FINISHUP_TUI=0`` is an explicit opt-out for anyone who prefers the prompt-loop
    menu; ``TERM=dumb`` and any CI marker are treated as automation.
    """

    env: Mapping[str, str] = os.environ if environment is None else environment
    if env.get("FINISHUP_TUI") == "0":
        return False
    if env.get("TERM", "") in {"dumb", ""}:
        return False
    if any(env.get(marker) for marker in _CI_MARKERS):
        return False
    return _real_terminal()


def tui_supported() -> bool:
    """True when the rendering dependency is importable in this installation."""

    from importlib.util import find_spec

    try:
        return find_spec("textual") is not None
    except ImportError, ValueError:
        return False


def run_tui(*, first_run: bool = False, cwd: Path | None = None) -> int:
    """Run the full-screen interface, returning a process exit code.

    Returns :data:`TUI_UNAVAILABLE` when the rendering dependency is not present,
    so the caller can fall back to the prompt-loop menu instead of failing.
    """

    try:
        from finishup.tui.app import FinishUpTui
    except ImportError:
        return TUI_UNAVAILABLE
    application = FinishUpTui(first_run=first_run, cwd=cwd)
    result = application.run()
    return result if isinstance(result, int) else 0
