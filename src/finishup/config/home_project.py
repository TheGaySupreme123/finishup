"""Explicit, process-local permission to treat exactly the user's home as a project.

Native artifacts carry this choice as an exact launcher argument. It grants no observation,
provider, or disclosure authority, and does not bypass filesystem safety checks.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_HOME_PROJECT: ContextVar[Path | None] = ContextVar("finishup_home_project", default=None)


def allowed_home_project() -> Path | None:
    return _HOME_PROJECT.get()


def home_project_allowed(path: Path, *, home: Path | None = None) -> bool:
    actual_home = Path.home() if home is None else home
    return path != Path(path.anchor) and path == actual_home and path == allowed_home_project()


@contextmanager
def home_project_scope(project: Path | None) -> Generator[None]:
    """Permit only an exact lexical home; ``None`` clears inherited permission for setup."""

    selected = None
    if project is not None:
        candidate = Path(os.path.abspath(project.expanduser()))
        if candidate == Path.home() and candidate != Path(candidate.anchor):
            selected = candidate
    token = _HOME_PROJECT.set(selected)
    try:
        yield
    finally:
        _HOME_PROJECT.reset(token)
