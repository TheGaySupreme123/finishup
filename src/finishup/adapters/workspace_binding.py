"""Bounded workspace-locator selection for host hook ingress.

Cursor and Codex hook processes do not have a stable, documented working
directory across all host surfaces.  This module selects a host-provided
workspace root when one is available, then normalizes that root to the
nearest Git toplevel without invoking Git or following symlinked path
components.

The returned string is transient input for the existing workspace-commitment
boundary.  This module neither logs nor persists it and never interpolates it
into a command.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

__all__ = [
    "MAX_WORKSPACE_LOCATOR_BYTES",
    "canonical_workspace_locator",
    "resolve_workspace_locator",
]

MAX_WORKSPACE_LOCATOR_BYTES: Final = 8_192
_MAX_WORKSPACE_ROOTS: Final = 32
_CURSOR_PROJECT_DIR: Final = "CURSOR_PROJECT_DIR"
_WORKSPACE_ROOTS: Final = "workspace_roots"


def _bounded_text(value: object) -> str | None:
    """Return byte-bounded exact filesystem path text, or reject it."""

    if type(value) is not str:
        return None
    try:
        encoded = os.fsencode(value)
    except UnicodeEncodeError:
        return None
    if not encoded or len(encoded) > MAX_WORKSPACE_LOCATOR_BYTES:
        return None
    # Hook payloads and environment values are user/host-controlled.  Control
    # characters are not valid input to this boundary even though some Unix
    # filesystems permit them in names.
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _home_path(env: Mapping[str, str], cwd: Path) -> Path:
    raw_home = _bounded_text(env.get("HOME"))
    if raw_home is None:
        try:
            return Path.home()
        except RuntimeError:
            return Path(cwd.anchor) if cwd.anchor else cwd
    return _absolute_lexical(raw_home, cwd)


def _absolute_lexical(raw: str, cwd: Path, *, home: Path | None = None) -> Path:
    """Make an absolute, lexical path without resolving symlink components."""

    # Hook callers historically accept ``.`` and ``~``.  Expand only the
    # current user's home supplied to this resolver; do not consult a second
    # ambient environment for host-controlled input.
    if raw == "~":
        raw = os.fspath(home if home is not None else _home_path({}, cwd))
    elif raw.startswith("~/"):
        raw = os.fspath(home if home is not None else _home_path({}, cwd)) + raw[1:]
    path = Path(raw)
    if not path.is_absolute():
        path = cwd / path
    return Path(os.path.normpath(os.fspath(path)))


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _path_components_are_safe(path: Path) -> bool:
    """Reject symlinked ancestors and non-directory path components."""

    current = Path(path.anchor)
    last_index = len(path.parts) - 1
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            facts = current.lstat()
        except FileNotFoundError:
            # Once a component is absent, descendants cannot be existing
            # filesystem entries.  They remain safe lexical fallback text.
            break
        except OSError:
            return False
        if stat.S_ISLNK(facts.st_mode):
            return False
        if index != last_index - 1 and not stat.S_ISDIR(facts.st_mode):
            return False
    return True


def _candidate_path(raw: object, *, cwd: Path, home: Path) -> Path | None:
    if isinstance(raw, os.PathLike):
        raw = os.fspath(cast(os.PathLike[str], raw))
    text = _bounded_text(raw)
    if text is None:
        return None
    try:
        path = _absolute_lexical(text, cwd, home=home)
    except OSError, RuntimeError, ValueError:
        return None
    if path == Path(path.anchor) or path == home:
        return None
    if not _path_components_are_safe(path):
        return None
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        or bool(facts.st_mode & 0o022)
    ):
        return None
    return path


def _git_marker(path: Path) -> bool | None:
    """Return whether ``path/.git`` is a safe Git marker.

    ``None`` means an unsafe marker (currently a symlink or an inaccessible
    entry), which fails closed instead of falling back to a different root.
    """

    marker = path / ".git"
    try:
        facts = marker.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    if stat.S_ISLNK(facts.st_mode):
        return None
    if stat.S_ISDIR(facts.st_mode) or stat.S_ISREG(facts.st_mode):
        if (hasattr(os, "geteuid") and facts.st_uid != os.geteuid()) or facts.st_mode & 0o022:
            return None
        return True
    return None


def _git_toplevel(path: Path, *, home: Path) -> Path | None:
    """Find the nearest safe Git marker, bounded by home and filesystem root."""

    current = path
    while current != Path(current.anchor) and current != home:
        marker = _git_marker(current)
        if marker is None:
            return None
        if marker:
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return path


def _workspace_roots(payload: Mapping[str, object] | None) -> tuple[object, ...] | None:
    if not isinstance(payload, Mapping) or _WORKSPACE_ROOTS not in payload:
        return None
    raw_roots = payload.get(_WORKSPACE_ROOTS)
    if type(raw_roots) is list:
        roots = tuple(cast(list[object], raw_roots))
    elif type(raw_roots) is tuple:
        roots = cast(tuple[object, ...], raw_roots)
    else:
        raise ValueError("workspace_roots_invalid")
    if len(roots) > _MAX_WORKSPACE_ROOTS:
        raise ValueError("workspace_roots_invalid")
    return roots


def _canonical_selected_workspace(selected: Path, *, home: Path) -> str | None:
    root = _git_toplevel(selected, home=home)
    if root is None:
        return None
    try:
        facts = root.lstat()
    except OSError:
        return None
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        or bool(facts.st_mode & 0o022)
    ):
        return None
    return os.fspath(root)


def canonical_workspace_locator(
    explicit: str | os.PathLike[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Canonicalize one explicit workspace for consent and control identity.

    Unlike hook ingress, this helper never consults Cursor payload or
    ``CURSOR_PROJECT_DIR`` precedence. The operator-selected path is normalized
    to the same nearest safe Git root used by hooks; non-Git paths remain exact.
    """

    actual_env: Mapping[str, str] = os.environ if env is None else env
    try:
        cwd = Path.cwd()
    except OSError:
        return None
    home = _home_path(actual_env, cwd)
    selected = _candidate_path(explicit, cwd=cwd, home=home)
    if selected is None:
        return None
    return _canonical_selected_workspace(selected, home=home)


def resolve_workspace_locator(
    explicit: str | os.PathLike[str] | None = None,
    payload: Mapping[str, object] | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve one transient workspace locator for a hook invocation.

    Binding order is ``payload["workspace_roots"]`` → ``CURSOR_PROJECT_DIR``
    → ``explicit``.  A single host root wins directly.  For multiple host
    roots, the deepest root that contains ``CURSOR_PROJECT_DIR`` wins; no
    matching root is an explicit refusal and does not fall through to a less
    trustworthy locator.  The chosen path is normalized to the nearest Git
    toplevel by walking ``.git`` entries (files and directories).  A path with
    no Git marker is returned as its safe, lexical non-Git locator.

    Invalid, home/root, inaccessible, or symlinked paths return ``None``.
    User-controlled path text is byte-bounded without Unicode normalization before any path
    operation, so distinct filesystem spellings cannot alias consent. No shell or Git command is
    executed.
    """

    actual_env: Mapping[str, str] = os.environ if env is None else env
    try:
        cwd = Path.cwd()
    except OSError:
        return None
    home = _home_path(actual_env, cwd)
    try:
        roots = _workspace_roots(payload)
    except ValueError:
        return None
    if roots:
        candidates = tuple(_candidate_path(raw, cwd=cwd, home=home) for raw in roots)
        if any(candidate is None for candidate in candidates):
            return None
        if len(roots) == 1:
            selected = candidates[0]
            assert selected is not None
        else:
            project = _candidate_path(actual_env.get(_CURSOR_PROJECT_DIR), cwd=cwd, home=home)
            if project is None:
                return None
            matching = tuple(
                candidate
                for candidate in candidates
                if candidate is not None and _path_is_under(project, candidate)
            )
            if not matching:
                return None
            # Longest path is the deterministic nearest ancestor.  The
            # lexical byte ordering is a stable tie-breaker for defensive
            # callers that provide duplicate-equivalent roots.
            selected = max(
                matching,
                key=lambda candidate: (len(candidate.parts), os.fsencode(os.fspath(candidate))),
            )
    else:
        raw_project = actual_env.get(_CURSOR_PROJECT_DIR)
        if raw_project is not None and raw_project != "":
            selected = _candidate_path(raw_project, cwd=cwd, home=home)
            if selected is None:
                return None
        else:
            selected = _candidate_path(explicit, cwd=cwd, home=home)
            if selected is None:
                return None

    return _canonical_selected_workspace(selected, home=home)
