"""Absolute paths from ``git rev-parse`` on every Git FinishUP supports, without ``--path-format``.

``git rev-parse --path-format=absolute`` only exists since Git 2.31. An older Git (2.25 on Ubuntu
20.04, 2.30 on Debian 11, and the images built on them, such as
``condaforge/miniforge3:24.9.2-0``) does not reject the unknown option: ``rev-parse`` echoes any
argument it does not recognise as a flag, so the output gains one extra line (the option itself)
and the paths that follow it come back in their default, possibly relative, form. Every caller
then failed closed, and the control handshake closed on every connection once the vault was
ready (#1040).

Callers therefore ask only queries whose answer is absolute on every supported Git
(``--show-toplevel``, ``--absolute-git-dir``) or, for ``--git-common-dir``, which has no absolute
spelling before 2.31, resolve its relative answer against the directory Git ran in (``-C`` or the
subprocess working directory). Git before 2.31 prints that answer relative to the directory it
was started in (``../.git`` from a subdirectory, ``.`` inside a bare repository) and an absolute
path for a linked worktree. ``absolute_rev_parse_path`` reproduces what
``--path-format=absolute`` prints: a relative answer is joined to that directory and the result is
canonicalised with the same forgiving ``realpath`` Git applies, so a commitment derived from it
does not depend on the Git version.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["absolute_rev_parse_path"]


def absolute_rev_parse_path(raw: bytes, cwd: Path) -> Path:
    """Return the absolute, canonical form of one path ``git rev-parse`` printed at ``cwd``.

    ``cwd`` must be the directory Git ran in. Raises ``ValueError`` for an empty answer, an answer
    carrying a NUL or newline, an answer that is an option Git echoed back, or a ``cwd`` that is
    not absolute; callers already map ``ValueError`` to their own closed refusal.
    """

    if not raw or b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise ValueError("git_path_invalid")
    if raw.startswith(b"-"):
        # A path Git prints never starts with a dash; an echoed option such as
        # ``--path-format=absolute`` does.
        raise ValueError("git_path_invalid")
    if not cwd.is_absolute():
        raise ValueError("git_cwd_not_absolute")
    printed = Path(os.fsdecode(raw))
    joined = printed if printed.is_absolute() else cwd / printed
    return Path(os.path.realpath(joined))
