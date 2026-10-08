"""Which observed writes change the work under test (tb4n2 R4, issue #1018, ADR-042).

An observed edit is one of four classes:

* ``deliverable`` — a file an obligation declares as its output (decided in the kernel from the
  declared delivered set, never here);
* ``workspace`` — any other path in the workspace, and a real write outside it (an installed
  package the task told the agent to patch);
* ``scratch`` — a temporary location outside the workspace (``/tmp`` and the platform temp
  roots): working notes the delivered work never reads;
* ``yoetz_owned`` — Yoetz's own material: a receipt or export the agent saved (``yoetz_receipt.md``),
  Yoetz's state directory, and the packaged Yoetz plugin and skill trees.

Only ``deliverable`` and ``workspace`` writes make an earlier verification stale. The rule is
lexical: paths are normalized as strings and never resolved through the filesystem, so ``..`` can
not climb out of a temporary root while still reading as inside it. Every class here is a closed
token; no path ever leaves this module.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterable
from typing import Final, Literal

__all__ = [
    "NON_COUNTING_WRITE_SCOPES",
    "WRITE_SCOPES",
    "WriteClass",
    "classify_write_path",
    "edit_write_scope",
    "non_counting_path",
    "scratch_path",
]

WriteClass = Literal["workspace", "outside_workspace", "scratch", "yoetz_owned"]
# The hook's closed ``write_scope`` structural fact: absent for an edit that stays in the
# workspace, otherwise the class every named path shares (``outside_workspace`` wins).
WRITE_SCOPES: Final = frozenset({"outside_workspace", "scratch", "yoetz_owned"})
# Write scopes that never make an earlier verification stale and never count as acting.
NON_COUNTING_WRITE_SCOPES: Final = frozenset({"scratch", "yoetz_owned"})

# Scratch roots every supported OS reserves for temporary files (issue E6, tb4n1: 28 of 33
# attempts flagged only `/tmp` logs). `/dev/` stays wholly exempt below for device targets.
TEMP_ROOTS: Final = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm")
# macOS per-user temporary directory: `/var/folders/<a>/<b>/T` (the `C` cache sibling is not
# temporary). `/var` is a symlink to `/private/var`, so both spellings name the same directory.
_MACOS_USER_TEMP: Final = re.compile(r"^/(?:private/)?var/folders/[^/]+/[^/]+/T(?:/|$)")
# WSL 2: the Windows per-user and system temporary directories as mounted under /mnt/<drive>.
_WSL_WINDOWS_TEMP: Final = re.compile(
    r"^/mnt/[a-z]/(?:users/[^/]+/appdata/local/temp|windows/temp)(?:/|$)", re.IGNORECASE
)
# The last component of an environment temp directory must name temporary space.
_TEMP_NAME: Final = re.compile(r"te?mp|scratch", re.IGNORECASE)
# A Yoetz receipt or export the agent saved as a file (tb4n2 cad S `/app/yoetz_receipt.md`,
# lake D `/app/output/yoetz_receipt.json`).
_YOETZ_ARTIFACT_NAME: Final = re.compile(
    r"^yoetz[-_.]?(?:receipt|export)s?(?:[-_.][a-z0-9]+)*\.(?:md|markdown|json|txt|text)$",
    re.IGNORECASE,
)
# Packaged Yoetz trees a host installation writes into a repository (generated, never the work).
_YOETZ_TREES: Final = (".agents/plugins/yoetz", ".agents/skills/yoetz")


def _normalize(path: str) -> str:
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def process_temp_roots(workspace: str | None) -> tuple[str, ...]:
    """This process's own temporary directory roots, from the environment only.

    ``TMPDIR``, ``TEMP`` and ``TMP`` are read lexically and never probed: ``tempfile.gettempdir``
    touches the filesystem, can fall back to the working directory and raises when no directory
    is usable. These values are host environment, so a root that is the filesystem root, contains
    the home directory, or is or contains the workspace is never trusted as scratch space.
    """

    home = os.environ.get("HOME")
    guarded = [posixpath.normpath(home)] if home and home.startswith("/") else []
    if workspace is not None and workspace.startswith("/"):
        guarded.append(posixpath.normpath(workspace))
    candidates: set[str] = set()
    for name in ("TMPDIR", "TEMP", "TMP"):
        raw = os.environ.get(name)
        if not raw or not raw.startswith("/") or "\x00" in raw:
            continue
        normalized = posixpath.normpath(raw)
        # Only a directory named as temporary space is trusted: a TMPDIR pointed at a
        # deliverable location (``/results``) must not hide real writes there.
        if _TEMP_NAME.search(posixpath.basename(normalized)) is None:
            continue
        candidates.add(normalized)
    return tuple(
        root
        for root in sorted(candidates)
        if root != "/" and not any(_under(path, root) for path in guarded)
    )


def scratch_path(path: str, workspace: str | None = None, *, environment: bool = True) -> bool:
    """Whether an absolute path lands in a temporary or device directory.

    ``environment=False`` uses only the fixed roots, never ``TMPDIR``/``TEMP``/``TMP``: a pure,
    replay-stable answer for the kernel.
    """

    normalized = _normalize(path)
    if normalized.startswith("/dev/"):
        return True
    if _MACOS_USER_TEMP.match(normalized) or _WSL_WINDOWS_TEMP.match(normalized):
        return True
    roots = (*TEMP_ROOTS, *(process_temp_roots(workspace) if environment else ()))
    return any(_under(normalized, root) for root in roots)


def non_counting_path(path: str) -> bool:
    """Whether a declared path is one the lexical rule could call scratch or Yoetz-owned.

    Pure (fixed temp roots only). The kernel uses it to keep the stale rule conservative: when a
    declared deliverable could itself be classified scratch or Yoetz-owned, no edit is exempt.
    """

    if type(path) is not str or not path:
        return False
    normalized = _normalize(path)
    if _YOETZ_ARTIFACT_NAME.match(posixpath.basename(normalized)) is not None:
        return True
    padded = "/" + normalized.lstrip("/")
    if any(f"/{tree}/" in padded + "/" for tree in _YOETZ_TREES):
        return True
    return normalized.startswith("/") and scratch_path(normalized, environment=False)


def _yoetz_owned(normalized: str, owned_roots: Iterable[str]) -> bool:
    if _YOETZ_ARTIFACT_NAME.match(posixpath.basename(normalized)) is not None:
        return True
    padded = "/" + normalized.lstrip("/")
    if any(f"/{tree}/" in padded + "/" for tree in _YOETZ_TREES):
        return True
    return any(
        root.startswith("/") and _under(normalized, _normalize(root)) for root in owned_roots
    )


def classify_write_path(
    path: str,
    *,
    workspace: str | None,
    inside: bool | None,
    owned_roots: Iterable[str] = (),
) -> WriteClass:
    """The class of one written path.

    ``inside`` is the caller's lexical answer to "is this path under the workspace root"
    (``None`` when no workspace is known: only a Yoetz-owned path is named then, and every other
    path is ``workspace``, since a temporary directory may be the workspace itself). A relative
    path is read against the workspace.
    """

    if type(path) is not str or not path:
        return "workspace"
    normalized = _normalize(path)
    if _yoetz_owned(normalized, owned_roots):
        return "yoetz_owned"
    absolute = normalized.startswith("/")
    if not absolute or inside is not False:
        # Inside the workspace (or unknown: no workspace root to compare with) every write counts.
        # A workspace may itself sit under a temporary root, and a log file there may be a
        # deliverable, so neither is ever exempt by location or name alone.
        return "workspace"
    if scratch_path(normalized, workspace):
        return "scratch"
    # A real write outside the workspace keeps counting and stays disclosed.
    return "outside_workspace"


def edit_write_scope(classes: Iterable[WriteClass]) -> str | None:
    """The closed ``write_scope`` fact for one edit naming *classes*, or ``None`` (workspace).

    ``outside_workspace`` wins over everything; any workspace path makes the edit an ordinary
    workspace edit; only an edit whose every path is scratch or Yoetz-owned is named so, and
    Yoetz-owned wins over scratch when both occur. An edit naming no path is a workspace edit.
    """

    seen = frozenset(classes)
    if not seen:
        return None
    if "outside_workspace" in seen:
        return "outside_workspace"
    if "workspace" in seen:
        return None
    return "yoetz_owned" if "yoetz_owned" in seen else "scratch"
