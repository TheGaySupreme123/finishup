"""Which observed writes change the work under test (tb4n2 R4, issue #1018, ADR-042).

An observed edit is one of five classes:

* ``deliverable`` — a file an obligation declares as its output (decided in the kernel from the
  declared delivered set, never here);
* ``workspace`` — any other path in the workspace, and a real write outside it (an installed
  package the task told the agent to patch);
* ``scratch`` — a temporary location outside the workspace (``/tmp`` and the platform temp
  roots): working notes the delivered work never reads;
* ``yoetz_owned`` — FinishUP's own material: a receipt or export the agent saved (``finishup_receipt.md``),
  FinishUP's state directory, and the packaged FinishUP plugin and skill trees;
* ``notes`` — the agent's own working notes inside the workspace (``NOTES.md``, ``todo.txt``):
  conventional names that are not source, tests or data (ADR-045). A declared output with such a
  name is a deliverable and keeps counting; a ``.log`` file is never named by its extension, since
  a workspace may itself sit under a temporary root and a log may be the deliverable.

A shell command that writes files (``> f``, ``tee f``, ``sed -i f``, ``cp a f``) is classified by
the same rules; a command whose every write is in the workspace carries the scope ``workspace``
so the kernel counts it as an edit (an observed edit is otherwise a tool call, and
``cat > solve.py <<EOF`` was invisible).

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
    "notes_artifact_name",
    "scratch_overlap",
    "finishup_artifact_name",
    "finishup_tree_overlap",
    "scratch_path",
]

WriteClass = Literal["workspace", "outside_workspace", "scratch", "yoetz_owned", "notes"]
# The hook's closed ``write_scope`` structural fact: absent for an edit-tool call that stays in
# the workspace, otherwise the class every named path shares (``outside_workspace`` wins).
# ``workspace`` appears only on a shell command whose attributable writes are in the workspace
# (ADR-045); an edit tool never reports it.
WRITE_SCOPES: Final = frozenset(
    {"outside_workspace", "scratch", "yoetz_owned", "notes", "workspace"}
)
# Write scopes that never make an earlier verification stale and never count as acting.
NON_COUNTING_WRITE_SCOPES: Final = frozenset({"scratch", "yoetz_owned", "notes"})

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
# A FinishUP receipt or export the agent saved as a file (tb4n2 cad S `/app/finishup_receipt.md`,
# lake D `/app/output/finishup_receipt.json`).
_FINISHUP_ARTIFACT_NAME: Final = re.compile(
    r"^finishup[-_.]?(?:receipt|export)s?(?:[-_.][a-z0-9]+)*\.(?:md|markdown|json|txt|text)$",
    re.IGNORECASE,
)
# Conventional names of the agent's own working notes and logs. Deliberately narrow: a name that
# could also be source, a test, data or documentation the task delivers (``README.md``,
# ``report.md``) is not here, and a declared output with one of these names keeps counting.
_NOTES_NAME: Final = re.compile(
    r"^(?:notes?|todo|todos|scratch|scratchpad|worklog|work[-_]log|progress|journal)"
    r"(?:[-_.][a-z0-9]+)*\.(?:md|markdown|txt|text)$",
    re.IGNORECASE,
)
# Packaged FinishUP trees a host installation writes into a repository (generated, never the work).
_FINISHUP_TREES: Final = (".agents/plugins/finishup", ".agents/skills/finishup")


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


def finishup_artifact_name(path: str) -> bool:
    """Whether a declared path could be classified FinishUP-owned: a receipt or export name, or a
    path in a packaged FinishUP tree (pure; the state and isolation roots are not consulted)."""

    return type(path) is str and bool(path) and _finishup_owned(_normalize(path), ())


def finishup_tree_overlap(path: str) -> bool:
    """Whether a declared path lies in, or is an ancestor of, a packaged FinishUP tree (pure).

    A declared deliverable there (a repository whose product is the FinishUP plugin or skill) is the
    work itself; a saved receipt is not. ``.agents/plugins/finishup`` and ``.agents/skills/finishup`` are
    the trees; the bare ``.agents``, ``.agents/plugins`` and ``.agents/skills`` directories contain
    them. A sibling such as ``.agents/skills/project-skill`` does not overlap.
    """

    if type(path) is not str or not path:
        return False
    padded = "/" + _normalize(path).lstrip("/") + "/"
    if any(f"/{tree}/" in padded for tree in _FINISHUP_TREES):
        return True
    return padded.endswith(("/.agents/", "/.agents/plugins/", "/.agents/skills/"))


def notes_artifact_name(path: str) -> bool:
    """Whether a path has a conventional notes or log name (pure; declared outputs override it)."""

    return type(path) is str and bool(path) and _notes_name(_normalize(path))


def _notes_name(normalized: str) -> bool:
    return _NOTES_NAME.match(posixpath.basename(normalized)) is not None


def scratch_overlap(path: str) -> bool:
    """Whether a declared absolute path lies under, or contains, a fixed temporary root (pure)."""

    if type(path) is not str or not path.startswith("/"):
        return False
    normalized = _normalize(path)
    return scratch_path(normalized, environment=False) or any(
        _under(root, normalized) for root in TEMP_ROOTS
    )


def _finishup_owned(normalized: str, owned_roots: Iterable[str]) -> bool:
    if _FINISHUP_ARTIFACT_NAME.match(posixpath.basename(normalized)) is not None:
        return True
    padded = "/" + normalized.lstrip("/")
    if any(f"/{tree}/" in padded + "/" for tree in _FINISHUP_TREES):
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
    (``None`` when no workspace is known: only a FinishUP-owned path is named then, and every other
    path is ``workspace``, since a temporary directory may be the workspace itself). A relative
    path is read against the workspace.
    """

    if type(path) is not str or not path:
        return "workspace"
    normalized = _normalize(path)
    if _finishup_owned(normalized, owned_roots):
        return "yoetz_owned"
    absolute = normalized.startswith("/")
    if not absolute or inside is not False:
        # Inside the workspace (or unknown: no workspace root to compare with) a write counts,
        # except the agent's own conventional notes and logs (``notes``; the kernel lets a
        # declared output with such a name override the class). A workspace may itself sit under
        # a temporary root, so location alone never exempts.
        return "notes" if _notes_name(normalized) else "workspace"
    if scratch_path(normalized, workspace, environment=False):
        return "scratch"
    if scratch_path(normalized, workspace):
        # The process's own TMPDIR is not a misplaced deliverable (no outside claim), but only the
        # fixed roots are named scratch: the kernel can check a declared deliverable against them
        # replay-stably, never against this environment (Codex review round 2).
        return "workspace"
    # A real write outside the workspace keeps counting and stays disclosed.
    return "outside_workspace"


def edit_write_scope(classes: Iterable[WriteClass]) -> str | None:
    """The closed ``write_scope`` fact for one edit naming *classes*, or ``None`` (workspace).

    ``outside_workspace`` wins over everything; any workspace path, or a mix of scratch and
    FinishUP-owned paths, makes the edit an ordinary workspace edit; only an edit whose every path is
    scratch, or every path FinishUP-owned, is named so. An edit naming no path is a workspace edit.
    """

    seen = frozenset(classes)
    if not seen:
        return None
    if "outside_workspace" in seen:
        return "outside_workspace"
    if "workspace" in seen or len(seen) > 1:
        # A mixed edit (scratch + FinishUP-owned, notes + anything) keeps counting: one token could
        # not carry both, and the kernel's deliverable precedence is per class (Codex review
        # round 3).
        return None
    return next(iter(seen))
