"""The closed workspace-effect fact of one observed tool call (PR #1080, ADR-033 amendment).

The hook compares a fingerprint of the project workspace taken before the host runs a call with
one taken after it (``adapters.workspace_fingerprint``) and sends one closed structural token,
``workspace_effect``, on the call's ``PostToolUse`` envelope:

* ``unchanged`` - both snapshots were complete and nothing in the workspace differs;
* ``changed`` - an entry was added, removed or modified;
* ``unavailable`` - FinishUP could not establish the comparison (no pre-call snapshot, a call the
  host reports as still running, a workspace beyond the walk bounds, an unreadable directory).

Materialization appends the token to the observed result's summary in one closed suffix form
(`` (workspace unchanged)``, `` (workspace changed)``, `` (workspace unverified)``), and the kernel
reads it back only from service-stamped observation results. Only ``unchanged`` can make an
observed command non-material for the closing review; ``unavailable`` reads exactly like
``changed`` there. No path, digest or command text is part of the fact.

**A later delivery of the same call** (PR #1080 round 6). A host call can be delivered twice: a
Codex session-stream copy carries no fingerprint, and a hook pass may repeat. When the call's
result is already recorded with another fact (or none), the service appends one observation-
authored evidence row under the call's action whose description is exactly
``Observed workspace effect=<token>`` (``workspace_effect_annotation``). Rows stay immutable; the
kernel folds every fact of the call: ``unchanged`` only when some delivery said ``unchanged`` and
none said ``changed`` or ``unavailable``.

**What the fingerprint does not fully walk.** ``path_beyond_workspace_fingerprint`` names the
declared paths the walk cannot vouch for, by the same rules the walk applies
(``adapters.workspace_fingerprint`` takes its constants from here): a path inside a VCS store the
walk records by identity only (``VCS_OPAQUE_DIRECTORIES``) or a VCS bookkeeping file it skips
(``vcs_bookkeeping_name``), anything below the first level of a dependency environment or tool
cache, a bytecode file in ``__pycache__``, or a saved FinishUP receipt or export. When a task
declares an output there, no command can be shown to have left it unchanged. A path outside the
workspace root is out of scope for the walk and for this rule.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Sequence
from typing import Final, cast

from finishup.domain.write_scope import WRITE_SCOPES, finishup_artifact_name

__all__ = [
    "BYTECODE_CACHE_DIRECTORY",
    "SHALLOW_DIRECTORY_NAMES",
    "VCS_BOOKKEEPING_FILES",
    "VCS_METADATA_DIRECTORIES",
    "VCS_OPAQUE_DIRECTORIES",
    "WORKSPACE_CHANGED",
    "WORKSPACE_EFFECTS",
    "WORKSPACE_EFFECT_ANNOTATION_PREFIX",
    "WORKSPACE_EFFECT_KEY",
    "WORKSPACE_UNAVAILABLE",
    "WORKSPACE_UNCHANGED",
    "bytecode_artifact_name",
    "path_beyond_workspace_fingerprint",
    "result_summary_with_workspace_effect",
    "saved_artifact_name",
    "vcs_bookkeeping_name",
    "workspace_effect_annotation",
    "workspace_effect_from_annotation",
    "workspace_effect_from_result_summary",
]

WORKSPACE_EFFECT_KEY: Final = "workspace_effect"
WORKSPACE_WRITE_SCOPES_KEY: Final = "workspace_write_scopes"
_SCOPES_RE: Final = re.compile(
    r" \(workspace writes ([a-z_,]+)\)(?= \(workspace (?:unchanged|changed|unverified)\)\Z|\Z)"
)


def workspace_write_scopes(value: object) -> tuple[str, ...] | None:
    """A bounded canonical set of existing closed classes; never paths or free text."""

    if type(value) not in {tuple, list}:
        return None
    items = cast(tuple[object, ...] | list[object], value)
    if len(items) > len(WRITE_SCOPES) or any(
        type(item) is not str or item not in WRITE_SCOPES for item in items
    ):
        return None
    scopes = cast(tuple[str, ...], tuple(items))
    return tuple(sorted(scopes)) if len(set(scopes)) == len(scopes) else None


def workspace_write_scopes_from_summary(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    match = _SCOPES_RE.search(value)
    if match is None:
        return None
    return () if match.group(1) == "none" else workspace_write_scopes(match.group(1).split(","))


def _scope_suffix(scopes: object) -> str:
    known = workspace_write_scopes(scopes)
    return "" if known is None else f" (workspace writes {','.join(known) or 'none'})"


WORKSPACE_UNCHANGED: Final = "unchanged"
WORKSPACE_CHANGED: Final = "changed"
WORKSPACE_UNAVAILABLE: Final = "unavailable"
WORKSPACE_EFFECTS: Final = frozenset(
    {WORKSPACE_UNCHANGED, WORKSPACE_CHANGED, WORKSPACE_UNAVAILABLE}
)

# The summary word for each effect. ``unavailable`` reads "unverified" to a person: the workspace
# may well be unchanged, FinishUP just could not establish it.
_SUMMARY_WORDS: Final = {
    WORKSPACE_UNCHANGED: "unchanged",
    WORKSPACE_CHANGED: "changed",
    WORKSPACE_UNAVAILABLE: "unverified",
}
_SUMMARY_EFFECTS: Final = {word: effect for effect, word in _SUMMARY_WORDS.items()}
_SUMMARY_SUFFIX_RE: Final = re.compile(r" \(workspace (unchanged|changed|unverified)\)\Z", re.ASCII)

# The exact description of the evidence row that carries a later delivery's fact for a call whose
# result is already recorded. The materializer writes it and the kernel reads it from these
# constants, so the two cannot drift; any other description is not a workspace fact.
WORKSPACE_EFFECT_ANNOTATION_PREFIX: Final = "Observed workspace effect="

# VCS metadata directories. The walk enters them but skips their exact internal churn (object
# stores, index, reflogs, refs; see ``adapters.workspace_fingerprint``); configuration, hooks and
# attribute files inside them are compared like any other file.
VCS_METADATA_DIRECTORIES: Final = frozenset({".git", ".hg", ".svn"})
# Inside VCS metadata: the internal stores recorded by identity only, at any depth (Git's object
# store, reflogs, refs, LFS objects, fsmonitor state, submodule and worktree administration,
# ``git fsck --lost-found`` output, Cursor's checkpoint store; Mercurial's store and caches;
# Subversion's pristine copies), and the bookkeeping files skipped (pointer files, packed refs,
# commit/merge messages, maintenance logs and locks; and, directly in the metadata root, any index
# file: Git's own, its split and temporary indexes, and the private index copies tools keep there).
# The walk and ``path_beyond_workspace_fingerprint`` both read these, so they cannot drift.
VCS_OPAQUE_DIRECTORIES: Final = frozenset(
    {
        "objects",
        "logs",
        "refs",
        "lfs",
        "rr-cache",
        "fsmonitor--daemon",
        "modules",
        "worktrees",
        "lost-found",
        "cursor",
        "store",
        "cache",
        "wcache",
        "pristine",
        "tmp",
    }
)
VCS_BOOKKEEPING_FILES: Final = frozenset(
    {
        "HEAD",
        "ORIG_HEAD",
        "FETCH_HEAD",
        "MERGE_HEAD",
        "MERGE_MSG",
        "MERGE_MODE",
        "MERGE_RR",
        "AUTO_MERGE",
        "REBASE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "COMMIT_EDITMSG",
        "TAG_EDITMSG",
        "packed-refs",
        "shallow",
        "gc.log",
        "gc.pid",
        "dirstate",
        "last-message.txt",
        "wlock",
        "lock",
        "wc.db",
        "wc.db-journal",
    }
)
_VCS_BOOKKEEPING_PREFIXES: Final = ("undo.",)
_VCS_BOOKKEEPING_SUFFIXES: Final = (".lock",)
# Dependency environments and tool caches. Only their first level is compared (files by content,
# subdirectories by identity): a full walk of a typical ``node_modules`` or virtual environment
# (tens to hundreds of thousands of entries) would exceed the whole snapshot budget on every call.
SHALLOW_DIRECTORY_NAMES: Final = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
    }
)
# Python's bytecode cache: walked, but the interpreter's own ``.pyc`` writes and the directory's
# creation are not workspace changes. Any other file inside it is compared.
BYTECODE_CACHE_DIRECTORY: Final = "__pycache__"
_BYTECODE_RE: Final = re.compile(r".+\.py[co](?:\.[0-9]+)?\Z", re.ASCII)

# Where one directory sits in the walk: ordinary, inside VCS metadata (its root, or deeper), the
# first level of a dependency environment or tool cache, or inside a bytecode cache.
_PLACE_NORMAL: Final = 0
_PLACE_VCS: Final = 1
_PLACE_SHALLOW: Final = 2
_PLACE_BYTECODE: Final = 3
_PLACE_VCS_ROOT: Final = 4


def result_summary_with_workspace_effect(
    summary: str, effect: object, scopes: object = None
) -> str:
    """Append the closed workspace suffix to an observed result summary when *effect* is known."""

    if type(effect) is not str or effect not in _SUMMARY_WORDS:
        return summary
    return f"{summary}{_scope_suffix(scopes)} (workspace {_SUMMARY_WORDS[effect]})"


def workspace_effect_from_result_summary(summary: object) -> str | None:
    """Read back the workspace effect ``result_summary_with_workspace_effect`` wrote, or ``None``."""

    if type(summary) is not str:
        return None
    match = _SUMMARY_SUFFIX_RE.search(summary)
    return None if match is None else _SUMMARY_EFFECTS[match.group(1)]


def workspace_effect_annotation(effect: object, scopes: object = None) -> str | None:
    """The exact evidence description carrying *effect* for an already recorded call."""

    if type(effect) is not str or effect not in WORKSPACE_EFFECTS:
        return None
    return f"{WORKSPACE_EFFECT_ANNOTATION_PREFIX}{effect}{_scope_suffix(scopes)}"


def workspace_effect_from_annotation(description: object) -> str | None:
    """Read back the effect ``workspace_effect_annotation`` wrote, or ``None``."""

    if type(description) is not str or not description.startswith(
        WORKSPACE_EFFECT_ANNOTATION_PREFIX
    ):
        return None
    effect = description[len(WORKSPACE_EFFECT_ANNOTATION_PREFIX) :].split(" (", 1)[0]
    scopes = workspace_write_scopes_from_summary(description)
    return effect if description == workspace_effect_annotation(effect, scopes) else None


def bytecode_artifact_name(name: str) -> bool:
    """A file name the interpreter writes into ``__pycache__`` (a ``.pyc`` or its temporary)."""

    return _BYTECODE_RE.match(name) is not None


def saved_artifact_name(name: str) -> bool:
    """A saved FinishUP receipt or export file name (ADR-042); the walk never records one."""

    lowered = name.lower()
    return ("receipt" in lowered or "export" in lowered) and finishup_artifact_name(name)


def vcs_bookkeeping_name(name: str, *, in_root: bool) -> bool:
    """A VCS bookkeeping file the walk skips (``in_root``: directly in the metadata root)."""

    return (
        name in VCS_BOOKKEEPING_FILES
        or name.startswith(_VCS_BOOKKEEPING_PREFIXES)
        or name.endswith(_VCS_BOOKKEEPING_SUFFIXES)
        or (in_root and "index" in name)
    )


def _normalized(path: str) -> str:
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def _beyond_walk(parts: Sequence[str], *, directory: bool) -> bool:
    """Whether the walk leaves this root-relative path uncompared, by its own rules."""

    place = _PLACE_NORMAL
    for index, name in enumerate(parts):
        if index + 1 == len(parts) and not directory:
            # The declared file itself.
            if saved_artifact_name(name):
                return True
            if place in {_PLACE_VCS, _PLACE_VCS_ROOT}:
                return vcs_bookkeeping_name(name, in_root=place == _PLACE_VCS_ROOT)
            return place == _PLACE_BYTECODE and bytecode_artifact_name(name)
        if place in {_PLACE_VCS, _PLACE_VCS_ROOT}:
            if name in VCS_OPAQUE_DIRECTORIES:
                return True  # recorded by identity only
            place = _PLACE_VCS
        elif place == _PLACE_SHALLOW:
            return True  # below the first level: recorded by identity only
        elif place == _PLACE_NORMAL:
            if name in VCS_METADATA_DIRECTORIES:
                place = _PLACE_VCS_ROOT
            elif name in SHALLOW_DIRECTORY_NAMES:
                place = _PLACE_SHALLOW
            elif name == BYTECODE_CACHE_DIRECTORY:
                place = _PLACE_BYTECODE
    # A declared directory that is itself VCS metadata or a dependency environment is compared
    # only in part.
    return place in {_PLACE_VCS_ROOT, _PLACE_SHALLOW}


def path_beyond_workspace_fingerprint(
    value: object, *, directory: bool = False, workspace_root: str | None = None
) -> bool:
    """Whether a declared path lies inside the workspace where the fingerprint cannot vouch for it.

    The walk's own rules, applied to the part of the path below the workspace root: inside a VCS
    store recorded by identity only or a VCS bookkeeping file the walk skips, below the first
    level of a dependency environment or tool cache, a bytecode file in ``__pycache__``, or a
    saved FinishUP receipt or export name; a declared ``directory`` that is VCS metadata or a
    dependency environment itself. Files directly inside a dependency environment and VCS files
    such as ``config`` or ``hooks/*`` are compared, so they are not beyond it.

    A relative value is read against the root, and one that leaves it is out of scope. An absolute
    value is judged below ``workspace_root`` (the task's absolute workspace root) and is out of
    scope outside it. With no known root, any ancestor of an absolute value may be the root, so it
    is beyond the walk when it would be for any of them (the conservative direction). Lexical
    only: the path is split on ``/`` and ``\\``, no filesystem is read, so replay never depends on
    the environment.
    """

    if type(value) is not str or not value:
        return False
    path = _normalized(value.replace("\\", "/"))
    if not path.startswith("/"):
        parts = [part for part in path.split("/") if part not in {"", "."}]
        if parts and parts[0] == "..":
            return False  # outside the root
        return _beyond_walk(parts, directory=directory)
    root = None
    if type(workspace_root) is str and workspace_root.startswith("/"):
        root = _normalized(workspace_root)
    if root is not None:
        if path != root and not path.startswith(root.rstrip("/") + "/"):
            return False  # outside the root
        below = path[len(root) :]
        return _beyond_walk([part for part in below.split("/") if part], directory=directory)
    parts = [part for part in path.split("/") if part]
    return any(_beyond_walk(parts[index:], directory=directory) for index in range(len(parts)))
