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
declared paths the walk cannot fully vouch for: anything inside VCS metadata or a dependency
environment or tool cache (compared only in part), a bytecode file, or a saved FinishUP receipt or
export. When a task declares an output there, no command can be shown to have left it unchanged.
"""

from __future__ import annotations

import re
from typing import Final

from finishup.domain.write_scope import finishup_artifact_name

__all__ = [
    "BYTECODE_CACHE_DIRECTORY",
    "SHALLOW_DIRECTORY_NAMES",
    "VCS_METADATA_DIRECTORIES",
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
    "workspace_effect_annotation",
    "workspace_effect_from_annotation",
    "workspace_effect_from_result_summary",
]

WORKSPACE_EFFECT_KEY: Final = "workspace_effect"
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


def result_summary_with_workspace_effect(summary: str, effect: object) -> str:
    """Append the closed workspace suffix to an observed result summary when *effect* is known."""

    if type(effect) is not str or effect not in _SUMMARY_WORDS:
        return summary
    return f"{summary} (workspace {_SUMMARY_WORDS[effect]})"


def workspace_effect_from_result_summary(summary: object) -> str | None:
    """Read back the workspace effect ``result_summary_with_workspace_effect`` wrote, or ``None``."""

    if type(summary) is not str:
        return None
    match = _SUMMARY_SUFFIX_RE.search(summary)
    return None if match is None else _SUMMARY_EFFECTS[match.group(1)]


def workspace_effect_annotation(effect: object) -> str | None:
    """The exact evidence description carrying *effect* for an already recorded call."""

    if type(effect) is not str or effect not in WORKSPACE_EFFECTS:
        return None
    return f"{WORKSPACE_EFFECT_ANNOTATION_PREFIX}{effect}"


def workspace_effect_from_annotation(description: object) -> str | None:
    """Read back the effect ``workspace_effect_annotation`` wrote, or ``None``."""

    if type(description) is not str or not description.startswith(
        WORKSPACE_EFFECT_ANNOTATION_PREFIX
    ):
        return None
    effect = description[len(WORKSPACE_EFFECT_ANNOTATION_PREFIX) :]
    return effect if effect in WORKSPACE_EFFECTS else None


def bytecode_artifact_name(name: str) -> bool:
    """A file name the interpreter writes into ``__pycache__`` (a ``.pyc`` or its temporary)."""

    return _BYTECODE_RE.match(name) is not None


def saved_artifact_name(name: str) -> bool:
    """A saved FinishUP receipt or export file name (ADR-042); the walk never records one."""

    lowered = name.lower()
    return ("receipt" in lowered or "export" in lowered) and finishup_artifact_name(name)


def path_beyond_workspace_fingerprint(value: object) -> bool:
    """Whether a declared path lies where the workspace fingerprint cannot vouch for it.

    Inside VCS metadata or a dependency environment or tool cache (each compared only in part), a
    bytecode file in ``__pycache__``, or a saved FinishUP receipt or export name. A path is split on ``/`` and ``\\`` only; no filesystem is
    read, so replay never depends on the environment.
    """

    if type(value) is not str or not value:
        return False
    parts = [part for part in re.split(r"[\\/]+", value) if part not in {"", "."}]
    if parts and saved_artifact_name(parts[-1]):
        return True
    for index, part in enumerate(parts):
        if part in VCS_METADATA_DIRECTORIES:
            return True
        if part in SHALLOW_DIRECTORY_NAMES and index + 1 < len(parts):
            # Only the first level is compared, and a declared delivery there is unusual enough
            # that the whole directory is treated as unvouched (the conservative direction).
            return True
        if part == BYTECODE_CACHE_DIRECTORY and bytecode_artifact_name(parts[-1]):
            return True
    return False
