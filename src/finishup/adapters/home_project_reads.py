"""Keep host state out of an explicitly selected HOME workspace (#1161).

These are read exclusions, never observation or disclosure authority. Ordinary project
roots retain their existing selection rules. Git pathspecs and direct reads share this rule.

In a home folder, dot-named files and directories are overwhelmingly host, tool and credential
state (``.ssh``, ``.aws``, ``.config``, ``.cargo/credentials.toml``, ``.vault-token``, ``.boto``,
a nested ``backup/.ssh`` and so on), and no fixed name list can enumerate them. So every path
with a dot-named component at any depth is excluded, the rule the reviewer's direct-read
selector already applies in every root. Named non-dot host trees and credential file names
complete the exclusion; all of it applies to tracked and untracked paths alike.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from finishup.domain.repository_excerpt import credential_name_patterns, credential_named_bytes

# Top-level non-dot trees that hold host or application state (macOS, Windows, Linux snaps).
_PRIVATE_TREES: Final = ("Library", "AppData", "snap")
# Local authentication files at any depth, beyond the ADR-031 credential-name heuristic.
_PRIVATE_FILES: Final = ("auth.json", "auth.toml", "oauth.json", "tokens.json")
_FOLDED_TREES: Final = tuple(tree.casefold() for tree in _PRIVATE_TREES)
_FOLDED_FILES: Final = frozenset(name.casefold() for name in _PRIVATE_FILES)


def home_private_path(root: Path, relative: bytes) -> bool:
    """Lexical, case-insensitive exclusion, including not-yet-created paths."""

    if root != Path.home():
        return False
    parts = relative.decode("utf-8", errors="surrogateescape").casefold().strip("/").split("/")
    return (
        credential_named_bytes(relative)
        or any(part.startswith(".") for part in parts)
        or parts[0] in _FOLDED_TREES
        or parts[-1] in _FOLDED_FILES
    )


def home_private_pathspecs(root: Path) -> tuple[str, ...]:
    """Negative Git pathspecs exclude tracked state as well as untracked state."""

    if root != Path.home():
        return ()
    return (
        # A dot-named entry at any depth, and everything beneath a dot-named directory.
        ":(top,exclude,glob)**/.*",
        ":(top,exclude,glob)**/.*/**",
        *(f":(top,exclude,icase,literal){tree}" for tree in _PRIVATE_TREES),
        *(f":(top,exclude,glob,icase)**/{name}" for name in _PRIVATE_FILES),
        *(f":(top,exclude,glob,icase)**/{name}" for name in credential_name_patterns()),
    )


def home_read_arguments(root: Path, arguments: Sequence[str]) -> tuple[str, ...]:
    """Constrain Git's path-reading commands before they open tracked content."""

    private = home_private_pathspecs(root)
    if not private:
        return tuple(arguments)
    skip = False
    for argument in arguments:
        if skip:
            skip = False
            continue
        if argument in {"-c", "-C", "--git-dir", "--work-tree"}:
            skip = True
            continue
        if argument.startswith("-"):
            continue
        if argument in {"diff", "ls-files", "status"}:
            return (*arguments, *(("--",) if "--" not in arguments else ()), *private)
        break
    return tuple(arguments)
