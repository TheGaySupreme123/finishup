"""Keep host state out of an explicitly selected HOME workspace (#1161).

These are read exclusions, never observation or disclosure authority. Ordinary project
roots retain their existing selection rules. Git pathspecs and direct reads share this rule.

In a home folder, dot-named files and directories are overwhelmingly host, tool and credential
state (``.ssh``, ``.aws``, ``.config``, ``.cargo/credentials.toml``, ``.vault-token``, ``.boto``,
a nested ``backup/.ssh`` and so on), and no fixed name list can enumerate them. So every path
with a dot-named component at any depth is excluded, the rule the reviewer's direct-read
selector already applies in every root. Named non-dot host trees (including a copied
``backup/Library``) and credential file names complete the exclusion; all of it applies to
tracked and untracked paths alike.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from finishup.domain.repository_excerpt import credential_name_patterns, credential_named_bytes

# Top-level non-dot trees that hold host or application state (macOS, Windows, Linux snaps).
_PRIVATE_TREES: Final = ("Library", "AppData", "snap")
# Their exact profile names also mark a copy at any depth (`backup/Library/Keychains`). Matching
# is case-sensitive below the top level so project folders such as `src/library` or snapcraft's
# `snap/` stay reviewable.
_COPIED_TREES: Final = ("Library", "AppData")
# Local authentication files at any depth, beyond the ADR-031 credential-name heuristic.
_PRIVATE_FILES: Final = (
    "auth.json",
    "auth.toml",
    "kubeconfig",
    "oauth.json",
    "token.json",
    "tokens.json",
)
_FOLDED_TREES: Final = tuple(tree.casefold() for tree in _PRIVATE_TREES)
_FOLDED_FILES: Final = frozenset(name.casefold() for name in _PRIVATE_FILES)


def home_private_path(root: Path, relative: bytes) -> bool:
    """Lexical exclusion, including not-yet-created paths.

    Any dot component excludes the path. Top-level host trees and credential/auth file names
    match case-insensitively; a copied profile tree below the top level matches only its exact
    name, so project folders such as ``src/library`` stay reviewable.
    """

    if root != Path.home():
        return False
    exact = relative.decode("utf-8", errors="surrogateescape").strip("/").split("/")
    parts = [part.casefold() for part in exact]
    return (
        credential_named_bytes(relative)
        or any(part.startswith(".") for part in parts)
        or parts[0] in _FOLDED_TREES
        or any(part in _COPIED_TREES for part in exact)
        or parts[-1] in _FOLDED_FILES
    )


def _identity(facts: os.stat_result) -> tuple[int, int]:
    return facts.st_dev, facts.st_ino


def home_private_location(path: str) -> bool:
    """Whether absolute ``path`` lies in the home directory's private state (#1220 review).

    Unlike ``home_private_path`` this decides by identity, not spelling: the home directory is
    found among ``path``'s ancestors by device and inode, so another spelling of it (``/Users/ALICE``
    on a case-insensitive volume, a bind mount) still counts. Each directory beneath it whose name
    folds to a private tree's is compared by identity with the tree's exact spelling and, when it
    is that tree, judged under that spelling. Ancestors are examined without following a link;
    a read beneath one never follows it either. An ancestor that cannot be examined (other than
    one that does not exist) excludes the path.
    """

    home = Path.home()
    try:
        home_identity = _identity(os.stat(home))
    except OSError:
        return False
    parts = path.strip("/").split("/")
    current = ""
    for index in range(len(parts) - 1):
        current += "/" + parts[index]
        try:
            facts = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if _identity(facts) != home_identity:
            continue
        canonical: list[str] = []
        base = current
        remainder = parts[index + 1 :]
        for depth, part in enumerate(remainder):
            name = part
            trees = _PRIVATE_TREES if depth == 0 else _COPIED_TREES
            for tree in trees:
                if tree != part and tree.casefold() == part.casefold():
                    try:
                        same = _identity(os.lstat(f"{base}/{tree}")) == _identity(
                            os.lstat(f"{base}/{part}")
                        )
                    except FileNotFoundError:
                        same = False
                    except OSError:
                        return True
                    if same:
                        name = tree
            canonical.append(name)
            base = f"{base}/{part}"
        relative = "/".join(canonical).encode("utf-8", errors="surrogateescape")
        return home_private_path(home, relative)
    return False


def home_private_pathspecs(root: Path) -> tuple[str, ...]:
    """Negative Git pathspecs exclude tracked state as well as untracked state."""

    if root != Path.home():
        return ()
    return (
        # A dot-named entry at any depth, and everything beneath a dot-named directory.
        ":(top,exclude,glob)**/.*",
        ":(top,exclude,glob)**/.*/**",
        *(f":(top,exclude,icase,literal){tree}" for tree in _PRIVATE_TREES),
        # A copied profile tree at any depth (exact case), and everything beneath it.
        *(f":(top,exclude,glob)**/{tree}" for tree in _COPIED_TREES),
        *(f":(top,exclude,glob)**/{tree}/**" for tree in _COPIED_TREES),
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
