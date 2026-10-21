"""Keep host state out of an explicitly selected HOME workspace (#1161).

These are read exclusions, never observation or disclosure authority. Ordinary project
roots retain their existing selection rules. Git pathspecs and direct reads share this list.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from finishup.domain.repository_excerpt import credential_name_patterns, credential_named_bytes

_PRIVATE_TREES: Final = (
    ".git",
    ".codex",
    ".claude",
    ".cursor",
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".kube",
    ".docker",
    ".config",
    ".local",
    ".cache",
    ".npm",
    ".t3",
    ".password-store",
    ".agents/plugins/finishup",
    ".agents/skills/finishup",
    ".agents/plugins/yoetz",
    ".agents/skills/yoetz",
    "Library",
    "AppData",
)
_PRIVATE_FILES: Final = ("auth.json", "auth.toml", "oauth.json", "tokens.json")
_PRIVATE_HOME_PREFIXES: Final = (".codex", ".claude", ".cursor", ".finishup", ".yoetz", ".yz-")
_PRIVATE_HOME_FILES: Final = (".gitconfig", ".bash_history", ".zsh_history", ".python_history")


def home_private_path(root: Path, relative: bytes) -> bool:
    """Lexical, case-insensitive exclusion, including not-yet-created paths."""

    if root != Path.home():
        return False
    path = relative.decode("utf-8", errors="surrogateescape").casefold().rstrip("/")
    return (
        credential_named_bytes(relative)
        or any(
            path == tree.casefold() or path.startswith(tree.casefold() + "/")
            for tree in _PRIVATE_TREES
        )
        or path.rsplit("/", 1)[-1] in _PRIVATE_FILES
        or path.split("/", 1)[0].startswith(_PRIVATE_HOME_PREFIXES)
        or path in _PRIVATE_HOME_FILES
    )


def home_private_pathspecs(root: Path) -> tuple[str, ...]:
    """Negative Git pathspecs exclude tracked state as well as untracked state."""

    if root != Path.home():
        return ()
    return (
        *(f":(top,exclude,icase,literal){tree}" for tree in _PRIVATE_TREES),
        *(f":(top,exclude,icase,literal){name}" for name in _PRIVATE_HOME_FILES),
        *(f":(top,exclude,glob,icase){prefix}*" for prefix in _PRIVATE_HOME_PREFIXES),
        *(f":(top,exclude,glob,icase){prefix}*/**" for prefix in _PRIVATE_HOME_PREFIXES),
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
