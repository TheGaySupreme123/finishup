"""A client's keyed claim on its workspace, sent to a FinishUP server on another machine (ADR-051).

A connection to a server on another machine names its workspace by a *claim*, never by a path:

``digest = HMAC-SHA256(claim_salt, "yoetz/workspace-claim/v1" NUL || identity_kind NUL || root)``

``identity_kind`` and ``root`` are the shared canonical-root rule
(``finishup.adapters.workspace_root``), the same pair a local service keys its repository
commitment over, so one repository is one claim however it is reached (any directory of a
checkout, any linked worktree of one repository). ``claim_salt`` is 32 random bytes kept per
server target (``target.json``): two client machines, or two targets, claim the same path with
unrelated digests, and the server derives its own commitment from the digest without ever
learning which directory it names.

Beside it travels the worktree digest:

``worktree = HMAC-SHA256(claim_salt, "yoetz/workspace-worktree/v1" NUL || worktree top level)``

over the one directory the connection's workspace agent serves (its locator, which hooks, the
MCP bridge and the CLI already resolve to the worktree's own top level). Linked worktrees of one
repository share the claim, and with it the repository's privacy authority and consent scope on
the server, but not the worktree digest: the server derives one workspace handle per worktree, so
a task's workspace reads are only ever answered from that task's own worktree. Nothing here
stores, logs or renders a directory; every failure is a closed token.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import posixpath
import secrets
from typing import Final

from finishup.adapters.workspace_root import (
    CanonicalWorkspaceRoot,
    RepositoryIdentityError,
    canonical_workspace_root,
    workspace_identity_preimage,
)
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator

__all__ = [
    "WORKSPACE_CLAIM_DOMAIN",
    "WORKSPACE_CLAIM_SALT_BYTES",
    "WORKSPACE_WORKTREE_DOMAIN",
    "new_claim_salt",
    "workspace_claim",
    "workspace_claim_for_root",
    "worktree_digest",
]

# Domain-separated like every FinishUP keyed digest, in the frozen ``yoetz/`` namespace (ADR-048).
WORKSPACE_CLAIM_DOMAIN: Final = b"yoetz/workspace-claim/v1\x00"
WORKSPACE_WORKTREE_DOMAIN: Final = b"yoetz/workspace-worktree/v1\x00"
# A target's claim salt (``finishup.client.targets.CLAIM_SALT_BYTES`` stores the same length).
WORKSPACE_CLAIM_SALT_BYTES: Final = 32


def _checked_salt(salt: object) -> bytes:
    if type(salt) is not bytes or len(salt) != WORKSPACE_CLAIM_SALT_BYTES:
        raise ValueError("workspace_claim_salt_invalid")
    return salt


def new_claim_salt() -> bytes:
    """A fresh claim salt for a new server target."""

    return secrets.token_bytes(WORKSPACE_CLAIM_SALT_BYTES)


def worktree_digest(worktree: str, salt: bytes) -> str:
    """The keyed digest of the worktree top level ``worktree`` (absolute, in normal form)."""

    key = _checked_salt(salt)
    if (
        type(worktree) is not str
        or not worktree.startswith("/")
        or posixpath.normpath(worktree) != worktree
        or worktree == "/"
    ):
        raise ValueError("workspace_worktree_invalid")
    digest = hmac.new(key, WORKSPACE_WORKTREE_DOMAIN + os.fsencode(worktree), hashlib.sha256)
    return "sha256:" + digest.hexdigest()


def workspace_claim_for_root(
    root: CanonicalWorkspaceRoot, salt: bytes, worktree: str
) -> WorkspaceClaim:
    """The claim on an already-resolved canonical workspace root under one target's salt.

    ``worktree`` is the top level of the one worktree of that repository the connection serves.
    """

    if type(root) is not CanonicalWorkspaceRoot:
        raise TypeError("workspace_root_invalid")
    key = _checked_salt(salt)
    digest = hmac.new(
        key, WORKSPACE_CLAIM_DOMAIN + workspace_identity_preimage(root), hashlib.sha256
    ).hexdigest()
    return WorkspaceClaim(
        identity_kind=root.identity_kind,
        digest="sha256:" + digest,
        worktree=worktree_digest(worktree, key),
    )


async def workspace_claim(locator: WorkspaceLocator, salt: bytes) -> WorkspaceClaim:
    """Resolve ``locator`` by the shared canonical-root rule and claim it under ``salt``.

    The worktree digest is over ``locator.path`` in normal form: the very directory the
    connection's workspace agent (``WorkspaceAgentHandler``) serves. The salt is checked before
    anything on disk is read. A locator the rule cannot resolve raises its closed
    ``RepositoryIdentityError`` (``repository_locator_unavailable``, say); the caller then has no
    claim and must not fall back to sending the path. The filesystem root is never claimed
    (``repository_locator_invalid``), as a hook or an MCP root never binds it
    (``adapters.workspace_binding``): a CLI or bridge started at ``/`` names no workspace.
    """

    _checked_salt(salt)
    if type(locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    worktree = posixpath.normpath(locator.path)
    if worktree == "/":
        raise RepositoryIdentityError("repository_locator_invalid")
    return workspace_claim_for_root(await canonical_workspace_root(locator), salt, worktree)
