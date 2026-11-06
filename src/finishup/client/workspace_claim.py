"""A client's keyed claim on its workspace, sent to a FinishUP server on another machine (ADR-051).

A connection to a server on another machine names its workspace by a *claim*, never by a path:

``digest = HMAC-SHA256(claim_salt, "yoetz/workspace-claim/v1" NUL || identity_kind NUL || root)``

``identity_kind`` and ``root`` are the shared canonical-root rule
(``finishup.adapters.workspace_root``), the same pair a local service keys its repository
commitment over, so one workspace is one claim however it is reached (any directory of a
checkout, any linked worktree of one repository). ``claim_salt`` is 32 random bytes kept per
server target (``target.json``): two client machines, or two targets, claim the same path with
unrelated digests, and the server derives its own commitment from the digest without ever
learning which directory it names. Nothing here stores, logs or renders the directory; every
failure is a closed token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from finishup.adapters.workspace_root import (
    CanonicalWorkspaceRoot,
    canonical_workspace_root,
    workspace_identity_preimage,
)
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator

__all__ = [
    "WORKSPACE_CLAIM_DOMAIN",
    "WORKSPACE_CLAIM_SALT_BYTES",
    "new_claim_salt",
    "workspace_claim",
    "workspace_claim_for_root",
]

# Domain-separated like every FinishUP keyed digest, in the frozen ``yoetz/`` namespace (ADR-048).
WORKSPACE_CLAIM_DOMAIN: Final = b"yoetz/workspace-claim/v1\x00"
# A target's claim salt (``finishup.client.targets.CLAIM_SALT_BYTES`` stores the same length).
WORKSPACE_CLAIM_SALT_BYTES: Final = 32


def _checked_salt(salt: object) -> bytes:
    if type(salt) is not bytes or len(salt) != WORKSPACE_CLAIM_SALT_BYTES:
        raise ValueError("workspace_claim_salt_invalid")
    return salt


def new_claim_salt() -> bytes:
    """A fresh claim salt for a new server target."""

    return secrets.token_bytes(WORKSPACE_CLAIM_SALT_BYTES)


def workspace_claim_for_root(root: CanonicalWorkspaceRoot, salt: bytes) -> WorkspaceClaim:
    """The claim on an already-resolved canonical workspace root under one target's salt."""

    if type(root) is not CanonicalWorkspaceRoot:
        raise TypeError("workspace_root_invalid")
    key = _checked_salt(salt)
    digest = hmac.new(
        key, WORKSPACE_CLAIM_DOMAIN + workspace_identity_preimage(root), hashlib.sha256
    ).hexdigest()
    return WorkspaceClaim(identity_kind=root.identity_kind, digest="sha256:" + digest)


async def workspace_claim(locator: WorkspaceLocator, salt: bytes) -> WorkspaceClaim:
    """Resolve ``locator`` by the shared canonical-root rule and claim it under ``salt``.

    The salt is checked before anything on disk is read. A locator the rule cannot resolve raises
    its closed ``RepositoryIdentityError`` (``repository_locator_unavailable``, say); the caller
    then has no claim and must not fall back to sending the path.
    """

    _checked_salt(salt)
    if type(locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    return workspace_claim_for_root(await canonical_workspace_root(locator), salt)
