"""Private repository locator canonicalization and opaque installation binding.

Which directory a locator names is the shared rule in ``finishup.adapters.workspace_root``; this
module keys that rule's preimage with the installation MAC, so the commitment the service keeps
is byte-identical to the one it kept before the rule was shared (ADR-051).
"""

from __future__ import annotations

from finishup.adapters.workspace_root import (
    RepositoryIdentityError,
    canonical_workspace_root,
    root_owned_checkout,
    workspace_identity_preimage,
)
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceClaim, WorkspaceLocator
from finishup.ports.keys import (
    REPOSITORY_CLAIM_MAC_DOMAIN,
    REPOSITORY_PRIVACY_MAC_DOMAIN,
    MacKeyHandle,
)
from finishup.ports.workspace_agent import workspace_handle_for_claim

__all__ = [
    "RepositoryIdentityError",
    "claim_repository_privacy_context",
    "resolve_repository_privacy_context",
    "root_owned_checkout",
]


async def resolve_repository_privacy_context(
    locator: WorkspaceLocator,
    key: MacKeyHandle,
) -> RepositoryPrivacyContext:
    """Resolve a transient locator and retain only an installation-keyed commitment."""

    root = await canonical_workspace_root(locator)
    return RepositoryPrivacyContext(
        commitment=key.mac(REPOSITORY_PRIVACY_MAC_DOMAIN, workspace_identity_preimage(root)),
        identity_kind=root.identity_kind,
        # Kept in memory beside the commitment it produced; see RepositoryPrivacyContext.
        workspace_locator=locator,
    )


def claim_repository_privacy_context(
    claim: WorkspaceClaim, key: MacKeyHandle
) -> RepositoryPrivacyContext:
    """Key a client's workspace claim into a ``client_claim`` repository identity (ADR-051).

    The installation MAC runs over ``identity_kind NUL digest`` under its own domain, so the
    commitment names the claim and nothing else: no path is resolved, read or kept, and a claim
    commitment can never equal one a locator produced. Every linked worktree of one repository
    shares that commitment; the workspace handle is derived from it and the claim's worktree
    digest, so each worktree is routed to its own agent (``workspace_handle_for_claim``).
    """

    if type(claim) is not WorkspaceClaim:
        raise TypeError("workspace_claim_invalid")
    preimage = claim.identity_kind.encode("ascii") + b"\x00" + claim.digest.encode("ascii")
    commitment = key.mac(REPOSITORY_CLAIM_MAC_DOMAIN, preimage)
    return RepositoryPrivacyContext(
        commitment=commitment,
        identity_kind="client_claim",
        workspace_locator=None,
        workspace_handle=workspace_handle_for_claim(commitment, claim.worktree),
    )
