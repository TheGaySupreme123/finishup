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
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from finishup.ports.keys import REPOSITORY_PRIVACY_MAC_DOMAIN, MacKeyHandle

__all__ = ["RepositoryIdentityError", "resolve_repository_privacy_context", "root_owned_checkout"]


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
