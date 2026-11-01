"""Consent-backed authority for generation-bound project coordination grants.

Project coordination is local disclosure, but a general or cross-repository project still needs
an explicit generation-bound grant.  This module bridges the ordinary project application to the
existing owner-only elevated-consent ceremony.  It never accepts an authority label from a caller
and never treats a pending request as approval.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from finishup.service.elevated_bootstrap import (
    ElevatedBootstrapError,
    clear_pending,
    consume_project_coordination_authorization,
    load_pending,
    load_project_coordination_audit_record_id,
    load_project_coordination_authorization,
    prepare_pending,
    project_coordination_grant_binding,
    project_coordination_target_digest,
)

__all__ = ["ProjectCoordinationGrantAuthority"]


class ProjectCoordinationGrantAuthority:
    """Implement ``CoordinationGrantAuthorizer`` with one-use local consent.

    ``authorize`` returns ``False`` after creating a pending consent request.  A caller must then
    complete the normal ``finishup consent review`` or exact current-chat ``authorize`` ceremony.  On
    a later call, only a matching owner-only authorization artifact is accepted.  The artifact is
    consumed after the catalog records the grant, so a crash between the two durable stores cannot
    lose the authority needed to recover the idempotent grant.
    """

    def __init__(self, *, state_path: Path | None = None) -> None:
        self._state_path = state_path

    async def prepare(
        self,
        project_id: str,
        membership_generation: int,
        audit_record_id: str,
    ) -> str:
        """Prepare the exact pending consent and return its target digest.

        The digest is safe structural evidence.  The pending file remains the only approval state;
        this method never returns an authorization token.
        """

        binding = project_coordination_grant_binding(
            project_id=project_id,
            membership_generation=membership_generation,
            audit_record_id=audit_record_id,
        )
        target_digest = project_coordination_target_digest(binding)
        try:
            existing = load_pending(_state=self._state_path)
            if existing is None:
                prepare_pending(
                    "project_coordination_grant",
                    target_digest=target_digest,
                    coordination_binding=binding,
                    _state=self._state_path,
                )
        except ElevatedBootstrapError:
            # The owner-only pending slot is authoritative.  A caller cannot replace another
            # operation's pending request merely by asking for a project grant.
            raise
        return target_digest

    async def authorize(
        self,
        project_id: str,
        membership_generation: int,
        action: Literal["grant", "revoke"],
        audit_record_id: str,
    ) -> bool:
        """Consume exact local consent for a grant; all other actions fail closed.

        Revoke is an authority-tightening operation and is intentionally not authorized through
        this widening-grant path.  The project application owns its immediate generation fence.
        """

        if action != "grant":
            return False
        project_coordination_grant_binding(
            project_id=project_id,
            membership_generation=membership_generation,
            audit_record_id=audit_record_id,
        )
        authorization = load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=membership_generation,
            audit_record_id=audit_record_id,
            _state=self._state_path,
        )
        if authorization is not None:
            return True
        # There is no approved artifact.  Preparing here keeps the ordinary project command
        # recoverable while still leaving the grant denied until the existing consent ceremony
        # produces the exact owner-only handoff.
        try:
            await self.prepare(project_id, membership_generation, audit_record_id)
        except ElevatedBootstrapError:
            # Existing pending/authorization state is intentionally not disclosed.  The caller
            # receives the normal bounded grant-required failure and can inspect consent status.
            return False
        return False

    async def recover_audit_record_id(
        self,
        project_id: str,
        membership_generation: int,
    ) -> str | None:
        """Return the stable event identity for this project's pending grant, if any."""

        try:
            return load_project_coordination_audit_record_id(
                project_id=project_id,
                membership_generation=membership_generation,
                _state=self._state_path,
            )
        except ElevatedBootstrapError:
            # The application will convert an unresolvable challenge into its ordinary bounded
            # grant-required result; do not disclose consent-store state through this resolver.
            return None

    async def consume(
        self,
        project_id: str,
        membership_generation: int,
        action: Literal["grant", "revoke"],
        audit_record_id: str,
    ) -> None:
        """Consume the exact handoff after the catalog mutation has committed.

        A missing artifact is treated as an already reconciled handoff.  The caller has already
        committed the generation-bound grant, and refusing that successful mutation because an
        idempotent cleanup raced would make a retry look like a failed grant.
        """

        if action != "grant":
            return
        authorization = None
        try:
            authorization = load_project_coordination_authorization(
                project_id=project_id,
                membership_generation=membership_generation,
                audit_record_id=audit_record_id,
                _state=self._state_path,
            )
        except ElevatedBootstrapError:
            # The catalog commit is already durable.  Preserve truthful idempotent success and
            # leave a corrupt/unclean owner-only artifact for the next local recovery/diagnostic
            # pass rather than turning cleanup trouble into a second approval requirement.
            authorization = None
        if authorization is not None:
            try:
                consume_project_coordination_authorization(
                    authorization,
                    _state=self._state_path,
                )
            except ElevatedBootstrapError:
                # As above, cleanup is retryable reconciliation after the catalog write.
                pass
        # The catalog write has committed this generation.  Remove only the pending row that
        # names the same project, generation, and audit identity; an unrelated owner ceremony
        # must remain untouched.  Leaving the consumed row behind would block the next
        # generation's exact challenge during a normal link/unlink lifecycle.
        try:
            pending = load_pending(_state=self._state_path)
            binding = None if pending is None else pending.coordination_binding
            if (
                binding is not None
                and binding.get("project_id") == project_id
                and binding.get("membership_generation") == str(membership_generation)
                and binding.get("audit_record_id") == audit_record_id
                and binding.get("action") == "grant"
            ):
                clear_pending(_state=self._state_path)
        except ElevatedBootstrapError:
            # Durable grant success remains truthful if owner-only cleanup is unavailable; the
            # next recovery pass can reconcile the stale pending artifact.
            pass
