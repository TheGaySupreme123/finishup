"""Task-declared verification scope for captured output, never for Stop gates.

A declaration selects existing authenticated output; it does not attest an agent's
result, grant capture/egress consent, or change the global runner classification.
"""

from __future__ import annotations

from finishup.domain.events import ActionKind, ObligationStatus, RequestedItemKind
from finishup.domain.observation import normalize_observed_command
from finishup.domain.values import ActionId
from finishup.kernel.observed_failures import command_identity
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import effective_obligation_ids, requested_command_identity


def declared_verification_commands(projection: ProjectionState) -> tuple[str, ...]:
    """Readable effective-plan commands and explicitly manifest-bearing run commands.

    Manifest metadata remains agent-declared. Only the exact installation-keyed
    command match in ``verification_capture_command`` can bind it to observed output.
    """

    commands: dict[str, None] = {}
    for obligation in effective_obligation_ids(
        projection.plans, projection.obligations, projection.coverage_gaps
    ):
        row = projection.obligations[obligation]
        payload = row.payload
        if (
            row.redacted
            or payload is None
            or payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
        ):
            continue
        for item in payload.requested_items:
            if item.item_kind is RequestedItemKind.COMMAND:
                command = normalize_observed_command(item.value)
                if command is not None:
                    commands[command] = None
    for row in projection.results.values():
        payload = row.payload
        if row.redacted or payload is None or payload.verification is None:
            continue
        action = projection.actions.get(payload.action_id)
        if (
            action is None
            or action.redacted
            or action.payload is None
            or action.payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        command = normalize_observed_command(action.payload.command)
        if command is not None and not command.startswith("omitted:"):
            commands[command] = None
    return tuple(commands)


def verification_capture_command(projection: ProjectionState, commitment: str) -> str | None:
    """Recover exact declared text matching one observed whole-command commitment.

    No prefix, argument, segment, filename, or heredoc-body inference is permitted.
    Without the service's installation key the existing identity helper fails closed.
    """

    for command in declared_verification_commands(projection):
        if requested_command_identity(command) == commitment:
            return command
    return None


def command_is_declared_verification(action_id: str | None, projection: ProjectionState) -> bool:
    """Whether one readable command action has a task-scoped declaration.

    An explicit manifest on this action counts as a declaration, never as observed
    execution. A hook action can instead match the declaration by its keyed identity.
    """

    if action_id is None:
        return False
    action = projection.actions.get(ActionId(action_id))
    if (
        action is None
        or action.redacted
        or action.payload is None
        or action.payload.action_kind is not ActionKind.COMMAND
    ):
        return False
    if any(
        not row.redacted
        and row.payload is not None
        and str(row.payload.action_id) == action_id
        and row.payload.verification is not None
        for row in projection.results.values()
    ):
        return True
    identity = command_identity(action.payload.command)
    if identity is not None:
        return verification_capture_command(projection, identity) is not None
    command = normalize_observed_command(action.payload.command)
    return command is not None and command in declared_verification_commands(projection)
