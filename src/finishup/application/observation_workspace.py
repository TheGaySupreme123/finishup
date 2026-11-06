"""Where observation verification reads a workspace: this machine, or a client's agent (ADR-051).

Observation verification (T11) opens the observed workspace, loads its owner-approved check
policy, hashes its subject state, lists and inspects its changed paths, and runs its approved
checks (T12). ``LocalObservationWorkspace`` does all of that on this machine, exactly as before.
A service that serves claim-bound clients composes a routed access instead
(``finishup.service.workspace_routing``), which sends a ``client:`` handle's reads to that
client's workspace agent; the coordinator and the verification worker never tell them apart.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from finishup.adapters.approved_checks import ApprovedCheckRunner
from finishup.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    list_changed_relative_paths,
    open_local_workspace,
)
from finishup.adapters.workspace_inspect import LocalWorkspaceInspectAdapter
from finishup.application.observation_check_policy import (
    ObservationCheckPolicy,
    load_observation_check_policy,
)
from finishup.ports.approved_checks import ApprovedCheckApproval
from finishup.ports.subject_state import LocalWorkspaceHandle, SubjectStateCapturePort
from finishup.ports.workspace_inspect import WorkspaceInspectPort

__all__ = ["LocalObservationWorkspace", "ObservationWorkspaceAccess"]


class ObservationWorkspaceAccess(Protocol):
    """The workspace reads of one observation verification; every one blocks (run it in a
    worker thread)."""

    def open(self, locator: str) -> LocalWorkspaceHandle: ...

    def load_policy(self, locator: str) -> tuple[ObservationCheckPolicy, bytes]: ...

    def subject_state(self) -> SubjectStateCapturePort: ...

    def list_changed(self, workspace: LocalWorkspaceHandle) -> tuple[str, ...]: ...

    def inspect_port(self) -> WorkspaceInspectPort: ...

    def runner(self, approvals: Mapping[str, ApprovedCheckApproval]) -> ApprovedCheckRunner: ...


@dataclass(frozen=True, slots=True)
class LocalObservationWorkspace:
    """This machine's own observation reads, unchanged."""

    def open(self, locator: str) -> LocalWorkspaceHandle:
        # The locator was retained under this workspace's observation grant; the service does
        # not inherit the host launcher's process-local HOME exception.
        return open_local_workspace(Path(locator), admitted_home_project=True)

    def load_policy(self, locator: str) -> tuple[ObservationCheckPolicy, bytes]:
        return load_observation_check_policy(Path(locator))

    def subject_state(self) -> SubjectStateCapturePort:
        return GitSubjectStateAdapter()

    def list_changed(self, workspace: LocalWorkspaceHandle) -> tuple[str, ...]:
        return list_changed_relative_paths(workspace)

    def inspect_port(self) -> WorkspaceInspectPort:
        return LocalWorkspaceInspectAdapter()

    def runner(self, approvals: Mapping[str, ApprovedCheckApproval]) -> ApprovedCheckRunner:
        return ApprovedCheckRunner(approvals)
