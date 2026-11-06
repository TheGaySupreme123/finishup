"""Route every service workspace read to the local adapter or to the client's workspace agent.

A task whose session opened on this machine names its workspace by an absolute path, and every
read below goes to the existing local adapter exactly as before. A claim-bound task (ADR-051)
names its workspace by the ``client:<16 hex>`` handle its connection's claim produced: then
every read goes to the client's workspace agent through ``WorkspaceAgentHub`` and the catalog
codecs (``finishup.ports.workspace_agent``), and no local adapter is ever handed that task's
workspace. The service never resolves a handle to a path on its own disk.

The adapters here are synchronous because the ports they stand in for are: their callers run
them in worker threads (``asyncio.to_thread``), and a blocking call reaches the hub's event loop
from there (``WorkspaceAgentHub.call_blocking``). What the agent returns is the client's
attestation (``CLIENT_ATTESTED``): the hub records each answer it delivers under that label,
and a claim-bound task's human receipts say so in a fixed line.

Failures keep their meaning. An agent answer that is one of change capture's own closed reasons
raises the same ``ChangeCaptureUnavailable`` a local read would; an agent that does not answer
raises ``WorkspaceAgentUnavailable``, which every caller records as a gap, never as a pass.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final, Protocol, cast

from finishup.adapters.approved_checks import ApprovedCheckCommand, ApprovedCheckRunner
from finishup.adapters.task_input_read import ReadDeadline
from finishup.application.observation_check_policy import (
    CHECK_POLICY_PATH,
    LEGACY_CHECK_POLICY_PATH,
    ObservationCheckPolicy,
    ObservationCheckPolicyAbsent,
    ObservationCheckPolicyAmbiguous,
    parse_observation_check_policy,
)
from finishup.application.observation_workspace import (
    LocalObservationWorkspace,
    ObservationWorkspaceAccess,
)
from finishup.domain.receipts import CLIENT_ATTESTED
from finishup.ports.approved_checks import ApprovedCheckApproval, ApprovedCheckResult
from finishup.ports.change_capture import (
    CHANGE_CAPTURE_UNAVAILABLE_REASONS,
    MAX_TASK_INPUT_FILES,
    ChangeCapturePort,
    ChangeCaptureUnavailable,
    ChangeLineCounts,
    CheckChangeCapture,
    CheckChangeMetadata,
    OutsideSnapshotRead,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
)
from finishup.ports.subject_state import (
    LocalWorkspaceHandle,
    SubjectStateCaptureCommand,
    SubjectStateCapturePort,
    SubjectStateCaptureResult,
)
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_DEADLINE_MS,
    ApprovedCheckRun,
    CaptureArguments,
    CaptureMetadataArguments,
    CheckPolicyRead,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    InspectArguments,
    ListBeneathArguments,
    ListChangedPathsArguments,
    LstatCandidatesArguments,
    LstatFacts,
    OpenWorkspaceArguments,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    SnapshotOutsideInputsArguments,
    SubjectStateCaptureArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    workspace_handle_valid,
)
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectPort,
    WorkspaceInspectResult,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.service.workspace_hub import WorkspaceAgentHub

__all__ = [
    "CLIENT_ATTESTED",
    "ClientWorkspaceReads",
    "RoutedApprovedCheckRunner",
    "RoutedChangeCapture",
    "RoutedObservationWorkspace",
    "WorkspaceFileReads",
    "WorkspaceRouting",
    "client_bound",
]

# Bounds on one agent answer, by family. Each exceeds the local adapter's own read bound so the
# agent's own fences, not this wait, decide a slow read; the round trip adds the rest.
_GIT_SECONDS: Final = 60.0
_READ_SECONDS: Final = 15.0
_SNAPSHOT_GRACE_SECONDS: Final = 5.0


def client_bound(workspace: object) -> bool:
    """Whether ``workspace`` names a claim-bound task's workspace (its ``client:`` handle)."""

    return workspace_handle_valid(workspace)


def _call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
    timeout_seconds: float,
) -> Any:  # noqa: ANN401 - the operation's own result type
    if hub is None:
        raise WorkspaceAgentUnavailable("hub_unavailable")
    # A long approved check plus its grace never asks for more than one call may wait.
    bounded = min(timeout_seconds, MAX_WORKSPACE_DEADLINE_MS / 1000)
    return hub.call_blocking(handle, operation, arguments, timeout_seconds=bounded)


def _capture_call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
) -> Any:  # noqa: ANN401 - the operation's own result type
    """A git-family call; an agent's own capture reason raises the local typed failure."""

    try:
        return _call(hub, handle, operation, arguments, _GIT_SECONDS)
    except WorkspaceAgentUnavailable as exc:
        reason = exc.agent_reason
        if reason is not None and reason in CHANGE_CAPTURE_UNAVAILABLE_REASONS:
            raise ChangeCaptureUnavailable(reason) from None
        raise


class RoutedChangeCapture:
    """``ChangeCapturePort`` plus its optional check-time extensions, routed per workspace.

    ``local`` is the service's own Git adapter; it serves every absolute workspace exactly as
    before and never sees a handle. ``lstat_probe`` stands in for the metadata-only ``lstat`` of
    outside-input candidates (``outside_inputs_not_admitted``): None keeps the local probe.
    """

    __slots__ = ("_hub", "_local")

    def __init__(self, local: ChangeCapturePort, hub: WorkspaceAgentHub | None) -> None:
        self._local = local
        self._hub = hub

    def __repr__(self) -> str:
        return "RoutedChangeCapture(<redacted>)"

    def read_task_base(self, workspace: str) -> TaskChangeBase:
        if not client_bound(workspace):
            return self._local.read_task_base(workspace)
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(workspace),
        )

    def capture(
        self,
        workspace: str,
        base: TaskChangeBase | None,
        *,
        priority_paths: tuple[str, ...] = (),
        input_paths: tuple[str, ...] = (),
        space_cut_paths: frozenset[str] = frozenset(),
    ) -> CheckChangeCapture:
        if not client_bound(workspace):
            # The exact call shape the caller made: a port without these options keeps working.
            options: dict[str, object] = {}
            if priority_paths:
                options["priority_paths"] = priority_paths
            if input_paths:
                options["input_paths"] = input_paths
            if space_cut_paths:
                options["space_cut_paths"] = space_cut_paths
            return self._local.capture(workspace, base, **options)  # pyright: ignore[reportArgumentType]
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CAPTURE,
            CaptureArguments(workspace, base, priority_paths, input_paths, space_cut_paths),
        )

    def capture_metadata(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeMetadata:
        if not client_bound(workspace):
            return self._local.capture_metadata(workspace, base)
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CAPTURE_METADATA,
            CaptureMetadataArguments(workspace, base),
        )

    def probe_requested_paths(
        self, workspace: str, values: tuple[str, ...]
    ) -> tuple[RequestedPathProbe, ...]:
        if not client_bound(workspace):
            return self._local_extension("probe_requested_paths")(workspace, values)
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.PROBE_REQUESTED_PATHS,
            ProbeRequestedPathsArguments(workspace, tuple(values)),
        )

    def count_change_lines(
        self, workspace: str, base_commit: str, base_paths: tuple[str, ...]
    ) -> ChangeLineCounts:
        if not client_bound(workspace):
            return self._local_extension("count_change_lines")(workspace, base_commit, base_paths)
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.COUNT_CHANGE_LINES,
            CountChangeLinesArguments(workspace, base_commit, tuple(base_paths)),
        )

    def classify_undeclared_references(
        self,
        workspace: str,
        deliverables: tuple[str, ...],
        candidates: tuple[str, ...],
        declared: tuple[str, ...] = (),
    ) -> tuple[tuple[int, int, str], ...]:
        if not client_bound(workspace):
            return self._local_extension("classify_undeclared_references")(
                workspace, deliverables, candidates, declared
            )
        return _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES,
            ClassifyUndeclaredReferencesArguments(
                workspace, tuple(deliverables), tuple(candidates), tuple(declared)
            ),
        )

    def lstat_probe(self, workspace: str) -> Callable[[str], os.stat_result | None] | None:
        """The candidate ``lstat`` for a claim-bound workspace; None keeps the local one."""

        if not client_bound(workspace):
            return None
        hub = self._hub

        def probe(path: str) -> os.stat_result | None:
            if not path.startswith("/"):
                return None
            (found,) = cast(
                tuple[LstatFacts | None, ...],
                _call(
                    hub,
                    workspace,
                    WorkspaceOperation.LSTAT_CANDIDATES,
                    LstatCandidatesArguments((path,)),
                    _READ_SECONDS,
                ),
            )
            return None if found is None else found.to_stat_result()

        return probe

    def _local_extension(self, name: str) -> Callable[..., Any]:
        method = getattr(self._local, name, None)
        if not callable(method):
            # Exactly what the caller's own ``getattr`` on the local adapter would have met.
            raise AttributeError(name)
        return cast(Callable[..., Any], method)


class WorkspaceFileReads(Protocol):
    """The reviewer's and the check's reads beneath roots, as ``adapters.task_input_read``."""

    def list_beneath(
        self,
        root: str,
        relative: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool],
        inspect: int = 128,
    ) -> tuple[tuple[tuple[str, bool], ...], bool] | None: ...

    def read_text_beneath(
        self, root: str, relative: str, *, excluded: tuple[str, ...], expired: Callable[[], bool]
    ) -> tuple[bytes, int] | None: ...

    def read_declared_test(
        self, location: str, *, excluded: tuple[str, ...], expired: Callable[[], bool] = ...
    ) -> bytes | None: ...

    def read_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int = MAX_TASK_INPUT_FILES,
        excluded: tuple[str, ...] = (),
        space_cut: frozenset[str] = frozenset(),
    ) -> tuple[TaskInputFile, ...]: ...

    def snapshot_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int,
        max_bytes: int,
        seconds: float,
        excluded: tuple[str, ...] = (),
    ) -> tuple[OutsideSnapshotRead, ...]: ...


class ClientWorkspaceReads:
    """Every read of one claim-bound task, answered by the client's workspace agent.

    Roots and locations are absolute paths the task's content or the owner's policy named, or
    the task's handle standing for the claimed root; the agent resolves and confines them. A
    reviewer read the agent could not answer raises ``WorkspaceAgentUnavailable`` (the review
    ends with that recorded reason); one it answered as unavailable or refused reads as nothing,
    exactly as a local read that found nothing.
    """

    __slots__ = ("_handle", "_hub")

    def __init__(self, hub: WorkspaceAgentHub | None, handle: str) -> None:
        if not workspace_handle_valid(handle):
            raise ValueError("workspace_handle_invalid")
        self._hub = hub
        self._handle = handle

    def __repr__(self) -> str:
        return "ClientWorkspaceReads(<redacted>)"

    def _read(self, operation: WorkspaceOperation, arguments: object) -> Any:  # noqa: ANN401
        try:
            return _call(self._hub, self._handle, operation, arguments, _READ_SECONDS)
        except WorkspaceAgentUnavailable as exc:
            if exc.agent_reason == "read_deadline":
                raise ReadDeadline("reviewer_read_deadline") from None
            if exc.reason in {"agent_refused", "agent_unavailable"}:
                return None
            raise

    def list_beneath(
        self,
        root: str,
        relative: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool],
        inspect: int = 128,
    ) -> tuple[tuple[tuple[str, bool], ...], bool] | None:
        del expired  # the call's own deadline bounds it; the caller checks its stop after
        return cast(
            tuple[tuple[tuple[str, bool], ...], bool] | None,
            self._read(
                WorkspaceOperation.LIST_BENEATH,
                ListBeneathArguments(root, relative, tuple(excluded), inspect),
            ),
        )

    def read_text_beneath(
        self, root: str, relative: str, *, excluded: tuple[str, ...], expired: Callable[[], bool]
    ) -> tuple[bytes, int] | None:
        del expired
        return cast(
            tuple[bytes, int] | None,
            self._read(
                WorkspaceOperation.READ_TEXT_BENEATH,
                ReadTextBeneathArguments(root, relative, tuple(excluded)),
            ),
        )

    def read_declared_test(
        self,
        location: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool] = lambda: False,
    ) -> bytes | None:
        del expired
        return cast(
            bytes | None,
            self._read(
                WorkspaceOperation.READ_DECLARED_TEST,
                ReadDeclaredTestArguments(location, tuple(excluded)),
            ),
        )

    def read_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int = MAX_TASK_INPUT_FILES,
        excluded: tuple[str, ...] = (),
        space_cut: frozenset[str] = frozenset(),
    ) -> tuple[TaskInputFile, ...]:
        found = _call(
            self._hub,
            self._handle,
            WorkspaceOperation.READ_OUTSIDE_INPUTS,
            ReadOutsideInputsArguments(
                tuple(roots), tuple(values), limit, tuple(excluded), frozenset(space_cut)
            ),
            _READ_SECONDS,
        )
        return cast(tuple[TaskInputFile, ...], found)

    def snapshot_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int,
        max_bytes: int,
        seconds: float,
        excluded: tuple[str, ...] = (),
    ) -> tuple[OutsideSnapshotRead, ...]:
        budget_ms = max(0, int(seconds * 1000))
        found = _call(
            self._hub,
            self._handle,
            WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
            SnapshotOutsideInputsArguments(
                tuple(roots), tuple(values), limit, max_bytes, budget_ms, tuple(excluded)
            ),
            seconds + _SNAPSHOT_GRACE_SECONDS,
        )
        return cast(tuple[OutsideSnapshotRead, ...], found)


@dataclass(frozen=True, slots=True)
class WorkspaceRouting:
    """The ready application's one routing point: the capture port and the per-task readers.

    ``hub`` is None only in an application composed without a daemon; a claim-bound read then
    fails as ``hub_unavailable`` and is recorded as a gap, never served from this disk. A local
    task's reads stay with each caller's own trusted readers (``reads_for`` answers None).
    """

    hub: WorkspaceAgentHub | None
    change_capture: RoutedChangeCapture

    @classmethod
    def compose(
        cls, hub: WorkspaceAgentHub | None, local_capture: ChangeCapturePort
    ) -> WorkspaceRouting:
        return cls(hub, RoutedChangeCapture(local_capture, hub))

    def reads_for(self, workspace: str | None) -> ClientWorkspaceReads | None:
        """The agent's readers for a claim-bound task's ``workspace``; None for a local one."""

        if workspace is not None and client_bound(workspace):
            return ClientWorkspaceReads(self.hub, workspace)
        return None

    def reads_excluding(self, excluded: Sequence[str]) -> ClientWorkspaceReads | None:
        """``reads_for`` the workspace a read names first among its exclusions (the readers'
        convention: the task's workspace, then this service's own directories)."""

        return self.reads_for(excluded[0] if excluded else None)


# --- observation verification (T11) and approved checks (T12) ------------------------------

_OBSERVATION_SECONDS: Final = 60.0
_CHECK_GRACE_SECONDS: Final = 30.0


class _ClientOpenedWorkspace:
    """Held inside a ``LocalWorkspaceHandle``: a claim-bound workspace its agent opened.

    ``workspace`` is the claim handle (the route to the agent), ``opened`` the agent's own
    opaque handle for the workspace it opened. Neither is a path on this machine. Several
    connections of one client may serve the same claim, and an agent may restart: an agent that
    does not know ``opened`` answers ``handle_unknown``, and ``_opened_call`` then opens the
    workspace again on the agent now serving the claim and keeps its new handle here.
    """

    __slots__ = ("opened", "workspace")

    workspace: str
    opened: str

    def __init__(self, workspace: str, opened: str) -> None:
        self.workspace = workspace
        self.opened = opened

    def __repr__(self) -> str:
        return "_ClientOpenedWorkspace(<redacted>)"


def _client_opened(handle: LocalWorkspaceHandle) -> _ClientOpenedWorkspace | None:
    descriptor = handle._validated_descriptor()  # pyright: ignore[reportPrivateUsage]
    return descriptor if type(descriptor) is _ClientOpenedWorkspace else None


def _observation_call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
    timeout_seconds: float = _OBSERVATION_SECONDS,
) -> Any:  # noqa: ANN401 - the operation's own result type
    return _call(hub, handle, operation, arguments, timeout_seconds)


def _open_on_agent(hub: WorkspaceAgentHub | None, workspace: str) -> str:
    return cast(
        str,
        _observation_call(
            hub,
            workspace,
            WorkspaceOperation.OPEN_WORKSPACE,
            OpenWorkspaceArguments(workspace, admitted_home_project=True),
            _READ_SECONDS,
        ),
    )


def _opened_call(
    hub: WorkspaceAgentHub | None,
    client: _ClientOpenedWorkspace,
    operation: WorkspaceOperation,
    arguments: Callable[[str], object],
    timeout_seconds: float = _OBSERVATION_SECONDS,
) -> Any:  # noqa: ANN401 - the operation's own result type
    """One call naming the agent-opened workspace; reopened once if the agent forgot it.

    The agent answering may not be the one that opened the workspace (another connection of the
    same client now serves the claim, or the agent restarted). It says ``handle_unknown``, and
    the workspace is opened again on it, exactly as first opened, before the call is retried
    once. Every other outcome is the call's own.
    """

    try:
        return _observation_call(
            hub, client.workspace, operation, arguments(client.opened), timeout_seconds
        )
    except WorkspaceAgentUnavailable as exc:
        if exc.agent_reason != "handle_unknown":
            raise
    client.opened = _open_on_agent(hub, client.workspace)
    return _observation_call(
        hub, client.workspace, operation, arguments(client.opened), timeout_seconds
    )


class _RoutedSubjectState:
    """``SubjectStateCapturePort``: a client-opened workspace is hashed by its agent."""

    __slots__ = ("_hub", "_local")

    def __init__(self, hub: WorkspaceAgentHub | None, local: SubjectStateCapturePort) -> None:
        self._hub = hub
        self._local = local

    def capture(self, command: SubjectStateCaptureCommand) -> SubjectStateCaptureResult:
        client = _client_opened(command.workspace)
        if client is None:
            return self._local.capture(command)
        return cast(
            SubjectStateCaptureResult,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.SUBJECT_STATE_CAPTURE,
                lambda opened: SubjectStateCaptureArguments(opened, command.expected_format),
            ),
        )


class _RoutedInspect:
    """``WorkspaceInspectPort``: a client-opened workspace is inspected by its agent."""

    __slots__ = ("_hub", "_local")

    def __init__(self, hub: WorkspaceAgentHub | None, local: WorkspaceInspectPort) -> None:
        self._hub = hub
        self._local = local

    def inspect(self, command: WorkspaceInspectCommand) -> WorkspaceInspectResult:
        client = _client_opened(command.workspace)
        if client is None:
            return self._local.inspect(command)
        return cast(
            WorkspaceInspectResult,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.INSPECT,
                lambda opened: InspectArguments(opened, command.relative_paths),
            ),
        )


class RoutedApprovedCheckRunner(ApprovedCheckRunner):
    """An approved check of a client-opened workspace runs on the client, by its agent.

    The service still decides first, exactly as its own runner does and before anything is
    sent: an approval this policy does not hold, a stale subject state or a network request is
    refused here. The agent then runs the argv only when its own copy of the owner-approved
    policy holds the same approval; its redacted output reaches this runner's output sink.
    """

    def __init__(
        self, approvals: Mapping[str, ApprovedCheckApproval], hub: WorkspaceAgentHub | None
    ) -> None:
        super().__init__(approvals)
        self._hub = hub

    def run(self, command: ApprovedCheckCommand) -> ApprovedCheckResult:
        if type(command) is not ApprovedCheckCommand:
            return super().run(command)
        client = _client_opened(command.workspace)
        approval = command.approval
        registered = self._approvals.get(approval.approval_commitment)
        if (
            client is None
            or registered is None
            or registered != approval
            or (
                command.expected_subject_state_digest is not None
                and command.expected_subject_state_digest != command.subject_state_digest
            )
            or approval.allow_network
        ):
            # Every one of these is decided before a workspace is touched.
            return super().run(command)
        run = cast(
            ApprovedCheckRun,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.RUN_APPROVED_CHECK,
                lambda opened: RunApprovedCheckArguments(
                    opened,
                    approval,
                    command.subject_state_digest,
                    command.expected_subject_state_digest,
                ),
                approval.timeout_seconds + _CHECK_GRACE_SECONDS,
            ),
        )
        sink = self._output_sink
        if run.output is not None and sink is not None:
            sink(run.output, run.output_redacted)
        return run.result


class RoutedObservationWorkspace:
    """``ObservationWorkspaceAccess``: a ``client:`` locator is read by its client's agent.

    Any other locator reads this machine through ``local``, unchanged. The service never
    resolves a handle to a path: the agent opens its own claimed root and returns an opaque
    handle for it, which only that agent can use.
    """

    __slots__ = ("_hub", "_local")

    def __init__(
        self, hub: WorkspaceAgentHub | None, local: ObservationWorkspaceAccess | None = None
    ) -> None:
        self._hub = hub
        self._local: ObservationWorkspaceAccess = (
            LocalObservationWorkspace() if local is None else local
        )

    def __repr__(self) -> str:
        return "RoutedObservationWorkspace(<redacted>)"

    def open(self, locator: str) -> LocalWorkspaceHandle:
        if not client_bound(locator):
            return self._local.open(locator)
        return LocalWorkspaceHandle._from_validated_descriptor(  # pyright: ignore[reportPrivateUsage]
            _ClientOpenedWorkspace(locator, _open_on_agent(self._hub, locator))
        )

    def load_policy(self, locator: str) -> tuple[ObservationCheckPolicy, bytes]:
        if not client_bound(locator):
            return self._local.load_policy(locator)
        try:
            read = cast(
                CheckPolicyRead,
                _observation_call(
                    self._hub,
                    locator,
                    WorkspaceOperation.LOAD_CHECK_POLICY,
                    WorkspaceOnlyArguments(locator),
                    _READ_SECONDS,
                ),
            )
        except WorkspaceAgentUnavailable as exc:
            # The agent's policy answers keep the local loader's exact typed outcomes.
            if exc.agent_reason == "policy_absent":
                raise ObservationCheckPolicyAbsent() from None
            if exc.agent_reason == "policy_ambiguous":
                raise ObservationCheckPolicyAmbiguous() from None
            if exc.agent_reason == "policy_invalid":
                raise ProtocolValueError("invalid_approved_check_policy") from None
            raise
        source = CHECK_POLICY_PATH if read.location == "current" else LEGACY_CHECK_POLICY_PATH
        return replace(parse_observation_check_policy(read.raw), source_path=source), read.raw

    def subject_state(self) -> SubjectStateCapturePort:
        return _RoutedSubjectState(self._hub, self._local.subject_state())

    def list_changed(self, workspace: LocalWorkspaceHandle) -> tuple[str, ...]:
        client = _client_opened(workspace)
        if client is None:
            return self._local.list_changed(workspace)
        return cast(
            tuple[str, ...],
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.LIST_CHANGED_PATHS,
                ListChangedPathsArguments,
            ),
        )

    def inspect_port(self) -> WorkspaceInspectPort:
        return _RoutedInspect(self._hub, self._local.inspect_port())

    def runner(self, approvals: Mapping[str, ApprovedCheckApproval]) -> ApprovedCheckRunner:
        return RoutedApprovedCheckRunner(approvals, self._hub)
