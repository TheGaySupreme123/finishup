"""Workspace routing: a path reads locally, a claim handle only through the agent (ADR-051)."""

from __future__ import annotations

import os
import stat
from typing import Any, cast

import pytest

from finishup.adapters.task_input_read import ReadDeadline
from finishup.ports.change_capture import ChangeCaptureUnavailable, TaskChangeBase
from finishup.ports.workspace_agent import (
    LstatFacts,
    OutsideSnapshotsRead,
    ReadTextBeneathArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
)
from finishup.service.workspace_hub import WorkspaceAgentHub
from finishup.service.workspace_routing import (
    ClientWorkspaceReads,
    RoutedChangeCapture,
    WorkspaceRouting,
    client_bound,
)

_HANDLE = "client:0123456789abcdef"
_BASE = TaskChangeBase("sha1", "b" * 40)


class _Hub:
    """Records every blocking call; answers from a script or raises."""

    def __init__(self, answer: object = None, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, WorkspaceOperation, object, float]] = []
        self.answer = answer
        self.error = error

    def call_blocking(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
    ) -> object:
        self.calls.append((handle, operation, arguments, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.answer


class _Local:
    """A local capture adapter that records what it was handed."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def read_task_base(self, workspace: str) -> TaskChangeBase:
        self.seen.append(("read_task_base", (workspace,), {}))
        return _BASE

    def capture(self, workspace: str, base: object, **options: object) -> str:
        self.seen.append(("capture", (workspace, base), options))
        return "local-capture"

    def capture_metadata(self, workspace: str, base: object) -> str:
        self.seen.append(("capture_metadata", (workspace, base), {}))
        return "local-metadata"

    def probe_requested_paths(self, workspace: str, values: tuple[str, ...]) -> tuple[str, ...]:
        self.seen.append(("probe_requested_paths", (workspace, values), {}))
        return ("probe",)


def _routed(hub: _Hub | None, local: _Local | None = None) -> RoutedChangeCapture:
    return RoutedChangeCapture(cast(Any, local or _Local()), cast(WorkspaceAgentHub | None, hub))


def test_a_local_workspace_reads_locally_exactly_as_called() -> None:
    hub, local = _Hub(), _Local()
    routed = _routed(hub, local)

    assert routed.read_task_base("/work/repo") == _BASE
    assert routed.capture("/work/repo", None) == "local-capture"
    assert routed.capture("/work/repo", _BASE, priority_paths=("a.py",)) == "local-capture"
    assert routed.capture_metadata("/work/repo", None) == "local-metadata"
    assert routed.probe_requested_paths("/work/repo", ("a.py",)) == ("probe",)
    assert routed.lstat_probe("/work/repo") is None

    assert hub.calls == []
    # An option the caller did not pass is not passed on: a port without it keeps working.
    assert local.seen[1] == ("capture", ("/work/repo", None), {})
    assert local.seen[2] == ("capture", ("/work/repo", _BASE), {"priority_paths": ("a.py",)})


def test_a_local_port_without_an_extension_stays_without_it() -> None:
    routed = _routed(_Hub())
    with pytest.raises(AttributeError):
        routed.count_change_lines("/work/repo", "a" * 40, ())


def test_a_claim_handle_reads_only_through_the_agent() -> None:
    hub, local = _Hub(answer=_BASE), _Local()
    routed = _routed(hub, local)

    assert routed.read_task_base(_HANDLE) == _BASE

    assert local.seen == []
    ((handle, operation, arguments, timeout),) = hub.calls
    assert (handle, operation) == (_HANDLE, WorkspaceOperation.READ_TASK_BASE)
    assert arguments == WorkspaceOnlyArguments(_HANDLE)
    assert timeout > 0


def test_an_agents_capture_reason_is_the_same_typed_failure_a_local_read_raises() -> None:
    hub = _Hub(error=WorkspaceAgentUnavailable("agent_unavailable", "not_git"))
    with pytest.raises(ChangeCaptureUnavailable) as caught:
        _routed(hub).capture_metadata(_HANDLE, None)
    assert caught.value.reason == "not_git"


@pytest.mark.parametrize("reason", ("no_agent", "agent_disconnected", "deadline_exceeded"))
def test_an_agent_that_did_not_answer_stays_typed_for_the_gap(reason: str) -> None:
    hub = _Hub(error=WorkspaceAgentUnavailable(reason))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        _routed(hub).capture(_HANDLE, None)
    assert caught.value.reason == reason


def test_without_a_hub_a_handle_is_unavailable_and_never_local() -> None:
    local = _Local()
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        _routed(None, local).read_task_base(_HANDLE)
    assert caught.value.reason == "hub_unavailable"
    assert local.seen == []


def test_the_candidate_lstat_of_a_claimed_workspace_is_the_agents() -> None:
    facts = LstatFacts(stat.S_IFREG | 0o600, 1_700_000_000_000_000_000, 1_700_000_000_000_000_000)
    hub = _Hub(answer=(facts,))
    probe = _routed(hub).lstat_probe(_HANDLE)
    assert probe is not None
    found = probe("/srv/shared/data.csv")
    assert found is not None and stat.S_ISREG(found.st_mode)
    assert found.st_mtime == pytest.approx(1_700_000_000.0)
    assert probe("relative/path") is None
    assert len(hub.calls) == 1
    assert isinstance(found, os.stat_result)


def test_a_reviewer_read_the_agent_refused_reads_as_nothing() -> None:
    reads = ClientWorkspaceReads(
        cast(
            WorkspaceAgentHub,
            _Hub(error=WorkspaceAgentUnavailable("agent_refused", "root_not_admitted")),
        ),
        _HANDLE,
    )
    assert reads.read_text_beneath(_HANDLE, "a.py", excluded=(), expired=lambda: False) is None


def test_an_agents_read_deadline_is_the_local_read_deadline() -> None:
    reads = ClientWorkspaceReads(
        cast(
            WorkspaceAgentHub,
            _Hub(error=WorkspaceAgentUnavailable("agent_unavailable", "read_deadline")),
        ),
        _HANDLE,
    )
    with pytest.raises(ReadDeadline):
        reads.list_beneath(_HANDLE, "", excluded=(), expired=lambda: False)


def test_a_reviewer_read_with_no_agent_raises_for_the_typed_ending() -> None:
    reads = ClientWorkspaceReads(
        cast(WorkspaceAgentHub, _Hub(error=WorkspaceAgentUnavailable("agent_disconnected"))),
        _HANDLE,
    )
    with pytest.raises(WorkspaceAgentUnavailable):
        reads.read_declared_test(_HANDLE + "/tests/test_a.py", excluded=())


def test_reviewer_reads_carry_the_handle_rooted_location_unchanged() -> None:
    hub = _Hub(answer=(b"print(1)\n", 9))
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), _HANDLE)
    assert reads.read_text_beneath(
        _HANDLE, "src/a.py", excluded=("/srv/finishup/state",), expired=lambda: False
    ) == (b"print(1)\n", 9)
    ((handle, operation, arguments, _timeout),) = hub.calls
    assert (handle, operation) == (_HANDLE, WorkspaceOperation.READ_TEXT_BENEATH)
    assert arguments == ReadTextBeneathArguments(_HANDLE, "src/a.py", ("/srv/finishup/state",))


def test_reviewer_reads_are_bounded_by_the_reviewers_own_read_budget() -> None:
    """A slow agent ends a review ``deadline`` as a slow local read does, never past it."""

    from finishup.application.reviewer_loop import LOCAL_READ_SECONDS

    hub = _Hub(answer=None)
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), _HANDLE)
    reads.list_beneath(_HANDLE, "", excluded=(), expired=lambda: False)
    reads.read_text_beneath(_HANDLE, "a.py", excluded=(), expired=lambda: False)
    reads.refused_paths(("a.py",))
    assert [call[3] for call in hub.calls] == [LOCAL_READ_SECONDS + 1.0] * 3


def test_a_listings_ignored_paths_are_probed_in_batches() -> None:
    """One round trip per 64 entries, never one per listed entry (ADR-051)."""

    from finishup.ports.change_capture import RequestedPathProbe
    from finishup.ports.workspace_agent import ProbeRequestedPathsArguments

    class _Probes(_Hub):
        def call_blocking(
            self,
            handle: str,
            operation: WorkspaceOperation,
            arguments: object,
            *,
            timeout_seconds: float,
        ) -> object:
            self.calls.append((handle, operation, arguments, timeout_seconds))
            values = cast(ProbeRequestedPathsArguments, arguments).values
            return tuple(
                RequestedPathProbe("inside", value, True, value.endswith(".log"))
                for value in values
            )

    hub = _Probes()
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), _HANDLE)
    names = tuple(f"src/f{index}.py" for index in range(127)) + ("build.log", "")
    assert reads.refused_paths(names) == frozenset({"build.log"})
    assert [len(cast(ProbeRequestedPathsArguments, call[2]).values) for call in hub.calls] == [
        64,
        64,
    ]
    assert all(call[1] is WorkspaceOperation.PROBE_REQUESTED_PATHS for call in hub.calls)
    assert reads.refused_paths(("",)) == frozenset() and len(hub.calls) == 2


@pytest.mark.parametrize(
    ("error", "refused"),
    (
        (WorkspaceAgentUnavailable("agent_unavailable", "not_git"), True),
        (WorkspaceAgentUnavailable("agent_refused", "workspace_not_claimed"), True),
        (ChangeCaptureUnavailable("not_git"), True),
        (WorkspaceAgentUnavailable("agent_disconnected"), None),
    ),
)
def test_an_unanswered_ignore_probe_refuses_the_batch_and_a_lost_agent_raises(
    error: Exception, refused: bool | None
) -> None:
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, _Hub(error=error)), _HANDLE)
    if refused is None:
        with pytest.raises(WorkspaceAgentUnavailable):
            reads.refused_paths(("a.py", "b.py"))
    else:
        assert reads.refused_paths(("a.py", "b.py")) == frozenset({"a.py", "b.py"})


def test_only_a_claim_handle_routes_to_the_agent() -> None:
    routing = WorkspaceRouting.compose(None, cast(Any, _Local()))
    assert routing.reads_for("/work/repo") is None
    assert routing.reads_for(None) is None
    assert routing.reads_for("client:not-a-handle") is None
    assert isinstance(routing.reads_for(_HANDLE), ClientWorkspaceReads)
    assert isinstance(routing.reads_excluding((_HANDLE, "/srv/state")), ClientWorkspaceReads)
    assert routing.reads_excluding(("/work/repo",)) is None
    assert client_bound(_HANDLE) and not client_bound("/work/repo")
    assert repr(routing.change_capture) == "RoutedChangeCapture(<redacted>)"


# --- observation verification and approved checks (T11, T12) -------------------------------

from finishup.adapters.approved_checks import ApprovedCheckCommand  # noqa: E402
from finishup.application.observation_check_policy import (  # noqa: E402
    LEGACY_CHECK_POLICY_PATH,
    ObservationCheckPolicyAbsent,
    parse_observation_check_policy,
)
from finishup.ports.approved_checks import (  # noqa: E402
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
    approved_check_result_digest,
)
from finishup.ports.subject_state import (  # noqa: E402
    LocalWorkspaceHandle,
    SubjectStateCaptureCommand,
    SubjectStateFormat,
)
from finishup.ports.workspace_agent import (  # noqa: E402
    ApprovedCheckRun,
    CheckPolicyRead,
    ListChangedPathsArguments,
    OpenWorkspaceArguments,
    RunApprovedCheckArguments,
    SubjectStateCaptureArguments,
)
from finishup.service.workspace_routing import RoutedObservationWorkspace  # noqa: E402

_OPENED = "rws_" + "0" * 32
_POLICY = (
    b'format = "yoetz.approved-check-policy/1"\n\n[[checks]]\nid = "smoke"\n'
    b'argv = ["/usr/bin/true"]\ntimeout_seconds = 10\nnetwork = false\n'
)


class _ScriptedHub(_Hub):
    """Answers each operation from a table."""

    def __init__(self, answers: dict[WorkspaceOperation, object]) -> None:
        super().__init__()
        self.answers = answers

    def call_blocking(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
    ) -> object:
        self.calls.append((handle, operation, arguments, timeout_seconds))
        answer = self.answers[operation]
        if isinstance(answer, Exception):
            raise answer
        return answer


class _LocalAccess:
    def __init__(self) -> None:
        self.opened: list[str] = []

    def open(self, locator: str) -> object:
        self.opened.append(locator)
        return "local-handle"

    def load_policy(self, locator: str) -> object:
        self.opened.append(locator)
        return "local-policy"

    def subject_state(self) -> object:
        return "local-subject"

    def list_changed(self, workspace: object) -> tuple[str, ...]:
        return ("local",)

    def inspect_port(self) -> object:
        return "local-inspect"

    def runner(self, approvals: object) -> object:
        return "local-runner"


def _observation(hub: _Hub, local: _LocalAccess | None = None) -> RoutedObservationWorkspace:
    return RoutedObservationWorkspace(cast(WorkspaceAgentHub, hub), cast(Any, local))


def test_a_local_observed_workspace_is_opened_and_read_here() -> None:
    hub, local = _Hub(), _LocalAccess()
    access = _observation(hub, local)
    assert access.open("/work/repo") == "local-handle"
    assert access.load_policy("/work/repo") == "local-policy"
    assert local.opened == ["/work/repo", "/work/repo"]
    assert hub.calls == []


def test_a_claimed_workspace_is_opened_hashed_and_listed_by_its_agent() -> None:
    from finishup.domain.values import SubjectStateRef
    from finishup.ports.subject_state import SubjectStateCaptureResult, SubjectStateStatus

    state = SubjectStateCaptureResult(
        SubjectStateStatus.CAPTURED,
        SubjectStateRef("sha256:" + "1" * 64, "sha256:" + "2" * 64, "git_structural_v1"),
        SubjectStateFormat.GIT_STRUCTURAL_V1,
        (),
        10,
        1,
    )
    hub = _ScriptedHub(
        {
            WorkspaceOperation.OPEN_WORKSPACE: _OPENED,
            WorkspaceOperation.LOAD_CHECK_POLICY: CheckPolicyRead("legacy", _POLICY),
            WorkspaceOperation.SUBJECT_STATE_CAPTURE: state,
            WorkspaceOperation.LIST_CHANGED_PATHS: ("src/app.py",),
        }
    )
    local = _LocalAccess()
    access = _observation(hub, local)

    handle = access.open(_HANDLE)
    assert (
        type(handle) is LocalWorkspaceHandle and repr(handle) == "LocalWorkspaceHandle(<redacted>)"
    )
    policy, raw = access.load_policy(_HANDLE)
    assert raw == _POLICY and policy.source_path == LEGACY_CHECK_POLICY_PATH
    assert policy.raw_digest == parse_observation_check_policy(_POLICY).raw_digest
    captured = access.subject_state().capture(
        SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
    )
    assert captured == state
    assert access.list_changed(handle) == ("src/app.py",)

    assert local.opened == []
    operations = [(call[0], call[1], call[2]) for call in hub.calls]
    assert operations == [
        (_HANDLE, WorkspaceOperation.OPEN_WORKSPACE, OpenWorkspaceArguments(_HANDLE, True)),
        (_HANDLE, WorkspaceOperation.LOAD_CHECK_POLICY, WorkspaceOnlyArguments(_HANDLE)),
        (
            _HANDLE,
            WorkspaceOperation.SUBJECT_STATE_CAPTURE,
            SubjectStateCaptureArguments(_OPENED, SubjectStateFormat.GIT_STRUCTURAL_V1),
        ),
        (_HANDLE, WorkspaceOperation.LIST_CHANGED_PATHS, ListChangedPathsArguments(_OPENED)),
    ]


def test_a_workspace_the_answering_agent_forgot_is_reopened_once_and_kept() -> None:
    """Another connection of the same client now serves the claim: it opens the workspace anew."""

    from finishup.domain.values import SubjectStateRef
    from finishup.ports.subject_state import SubjectStateCaptureResult, SubjectStateStatus

    state = SubjectStateCaptureResult(
        SubjectStateStatus.CAPTURED,
        SubjectStateRef("sha256:" + "1" * 64, "sha256:" + "2" * 64, "git_structural_v1"),
        SubjectStateFormat.GIT_STRUCTURAL_V1,
        (),
        10,
        1,
    )
    reopened = "rws_" + "1" * 32

    class _ForgettingHub(_Hub):
        """The first agent opened ``_OPENED``; the agent answering now knows only its own."""

        def __init__(self) -> None:
            super().__init__()
            self.opens = 0

        def call_blocking(
            self,
            handle: str,
            operation: WorkspaceOperation,
            arguments: object,
            *,
            timeout_seconds: float,
        ) -> object:
            self.calls.append((handle, operation, arguments, timeout_seconds))
            if operation is WorkspaceOperation.OPEN_WORKSPACE:
                self.opens += 1
                return _OPENED if self.opens == 1 else reopened
            if operation is WorkspaceOperation.SUBJECT_STATE_CAPTURE:
                if cast(SubjectStateCaptureArguments, arguments).handle != reopened:
                    raise WorkspaceAgentUnavailable("agent_unavailable", "handle_unknown")
                return state
            if cast(ListChangedPathsArguments, arguments).handle != reopened:
                raise WorkspaceAgentUnavailable("agent_unavailable", "handle_unknown")
            return ("src/app.py",)

    hub = _ForgettingHub()
    access = _observation(hub)
    handle = access.open(_HANDLE)
    command = SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
    assert access.subject_state().capture(command) == state
    # The new handle is kept: the next call names it at once.
    assert access.list_changed(handle) == ("src/app.py",)
    assert [call[1] for call in hub.calls] == [
        WorkspaceOperation.OPEN_WORKSPACE,
        WorkspaceOperation.SUBJECT_STATE_CAPTURE,
        WorkspaceOperation.OPEN_WORKSPACE,
        WorkspaceOperation.SUBJECT_STATE_CAPTURE,
        WorkspaceOperation.LIST_CHANGED_PATHS,
    ]
    assert hub.calls[2][2] == OpenWorkspaceArguments(_HANDLE, True)
    assert repr(handle) == "LocalWorkspaceHandle(<redacted>)"


def test_any_other_agent_answer_is_never_retried() -> None:
    hub = _ScriptedHub(
        {
            WorkspaceOperation.OPEN_WORKSPACE: _OPENED,
            WorkspaceOperation.LIST_CHANGED_PATHS: WorkspaceAgentUnavailable(
                "agent_unavailable", "workspace_not_claimed"
            ),
        }
    )
    access = _observation(hub)
    handle = access.open(_HANDLE)
    with pytest.raises(WorkspaceAgentUnavailable):
        access.list_changed(handle)
    assert [call[1] for call in hub.calls] == [
        WorkspaceOperation.OPEN_WORKSPACE,
        WorkspaceOperation.LIST_CHANGED_PATHS,
    ]


def test_an_agent_without_a_policy_is_the_ordinary_opt_out() -> None:
    hub = _ScriptedHub(
        {
            WorkspaceOperation.LOAD_CHECK_POLICY: WorkspaceAgentUnavailable(
                "agent_unavailable", "policy_absent"
            )
        }
    )
    with pytest.raises(ObservationCheckPolicyAbsent):
        _observation(hub, _LocalAccess()).load_policy(_HANDLE)


def test_an_approved_check_runs_on_the_client_and_hands_over_its_redacted_output() -> None:
    policy = parse_observation_check_policy(_POLICY)
    (approval,) = policy.checks
    subject = "sha256:" + "3" * 64
    output = b"ok\n"
    import hashlib

    digest = "sha256:" + hashlib.sha256(output).hexdigest()
    result = ApprovedCheckResult(
        ApprovedCheckStatus.PASSED,
        ApprovedCheckOutcome.SUCCESS,
        0,
        digest,
        len(output),
        subject,
        approval.approval_commitment,
        approved_check_result_digest(
            ApprovedCheckStatus.PASSED,
            ApprovedCheckOutcome.SUCCESS,
            0,
            digest,
            len(output),
            subject,
            approval.approval_commitment,
            5,
        ),
        5,
    )
    hub = _ScriptedHub(
        {
            WorkspaceOperation.OPEN_WORKSPACE: _OPENED,
            WorkspaceOperation.RUN_APPROVED_CHECK: ApprovedCheckRun(result, output, True),
        }
    )
    access = _observation(hub, _LocalAccess())
    handle = access.open(_HANDLE)
    runner = access.runner({approval.approval_commitment: approval})
    seen: list[tuple[bytes, bool]] = []

    def sink(data: bytes, redacted: bool) -> None:
        seen.append((data, redacted))

    runner._output_sink = sink  # pyright: ignore[reportPrivateUsage]

    assert runner.run(ApprovedCheckCommand(handle, approval, subject, subject)) == result
    assert seen == [(output, True)]
    _handle, operation, arguments, timeout = hub.calls[-1]
    assert operation is WorkspaceOperation.RUN_APPROVED_CHECK
    assert arguments == RunApprovedCheckArguments(_OPENED, approval, subject, subject)
    assert timeout > approval.timeout_seconds


def test_an_approval_this_policy_does_not_hold_is_refused_before_anything_is_sent() -> None:
    policy = parse_observation_check_policy(_POLICY)
    (approval,) = policy.checks
    hub = _ScriptedHub({WorkspaceOperation.OPEN_WORKSPACE: _OPENED})
    access = _observation(hub, _LocalAccess())
    handle = access.open(_HANDLE)
    subject = "sha256:" + "3" * 64
    refused = access.runner({}).run(ApprovedCheckCommand(handle, approval, subject))
    stale = access.runner({approval.approval_commitment: approval}).run(
        ApprovedCheckCommand(handle, approval, subject, "sha256:" + "4" * 64)
    )
    assert refused.outcome is ApprovedCheckOutcome.NOT_APPROVED
    assert stale.status is ApprovedCheckStatus.STALE
    assert [call[1] for call in hub.calls] == [WorkspaceOperation.OPEN_WORKSPACE]


def test_an_agent_call_never_waits_past_the_catalog_deadline() -> None:
    hub = _Hub(answer=_BASE)
    _routed(hub).read_task_base(_HANDLE)
    hub.answer = OutsideSnapshotsRead(())  # the snapshot's own answer shape
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), _HANDLE)
    reads.snapshot_outside_inputs(("/srv",), ("/srv/a",), limit=1, max_bytes=1, seconds=299.0)
    assert all(0 < call[3] <= 300.0 for call in hub.calls)
