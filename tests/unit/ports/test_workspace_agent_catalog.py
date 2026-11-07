"""The workspace-agent operation catalog (ADR-051): exact round trips, bounds, closed reasons."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from finishup.domain.values import SubjectStateRef, freeze_json
from finishup.ports import workspace_agent as catalog
from finishup.ports.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
    approval_commitment,
    approved_check_result_digest,
)
from finishup.ports.change_capture import (
    CHANGE_CAPTURE_UNAVAILABLE_REASONS,
    ChangeLineCount,
    ChangeLineCounts,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
    NestedUntrackedBaseline,
    OutsideSnapshotRead,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
    UntrackedBaselineFile,
)
from finishup.ports.subject_state import (
    SubjectStateBound,
    SubjectStateCaptureResult,
    SubjectStateFormat,
    SubjectStateLimitation,
    SubjectStateLimitDetail,
    SubjectStateStatus,
)
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_FRAME_BYTES,
    MAX_WORKSPACE_PAYLOAD_BYTES,
    WORKSPACE_FAILURE_REASONS,
    WORKSPACE_OPERATION_CATALOG,
    WORKSPACE_OPERATION_FAMILIES,
    WORKSPACE_OPERATION_NAMES,
    WORKSPACE_REFUSAL_REASONS,
    WORKSPACE_REPLY_REASONS,
    WORKSPACE_UNAVAILABLE_REASONS,
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
    OutsideInputsRead,
    OutsideSnapshotsRead,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    SnapshotOutsideInputsArguments,
    SubjectStateCaptureArguments,
    WorkspaceCodecError,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    change_capture_unavailable_reason,
    new_remote_workspace_handle,
    operation_spec,
    outcome_for_reason,
    remote_workspace_handle_valid,
    workspace_handle_for_claim,
    workspace_handle_valid,
)
from finishup.ports.workspace_inspect import (
    InspectedArtifact,
    WorkspaceInspectLimitation,
    WorkspaceInspectResult,
    WorkspaceInspectStatus,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

_HANDLE = "client:0123456789abcdef"
_REMOTE = "rws_" + "a" * 32
_SHA_A = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64


def _base() -> TaskChangeBase:
    return TaskChangeBase(
        "sha1",
        "a" * 40,
        "task_start",
        (UntrackedBaselineFile("new.txt", "sha256:" + "0" * 64),),
        True,
        (("vendor/lib", "b" * 40),),
        (
            NestedUntrackedBaseline(
                "vendor/lib", True, (UntrackedBaselineFile("x.c", "sha256:" + "1" * 64),)
            ),
        ),
    )


def _approval(timeout: float = 30.0) -> ApprovedCheckApproval:
    argv = ("pytest", "-q", "tests/unit")
    return ApprovedCheckApproval(
        approval_id="unit-tests",
        argv=argv,
        allow_network=False,
        timeout_seconds=timeout,
        approval_commitment=approval_commitment("unit-tests", argv, allow_network=False),
    )


def _check_result(output: bytes | None) -> ApprovedCheckResult:
    status, outcome = ApprovedCheckStatus.PASSED, ApprovedCheckOutcome.SUCCESS
    exit_status = 0
    digest = None if output is None else "sha256:" + hashlib.sha256(output).hexdigest()
    size = 0 if output is None else len(output)
    if output is None:
        status, outcome, exit_status = (
            ApprovedCheckStatus.TIMEOUT,
            ApprovedCheckOutcome.TIMEOUT,
            None,
        )
    commitment = _approval().approval_commitment
    return ApprovedCheckResult(
        status=status,
        outcome=outcome,
        exit_status=exit_status,
        output_digest=digest,
        output_bytes=size,
        subject_state_digest=_SHA_A,
        approval_commitment=commitment,
        result_digest=approved_check_result_digest(
            status, outcome, exit_status, digest, size, _SHA_A, commitment, 1234
        ),
        duration_ms=1234,
    )


# One representative argument value and several result values per operation.
_ARGUMENTS: dict[WorkspaceOperation, tuple[object, ...]] = {
    WorkspaceOperation.READ_TASK_BASE: (WorkspaceOnlyArguments(_HANDLE),),
    WorkspaceOperation.CAPTURE: (
        CaptureArguments(
            _HANDLE,
            _base(),
            ("src/app.py",),
            ("docs/spec.md", "docs/My Notes.md", "docs/My"),
            frozenset({"docs/My", "Notes.md"}),
        ),
        CaptureArguments(_HANDLE, None),
    ),
    WorkspaceOperation.CAPTURE_METADATA: (
        CaptureMetadataArguments(_HANDLE, _base()),
        CaptureMetadataArguments(_HANDLE, None),
    ),
    WorkspaceOperation.PROBE_REQUESTED_PATHS: (
        ProbeRequestedPathsArguments(_HANDLE, ("out/report.json", "/abs/elsewhere", ".")),
    ),
    WorkspaceOperation.COUNT_CHANGE_LINES: (
        CountChangeLinesArguments(_HANDLE, "c" * 64, ("src/app.py",)),
    ),
    WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES: (
        ClassifyUndeclaredReferencesArguments(
            _HANDLE, ("cracker.py",), ("model.bin", "weights/a.pt"), ("cracker.py",)
        ),
    ),
    WorkspaceOperation.READ_OUTSIDE_INPUTS: (
        ReadOutsideInputsArguments(
            ("/data/inputs",),
            ("/data/inputs/spec.md", "/data/inputs/"),
            4,
            ("/srv/dev/repo",),
            frozenset({"/data/inputs/a"}),
        ),
    ),
    WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS: (
        SnapshotOutsideInputsArguments(
            ("/data/inputs",), ("/data/inputs/spec.md",), 16, 262_144, 5_000, ("/srv/dev/repo",)
        ),
    ),
    WorkspaceOperation.READ_DECLARED_TEST: (
        ReadDeclaredTestArguments("/srv/tests/test_spec.py", ("/srv/dev/repo",)),
    ),
    WorkspaceOperation.READ_TEXT_BENEATH: (
        ReadTextBeneathArguments("/srv/dev/repo", "src/app.py", ()),
        ReadTextBeneathArguments("/srv/dev/repo", "", ()),
    ),
    WorkspaceOperation.LIST_BENEATH: (ListBeneathArguments("/srv/dev/repo", "src", (), 128),),
    WorkspaceOperation.LSTAT_CANDIDATES: (
        LstatCandidatesArguments(("/data/inputs", "/data/inputs/spec.md")),
    ),
    WorkspaceOperation.OPEN_WORKSPACE: (
        OpenWorkspaceArguments(_HANDLE, True),
        OpenWorkspaceArguments(_HANDLE),
    ),
    WorkspaceOperation.LOAD_CHECK_POLICY: (WorkspaceOnlyArguments(_HANDLE),),
    WorkspaceOperation.SUBJECT_STATE_CAPTURE: (SubjectStateCaptureArguments(_REMOTE),),
    WorkspaceOperation.LIST_CHANGED_PATHS: (ListChangedPathsArguments(_REMOTE, 64),),
    WorkspaceOperation.INSPECT: (InspectArguments(_REMOTE, ("src/app.py", "README.md")),),
    WorkspaceOperation.RUN_APPROVED_CHECK: (
        RunApprovedCheckArguments(_REMOTE, _approval(), _SHA_A, None),
        RunApprovedCheckArguments(_REMOTE, _approval(2.5555), _SHA_A, _SHA_B),
    ),
}

_RESULTS: dict[WorkspaceOperation, tuple[object, ...]] = {
    WorkspaceOperation.READ_TASK_BASE: (_base(), TaskChangeBase("sha256", "d" * 64)),
    WorkspaceOperation.CAPTURE: (
        CheckChangeCapture(
            base="task_start",
            text=b"diff --git a/src/app.py b/src/app.py\n+\tprint('\xc3\xa9')\n",
            tracked_files=1,
            untracked_files=1,
            omitted_files=1,
            truncated=True,
            base_commit="a" * 40,
            inputs=(
                TaskInputFile("docs/spec.md", b"the spec\n", 9),
                TaskInputFile(
                    "/data/inputs/spec.md",
                    b"outside",
                    7,
                    True,
                    "outside_workspace",
                    False,
                    "/data/inputs",
                    "task_start",
                    "same",
                ),
            ),
            outside_inputs_not_admitted=True,
        ),
    ),
    WorkspaceOperation.CAPTURE_METADATA: (
        CheckChangeMetadata(
            base="head",
            entries=(
                ChangeMetadataEntry("M", "src/app.py"),
                ChangeMetadataEntry("R", "new.py", False, "old.py"),
                ChangeMetadataEntry("??", "notes\tdraft.txt", True),
            ),
            tracked_files=3,
            untracked_files=2,
            omitted_files=1,
            truncated=True,
            base_commit="c" * 64,
            unrepresentable_files=1,
        ),
    ),
    WorkspaceOperation.PROBE_REQUESTED_PATHS: (
        (
            RequestedPathProbe("inside", "out/report.json", True, False, size_bytes=12),
            RequestedPathProbe("outside"),
            RequestedPathProbe("inside", ".", True, False, holds_file=True),
            RequestedPathProbe(
                "inside", "build/x", False, True, "repository_file", "build/.gitignore"
            ),
        ),
        (),
    ),
    WorkspaceOperation.COUNT_CHANGE_LINES: (
        ChangeLineCounts(
            (
                ChangeLineCount("a.py", 3, 1),
                ChangeLineCount("b.bin", None, None),
                ChangeLineCount("u.txt", 5, 0, True),
            ),
            (10, None),
            False,
        ),
    ),
    WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES: (
        ((0, 0, "dependency"), (0, 1, "ambiguous")),
        (),
    ),
    WorkspaceOperation.READ_OUTSIDE_INPUTS: (
        OutsideInputsRead(
            (
                TaskInputFile(
                    "/data/inputs/spec.md",
                    b"spec",
                    4,
                    False,
                    "outside_workspace",
                    root="/data/inputs",
                ),
            ),
        ),
        OutsideInputsRead((), (0, 2)),
        OutsideInputsRead(()),
    ),
    WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS: (
        OutsideSnapshotsRead(
            (
                OutsideSnapshotRead("/data/inputs", "/data/inputs/a.txt", 5, b"hello", None),
                OutsideSnapshotRead(
                    "/data/inputs", "/data/inputs/big.bin", 999_999, None, "too_large"
                ),
                OutsideSnapshotRead("/data/inputs", "/data/inputs/gone", 0, None, "unreadable"),
            ),
            (1,),
        ),
        OutsideSnapshotsRead(()),
    ),
    WorkspaceOperation.READ_DECLARED_TEST: (b"def test_x():\n    assert True\n", None),
    WorkspaceOperation.READ_TEXT_BENEATH: ((b"abc\x00\xff", 5), (b"", 2_000_000), None),
    WorkspaceOperation.LIST_BENEATH: (((("a.py", False), ("pkg", True)), True), ((), False), None),
    WorkspaceOperation.LSTAT_CANDIDATES: (
        (
            LstatFacts(stat.S_IFDIR | 0o755, 1_700_000_000_123_456_789, 1_700_000_001_000_000_001),
            None,
            LstatFacts(stat.S_IFREG | 0o644, 0, 5),
        ),
    ),
    WorkspaceOperation.OPEN_WORKSPACE: (_REMOTE,),
    WorkspaceOperation.LOAD_CHECK_POLICY: (
        CheckPolicyRead("current", b'[[check]]\nid = "unit"\n'),
        CheckPolicyRead("legacy", b"\x00raw"),
    ),
    WorkspaceOperation.SUBJECT_STATE_CAPTURE: (
        SubjectStateCaptureResult(
            SubjectStateStatus.CAPTURED,
            SubjectStateRef(_SHA_A, _SHA_B, "git_structural_v1"),
            SubjectStateFormat.GIT_STRUCTURAL_V1,
            (),
            1_024,
            3,
        ),
        SubjectStateCaptureResult(
            SubjectStateStatus.UNSUPPORTED,
            None,
            SubjectStateFormat.GIT_STRUCTURAL_V1,
            (SubjectStateLimitation.FILE_LIMIT_EXCEEDED, SubjectStateLimitation.NOT_GIT),
            0,
            0,
            (SubjectStateLimitDetail(SubjectStateBound.UNTRACKED_FILE_COUNT, 10_001, 10_000),),
        ),
    ),
    WorkspaceOperation.LIST_CHANGED_PATHS: (("README.md", "src/app.py"), ()),
    WorkspaceOperation.INSPECT: (
        WorkspaceInspectResult(
            WorkspaceInspectStatus.PARTIAL,
            (InspectedArtifact("src/app.py", _SHA_A, b"print(1)\n", False, 9),),
            (WorkspaceInspectLimitation.NOT_A_FILE,),
            _SHA_B,
        ),
        WorkspaceInspectResult(
            WorkspaceInspectStatus.REJECTED, (), (WorkspaceInspectLimitation.UNSAFE_ROOT,), None
        ),
    ),
    WorkspaceOperation.RUN_APPROVED_CHECK: (
        ApprovedCheckRun(_check_result(b"3 passed\n"), b"3 passed\n", True),
        ApprovedCheckRun(_check_result(None)),
    ),
}


def _through_wire(value: JsonValue) -> JsonValue:
    """The value as the peer receives it: canonical bytes, strictly parsed, then frozen."""

    return freeze_json(strict_json_parse(canonical_encode(value)))


# --- the catalog's shape ------------------------------------------------------------------


def test_the_catalog_holds_exactly_the_eighteen_operations_in_three_families() -> None:
    assert len(WorkspaceOperation) == 18
    assert set(WORKSPACE_OPERATION_CATALOG) == set(WorkspaceOperation)
    assert WORKSPACE_OPERATION_NAMES == tuple(
        sorted((operation.value for operation in WorkspaceOperation), key=str.encode)
    )
    families: dict[str, set[str]] = {}
    for name, family in WORKSPACE_OPERATION_FAMILIES.items():
        families.setdefault(family, set()).add(name)
    assert families == {
        "git": {
            "read_task_base",
            "capture",
            "capture_metadata",
            "probe_requested_paths",
            "count_change_lines",
            "classify_undeclared_references",
        },
        "reads": {
            "read_outside_inputs",
            "snapshot_outside_inputs",
            "read_declared_test",
            "read_text_beneath",
            "list_beneath",
            "lstat_candidates",
        },
        "observation": {
            "open_workspace",
            "load_check_policy",
            "subject_state_capture",
            "list_changed_paths",
            "inspect",
            "run_approved_check",
        },
    }
    for spec in WORKSPACE_OPERATION_CATALOG.values():
        assert 1 <= spec.max_argument_bytes <= MAX_WORKSPACE_PAYLOAD_BYTES
        assert 1 <= spec.max_result_bytes <= MAX_WORKSPACE_PAYLOAD_BYTES
    assert set(_ARGUMENTS) == set(_RESULTS) == set(WorkspaceOperation)


def test_mirrored_bounds_equal_their_sources() -> None:
    from finishup.adapters import git_change_capture, task_input_read
    from finishup.application import observation_check_policy
    from finishup.ports import control
    from finishup.service import control_protocol

    assert MAX_WORKSPACE_FRAME_BYTES == control_protocol.MAX_CONTROL_FRAME_BYTES
    assert catalog.MAX_WORKSPACE_DEADLINE_MS == control._MAX_DEADLINE_MS  # pyright: ignore[reportPrivateUsage]
    mirrored = {
        "_MAX_REQUESTED_PATH_PROBES": git_change_capture._MAX_REQUESTED_PATH_PROBES,  # pyright: ignore[reportPrivateUsage]
        "_MAX_REFERENCE_DELIVERABLES": git_change_capture._MAX_REFERENCE_DELIVERABLES,  # pyright: ignore[reportPrivateUsage]
        "_MAX_REFERENCE_CANDIDATES": git_change_capture._MAX_REFERENCE_CANDIDATES,  # pyright: ignore[reportPrivateUsage]
        "_MAX_REFERENCE_PAIRS": git_change_capture._MAX_REFERENCE_PAIRS,  # pyright: ignore[reportPrivateUsage]
        "_MAX_TASK_INPUT_READ_BYTES": task_input_read.MAX_TASK_INPUT_READ_BYTES,
        "_MAX_POLICY_BYTES": observation_check_policy._MAX_POLICY_BYTES,  # pyright: ignore[reportPrivateUsage]
    }
    for name, expected in mirrored.items():
        assert getattr(catalog, name) == expected, name


def test_moved_value_types_keep_their_adapter_names() -> None:
    from finishup.adapters import approved_checks, task_input_read

    assert task_input_read.OutsideSnapshotRead is OutsideSnapshotRead
    assert approved_checks.ApprovedCheckResult is ApprovedCheckResult
    assert approved_checks.ApprovedCheckApproval is ApprovedCheckApproval
    assert approved_checks.approval_commitment is approval_commitment


# --- exact round trips --------------------------------------------------------------------


@pytest.mark.parametrize("operation", list(WorkspaceOperation), ids=lambda item: item.value)
def test_every_operation_round_trips_its_arguments_exactly(operation: WorkspaceOperation) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[operation]
    for value in _ARGUMENTS[operation]:
        wire = spec.encode_arguments(value)
        assert type(wire) is dict
        assert len(canonical_encode(wire)) <= spec.max_argument_bytes
        decoded = spec.decode_arguments(_through_wire(wire))
        assert decoded == value
        assert spec.encode_arguments(decoded) == wire


@pytest.mark.parametrize("operation", list(WorkspaceOperation), ids=lambda item: item.value)
def test_every_operation_round_trips_its_results_exactly(operation: WorkspaceOperation) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[operation]
    for value in _RESULTS[operation]:
        wire = spec.encode_result(value)
        assert len(canonical_encode(wire)) <= spec.max_result_bytes
        decoded = spec.decode_result(_through_wire(wire))
        assert decoded == value
        assert canonical_encode(spec.encode_result(decoded)) == canonical_encode(wire)


def test_change_captures_keep_the_stored_object_bytes() -> None:
    """A capture the agent carries is byte-identical to the object the service stores."""

    from finishup.ports.change_capture import encode_check_change, encode_task_change_base

    capture = cast(CheckChangeCapture, _RESULTS[WorkspaceOperation.CAPTURE][0])
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.CAPTURE]
    assert canonical_encode(spec.encode_result(capture)) == encode_check_change(capture)
    base_spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_TASK_BASE]
    assert canonical_encode(base_spec.encode_result(_base())) == encode_task_change_base(_base())


def test_bytes_travel_as_canonical_base64() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_TEXT_BENEATH]
    assert spec.encode_result((b"\x00\xffab", 4)) == {"data": "AP9hYg==", "size": 4}
    for spelling in ("AP9hYg", "AP9hYg==\n", "AP9hYh==", "AP9h Yg=="):
        with pytest.raises(WorkspaceCodecError) as refused:
            spec.decode_result({"data": spelling, "size": 4})
        assert refused.value.reason == "result_invalid"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("path", 5),
        ("path", ["/data/inputs/spec.md"]),
        ("redacted", 0),
        ("size", True),
        ("size", "4"),
        ("origin", ["outside_workspace"]),
        ("root", 7),
        ("baseline", {"task_start": True}),
        ("current_state", ["unchanged"]),
    ],
)
def test_a_wrong_typed_task_input_field_is_a_refused_result(name: str, value: object) -> None:
    """A workspace agent's reply is untrusted: a wrong-typed field is ``result_invalid``, never
    an ``AttributeError`` or ``TypeError`` escaping from inside the value type."""

    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_OUTSIDE_INPUTS]
    read = OutsideInputsRead(
        (
            TaskInputFile(
                "/data/inputs/spec.md",
                b"spec",
                4,
                False,
                "outside_workspace",
                root="/data/inputs",
                baseline="task_start",
                current_state="same",
            ),
        ),
    )
    encoded = cast(dict[str, Any], strict_json_parse(canonical_encode(spec.encode_result(read))))
    assert spec.decode_result(encoded) == read
    encoded["inputs"][0][name] = value
    with pytest.raises(WorkspaceCodecError) as refused:
        spec.decode_result(encoded)
    assert refused.value.reason == "result_invalid"


def test_the_approved_check_timeout_is_the_exact_float() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.RUN_APPROVED_CHECK]
    for timeout in (0.1, 2.5555, 30.0, 299.99999999999994, 300.0):
        value = RunApprovedCheckArguments(_REMOTE, _approval(timeout), _SHA_A)
        wire = spec.encode_arguments(value)
        decoded = cast(RunApprovedCheckArguments, spec.decode_arguments(wire))
        assert decoded.approval.timeout_seconds == timeout
    wire = spec.encode_arguments(RunApprovedCheckArguments(_REMOTE, _approval(30.0), _SHA_A))
    approval = dict(cast(dict[str, Any], wire["approval"]))
    for spelling in ("30", "30.00", "3e1", "030.0", "-1.0"):
        approval["timeout_seconds"] = spelling
        with pytest.raises(WorkspaceCodecError) as refused:
            spec.decode_arguments({**wire, "approval": approval})
        assert refused.value.reason == "arguments_invalid"


# --- properties ---------------------------------------------------------------------------

_PATH_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=40,
)


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=4096), st.integers(min_value=0, max_value=1 << 40))
def test_text_reads_round_trip(data: bytes, extra: int) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_TEXT_BENEATH]
    for value in ((data, len(data)), (b"", len(data) + extra)):
        assert spec.decode_result(_through_wire(spec.encode_result(value))) == value
    declared = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_DECLARED_TEST]
    assert declared.decode_result(_through_wire(declared.encode_result(data))) == data


@settings(max_examples=60, deadline=None)
@given(st.lists(_PATH_TEXT, max_size=64), st.lists(_PATH_TEXT, max_size=64))
def test_path_lists_and_sets_round_trip(values: list[str], cut: list[str]) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.CAPTURE]
    value = CaptureArguments(_HANDLE, None, tuple(values), tuple(reversed(values)), frozenset(cut))
    wire = spec.encode_arguments(value)
    assert wire["space_cut_paths"] == sorted(set(cut), key=str.encode)
    assert spec.decode_arguments(_through_wire(wire)) == value
    probe = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.PROBE_REQUESTED_PATHS]
    probes = ProbeRequestedPathsArguments(_HANDLE, tuple(values))
    assert probe.decode_arguments(_through_wire(probe.encode_arguments(probes))) == probes


_STATUS = st.text(alphabet="ACDMRTU?!", min_size=1, max_size=2)
_ENTRY_PATH = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00\r\n"),
    min_size=1,
    max_size=30,
)


@st.composite
def _metadata(draw: st.DrawFn) -> CheckChangeMetadata:
    rows = draw(
        st.lists(
            st.tuples(_STATUS, _ENTRY_PATH, st.booleans(), st.one_of(st.none(), _ENTRY_PATH)),
            max_size=20,
        )
    )
    entries = tuple(
        ChangeMetadataEntry("R" if original is not None else status, path, untracked, original)
        for status, path, untracked, original in rows
    )
    omitted = draw(st.integers(min_value=0, max_value=5))
    unrepresentable = draw(st.integers(min_value=0, max_value=omitted))
    return CheckChangeMetadata(
        base=draw(st.sampled_from(("task_start", "first_check", "head", "empty"))),
        entries=entries,
        tracked_files=len(entries) + omitted,
        untracked_files=draw(st.integers(min_value=0, max_value=5)),
        omitted_files=omitted,
        truncated=bool(omitted) or draw(st.booleans()),
        base_commit=draw(st.sampled_from(("", "a" * 40, "b" * 64))),
        unrepresentable_files=unrepresentable,
    )


@settings(max_examples=80, deadline=None)
@given(_metadata())
def test_change_metadata_round_trips(value: CheckChangeMetadata) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.CAPTURE_METADATA]
    assert spec.decode_result(_through_wire(spec.encode_result(value))) == value


@settings(max_examples=80, deadline=None)
@given(
    st.lists(
        st.tuples(
            _ENTRY_PATH,
            st.one_of(st.none(), st.integers(min_value=0, max_value=1 << 40)),
            st.one_of(st.none(), st.integers(min_value=0, max_value=1 << 40)),
            st.booleans(),
        ),
        max_size=30,
    ),
    st.lists(st.one_of(st.none(), st.integers(min_value=0, max_value=1 << 40)), max_size=64),
    st.booleans(),
)
def test_line_counts_round_trip(
    changed: list[tuple[str, int | None, int | None, bool]],
    base_lines: list[int | None],
    truncated: bool,
) -> None:
    value = ChangeLineCounts(
        tuple(ChangeLineCount(*row) for row in changed), tuple(base_lines), truncated
    )
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.COUNT_CHANGE_LINES]
    assert spec.decode_result(_through_wire(spec.encode_result(value))) == value


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.one_of(
            st.none(),
            st.builds(
                LstatFacts,
                st.integers(min_value=0, max_value=0o177777),
                st.integers(min_value=-(2**62), max_value=2**62),
                st.integers(min_value=-(2**62), max_value=2**62),
            ),
        ),
        max_size=40,
    )
)
def test_lstat_facts_round_trip(value: list[LstatFacts | None]) -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.LSTAT_CANDIDATES]
    assert spec.decode_result(_through_wire(spec.encode_result(tuple(value)))) == tuple(value)


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.text(
                alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00/"),
                min_size=1,
                max_size=20,
            ),
            st.booleans(),
        ),
        max_size=40,
    ),
    st.booleans(),
)
def test_listings_round_trip(entries: list[tuple[str, bool]], truncated: bool) -> None:
    value = (tuple(entries), truncated)
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.LIST_BENEATH]
    assert spec.decode_result(_through_wire(spec.encode_result(value))) == value


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=1, max_size=2048), st.booleans())
def test_approved_check_runs_round_trip(output: bytes, redacted: bool) -> None:
    value = ApprovedCheckRun(_check_result(output), output, redacted)
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.RUN_APPROVED_CHECK]
    assert spec.decode_result(_through_wire(spec.encode_result(value))) == value


# --- refusals -----------------------------------------------------------------------------


def test_the_exact_key_set_is_the_only_accepted_shape() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_TEXT_BENEATH]
    wire = spec.encode_arguments(ReadTextBeneathArguments("/srv/dev/repo", "src/app.py"))
    for broken in (
        {**wire, "extra": True},
        {key: value for key, value in wire.items() if key != "excluded"},
        {**wire, "root": "relative/root"},
        {**wire, "relative": "bad\x00path"},
        ["not", "an", "object"],
    ):
        with pytest.raises(WorkspaceCodecError) as refused:
            spec.decode_arguments(broken)
        assert refused.value.reason == "arguments_invalid"
        assert str(refused.value) == "arguments_invalid"


def test_handles_are_refused_unless_they_are_the_claimed_shape() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_TASK_BASE]
    for handle in ("/srv/dev/repo", "client:XYZ", "client:0123456789abcdef0", _REMOTE):
        with pytest.raises(WorkspaceCodecError):
            spec.decode_arguments({"workspace": handle})
    observation = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.INSPECT]
    with pytest.raises(WorkspaceCodecError):
        observation.decode_arguments({"handle": _HANDLE, "relative_paths": ["a.py"]})
    with pytest.raises(WorkspaceCodecError):
        observation.decode_arguments({"handle": _REMOTE, "relative_paths": ["../escape"]})


def test_argument_counts_are_bounded() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.PROBE_REQUESTED_PATHS]
    with pytest.raises(ValueError):
        ProbeRequestedPathsArguments(_HANDLE, tuple(f"p{index}" for index in range(65)))
    with pytest.raises(WorkspaceCodecError) as refused:
        spec.decode_arguments(
            {"values": [f"p{index}" for index in range(65)], "workspace": _HANDLE}
        )
    assert refused.value.reason == "arguments_invalid"
    with pytest.raises(WorkspaceCodecError) as wrong_type:
        spec.encode_arguments(WorkspaceOnlyArguments(_HANDLE))
    assert wrong_type.value.reason == "arguments_invalid"


def test_oversized_payloads_are_refused_by_size() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.OPEN_WORKSPACE]
    with pytest.raises(WorkspaceCodecError) as large:
        spec.decode_arguments({"admitted_home_project": False, "workspace": "x" * 2048})
    assert large.value.reason == "arguments_too_large"
    policy = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.LOAD_CHECK_POLICY]
    with pytest.raises(WorkspaceCodecError) as too_large:
        policy.decode_result({"location": "current", "policy": "A" * (700 * 1024)})
    assert too_large.value.reason == "result_too_large"


def test_a_tampered_approved_check_result_is_refused() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.RUN_APPROVED_CHECK]
    good = cast(
        dict[str, Any], spec.encode_result(ApprovedCheckRun(_check_result(b"ok\n"), b"ok\n"))
    )
    forged_result = {**good["result"], "duration_ms": 1}
    with pytest.raises(WorkspaceCodecError) as digest:
        spec.decode_result({**good, "result": forged_result})
    assert digest.value.reason == "result_invalid"
    with pytest.raises(WorkspaceCodecError) as output:
        spec.decode_result({**good, "output": "bm8K"})
    assert output.value.reason == "result_invalid"
    with pytest.raises(ValueError):
        ApprovedCheckRun(_check_result(None), b"output without a digest")


def test_inconsistent_snapshot_rows_are_refused() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS]
    row = {"path": "/data/a", "reason": "too_large", "root": "/data", "size": 1, "text": "aGk="}
    with pytest.raises(WorkspaceCodecError):
        spec.decode_result([row])
    with pytest.raises(WorkspaceCodecError):
        spec.decode_result([{**row, "reason": "stale", "text": None}])
    with pytest.raises(WorkspaceCodecError):
        spec.encode_result((OutsideSnapshotRead("/data", "/data/a", 1, None, None),))


# --- honest fitting of listings that outgrow a frame ---------------------------------------


def test_an_oversized_change_listing_is_cut_and_counted_as_omitted() -> None:
    path = "d/" + "x" * 4000
    entries = tuple(ChangeMetadataEntry("M", f"{path}{index}") for index in range(2_000))
    value = CheckChangeMetadata(
        base="head",
        entries=entries,
        tracked_files=len(entries),
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.CAPTURE_METADATA]
    wire = spec.encode_result(value)
    assert len(canonical_encode(wire)) <= spec.max_result_bytes
    fitted = cast(CheckChangeMetadata, spec.decode_result(wire))
    kept = len(fitted.entries)
    assert 0 < kept < len(entries)
    assert fitted.entries == entries[:kept]
    assert fitted.truncated is True
    assert fitted.omitted_files == len(entries) - kept
    # The next entry would not have fit: the cut keeps as much as one frame can carry.
    longer = replace(fitted, entries=entries[: kept + 1], omitted_files=len(entries) - kept - 1)
    encode = spec._encode_result  # pyright: ignore[reportPrivateUsage]
    assert len(canonical_encode(encode(longer))) > spec.max_result_bytes


def test_oversized_line_counts_are_cut_and_marked_truncated() -> None:
    changed = tuple(ChangeLineCount("y" * 4000 + str(index), 1, 0) for index in range(2_000))
    value = ChangeLineCounts(changed, (1,), False)
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.COUNT_CHANGE_LINES]
    fitted = cast(ChangeLineCounts, spec.decode_result(spec.encode_result(value)))
    assert fitted.truncated is True
    assert 0 < len(fitted.changed) < len(changed)
    assert fitted.changed == changed[: len(fitted.changed)]
    assert fitted.base_lines == (1,)


def test_a_result_that_cannot_be_cut_is_too_large() -> None:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.PROBE_REQUESTED_PATHS]
    # A control character costs six bytes once JSON-escaped: 64 such probes outgrow the bound.
    escaped = "\x01" * 8_000
    probes = tuple(
        RequestedPathProbe("inside", escaped, True, True, "repository_file", escaped)
        for _ in range(64)
    )
    with pytest.raises(WorkspaceCodecError) as refused:
        spec.encode_result(probes)
    assert refused.value.reason == "result_too_large"
    with pytest.raises(WorkspaceCodecError) as invalid:
        WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.LIST_CHANGED_PATHS].encode_result(
            ("b.py", "a.py")
        )
    assert invalid.value.reason == "result_invalid"


# --- reasons, handles and lstat facts ------------------------------------------------------


def test_reply_reasons_are_closed_disjoint_and_keep_change_capture_tokens() -> None:
    assert WORKSPACE_REPLY_REASONS == (
        WORKSPACE_REFUSAL_REASONS | WORKSPACE_UNAVAILABLE_REASONS | WORKSPACE_FAILURE_REASONS
    )
    assert not WORKSPACE_REFUSAL_REASONS & WORKSPACE_UNAVAILABLE_REASONS
    assert CHANGE_CAPTURE_UNAVAILABLE_REASONS <= WORKSPACE_UNAVAILABLE_REASONS
    assert {item.value for item in SubjectStateLimitation} <= WORKSPACE_UNAVAILABLE_REASONS
    for reason in CHANGE_CAPTURE_UNAVAILABLE_REASONS:
        assert change_capture_unavailable_reason(reason) == reason
        assert outcome_for_reason(reason) == "unavailable"
    assert change_capture_unavailable_reason("root_not_admitted") is None
    assert outcome_for_reason("root_not_admitted") == "refused"
    assert outcome_for_reason("internal_error") == "failed"
    with pytest.raises(ValueError):
        outcome_for_reason("not_a_reason")


def test_operation_lookup_is_closed() -> None:
    assert operation_spec("capture") is WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.CAPTURE]
    assert operation_spec(WorkspaceOperation.INSPECT) is not None
    for unknown in ("rm_rf", "", None, 3, b"capture"):
        assert operation_spec(unknown) is None


def test_workspace_handles_come_from_the_commitment_and_the_worktree() -> None:
    commitment = "hmac-sha256:" + "0123456789abcdef" + "f" * 48
    worktree = "sha256:" + "1" * 64
    expected = hashlib.sha256(
        b"yoetz/workspace-handle/v1\x00" + commitment.encode() + b"\x00" + worktree.encode()
    ).hexdigest()[:16]
    handle = workspace_handle_for_claim(commitment, worktree)
    assert handle == "client:" + expected
    assert workspace_handle_valid(handle) and workspace_handle_valid(_HANDLE)
    # Linked worktrees of one repository share the commitment, never a handle.
    assert workspace_handle_for_claim(commitment, "sha256:" + "2" * 64) != handle
    assert workspace_handle_for_claim("hmac-sha256:" + "e" * 64, worktree) != handle
    for invalid in ("client:0123456789ABCDEF", "client:", "/srv/dev/repo", None):
        assert not workspace_handle_valid(invalid)
    with pytest.raises(ValueError, match="workspace_commitment_invalid"):
        workspace_handle_for_claim("sha256:" + "0" * 64, worktree)
    with pytest.raises(ValueError, match="workspace_worktree_invalid"):
        workspace_handle_for_claim(commitment, "/srv/dev/repo")
    first, second = new_remote_workspace_handle(), new_remote_workspace_handle()
    assert first != second
    assert remote_workspace_handle_valid(first) and remote_workspace_handle_valid(second)
    assert not remote_workspace_handle_valid(_HANDLE)


def test_lstat_facts_reproduce_the_original_stat_times(tmp_path: Path) -> None:
    target = tmp_path / "input.txt"
    target.write_text("x", encoding="utf-8")
    os.utime(target, ns=(1_700_000_000_123_456_789, 1_700_000_000_987_654_321))
    for path in (target, tmp_path):
        original = os.lstat(path)
        facts = LstatFacts.from_stat_result(original)
        rebuilt = facts.to_stat_result()
        assert rebuilt.st_mode == original.st_mode
        assert rebuilt.st_mtime == original.st_mtime
        assert rebuilt.st_ctime == original.st_ctime
        assert rebuilt.st_mtime_ns == original.st_mtime_ns
    assert LstatFacts.from_stat_result(os.lstat(target)).is_regular_file
    assert LstatFacts.from_stat_result(os.lstat(tmp_path)).is_directory


def test_codec_errors_are_closed_and_name_no_value() -> None:
    with pytest.raises(ValueError, match="workspace_codec_reason_invalid"):
        WorkspaceCodecError("/srv/dev/secret")
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation.READ_DECLARED_TEST]
    with pytest.raises(WorkspaceCodecError) as refused:
        spec.decode_arguments({"excluded": [], "location": "relative/secret-name.py"})
    assert "secret-name" not in f"{refused.value!r} {refused.value}"
