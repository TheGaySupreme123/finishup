"""Service-side capture, storage and recovery of the check-time change (ADR-031).

The pure case builder never touches Git or the object store. This module is the narrow service
step between them: it records the task-start base when a task is created, captures the check-time
change through ``ChangeCapturePort`` for one check, applies the same capture-time redaction native
observation content receives, stores the result as one encrypted ``change_capture`` object, and
reloads exactly that object when a durable AI-powered review job is recovered. The composition
persists ``CheckChangeOutcome.binding_json()`` in the job's semantic-case object so a replay
rebuilds a byte-identical case instead of re-reading a working tree that has since changed.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
import shlex
import stat
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Final, TypedDict, cast

from finishup.application.semantic_case import CheckTimeChange, check_time_change_shown_record
from finishup.domain.events import (
    MAX_CHECK_CHANGE_SHOWN_FILES,
    ActionKind,
    CheckChangePartialFile,
    CheckChangeShownFiles,
    RequestedItemKind,
    RequestedItemRole,
)
from finishup.domain.observation_selection import command_is_verification
from finishup.domain.privacy import ReviewSelectionPolicy, admitted_input_root_valid
from finishup.domain.receipts import CHECK_TIME_CHANGE_UNAVAILABLE_REASONS
from finishup.domain.repository_excerpt import credential_named_bytes
from finishup.domain.values import ObligationId
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    RequestedOutputState,
    effective_obligations,
    superseded_unnamed_outputs,
)
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER, redact_sensitive_content
from finishup.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    MAX_CHECK_CHANGE_TEXT_BYTES,
    MAX_TASK_INPUT_FILES,
    MAX_TASK_INPUT_TEXT_BYTES,
    TASK_CHANGE_BASE_MEDIA_TYPE,
    ChangeCapturePort,
    ChangeCaptureUnavailable,
    ChangeLineCounts,
    CheckChangeCapture,
    CheckChangeMetadata,
    CheckWorkspaceSource,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
    decode_check_change,
    decode_task_change_base,
    drop_space_cut_words,
    encode_check_change,
    encode_task_change_base,
)
from finishup.ports.clock import ClockPort
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import JsonValue

__all__ = [
    "declared_output_paths",
    "OutsideInputReader",
    "outside_input_candidates",
    "outside_inputs_not_admitted",
    "review_input_paths",
    "space_cut_input_paths",
    "task_input_paths",
    "verification_input_paths",
    "CheckChangeOutcome",
    "capture_structural_check_change",
    "capture_check_time_change",
    "check_change_shown_files",
    "check_time_change_selected",
    "UndeclaredReferenceRead",
    "record_task_change_base",
    "recover_check_time_change",
]

_COMPONENT: Final = "semantic_composition"
_MAX_REDACTION_PASSES: Final = 64
# Keyed per-file commitments share the change_capture commitment key with a message prefix that
# no stored change_capture object (canonical JSON, starting with ``{``) can begin with.
_SHOWN_FILE_DOMAIN: Final = b"yoetz/check-change-shown-file/v1\x00"
_SHOWN_VIEW_DOMAIN: Final = b"yoetz/check-change-shown-view/v1\x00"
_STRUCTURAL_METADATA_UNAVAILABLE: Final = "metadata_unavailable"


@dataclass(frozen=True, slots=True)
class CheckChangeOutcome:
    """What the service could provide for one check: the change, its absence, or neither.

    ``NOT_OFFERED`` (no change and not unavailable) means no trusted workspace source was bound,
    as for an embedded application without a control session; the case then carries neither the
    change nor a gap, exactly as before ADR-031. ``reason`` is the closed code for why an
    unavailable change could not be captured (``None`` for a job frozen before reasons existed).
    """

    change: CheckTimeChange | None = None
    unavailable: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.change is not None and type(self.change) is not CheckTimeChange:
            raise TypeError("check_change_outcome_invalid")
        if type(self.unavailable) is not bool or (self.unavailable and self.change is not None):
            raise ValueError("check_change_outcome_invalid")
        if self.reason is not None and (
            not self.unavailable or self.reason not in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS
        ):
            raise ValueError("check_change_outcome_invalid")

    @property
    def offered(self) -> bool:
        return self.change is not None or self.unavailable

    def binding_json(self) -> JsonValue:
        """The durable pointer a recovered job reloads; never content."""

        ref = None if self.change is None else self.change.object_ref
        return cast(
            JsonValue,
            {
                "object": None
                if ref is None
                else {
                    "commitment": ref.commitment,
                    "envelope_digest": ref.envelope_digest,
                    "object_id": ref.object_id,
                },
                "schema": "yoetz.check-change-binding/1",
                "unavailable": self.unavailable,
                # Frozen with the job so a recovered job rebuilds the same disclosed reason.
                **({} if self.reason is None else {"reason": self.reason}),
            },
        )


async def check_change_shown_files(
    runtime: TaskRuntime,
    change: CheckTimeChange,
    shown_bytes: int,
    served: Sequence[tuple[int, int]] = (),
) -> CheckChangeShownFiles:
    """Keyed commitments to the changed files one review packet carried (ADR-031).

    Each file is committed with the task bundle's own object commitment key over its base and its
    ``diff --git`` line, so no path is recorded, the same file under the same base commits the
    same way in every check of the task, and a file under a different base or of a different
    change kind does not match. A file the packet carried in part keeps how many of its bytes and
    redaction markers reached the packet. Only shown files count
    toward the record's bound; past it the first files in change order are kept and the record
    says it is incomplete. A recovered job derives the same commitments from its stored object.
    ``served`` are the change intervals the current-file sections an in-check follow-up served
    carried (tb4n5): a file they show is recorded like one the leading bytes show, and a file
    shown through interior or disjoint intervals uses an exact partial interval view, with
    no clean-prefix or whole-file claim (issue #1079, F3).
    """

    files, representable = check_time_change_shown_record(change.capture, shown_bytes, served)
    complete = representable and len(files) <= MAX_CHECK_CHANGE_SHOWN_FILES
    base = change.capture.base_commit.encode("ascii")
    fully: set[str] = set()
    partially: dict[str, CheckChangePartialFile] = {}
    for file in files[:MAX_CHECK_CHANGE_SHOWN_FILES]:
        commitment = await runtime.objects.commitment_for(
            _SHOWN_FILE_DOMAIN + base + b"\x00" + file.identity, ObjectKind.CHANGE_CAPTURE
        )
        if file.whole:
            fully.add(commitment)
        else:
            # The view's structure (where markers and hunks lie), under the same key: a repair
            # covers this file in part only with an identical view (R945-02).
            view_commitment = await runtime.objects.commitment_for(
                _SHOWN_VIEW_DOMAIN + base + b"\x00" + file.identity + b"\x00" + file.view,
                ObjectKind.CHANGE_CAPTURE,
            )
            partially[commitment] = CheckChangePartialFile(
                commitment,
                file.shown_bytes,
                file.redactions,
                file.section_admitted,
                file.clean_bytes,
                view_commitment,
            )
    for commitment in fully:
        partially.pop(commitment, None)
    return CheckChangeShownFiles(
        tuple(sorted(fully, key=str.encode)),
        tuple(partially[commitment] for commitment in sorted(partially, key=str.encode)),
        complete=complete,
    )


def check_time_change_selected(selection: ReviewSelectionPolicy) -> bool:
    """Whether this review recipe would carry a check-time change at all."""

    return selection.carries_check_time_change


async def _read(runtime: TaskRuntime, ref: ObjectRef) -> bytes:
    return b"".join([chunk async for chunk in runtime.objects.open_verified(ref)])


async def _store(runtime: TaskRuntime, data: bytes, media_type: str, clock: ClockPort) -> ObjectRef:
    staged = await runtime.objects.stage(
        ObjectSource(data=data, declared_size=len(data)),
        ObjectMetadata(ObjectKind.CHANGE_CAPTURE, media_type, runtime.task_id, clock.now_utc()),
    )
    return await runtime.objects.finalize(staged)


async def _resolve(
    runtime: TaskRuntime, object_id: str, envelope_digest: str, media_type: str
) -> ObjectRef:
    ref = await runtime.objects.resolve_verified(object_id, envelope_digest)
    if (
        type(ref) is not ObjectRef
        or ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
        or ref.metadata.media_type != media_type
        or ref.metadata.task_id != runtime.task_id
    ):
        raise ValueError("check_change_object_invalid")
    return ref


async def _load_task_base(runtime: TaskRuntime, request_id: str) -> TaskChangeBase | None:
    return (await _load_task_base_and_start(runtime, request_id))[0]


async def _load_task_base_and_start(
    runtime: TaskRuntime, request_id: str
) -> tuple[TaskChangeBase | None, float | None]:
    """The task's kept base, and when a ``task_start`` base was recorded (POSIX seconds).

    A ``task_start`` base is recorded right after the task is created, before the creating
    request returns, so its object's creation time is when the task started (issue #1102); a
    ``first_check`` base, or none, gives no start time.
    """

    loader = getattr(runtime.ledger, "load_task_change_base", None)
    if not callable(loader):
        return None, None
    try:
        ref = await cast(Callable[[], Awaitable[ObjectRef | None]], loader)()
        if ref is None:
            return None, None
        if (
            ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
            or ref.metadata.media_type != TASK_CHANGE_BASE_MEDIA_TYPE
            or ref.metadata.task_id != runtime.task_id
        ):
            raise ValueError("task_change_base_invalid")
        base = decode_task_change_base(await _read(runtime, ref))
        started = ref.metadata.created_at.timestamp() if base.origin == "task_start" else None
        return base, started
    except Exception as exc:
        # An unreadable base degrades to the HEAD base, which the case discloses as
        # ``check_time_change_base_unavailable``; it never blocks the review.
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="check_time_change_base_unreadable",
            request_id=request_id,
        )
        return None, None


async def _pin_first_check_base(
    runtime: TaskRuntime,
    port: ChangeCapturePort,
    workspace: str,
    clock: ClockPort,
    request_id: str,
) -> TaskChangeBase | None:
    """Pin HEAD as the base of a task that has none, through the task-start base seam.

    A task created before ADR-031, or whose start base could not be recorded, would otherwise
    diff every check against a HEAD that moves with each commit, so the files one review saw
    could never match the next review's. The first check records HEAD once as a ``first_check``
    base; every later check of the task diffs from it, keeping committed work in the change. The
    case still discloses ``check_time_change_base_unavailable``: it is not the task-start commit.
    When the pin cannot be recorded the check falls back to HEAD, exactly as before.
    """

    recorder = getattr(runtime.ledger, "record_task_change_base", None)
    loader = getattr(runtime.ledger, "load_task_change_base", None)
    if not callable(recorder) or not callable(loader):
        return None
    try:
        head = await asyncio.to_thread(port.read_task_base, workspace)
        if type(head) is not TaskChangeBase:
            raise TypeError("task_change_base_invalid")
        # Only the task's own start can say which untracked files predate the task (#1045).
        pinned = replace(
            head,
            origin="first_check",
            untracked=(),
            untracked_complete=False,
            nested=(),
            nested_untracked=(),
        )
        ref = await _store(
            runtime, encode_task_change_base(pinned), TASK_CHANGE_BASE_MEDIA_TYPE, clock
        )
        if await cast(Callable[[ObjectRef], Awaitable[bool]], recorder)(ref):
            return pinned
        # Another check of this task pinned first: use the base the task kept.
        return await _load_task_base(runtime, request_id)
    except ChangeCaptureUnavailable as exc:
        record_bounded_event_without_raising(
            component=_COMPONENT,
            operation="check_time_change_base_not_pinned",
            reason=exc.reason,
            request_id=request_id,
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="check_time_change_base_pin_failed",
            request_id=request_id,
        )
    return None


def _redacted_text(text: bytes) -> tuple[bytes, bool]:
    """Redact until a pass finds nothing; ``redaction_incomplete`` past the pass bound.

    A concrete credential shape reads ``[REDACTED]``. A value that only looks like a credential
    (``password=config.POSTGRES_PASSWORD``) reads ``[withheld-by-yoetz:possible-credential]``,
    the self-describing marker egress uses (tb4n5 live-database-cutover): a bare ``[REDACTED]`` in
    source read as an undefined name to the reviewer. The same spans are withheld either way;
    only the marker differs, and redaction still runs at capture whatever the owner's
    possible-credential opt-out says.
    """

    redacted = False
    for _ in range(_MAX_REDACTION_PASSES):
        replaced, detected = redact_sensitive_content(
            text, heuristic_marker=EGRESS_CREDENTIAL_PLACEHOLDER
        )
        if not detected:
            break
        text, redacted = replaced, True
    else:
        raise ChangeCaptureUnavailable("redaction_incomplete")
    if redacted:
        text = text.decode("utf-8", errors="replace").encode("utf-8")
    return text, redacted


def _redacted_inputs(inputs: tuple[TaskInputFile, ...]) -> tuple[TaskInputFile, ...]:
    """Redact each task input file like the change (#1045); drop one that cannot be redacted."""

    kept: list[TaskInputFile] = []
    for item in inputs:
        try:
            text, redacted = _redacted_text(item.text)
            if redacted:
                limit = MAX_TASK_INPUT_TEXT_BYTES + 256
                text = text[:limit].decode("utf-8", errors="ignore").encode("utf-8")
                item = replace(item, text=text, redacted=True)
        except ChangeCaptureUnavailable, ValueError:
            # Withheld whole, never offered partly redacted; the change itself still stands.
            continue
        kept.append(item)
    return tuple(kept)


def _redacted(capture: CheckChangeCapture) -> CheckChangeCapture:
    """Apply native capture's redaction; the egress never-send scan still runs on every part.

    One scanner call reports a bounded number of findings, and source code such as a parser can
    hold more credential-shaped assignments (``token = ...``) than that. Scanning again until a
    pass finds nothing redacts every span; text that still has findings after the pass bound is
    withheld whole, never offered partly redacted. Task input files the read carried (#1045) get
    the same redaction, each on its own; an input redacted or withheld marks the capture
    ``redacted`` even when the change text needed nothing, so the review discloses it.
    """

    inputs = _redacted_inputs(capture.inputs)
    if inputs != capture.inputs or any(item.redacted for item in inputs):
        # An input the reader already redacted (a summary that withheld a value, PR #1086 review
        # R1-04) is disclosed like one this pass redacted.
        capture = replace(capture, inputs=inputs, redacted=True)
    text, redacted = _redacted_text(capture.text)
    if not redacted:
        return capture
    truncated = capture.truncated
    if len(text) > MAX_CHECK_CHANGE_TEXT_BYTES:
        text = text[:MAX_CHECK_CHANGE_TEXT_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
        truncated = True
    return replace(capture, text=text, redacted=True, truncated=truncated)


def _workspace_relative(value: str, workspace: str) -> str:
    """``value`` as a repository-relative path when it names one lexically; else unchanged."""

    if value.startswith("/"):
        root = os.path.normpath(workspace).rstrip("/") + "/"
        path = os.path.normpath(value)
        return path[len(root) :] if path.startswith(root) else value
    return os.path.normpath(value)


def _with_input_origins(
    capture: CheckChangeCapture, verification_paths: frozenset[str], workspace: str
) -> CheckChangeCapture:
    """Mark each input only a verification command named (issue #1082); the bytes are unchanged."""

    if not verification_paths or not capture.inputs:
        return capture
    oracle = {_workspace_relative(value, workspace) for value in verification_paths}
    inputs = tuple(
        replace(item, origin="verification")
        if item.origin == "task" and item.path in oracle
        else item
        for item in capture.inputs
    )
    return capture if inputs == capture.inputs else replace(capture, inputs=inputs)


# Reads the candidate paths beneath the owner's admitted outside-workspace roots (issue #1082):
# ``(values, room, workspace, space_cut)``, ``space_cut`` the values only the spaces of a quoted
# value cut out (``space_cut_input_paths``, issue #1112 review). Bound by the service to the
# effective policy's roots, so this layer never sees a root itself; the workspace is never read
# from, by path or by identity.
type OutsideInputReader = Callable[
    [tuple[str, ...], int, str, frozenset[str]], tuple[TaskInputFile, ...]
]


def _within(path: str, workspace: str) -> bool:
    """Whether ``path`` is the workspace or beneath it, compared case-folded (PR #1086 R1-02).

    Case-folding errs toward refusing: on a case-insensitive file system ``/shared/caserepo``
    is the workspace ``/shared/CaseRepo``, and on a case-sensitive one a differently cased
    sibling is merely not read from outside.
    """

    folded = os.path.normpath(path).casefold()
    root = os.path.normpath(workspace).casefold().rstrip("/")
    return folded == root or folded.startswith(root + "/")


def _with_outside_inputs(
    capture: CheckChangeCapture,
    input_paths: tuple[str, ...],
    reader: OutsideInputReader | None,
    workspace: str,
    *,
    verification_paths: frozenset[str],
    space_cut_paths: frozenset[str] = frozenset(),
) -> CheckChangeCapture:
    """Add inputs the task names beneath an admitted outside root, in the room left (#1082).

    Only paths the task itself names (its statement or a ``role: input`` item) may be read
    outside the workspace (ADR-009): ``verification_paths``, the candidates only an agent-recorded
    verification command named, are oracle candidates for the repository read alone and are
    never offered to the reader (PR #1086 review R1-05).

    A path inside the workspace is never offered here, even beneath an admitted root: the
    repository read alone decides those, because only it can prove a file unchanged since the
    task started (the agent may have written it) and not ignored. The reader refuses the
    workspace by device and inode at every level of its walk, so an admitted directory that
    contains the workspace, or a differently spelled path to it, cannot enumerate its files
    (PR #1086 review R1-02); every file the reader returns is checked here again.

    Issue #1102: a file the task names outside the workspace outranks what the repository read
    chose beneath a task-named directory (its listing and the members FinishUP picked), so that
    material gives way to it and keeps only the room left after it.
    """

    named = tuple(item for item in capture.inputs if not _directory_material(item))
    chosen = tuple(item for item in capture.inputs if _directory_material(item))
    room = MAX_TASK_INPUT_FILES - len(named)
    outside = tuple(
        value
        for value in input_paths
        if value.startswith("/")
        and value not in verification_paths
        and not _within(value, workspace)
    )
    if reader is None or room < 1 or not outside:
        return capture
    present = {item.path for item in capture.inputs}
    added: list[TaskInputFile] = []
    for item in reader(outside, room, workspace, space_cut_paths & frozenset(outside)):
        if (
            item.origin != "outside_workspace"
            or not item.path.startswith("/")
            or _within(item.path, workspace)
            or item.path in present
            or len(added) >= room
        ):
            continue
        present.add(item.path)
        added.append(item)
    if not added:
        return capture
    return replace(capture, inputs=(*named, *added, *chosen)[:MAX_TASK_INPUT_FILES])


def _directory_material(item: TaskInputFile) -> bool:
    """A listing of a task-named directory, or a member FinishUP chose beneath one (#1102)."""

    return item.origin == "task_directory" or (item.summary and item.path.endswith("/"))


class _CaptureOptions(TypedDict, total=False):
    """The ``ChangeCapturePort.capture`` options a check asks for; absent when not asked."""

    priority_paths: tuple[str, ...]
    input_paths: tuple[str, ...]
    space_cut_paths: frozenset[str]


def _capture_redacted(
    port: ChangeCapturePort,
    workspace: str,
    base: TaskChangeBase | None,
    priority_paths: tuple[str, ...] = (),
    input_paths: tuple[str, ...] = (),
    verification_paths: frozenset[str] = frozenset(),
    outside_reader: OutsideInputReader | None = None,
    *,
    admitted_roots: tuple[str, ...] = (),
    task_started_at: float | None = None,
    space_cut_paths: frozenset[str] = frozenset(),
) -> CheckChangeCapture:
    # A port without deliverable ordering or task inputs (an embedded or test port) is called
    # exactly as before when neither is asked for.
    options: _CaptureOptions = {}
    if priority_paths:
        options["priority_paths"] = priority_paths
    if input_paths:
        options["input_paths"] = input_paths
    # Issue #1112 review: only these candidates may give way to a spaced one on disk.
    space_cut_paths = space_cut_paths & frozenset(input_paths)
    if space_cut_paths:
        options["space_cut_paths"] = space_cut_paths
    capture = port.capture(workspace, base, **options)
    if type(capture) is not CheckChangeCapture:
        raise TypeError("check_change_capture_invalid")
    capture = _with_input_origins(capture, verification_paths, workspace)
    # Every input, inside the repository or beneath an admitted root, takes the same redaction.
    capture = _redacted(
        _with_outside_inputs(
            capture,
            input_paths,
            outside_reader,
            workspace,
            verification_paths=verification_paths,
            space_cut_paths=space_cut_paths,
        )
    )
    # Issue #1102 (RC6f): decided once, here, against the root this read used, and frozen into
    # the stored object, so a recovered job replays the decision instead of re-reading the disk.
    if outside_inputs_not_admitted(
        input_paths,
        verification_paths,
        workspace,
        admitted_roots,
        priority_paths,
        task_started_at=task_started_at,
        space_cut=space_cut_paths,
    ):
        capture = replace(capture, outside_inputs_not_admitted=True)
    return capture


async def capture_check_time_change(
    *,
    runtime: TaskRuntime,
    source: CheckWorkspaceSource,
    route_repository_commitment: str,
    port: ChangeCapturePort,
    clock: ClockPort,
    request_id: str,
    priority_paths: tuple[str, ...] = (),
    input_paths: tuple[str, ...] = (),
    verification_paths: frozenset[str] = frozenset(),
    outside_reader: OutsideInputReader | None = None,
    admitted_roots: tuple[str, ...] = (),
    space_cut_paths: frozenset[str] = frozenset(),
) -> CheckChangeOutcome:
    """Capture, redact and store one check's change; every failure is a disclosed absence.

    ``priority_paths`` are the declared deliverables (``declared_output_paths``), rendered first.
    ``input_paths`` are candidate task input files (``review_input_paths``, issues #1045 and
    #1082); ``verification_paths`` are those only a recorded verification command named, whose
    inputs are labelled as the verification's oracle and are never read outside the workspace.
    ``outside_reader`` reads the task's own candidates beneath the outside-workspace roots the
    owner admitted in the repository grant (#1082); the service passes it only when the effective
    policy admits a root and the recipe carries task inputs. ``admitted_roots`` are those roots
    themselves: the capture records, as one closed flag, whether the task names an existing input
    outside the workspace that none of them covers (``outside_inputs_not_admitted``, #1102).
    ``space_cut_paths`` are the candidates only the spaces of a quoted value cut out
    (``space_cut_input_paths``); no other candidate ever gives way to a spaced one on disk.
    """

    if type(source) is not CheckWorkspaceSource:
        raise TypeError("check_workspace_source_invalid")
    if not hmac.compare_digest(
        source.repository_commitment.encode("ascii"),
        route_repository_commitment.encode("ascii"),
    ):
        # The connection's workspace is not the task's repository. Never read it for this task.
        record_bounded_event_without_raising(
            component=_COMPONENT,
            operation="check_time_change_unavailable",
            reason="repository_mismatch",
            request_id=request_id,
        )
        return CheckChangeOutcome(unavailable=True, reason="repository_mismatch")
    base, task_started_at = await _load_task_base_and_start(runtime, request_id)
    if base is None:
        base = await _pin_first_check_base(runtime, port, source.workspace, clock, request_id)
    try:
        # Capture and every redaction pass run off the event loop: a parser-sized change needs
        # dozens of full scans, which would otherwise stall every other connection for seconds.
        capture = await asyncio.to_thread(
            _capture_redacted,
            port,
            source.workspace,
            base,
            priority_paths,
            input_paths,
            verification_paths,
            outside_reader,
            admitted_roots=admitted_roots,
            task_started_at=task_started_at,
            space_cut_paths=space_cut_paths,
        )
        ref = await _store(runtime, encode_check_change(capture), CHECK_CHANGE_MEDIA_TYPE, clock)
        return CheckChangeOutcome(CheckTimeChange(ref, capture))
    except ChangeCaptureUnavailable as exc:
        record_bounded_event_without_raising(
            component=_COMPONENT,
            operation="check_time_change_unavailable",
            reason=exc.reason,
            request_id=request_id,
        )
        return CheckChangeOutcome(unavailable=True, reason=exc.reason)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="check_time_change_capture_failed",
            request_id=request_id,
        )
    return CheckChangeOutcome(unavailable=True, reason="capture_failed")


async def capture_structural_check_change(
    *,
    runtime: TaskRuntime,
    source: CheckWorkspaceSource,
    route_repository_commitment: str,
    port: ChangeCapturePort,
    clock: ClockPort,
    request_id: str,
) -> tuple[CheckChangeMetadata | None, str | None]:
    """Capture path/status facts for local structural accounting without reading file content.

    A port that only implements the content-returning ``capture`` method is deliberately treated
    as unavailable.  Structural accounting must never turn that method into an implicit content
    authorization; the semantic path owns the separate full capture when its recipe selects it.
    """

    if type(source) is not CheckWorkspaceSource:
        raise TypeError("check_workspace_source_invalid")
    if not hmac.compare_digest(
        source.repository_commitment.encode("ascii"),
        route_repository_commitment.encode("ascii"),
    ):
        return None, "repository_mismatch"
    metadata_capture = getattr(port, "capture_metadata", None)
    if not callable(metadata_capture):
        # Older/embedded ports have no metadata-only seam.  The caller records an explicit
        # structural unknown rather than falling back to the content-returning capture.
        return None, _STRUCTURAL_METADATA_UNAVAILABLE
    base = await _load_task_base(runtime, request_id)
    if base is None:
        base = await _pin_first_check_base(runtime, port, source.workspace, clock, request_id)
    try:
        capture = await asyncio.to_thread(metadata_capture, source.workspace, base)
        if type(capture) is not CheckChangeMetadata:
            raise TypeError("check_change_metadata_invalid")
    except ChangeCaptureUnavailable as exc:
        return None, exc.reason
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="check_time_change_structural_capture_failed",
            request_id=request_id,
        )
        return None, "capture_failed"
    return capture, None


async def recover_check_time_change(runtime: TaskRuntime, binding: object) -> CheckChangeOutcome:
    """Reload the exact outcome a durable job froze; raise when it cannot be authenticated."""

    if type(binding) is not dict:
        raise ValueError("check_change_binding_invalid")
    source = cast(dict[str, object], binding)
    if set(source) - {"reason"} != {"object", "schema", "unavailable"} or (
        source["schema"] != "yoetz.check-change-binding/1"
    ):
        raise ValueError("check_change_binding_invalid")
    unavailable = source["unavailable"]
    pointer = source["object"]
    reason = source.get("reason")
    if type(unavailable) is not bool or (
        reason is not None
        and (type(reason) is not str or reason not in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS)
    ):
        raise ValueError("check_change_binding_invalid")
    if pointer is None:
        return CheckChangeOutcome(unavailable=unavailable, reason=reason)
    if unavailable or type(pointer) is not dict:
        raise ValueError("check_change_binding_invalid")
    fields = cast(dict[str, object], pointer)
    if set(fields) != {"commitment", "envelope_digest", "object_id"}:
        raise ValueError("check_change_binding_invalid")
    ref = await _resolve(
        runtime,
        cast(str, fields["object_id"]),
        cast(str, fields["envelope_digest"]),
        CHECK_CHANGE_MEDIA_TYPE,
    )
    if ref.commitment != fields["commitment"]:
        raise ValueError("check_change_binding_invalid")
    return CheckChangeOutcome(CheckTimeChange(ref, decode_check_change(await _read(runtime, ref))))


async def record_task_change_base(
    *,
    runtime: TaskRuntime,
    port: ChangeCapturePort,
    workspace: str,
    clock: ClockPort,
    request_id: str | None = None,
) -> bool:
    """Record HEAD as the task-start base once; ``False`` when kept already or not possible.

    Called right after a task is created, before the creating request returns, so no agent edit
    or commit can precede it. A failure leaves the task without a base; its checks then show the
    change against HEAD and disclose ``check_time_change_base_unavailable``.
    """

    recorder = getattr(runtime.ledger, "record_task_change_base", None)
    loader = getattr(runtime.ledger, "load_task_change_base", None)
    if not callable(recorder) or not callable(loader):
        return False
    try:
        if await cast(Callable[[], Awaitable[ObjectRef | None]], loader)() is not None:
            return False
        base = await asyncio.to_thread(port.read_task_base, workspace)
        if type(base) is not TaskChangeBase:
            raise TypeError("task_change_base_invalid")
        ref = await _store(
            runtime, encode_task_change_base(base), TASK_CHANGE_BASE_MEDIA_TYPE, clock
        )
        return await cast(Callable[[ObjectRef], Awaitable[bool]], recorder)(ref)
    except ChangeCaptureUnavailable as exc:
        record_bounded_event_without_raising(
            component="start",
            operation="task_change_base_unavailable",
            reason=exc.reason,
            request_id=request_id,
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="start",
            operation="task_change_base_record_failed",
            request_id=request_id,
        )
    return False


_MAX_REQUESTED_OUTPUT_PROBES: Final = 64
_PROBED_KINDS: Final = frozenset({RequestedItemKind.FILE, RequestedItemKind.DIRECTORY})
_NOT_A_PLAIN_PATH: Final = re.compile(r"[\s*?\[\]{}~$`]|://")


def _plain_path(value: str) -> bool:
    """Whether a requested file value is one literal path FinishUP can locate.

    A value with whitespace (trailing prose), a glob or brace pattern, a home or variable
    expansion, or a URL names no single path, so it is never reported absent; it is left out of
    the read entirely rather than guessed at.
    """

    return bool(value) and _NOT_A_PLAIN_PATH.search(value) is None


def declared_output_paths(projection: ProjectionState) -> tuple[str, ...]:
    """The requested file and directory values the check-time change renders first (tb4n2 R7).

    ``role: output`` items come first, then requested files with no role (an
    ``obligation_published`` 1.0.0 item names a deliverable too); declared inputs never count.
    Only plain literal paths are kept, deduplicated in obligation order and bounded like the
    requested-output probe. The values only order the change; nothing here is stored.
    """

    declared: list[str] = []
    unroled: list[str] = []
    described: list[str] = []
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if item.item_kind is RequestedItemKind.CHANGE:
                # Issue #1082 (sglang, react-lead-form): a requested change that names its
                # files in prose ("parser fixes in a/b.py and c/d.py") names deliverables too.
                # They rank after every literal declaration, and only order the change.
                described.extend(_named_files(item.value))
                continue
            if item.item_kind not in _PROBED_KINDS or not _plain_path(item.value):
                continue
            if item.role is RequestedItemRole.OUTPUT:
                declared.append(item.value)
            elif item.role is None:
                unroled.append(item.value)
    return tuple(dict.fromkeys((*declared, *unroled, *described)))[:_MAX_REQUESTED_OUTPUT_PROBES]


# Words of the task statement that name a file (issue #1045): a path with a slash, or a file name
# with a short extension holding a letter (``DESIGN.md``, ``main.c``; never ``e.g`` or ``3.10``).
# Quotes, brackets and sentence punctuation around a word are not part of it.
_STATEMENT_WORD: Final = re.compile(r"[^\s`'\"()<>\[\]{},;]+")
_STATEMENT_WORD_EDGE: Final = ".:!?*"
_STATEMENT_FILE_NAME: Final = re.compile(
    r"(?P<stem>[A-Za-z0-9_@+~=-][A-Za-z0-9_.@+~=-]*)\.(?P<extension>[A-Za-z0-9]{1,10})"
)
_MAX_STATEMENT_INPUT_CANDIDATES: Final = 16
# Issue #1102 (RC6d): a path the statement quotes or escapes keeps its spaces
# (``"/app/My Docs/spec.md"``, ``/app/My\ Docs/spec.md``). One token is a quoted span or a word,
# and a word may hold ``\ ``. Unquoted, unescaped text splits exactly as ``_STATEMENT_WORD`` does,
# and a quoted span still yields those same words; when it holds a spaced path, the path comes
# first and the words the spaces cut from its head and middle are dropped (``_statement_words``).
# An apostrophe inside a word (``don't``) never opens a span.
_STATEMENT_TOKEN: Final = re.compile(
    r"`(?P<tick>[^`\n]{1,1024})`"
    r"|\"(?P<double>[^\"\n]{1,1024})\""
    r"|(?<![A-Za-z0-9])'(?P<single>[^'\n]{1,1024})'(?![A-Za-z0-9])"
    r"|(?P<word>(?:\\ |[^\s`'\"()<>\[\]{},;])+)"
)
_SPACED_NOT_PLAIN: Final = re.compile(r"[\t\n\r\f\v*?\[\]{}~$`]|://|  ")
_SPACED_FILE_NAME: Final = re.compile(r"[^/]*[A-Za-z0-9_)]\.(?P<extension>[A-Za-z0-9]{1,10})")
_MAX_PATH_SPACES: Final = 8
# A quoted shell command (``cd /app/vllm && pytest``, ``cat a | grep b``, ``make > out.txt``) is
# never one path: a word that is or starts with a shell operator or redirection marks it.
_SPACED_COMMAND_WORD: Final = re.compile(r"\A(?:[&|;<>]|[0-9]+[<>])")
# A word like these between two parts holding ``/`` may join two paths (``"src/dedup and
# src/util"``) or sit inside one folder name (``"/app/Terms and Conditions/terms.pdf"``): only the
# disk can tell, so the read decides (``_spaced_candidate``).
_SPACED_JOINING_WORDS: Final = frozenset(
    {"and", "or", "then", "to", "into", "from", "with", "vs", "versus", "plus"}
)


def _statement_file_word(word: str) -> str | None:
    value = word.strip(_STATEMENT_WORD_EDGE)
    if not value or "://" in value or value.endswith("/") or len(value) > 1_024:
        return None
    name = value.rsplit("/", 1)[-1]
    match = _STATEMENT_FILE_NAME.fullmatch(name)
    if "/" in value.strip("/"):
        # A path with a directory part names a file unless its last part is plainly not one.
        return value if name and not name.startswith("-") else None
    if match is None or not any(char.isalpha() for char in match.group("extension")):
        return None
    if len(match.group("extension")) == 1 and len(match.group("stem")) < 2:
        return None
    return value


def _names_a_file(word: str) -> bool:
    """Whether one space-free word ends in a file name with a lettered extension."""

    match = _STATEMENT_FILE_NAME.fullmatch(word.rsplit("/", 1)[-1])
    return match is not None and any(char.isalpha() for char in match.group("extension"))


def _spaced_candidate(value: str) -> tuple[str, bool] | None:
    """One literal read-only path holding single spaces, and whether it is one for certain.

    Issue #1102 (RC6d). The value must have a directory part or end in ``/``, or end in a file
    name with a lettered extension; hold one to eight single spaces and no other whitespace, glob,
    brace, home or variable expansion, backtick or URL; and be at most 1024 characters. Prose
    ahead of an absolute path (``see /app/My Docs/spec.md``) is dropped. ``None`` for a span that
    is surely no one path: two absolute paths (``ls /app/data /app/models``), a command word ahead
    of two paths (``diff src/dedup src/util``), earlier words that already name a whole file
    (``docs/a.md and docs/b.md``) or a folder (``/app/parser/ fails``), an option-like word
    (``pytest -q tests/test_a.py``) or a shell operator (``cd /app/vllm && pytest``). ``False``
    when only the disk can tell: a word like ``and`` joins two parts holding ``/``
    (``/app/Terms and Conditions/terms.pdf``, ``src/dedup and src/util``), a later word starts
    with the first one's first component (``docs/Makefile docs/Dockerfile``), or the spaced last
    component is no file name and no ``/`` follows it (``/app/test data``, ``/app/config is
    read-only``). Such a span is offered ahead of its own words, and the read keeps those words
    only when the whole value names nothing there (``drop_space_cut_words``).
    """

    value = value.strip(_STATEMENT_WORD_EDGE)
    if " /" in value:
        value = value[value.index(" /") + 1 :]
    words = value.split(" ")
    if (
        " " not in value
        or " /" in value
        or value != value.strip(" ")
        or value.count(" ") > _MAX_PATH_SPACES
        or len(value) > 1_024
        or _SPACED_NOT_PLAIN.search(value) is not None
        or any(_names_a_file(word) or word.endswith("/") for word in words[:-1])
        or any(word.startswith("-") for word in words[1:])
        or any(_SPACED_COMMAND_WORD.match(word) is not None for word in words)
        or ("/" not in words[0] and sum("/" in word for word in words[1:]) > 1)
    ):
        return None
    name = value.rstrip("/").rsplit("/", 1)[-1]
    if not name or name.startswith("-"):
        return None
    head = words[0].split("/", 1)[0]
    certain = not any(
        word.casefold() in _SPACED_JOINING_WORDS and "/" in before and "/" in after
        for before, word, after in zip(words, words[1:], words[2:], strict=False)
    ) and not (
        # A later word that starts where the first one does (``docs/Makefile docs/Dockerfile``)
        # may be a second path.
        head and "/" in words[0] and any(word.split("/", 1)[0] == head for word in words[1:])
    )
    # The last component may hold a space only as a file name with a lettered extension, or
    # when a ``/`` follows it: ``/app/My Docs/`` is a folder, ``/app/test data`` may be one.
    last = value.rsplit("/", 1)[-1]
    if " " in last:
        match = _SPACED_FILE_NAME.fullmatch(last)
        if match is None or not any(char.isalpha() for char in match.group("extension")):
            if "/" not in value:
                return None
            certain = False
    return value, certain


def _statement_words(text: str) -> list[tuple[str, bool]]:
    """The statement's words, a quoted or escaped path with spaces kept whole (issue #1102).

    Each word comes with whether the spaces cut it from a quoted spaced value offered whole
    beside it (``True``) rather than standing alone in the statement (``False``). Only a cut word
    may give way to that value on disk (``drop_space_cut_words``); a word the statement also names
    on its own is never dropped (#1112 review).
    """

    words: list[tuple[str, bool]] = []
    for match in _STATEMENT_TOKEN.finditer(text):
        word = match.group("word")
        if word is not None:
            words.append((word.replace("\\ ", " "), False))
            continue
        content = match.group("tick") or match.group("double") or match.group("single") or ""
        spaced = _spaced_candidate(content)
        if spaced is None:
            words.extend((part, False) for part in _STATEMENT_WORD.findall(content))
            continue
        value, certain = spaced
        words.append((value, False))
        start = content.find(value)
        end = start + len(value)
        if not certain:
            # Only the disk can tell a folder from prose: every word still counts after the
            # whole value, and the read drops the ones the spaces cut from it when the whole value
            # names something. Prose before the value is no word of it.
            words.extend(
                (fragment.group(0), fragment.start() >= start)
                for fragment in _STATEMENT_WORD.finditer(content)
            )
            continue
        # Prose before the path still counts. So does the last word of a relative path whose
        # earlier words hold no ``/``, when it names a file or a folder with a directory part: a
        # quoted command (``cat docs/spec.md``) can pass for a spaced path, and the file it names
        # must not be lost. No other word the spaces cut counts: ``/shared/legacy`` of
        # ``"/shared/legacy app/main.c"``, ``data/`` of ``"src/test data/"`` and ``Notes.md`` of
        # ``"docs/My Notes.md"`` are no path the task names (#1102 review).
        tail = not value.startswith("/") and not any("/" in part for part in value.split(" ")[:-1])
        for fragment in _STATEMENT_WORD.finditer(content):
            text_value = fragment.group(0)
            if fragment.start() < start:
                words.append((text_value, False))
            elif tail and fragment.end() >= end:
                kept = text_value.strip(_STATEMENT_WORD_EDGE)
                if _names_a_file(kept) or (kept.endswith("/") and "/" in kept.rstrip("/")):
                    words.append((text_value, True))
    return words


def _input_path(value: str) -> bool:
    """Whether a read-only input value is one literal path: plain, or with single spaces.

    Read-only inputs only. A requested output keeps ``_plain_path``: a requested value with
    whitespace is prose and is never reported absent (#977).
    """

    if _plain_path(value):
        return True
    spaced = _spaced_candidate(value)
    return spaced is not None and spaced[0] == value


def _statement_directory(value: str) -> bool:
    """Whether a statement word names a directory the read may list (issues #1082, #1102).

    A word ending in ``/`` (``src/dedup/``, ``/shared/legacy_app/``), or an absolute path of one
    component (``/app``, the commonest way a task names its whole workspace). Never ``/`` or
    ``./`` and never a word without a letter. Whether it is a directory at all is the read's
    business: a value that is not one is skipped there.
    """

    if not value or value in {"/", "./"} or not any(char.isalpha() for char in value):
        return False
    if not value.endswith("/") and not (value.startswith("/") and value.count("/") == 1):
        return False
    return _input_path(value)


def _named_files(text: str) -> list[str]:
    """The plain literal file paths ``text`` names, in order (the statement-word rule)."""

    named: list[str] = []
    for word in _STATEMENT_WORD.findall(text):
        value = _statement_file_word(word)
        if value is not None and _plain_path(value):
            named.append(value)
    return named


# Issue #1082: a test or fixture file a recorded verification command names is the oracle the
# reviewer needs beside the run's output. At most this many such paths are offered, newest
# command first, and they compete for the same four task-input files.
_MAX_VERIFICATION_INPUT_CANDIDATES: Final = 4
_PYTEST_NODE_SUFFIX: Final = re.compile(r"::.*\Z")


def verification_input_paths(projection: ProjectionState) -> tuple[str, ...]:
    """Files the recorded verification commands name, newest command first (issue #1082).

    A command counts only when ``command_is_verification`` classes it as a test, build, lint or
    typecheck run and a readable result records that it ran. Its operands are split like a shell
    would (an unparsable command names nothing); a pytest node id keeps only its file. Only plain
    literal file paths count. The command text is the agent's own record, so it only selects
    candidates: the adapter reads one only when it lies in the repository, is unchanged since the
    task started, is not ignored and is not credential-named, exactly like a statement-named
    input. A test the agent wrote or changed is therefore never read here; it is in the change.
    """

    # Each command is ranked by its latest run, so a re-run moves its files ahead of a command run
    # in between.
    latest: dict[str, int] = {}
    for row in projection.results.values():
        payload = row.payload
        if payload is None or row.redacted:
            continue
        action = projection.actions.get(payload.action_id)
        if (
            action is None
            or action.payload is None
            or action.redacted
            or action.payload.action_kind is not ActionKind.COMMAND
            or action.payload.command is None
        ):
            continue
        command = action.payload.command
        if command not in latest and not command_is_verification(command):
            continue
        latest[command] = max(latest.get(command, row.source_frontier), row.source_frontier)
    candidates: list[str] = []
    for command, _ in sorted(latest.items(), key=lambda run: (-run[1], run[0])):
        try:
            words = shlex.split(command, posix=True)
        except ValueError:
            continue
        for word in words[1:]:
            if word.startswith("-"):
                continue
            value = _statement_file_word(_PYTEST_NODE_SUFFIX.sub("", word).removeprefix("./"))
            if value is not None and _input_path(value) and "." in value.rsplit("/", 1)[-1]:
                candidates.append(value)
    return tuple(dict.fromkeys(candidates))[:_MAX_VERIFICATION_INPUT_CANDIDATES]


def review_input_paths(
    projection: ProjectionState, statement: str | None
) -> tuple[tuple[str, ...], frozenset[str]]:
    """Candidate task input files in read order, and those only a verification command names.

    Issue #1082: the task's own files come first, but the newest verification oracle takes the
    fourth candidate place, so a statement that names many files cannot crowd out every test the
    work was checked against. Order matters only while the four-file read bound binds.
    """

    named = task_input_paths(projection, statement)
    oracle = tuple(path for path in verification_input_paths(projection) if path not in named)
    ordered = (*named[:3], *oracle[:1], *named[3:], *oracle[1:])
    bound = _MAX_STATEMENT_INPUT_CANDIDATES + _MAX_VERIFICATION_INPUT_CANDIDATES
    return tuple(ordered)[:bound], frozenset(oracle)


def task_input_paths(projection: ProjectionState, statement: str | None) -> tuple[str, ...]:
    """Candidate read-only task input files and directories for the check-time read (#1045).

    The files the task statement names (a spec, the source to port, a rulebook, ``DESIGN.md``) in
    the order it names them, then the ``role: input`` requested files of effective obligations,
    then the directories either names (issues #1082, #1102). A path the statement quotes or
    escapes keeps its spaces; otherwise only plain literal paths count, at most 16 in all. A
    quoted span only the disk can tell apart (``"/app/test data"``) comes whole ahead of its own
    words, and the read keeps those words only when the whole value names nothing there
    (``drop_space_cut_words``, for the ``space_cut_input_paths`` among them). The statement is
    read in process only to find these words; nothing here is stored or logged, and the adapter
    reads a candidate only when it lies inside the repository, is unchanged by the task, is not
    ignored and is not credential-named.
    """

    return _task_input_candidates(projection, statement)[0]


def space_cut_input_paths(projection: ProjectionState, statement: str | None) -> frozenset[str]:
    """The review candidates only the spaces of a quoted spaced value cut out (#1102, #1112).

    Among ``review_input_paths``' candidates, those the statement names only as a word of a quoted
    spaced value it offers whole (``/app/test`` of ``"/app/test data"``): the only candidates a
    read may drop when that whole value names something there (``drop_space_cut_words``). A path
    the statement also names on its own (``Notes.md`` of ``Read "docs/My Notes.md" and
    Notes.md``), a ``role: input`` item or a recorded verification operand is never one. In
    process only, derived from the frozen case like the candidates themselves; never stored.
    """

    candidates, cut = _task_input_candidates(projection, statement)
    if not cut:
        return frozenset()
    named = set(candidates)
    return frozenset(cut - set(verification_input_paths(projection))) & named


def _task_input_candidates(
    projection: ProjectionState, statement: str | None
) -> tuple[tuple[str, ...], frozenset[str]]:
    """``task_input_paths``' candidates, and those only the spaces of a quoted value cut out."""

    candidates: list[str] = []
    directories: list[str] = []
    # Issue #1112 review: which candidate values stood alone somewhere, and which only came from
    # splitting a quoted spaced value, so a split word never takes an independently named path
    # down with it.
    alone: set[str] = set()
    cut: set[str] = set()
    if type(statement) is str:
        for word, split in _statement_words(statement):
            spaced = _spaced_candidate(word) if " " in word else None
            value = spaced[0] if spaced is not None else _statement_file_word(word)
            if value is not None and not value.endswith("/") and _input_path(value):
                candidates.append(value)
                (cut if split else alone).add(value)
                continue
            # Issue #1102: a directory the statement names ("the code lives in src/dedup/", "the
            # legacy app in /shared/legacy_app/", the workspace "/app") is offered after every
            # file, so named files keep priority. Inside the repository the read lists its
            # unchanged files and reads the ones most related to the change; outside it, only a
            # root the owner admitted lists one. A no-slash ``/app/vllm`` keeps its place above:
            # the read decides by what the path is.
            folder = word.strip(_STATEMENT_WORD_EDGE) if value is None else value
            if _statement_directory(folder):
                directories.append(folder)
                (cut if split else alone).add(folder)
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if item.role is not RequestedItemRole.INPUT or not _input_path(item.value):
                continue
            if item.item_kind is RequestedItemKind.FILE:
                candidates.append(item.value)
                alone.add(item.value)
            elif item.item_kind is RequestedItemKind.DIRECTORY:
                directories.append(item.value)
                alone.add(item.value)
    ordered = tuple(dict.fromkeys((*candidates, *directories)))[:_MAX_STATEMENT_INPUT_CANDIDATES]
    return ordered, frozenset(value for value in ordered if value in cut and value not in alone)


# Issue #1102 (RC6f): absolute trees that hold the system's own programs, libraries, devices,
# processes and host configuration. A task that names ``/usr/bin/python3`` names a tool, not an
# input the reviewer lacks, and no root beneath the device, process or configuration trees may be
# admitted at all (``domain.privacy``).
_SYSTEM_TREES: Final = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/nix",
    "/private/etc",
    "/private/var/run",
    "/proc",
    "/run",
    "/sbin",
    "/snap",
    "/sys",
    "/usr",
    "/var/run",
)
# Scratch, log, cache, package-state and output trees: a task names them as places to write
# ("write the answer to /tmp/answer.txt", "log to /var/log/app.log", "results go in /output/"),
# not as material to read.
_OUTPUT_TREES: Final = (
    "/logs",
    "/output",
    "/outputs",
    "/private/tmp",
    "/private/var/folders",
    "/private/var/tmp",
    "/results",
    "/tmp",
    "/var/cache",
    "/var/folders",
    "/var/lib",
    "/var/log",
    "/var/tmp",
)
# A top-level folder named whole is a candidate (``/data``, ``/legacy``) unless it is a tree of
# homes, installed software or system state, never itself one task's input folder.
_TOP_LEVEL_CONTAINERS: Final = frozenset(
    {
        "/Applications",
        "/Library",
        "/System",
        "/Users",
        "/Volumes",
        "/home",
        "/media",
        "/mnt",
        "/opt",
        "/private",
        "/root",
        "/srv",
        "/var",
    }
)
# A path through an installed program or package tree names a tool (``/opt/conda/bin/python``).
_TOOL_COMPONENTS: Final = frozenset(
    {"bin", "dist-packages", "node_modules", "sbin", "site-packages"}
)


def _lstat_or_none(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError, ValueError:
        return None


def outside_input_candidates(
    candidates: Iterable[str],
    oracle: frozenset[str],
    workspace: str,
    admitted_roots: Iterable[str],
    outputs: Iterable[str],
) -> tuple[str, ...]:
    """The candidates that lexically could be an unadmitted outside input, normalized (#1102).

    The lexical half of ``outside_inputs_not_admitted``: an absolute candidate the task itself
    names (not in ``oracle``), outside ``workspace`` (case-folded, as the outside read compares
    it), not a declared output (``outputs``), in no system, scratch, log, cache or package-state
    tree, through no ``bin`` or installed-package directory, with no hidden component, at or
    beneath a path the owner may admit as a root (``admitted_input_root_valid``), not
    credential-named, and at or beneath none of ``admitted_roots``. A top-level folder named
    whole (``/data``) counts unless it is a tree of homes, installed software or system state
    (``/home``, ``/opt``, ``/var``). Nothing on disk is consulted; in process only.
    """

    roots = tuple(os.path.normpath(root) for root in admitted_roots)
    declared = {os.path.normpath(value) for value in outputs if value.startswith("/")}
    eligible: list[str] = []
    for value in candidates:
        if not value.startswith("/") or value in oracle or "\x00" in value:
            continue
        path = os.path.normpath(value)
        parts = path.split("/")[1:]
        ancestors = ("/" + "/".join(parts[:depth]) for depth in range(1, len(parts) + 1))
        if (
            not parts
            or not parts[0]
            or path in _TOP_LEVEL_CONTAINERS
            or path in declared
            or _within(path, workspace)
            or any(
                path == tree or path.startswith(tree + "/")
                for tree in (*_SYSTEM_TREES, *_OUTPUT_TREES)
            )
            or any(part.startswith(".") or part in _TOOL_COMPONENTS for part in parts)
            or not any(admitted_input_root_valid(ancestor) for ancestor in ancestors)
            or credential_named_bytes(os.fsencode(path))
            or any(path == root or path.startswith(root + "/") for root in roots)
        ):
            continue
        eligible.append(path)
    return tuple(dict.fromkeys(eligible))


def outside_inputs_not_admitted(
    candidates: Iterable[str],
    oracle: frozenset[str],
    workspace: str,
    admitted_roots: Iterable[str],
    outputs: Iterable[str],
    *,
    task_started_at: float | None,
    probe: Callable[[str], os.stat_result | None] | None = None,
    space_cut: Collection[str] = frozenset(),
) -> bool:
    """Whether the task names an existing input outside the workspace no admitted root covers.

    Issue #1102 (RC6f). ``candidates`` are ``review_input_paths``' candidates and ``oracle`` those
    only a recorded verification command named, which are never read outside the workspace and
    so never count. A candidate counts only when FinishUP can tell it is an input:

    * lexically, it is one of ``outside_input_candidates``: absolute, outside ``workspace``,
      not a declared output, in no system, scratch, log, cache or package-state tree, not
      hidden or credential-named, at or beneath a path the owner may admit, and at or beneath
      none of ``admitted_roots``; a top-level folder (``/data``) counts, a tree of homes,
      installed software or system state (``/home``, ``/opt``, ``/var``) does not;
    * a word the spaces cut from a spaced candidate that ``probe`` finds there
      (``/shared/legacy`` of ``/shared/legacy app``) never counts (``drop_space_cut_words``),
      when it is one of ``space_cut`` (``space_cut_input_paths``) and so not also named alone;
    * on disk, ``probe`` (``lstat``: metadata only, never following a final link, never opening
      content) finds a regular file or a directory there whose modification and change times
      both predate ``task_started_at``; a top-level path only as a directory, since no root the
      owner may admit covers a file like ``/spec.md``. A route (``GET /api/v1/users``) names
      nothing on disk, and a file the agent wrote during the task (``/root/model.pt``) is its
      output, not an input. Without a task-start time nothing counts.

    A closed yes or no, decided once when the check-time read runs and frozen into its object:
    no path is returned or kept.
    """

    if task_started_at is None:
        return False
    lookup = _lstat_or_none if probe is None else probe
    found: dict[str, os.stat_result | None] = {}

    def metadata(path: str) -> os.stat_result | None:
        if path not in found:
            found[path] = lookup(path)
        return found[path]

    def names_something(path: str) -> bool:
        status = metadata(path)
        return status is not None and (stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode))

    lexical = outside_input_candidates(candidates, oracle, workspace, admitted_roots, outputs)
    # The lexical candidates are normalized, so the cut words are compared normalized too; a
    # spelling the task also named on its own keeps the path.
    alone = {os.path.normpath(value) for value in candidates if value not in space_cut}
    cut = {os.path.normpath(value) for value in space_cut if value.startswith("/")} - alone
    for path in drop_space_cut_words(lexical, names_something, cut):
        status = metadata(path)
        if (
            status is None
            or not (stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode))
            # A top-level path counts only as a folder: no root can cover ``/spec.md``.
            or (path.count("/") == 1 and not stat.S_ISDIR(status.st_mode))
            or max(status.st_mtime, status.st_ctime) >= task_started_at
        ):
            continue
        return True
    return False


async def requested_output_states(
    *,
    projection: ProjectionState,
    capture: CheckChangeMetadata | None,
    source: CheckWorkspaceSource | None,
    port: object | None,
    request_id: str,
) -> dict[tuple[ObligationId, int], RequestedOutputState]:
    """Read where each requested file of an effective obligation stands at check time (#977).

    Metadata only, through the same hardened Git seam as the structural change capture, and only
    after that capture succeeded for this check's own repository (so the repository fence already
    held). A requested file is ``changed`` when the check-time change lists it, ``deleted`` when
    the change deletes it, and ``unverified`` when no read could be made. Nothing here is stored:
    the result becomes closed gap codes and a finding fact, never a path.
    """

    items: list[tuple[ObligationId, int, str]] = []
    directories: set[tuple[ObligationId, int]] = set()
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for index, item in enumerate(payload.requested_items):
            # A declared input is never an output fact, so it is not read at all (#1002). A
            # directory is located like a file; an existing one that holds no file is absent.
            if (
                item.item_kind in _PROBED_KINDS
                and item.role is not RequestedItemRole.INPUT
                and _plain_path(item.value)
            ):
                items.append((obligation, index, item.value))
                if item.item_kind is RequestedItemKind.DIRECTORY:
                    directories.add((obligation, index))
    # tb4n5 (ADR-033 amendment): an output a plan correction dropped without naming it is still
    # requested, so it is read like an effective obligation's.
    for obligation, index in superseded_unnamed_outputs(projection):
        payload = projection.obligations[obligation].payload
        if payload is None or not _plain_path(payload.requested_items[index].value):
            continue
        items.append((obligation, index, payload.requested_items[index].value))
        if payload.requested_items[index].item_kind is RequestedItemKind.DIRECTORY:
            directories.add((obligation, index))
    if not items:
        return {}
    unverified = {
        (obligation, index): RequestedOutputState("unverified") for obligation, index, _ in items
    }
    probe = getattr(port, "probe_requested_paths", None)
    if capture is None or source is None or not callable(probe):
        return unverified
    bounded = items[:_MAX_REQUESTED_OUTPUT_PROBES]
    try:
        raw_probes: object = await asyncio.to_thread(
            cast(Callable[[str, tuple[str, ...]], object], probe),
            source.workspace,
            tuple(v for _, _, v in bounded),
        )
        if type(raw_probes) is not tuple:
            raise TypeError("requested_path_probe_invalid")
        probes = cast(tuple[object, ...], raw_probes)
        if len(probes) != len(bounded):
            raise TypeError("requested_path_probe_invalid")
    except ChangeCaptureUnavailable:
        return unverified
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="requested_output_probe_failed",
            request_id=request_id,
        )
        return unverified
    changed = {entry.path for entry in capture.entries if not entry.status.startswith("D")}
    deleted = {entry.path for entry in capture.entries if entry.status.startswith("D")}
    deleted.update(
        entry.original_path
        for entry in capture.entries
        if entry.original_path is not None and entry.status.startswith("R")
    )
    created = {
        entry.path for entry in capture.entries if entry.untracked or entry.status.startswith("A")
    }
    states = dict(unverified)
    relatives: dict[tuple[ObligationId, int], str] = {}
    for (obligation, index, _value), result in zip(bounded, probes, strict=True):
        if type(result) is not RequestedPathProbe:
            continue
        if result.location == "outside" or result.relative is None:
            states[(obligation, index)] = RequestedOutputState("outside")
            continue
        relatives[(obligation, index)] = result.relative
        listed = _changed_at_or_under(result.relative, changed)
        exists = result.exists
        if (obligation, index) in directories and exists and result.holds_file is False:
            # An empty directory (or one holding only empty directories) delivers nothing; Git
            # cannot even record it. Unknown (``None``) never makes it absent.
            exists = False
        states[(obligation, index)] = RequestedOutputState(
            "inside",
            exists=exists,
            ignored=result.ignored,
            # Local excludes are not delivered with the repository; a .gitignore the task's own
            # change created is the work's. A pre-existing .gitignore the task merely edited is
            # never attributed to it: the matching rule may be the repository's own.
            ignored_by_task=result.ignore_source == "info_exclude"
            or (
                result.ignore_source == "repository_file"
                and result.ignore_file is not None
                and result.ignore_file in created
            ),
            # A truncated listing cannot prove a path unchanged.
            changed=True if listed else (None if capture.truncated else False),
            # A requested directory whose files the change deleted was deleted, not left absent.
            deleted=result.relative != "." and _changed_at_or_under(result.relative, deleted),
            size_bytes=result.size_bytes if exists is True else None,
            relative=result.relative,
        )
    return await _with_declared_line_counts(
        projection=projection,
        capture=capture,
        source=source,
        port=port,
        states=states,
        relatives=relatives,
        request_id=request_id,
    )


async def _with_declared_line_counts(
    *,
    projection: ProjectionState,
    capture: CheckChangeMetadata,
    source: CheckWorkspaceSource,
    port: object,
    states: dict[tuple[ObligationId, int], RequestedOutputState],
    relatives: dict[tuple[ObligationId, int], str],
    request_id: str,
) -> dict[tuple[ObligationId, int], RequestedOutputState]:
    """Add the ADR-035 / ADR-045 line counts to each existing declared delivered file.

    Runs only when such a file exists, through the adapter's bounded, metadata-only line-count
    read. ``lines`` is the file's current line count: a tracked file's base count adjusted by the
    change, an untracked (new) file's own count, or the base count of an unchanged tracked file
    (ADR-045: a deliverable created in the session has no base, and its history is what the
    earlier checks recorded). ``base_lines`` and ``lines_lost`` stay what ADR-035 defined, for a
    tracked file the change modified. ``undeclared_lines_added`` sums the net lines the change
    added to files outside the declared delivered set (a declared ``directory`` covers the files
    beneath it). A read that fails leaves the counts ``None``, so the dependent facts are simply
    not raised.
    """

    from finishup.kernel.delivered_set import declared_delivered_items

    count = getattr(port, "count_change_lines", None)
    probe = getattr(port, "probe_requested_paths", None)
    if not callable(count) or not callable(probe) or not capture.base_commit:
        return states
    declared = declared_delivered_items(projection)
    candidates = [
        (obligation, index)
        for obligation, index, kind, _value in declared
        if kind == "file"
        and (obligation, index) in relatives
        and states[(obligation, index)].exists is True
        and not states[(obligation, index)].deleted
    ]
    if not candidates:
        return states
    declared_files = {
        relatives[(obligation, index)]
        for obligation, index, _kind, _value in declared
        if (obligation, index) in relatives
    }
    # Only a literal directory path below the root is declared; a malformed value or the root
    # itself would mark every file as declared or fail the probe.
    directory_values = tuple(
        value
        for _obligation, _index, kind, value in declared
        if kind == "directory" and _plain_path(value) and value.strip("/.") != ""
    )[:_MAX_REQUESTED_OUTPUT_PROBES]
    base_paths = tuple(sorted({relatives[item] for item in candidates}))
    try:
        directories: tuple[str, ...] = ()
        if directory_values:
            raw_directories = await asyncio.to_thread(
                cast(Callable[[str, tuple[str, ...]], object], probe),
                source.workspace,
                directory_values,
            )
            if type(raw_directories) is not tuple:
                raise TypeError("requested_path_probe_invalid")
            directories = tuple(
                result.relative
                for result in cast(tuple[object, ...], raw_directories)
                if type(result) is RequestedPathProbe and result.relative is not None
            )
        raw_counts = await asyncio.to_thread(
            cast(Callable[[str, str, tuple[str, ...]], object], count),
            source.workspace,
            capture.base_commit,
            base_paths,
        )
        if type(raw_counts) is not ChangeLineCounts or len(raw_counts.base_lines) != len(
            base_paths
        ):
            raise TypeError("change_line_counts_invalid")
    except ChangeCaptureUnavailable:
        return states
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="declared_output_line_count_failed",
            request_id=request_id,
        )
        return states

    def is_declared(path: str) -> bool:
        return path in declared_files or any(
            path.startswith(directory + "/") for directory in directories
        )

    undeclared_added = 0
    rows: dict[str, tuple[int | None, int | None, bool]] = {}
    for row in raw_counts.changed:
        if row.path in base_paths:
            rows[row.path] = (row.added, row.removed, row.untracked)
        elif not is_declared(row.path) and row.added is not None and row.removed is not None:
            undeclared_added += max(0, row.added - row.removed)
    base_by_path = dict(zip(base_paths, raw_counts.base_lines, strict=True))
    modified = {entry.path for entry in capture.entries if entry.status == "M"}
    annotated = dict(states)
    for item in candidates:
        path = relatives[item]
        base = base_by_path.get(path)
        added, removed, untracked = rows.get(path, (None, None, False))
        lost: int | None = None
        lines: int | None
        if path not in rows:
            # Tracked and unchanged since the task base (or a file the read could not list).
            lines = base
        elif untracked:
            # A new file: its own newline count (``added``); it has no base.
            lines = added
        elif added is None or removed is None or base is None:
            lines = None
        else:
            lines = max(0, base - removed + added)
            lost = removed - added
        annotated[item] = replace(
            states[item],
            lines=lines,
            counts_truncated=raw_counts.truncated,
            # ADR-035's fields keep their meaning: a tracked file the change modified.
            base_lines=base,
            lines_lost=lost if path in modified else None,
            undeclared_lines_added=undeclared_added,
        )
    return annotated


def _changed_at_or_under(relative: str, changed: set[str]) -> bool:
    """Whether the change touches ``relative`` itself or any path beneath it.

    The capture lists files, never directories (untracked entries come from ``git ls-files
    --others``), so a requested directory such as ``src`` is changed when a file under it is
    (tb4n1 E1: four new ``src/*.sv`` files left ``/app/src`` reported unchanged). The root
    (``.``) is changed by any change.
    """

    if relative == ".":
        return bool(changed)
    if relative in changed:
        return True
    prefix = relative.rstrip("/") + "/"
    return any(path.startswith(prefix) for path in changed)


_MAX_REFERENCE_DELIVERABLES: Final = 16
_MAX_REFERENCE_CANDIDATES: Final = 1_024


@dataclass(frozen=True, slots=True)
class UndeclaredReferenceRead:
    """One check-time read of what declared deliverables name (#1044, tb4n5).

    ``pairs`` are the ``(deliverable, referenced file)`` root-relative dependency pairs;
    ``ambiguous`` how many created, undeclared files each deliverable names only by an ambiguous
    basename (a declared file shares it, or nothing ties it to the file's directory), never which.
    """

    pairs: tuple[tuple[str, str], ...] = ()
    ambiguous: tuple[tuple[str, int], ...] = ()


async def undeclared_references(
    *,
    projection: ProjectionState,
    capture: CheckChangeMetadata | None,
    source: CheckWorkspaceSource | None,
    port: object | None,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    blocked: Iterable[ObligationId] | None,
    request_id: str,
) -> UndeclaredReferenceRead:
    """Which declared deliverables name which file the change created but no item declares.

    tb4n2 R2 / tb4n4 (ADR-035 amendment, ``deliverable_references_undeclared_file``, #1044).
    Returns the ``(deliverable, referenced file)`` root-relative path pairs the adapter classified
    as dependencies, sorted, and per deliverable how many created files it names only by an
    ambiguous basename (tb4n5, never named). The candidates are the files the check-time change
    created (untracked, or added with status ``A``) minus every declared ``file``/``directory``
    value of any role (a declared directory covers the files beneath it); pre-existing tracked
    files are never candidates. The adapter's bounded local read of each declared source
    deliverable returns index pairs into the tuples it was given, so no path leaves it that this
    function did not hand it. Any failure is empty: the fact is simply not raised.
    """

    from finishup.kernel.delivered_set import undeclared_reference_inputs

    empty = UndeclaredReferenceRead()
    classify = getattr(port, "classify_undeclared_references", None)
    find = getattr(port, "find_undeclared_references", None)
    probe = getattr(port, "probe_requested_paths", None)
    if (
        capture is None
        or source is None
        or not (callable(classify) or callable(find))
        or not callable(probe)
    ):
        return empty
    created = {
        entry.path for entry in capture.entries if entry.untracked or entry.status.startswith("A")
    }
    if not created:
        return empty
    deliverables, declared = undeclared_reference_inputs(projection, states, blocked=blocked)
    deliverables = tuple(value for value in deliverables if _plain_path(value))
    if not deliverables:
        return empty
    values = tuple(
        dict.fromkeys((*deliverables, *(value for value in declared if _plain_path(value))))
    )
    if len(values) > _MAX_REQUESTED_OUTPUT_PROBES:
        # Codex review 3: an unprobed declaration could be reported as undeclared. A fact FinishUP
        # cannot compute exactly is not raised.
        return empty
    try:
        raw_probes = await asyncio.to_thread(
            cast(Callable[[str, tuple[str, ...]], object], probe), source.workspace, values
        )
        if type(raw_probes) is not tuple or len(cast(tuple[object, ...], raw_probes)) != len(
            values
        ):
            raise TypeError("requested_path_probe_invalid")
        relatives: dict[str, str] = {}
        for value, result in zip(values, cast(tuple[object, ...], raw_probes), strict=True):
            if type(result) is RequestedPathProbe and result.relative is not None:
                relatives[value] = result.relative
        if "." in relatives.values():
            # The root itself is declared: every created file is part of the delivery.
            return empty
        covered = set(relatives.values())

        def is_declared(path: str) -> bool:
            return path in covered or any(path.startswith(root + "/") for root in covered)

        targets = tuple(
            dict.fromkeys(relatives[value] for value in deliverables if value in relatives)
        )[:_MAX_REFERENCE_DELIVERABLES]
        candidates = tuple(
            sorted(path for path in created if _plain_relative(path) and not is_declared(path))
        )[:_MAX_REFERENCE_CANDIDATES]
        if not targets or not candidates:
            return empty
        # Every declared item, any role: a basename-only literal that a declared file shares
        # most plausibly names that file (tb4n5 biped, the #1044 follow-up).
        declared_paths = tuple(sorted(path for path in covered if _plain_relative(path)))[
            :_MAX_REFERENCE_CANDIDATES
        ]
        reader = classify if callable(classify) else find
        found: object = await asyncio.to_thread(
            cast(
                Callable[[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], object],
                reader,
            ),
            source.workspace,
            targets,
            candidates,
            declared_paths,
        )
        if type(found) is not tuple:
            raise TypeError("undeclared_reference_pairs_invalid")
        pairs: set[tuple[str, str]] = set()
        ambiguous: dict[str, int] = {}
        for row in cast(tuple[object, ...], found):
            if type(row) is not tuple or len(cast(tuple[object, ...], row)) not in {2, 3}:
                raise TypeError("undeclared_reference_pairs_invalid")
            fields = cast(tuple[object, ...], row)
            kind = fields[2] if len(fields) == 3 else "dependency"
            if any(type(index) is not int for index in fields[:2]) or kind not in {
                "dependency",
                "ambiguous",
            }:
                raise TypeError("undeclared_reference_pairs_invalid")
            target, candidate = cast(tuple[int, int], fields[:2])
            if not (0 <= target < len(targets) and 0 <= candidate < len(candidates)):
                raise TypeError("undeclared_reference_pairs_invalid")
            if kind == "dependency":
                pairs.add((targets[target], candidates[candidate]))
            else:
                ambiguous[targets[target]] = ambiguous.get(targets[target], 0) + 1
        return UndeclaredReferenceRead(
            tuple(sorted(pairs, key=lambda item: (os.fsencode(item[0]), os.fsencode(item[1])))),
            tuple(sorted(ambiguous.items(), key=lambda item: os.fsencode(item[0]))),
        )
    except ChangeCaptureUnavailable:
        return empty
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="undeclared_reference_read_failed",
            request_id=request_id,
        )
        return empty


def _plain_relative(path: str) -> bool:
    """Whether a change entry path is a plain root-relative path the reference read accepts."""

    return (
        bool(path)
        and not path.startswith("/")
        and not any(char in path for char in "\x00\r\n")
        and all(part not in {"", ".", ".."} for part in path.split("/"))
    )
