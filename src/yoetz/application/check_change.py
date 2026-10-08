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
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Final, cast

from yoetz.application.semantic_case import CheckTimeChange, check_time_change_shown_files
from yoetz.domain.events import (
    MAX_CHECK_CHANGE_SHOWN_FILES,
    CheckChangePartialFile,
    CheckChangeShownFiles,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.privacy import ReviewSelectionPolicy
from yoetz.domain.receipts import CHECK_TIME_CHANGE_UNAVAILABLE_REASONS
from yoetz.domain.values import ObligationId
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import RequestedOutputState, effective_obligations
from yoetz.observability.logging import (
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from yoetz.observability.privacy import redact_sensitive_content
from yoetz.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    MAX_CHECK_CHANGE_TEXT_BYTES,
    TASK_CHANGE_BASE_MEDIA_TYPE,
    ChangeCapturePort,
    ChangeCaptureUnavailable,
    ChangeLineCounts,
    CheckChangeCapture,
    CheckChangeMetadata,
    CheckWorkspaceSource,
    RequestedPathProbe,
    TaskChangeBase,
    decode_check_change,
    decode_task_change_base,
    encode_check_change,
    encode_task_change_base,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from yoetz.ports.runtime import TaskRuntime
from yoetz.protocol.canonical import JsonValue

__all__ = [
    "CheckChangeOutcome",
    "capture_structural_check_change",
    "capture_check_time_change",
    "check_change_shown_files",
    "check_time_change_selected",
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
) -> CheckChangeShownFiles:
    """Keyed commitments to the changed files one review packet carried (ADR-031).

    Each file is committed with the task bundle's own object commitment key over its base and its
    ``diff --git`` line, so no path is recorded, the same file under the same base commits the
    same way in every check of the task, and a file under a different base or of a different
    change kind does not match. A file the packet carried in part keeps how many of its bytes and
    redaction markers reached the packet. Only shown files count
    toward the record's bound; past it the first files in change order are kept and the record
    says it is incomplete. A recovered job derives the same commitments from its stored object.
    """

    files = check_time_change_shown_files(change.capture, shown_bytes)
    complete = len(files) <= MAX_CHECK_CHANGE_SHOWN_FILES
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
    loader = getattr(runtime.ledger, "load_task_change_base", None)
    if not callable(loader):
        return None
    try:
        ref = await cast(Callable[[], Awaitable[ObjectRef | None]], loader)()
        if ref is None:
            return None
        if (
            ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
            or ref.metadata.media_type != TASK_CHANGE_BASE_MEDIA_TYPE
            or ref.metadata.task_id != runtime.task_id
        ):
            raise ValueError("task_change_base_invalid")
        return decode_task_change_base(await _read(runtime, ref))
    except Exception as exc:
        # An unreadable base degrades to the HEAD base, which the case discloses as
        # ``check_time_change_base_unavailable``; it never blocks the review.
        record_unexpected_exception_without_raising(
            exc,
            component=_COMPONENT,
            operation="check_time_change_base_unreadable",
            request_id=request_id,
        )
        return None


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
        pinned = replace(head, origin="first_check")
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


def _redacted(capture: CheckChangeCapture) -> CheckChangeCapture:
    """Apply native capture's redaction; the egress never-send scan still runs on every part.

    One scanner call reports a bounded number of findings, and source code such as a parser can
    hold more credential-shaped assignments (``token = ...``) than that. Scanning again until a
    pass finds nothing redacts every span; text that still has findings after the pass bound is
    withheld whole, never offered partly redacted.
    """

    text = capture.text
    redacted = False
    for _ in range(_MAX_REDACTION_PASSES):
        replaced, detected = redact_sensitive_content(text)
        if not detected:
            break
        text, redacted = replaced, True
    else:
        raise ChangeCaptureUnavailable("redaction_incomplete")
    if not redacted:
        return capture
    text = text.decode("utf-8", errors="replace").encode("utf-8")
    truncated = capture.truncated
    if len(text) > MAX_CHECK_CHANGE_TEXT_BYTES:
        text = text[:MAX_CHECK_CHANGE_TEXT_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
        truncated = True
    return replace(capture, text=text, redacted=True, truncated=truncated)


def _capture_redacted(
    port: ChangeCapturePort, workspace: str, base: TaskChangeBase | None
) -> CheckChangeCapture:
    capture = port.capture(workspace, base)
    if type(capture) is not CheckChangeCapture:
        raise TypeError("check_change_capture_invalid")
    return _redacted(capture)


async def capture_check_time_change(
    *,
    runtime: TaskRuntime,
    source: CheckWorkspaceSource,
    route_repository_commitment: str,
    port: ChangeCapturePort,
    clock: ClockPort,
    request_id: str,
) -> CheckChangeOutcome:
    """Capture, redact and store one check's change; every failure is a disclosed absence."""

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
    base = await _load_task_base(runtime, request_id)
    if base is None:
        base = await _pin_first_check_base(runtime, port, source.workspace, clock, request_id)
    try:
        # Capture and every redaction pass run off the event loop: a parser-sized change needs
        # dozens of full scans, which would otherwise stall every other connection for seconds.
        capture = await asyncio.to_thread(_capture_redacted, port, source.workspace, base)
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
    """Whether a requested file value is one literal path Yoetz can locate.

    A value with whitespace (trailing prose), a glob or brace pattern, a home or variable
    expansion, or a URL names no single path, so it is never reported absent; it is left out of
    the read entirely rather than guessed at.
    """

    return bool(value) and _NOT_A_PLAIN_PATH.search(value) is None


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
    """Add the ADR-035 line counts to each declared delivered file the change modified.

    Runs only when such a file exists, through the adapter's bounded, metadata-only line-count
    read. ``undeclared_lines_added`` sums the net lines the change added to files outside the
    declared delivered set (a declared ``directory`` covers the files beneath it). A read that
    fails leaves the counts ``None``, so the content-moved disclosure is simply not raised.
    """

    from yoetz.kernel.delivered_set import declared_delivered_items

    count = getattr(port, "count_change_lines", None)
    probe = getattr(port, "probe_requested_paths", None)
    if not callable(count) or not callable(probe) or not capture.base_commit:
        return states
    modified = {entry.path for entry in capture.entries if entry.status == "M"}
    declared = declared_delivered_items(projection)
    candidates = [
        (obligation, index)
        for obligation, index, kind, _value in declared
        if kind == "file"
        and (obligation, index) in relatives
        and relatives[(obligation, index)] in modified
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
    lost_by_path: dict[str, int | None] = {}
    for row in raw_counts.changed:
        if row.added is None or row.removed is None:
            if row.path in base_paths:
                lost_by_path[row.path] = None
            continue
        if row.path in base_paths:
            lost_by_path[row.path] = row.removed - row.added
        elif not is_declared(row.path):
            undeclared_added += max(0, row.added - row.removed)
    base_by_path = dict(zip(base_paths, raw_counts.base_lines, strict=True))
    annotated = dict(states)
    for item in candidates:
        path = relatives[item]
        annotated[item] = replace(
            states[item],
            base_lines=base_by_path.get(path),
            lines_lost=lost_by_path.get(path),
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
