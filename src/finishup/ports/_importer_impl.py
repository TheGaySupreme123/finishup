"""Bounded Codex JSONL capture and durable import-resume boundary."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, cast

from finishup.domain.events import EventDraft, EventSchema
from finishup.domain.values import (
    EventId,
    EvidenceId,
    Frontier,
    JsonObject,
    RequestId,
    SessionId,
    TaskId,
    Timestamp,
    WriterId,
    event_id,
    evidence_id,
    request_id,
    session_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
    writer_id,
)
from finishup.ports.importer import ImportLineStatus
from finishup.ports.ledger import AppendResult
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.coverage import Coverage
from finishup.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import MAX_CANONICAL_REQUEST_BYTES, MAX_EVENTS_PER_BATCH

__all__ = [
    "CapturedImportSource",
    "EncryptedImportReportRef",
    "ImportAllocation",
    "ImportAllocationOutcome",
    "ImportBatch",
    "ImportBatchSelection",
    "ImportByteSource",
    "ImportCaptureInput",
    "ImportCommand",
    "ImportEventCandidate",
    "ImportGap",
    "ImportLineOutcome",
    "ImportLineStatus",
    "ImportPhase",
    "ImportReviewSource",
    "ImportSafeReason",
    "ImportSourceIdentity",
    "ImportState",
    "ImportStatusSnapshot",
    "ImporterPort",
    "PreparedImportPlan",
]

type ImportSourceKind = Literal["file", "stdin"]

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
_MAX_SOURCE_BYTES = 4_194_304
_MAX_LINE_BYTES = 1_048_576
_MAX_LINES = 20_000
_MAX_BATCHES = 1_024
_MAX_STATUS_JOBS = 64
_MAX_ARGV_ITEMS = 256
_MAX_INPUT_TEXT = 4_096
_TOKEN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/+-]{0,127}$", re.ASCII)
_GAP_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_QUARANTINE_CODES = frozenset(
    {
        "import_batch_identity_contradiction",
        "import_commit_state_ambiguous",
        "import_object_identity_contradiction",
        "import_phase_state_contradiction",
        "import_plan_identity_contradiction",
        "import_report_identity_contradiction",
        "import_source_identity_contradiction",
    }
)


class ImportAllocationOutcome(str, Enum):  # noqa: UP042 - exact durable wire enum
    RESERVED = "reserved"
    RESUMED = "resumed"
    REPLAYED = "replayed"


class ImportState(str, Enum):  # noqa: UP042 - exact durable wire enum
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


class ImportPhase(str, Enum):  # noqa: UP042 - exact durable wire enum
    SOURCE_RESERVED = "source_reserved"
    PLAN_READY = "plan_ready"
    PUBLISHING = "publishing"
    REPORT_READY = "report_ready"
    REPORT_PUBLISHED = "report_published"
    TERMINAL = "terminal"


def _invalid(reason: str = "import_value_invalid") -> ProtocolValueError:
    if reason not in PROTOCOL_REASON_CODES:
        reason = "invalid_event_value_type"
    return ProtocolValueError(reason)


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _gap_code(value: object) -> str:
    if type(value) is not str or _GAP_RE.fullmatch(value) is None:
        raise _invalid("invalid_known_gap")
    return value


def _nonnegative(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _invalid()
    return value


def _positive(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise _invalid()
    return value


def _exact_tuple(value: object, *, maximum: int) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise _invalid()
    result = cast(tuple[object, ...], value)
    if len(result) > maximum:
        raise _invalid()
    return result


def _sorted_ids(
    value: object,
    *,
    kind: IdKind | None = None,
    maximum: int = 64,
) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=maximum)
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        if type(item) is not str:
            raise _invalid()
        member = item
        if kind is not None:
            validate_id(kind, member)
        elif not member.isascii() or not 1 <= len(member) <= 128:
            raise _invalid()
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _ordered_ids(value: object, *, kind: IdKind, maximum: int) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=maximum)
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        member = validate_id(kind, item)
        if member in seen:
            raise _invalid("duplicate_set_member")
        seen.add(member)
        result.append(member)
    return tuple(result)


def _object_ref(value: object, kind: ObjectKind) -> ObjectRef:
    if type(value) is not ObjectRef or value.metadata.kind is not kind:
        raise _invalid("import_object_invalid")
    return value


def _object_ref_or_none(value: object, kind: ObjectKind) -> ObjectRef | None:
    if value is None:
        return None
    return _object_ref(value, kind)


def _digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid("invalid_digest")
    return validate_sha256_digest(value)


def _digest_or_none(value: object) -> str | None:
    if value is None:
        return None
    return _digest(value)


def _timestamp_or_none(value: object) -> Timestamp | None:
    if value is None:
        return None
    if type(value) is not Timestamp:
        raise _invalid("invalid_timestamp")
    return value


def _canonical_structural_bytes(value: object) -> tuple[bytes, JsonObject]:
    if type(value) is not bytes or not 1 <= len(value) <= MAX_CANONICAL_REQUEST_BYTES:
        raise _invalid("import_structural_result_invalid")
    try:
        parsed = strict_json_parse(value)
    except ProtocolValueError as exc:
        raise _invalid("import_structural_result_invalid") from exc
    if not isinstance(parsed, Mapping):
        raise _invalid("import_structural_result_invalid")
    row = JsonObject(cast(Mapping[object, object], parsed))
    if canonical_encode(row) != value:
        raise _invalid("import_structural_result_invalid")
    return value, row


class ImportByteSource(Protocol):
    @property
    def declared_size(self) -> int | None: ...

    def __aiter__(self) -> AsyncIterator[bytes]: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class ImportCaptureInput:
    source: ImportByteSource
    codex_version: str
    codex_capability_profile_id: str
    argv: tuple[str, ...]
    working_directory_identity_input: str
    exit_status: int
    captured_at: Timestamp
    source_kind: ImportSourceKind

    def __post_init__(self) -> None:
        if not hasattr(self.source, "__aiter__") or not hasattr(self.source, "close"):
            raise _invalid("import_source_invalid")
        declared = self.source.declared_size
        if declared is not None:
            _nonnegative(declared, maximum=_MAX_SOURCE_BYTES)
        object.__setattr__(self, "codex_version", _token(self.codex_version))
        object.__setattr__(
            self,
            "codex_capability_profile_id",
            _token(self.codex_capability_profile_id),
        )
        raw_argv = _exact_tuple(self.argv, maximum=_MAX_ARGV_ITEMS)
        argv: list[str] = []
        for item in raw_argv:
            if (
                type(item) is not str
                or len(item) > _MAX_INPUT_TEXT
                or "\x00" in item
                or "\r" in item
                or "\n" in item
            ):
                raise _invalid("import_capture_metadata_invalid")
            argv.append(item)
        object.__setattr__(self, "argv", tuple(argv))
        if (
            type(self.working_directory_identity_input) is not str
            or not 1 <= len(self.working_directory_identity_input) <= _MAX_INPUT_TEXT
            or "\x00" in self.working_directory_identity_input
            or "\r" in self.working_directory_identity_input
            or "\n" in self.working_directory_identity_input
        ):
            raise _invalid("import_capture_metadata_invalid")
        if type(self.exit_status) is not int or not -1 <= self.exit_status <= 255:
            raise _invalid("import_capture_metadata_invalid")
        if type(self.captured_at) is not Timestamp:
            raise _invalid("invalid_timestamp")
        if self.source_kind not in {"file", "stdin"}:
            raise _invalid("import_source_invalid")

    def __repr__(self) -> str:
        return "<ImportCaptureInput redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class CapturedImportSource:
    source_object: ObjectRef
    source_commitment: str
    byte_count: int
    line_count: int
    final_newline: bool
    metadata_digest: str
    codex_capability_profile_id: str
    codex_version: str
    exit_status: int
    source_kind: ImportSourceKind
    capture_metadata_object: ObjectRef
    stderr_present: Literal[False]
    stderr_captured_bytes: Literal[0]
    stderr_truncated: Literal[False]
    stderr_commitment: None

    def __post_init__(self) -> None:
        _object_ref(self.source_object, ObjectKind.IMPORT_SOURCE)
        validate_commitment(self.source_commitment)
        if self.source_object.commitment != self.source_commitment:
            raise _invalid("import_source_invalid")
        _nonnegative(self.byte_count, maximum=_MAX_SOURCE_BYTES)
        if self.source_object.plaintext_size != self.byte_count:
            raise _invalid("import_source_invalid")
        _nonnegative(self.line_count, maximum=_MAX_LINES)
        if type(self.final_newline) is not bool:
            raise _invalid("import_source_invalid")
        if (self.byte_count == 0) != (self.line_count == 0) or (
            self.final_newline and self.byte_count == 0
        ):
            raise _invalid("import_source_invalid")
        _digest(self.metadata_digest)
        object.__setattr__(
            self,
            "codex_capability_profile_id",
            _token(self.codex_capability_profile_id),
        )
        object.__setattr__(self, "codex_version", _token(self.codex_version))
        if type(self.exit_status) is not int or not -1 <= self.exit_status <= 255:
            raise _invalid("import_capture_metadata_invalid")
        if self.source_kind not in {"file", "stdin"}:
            raise _invalid("import_source_invalid")
        _object_ref(self.capture_metadata_object, ObjectKind.IMPORT_SOURCE_MANIFEST)
        if (
            self.stderr_present is not False
            or self.stderr_captured_bytes != 0
            or self.stderr_truncated is not False
            or self.stderr_commitment is not None
        ):
            raise _invalid("import_capture_metadata_invalid")


@dataclass(frozen=True, slots=True)
class ImportSourceIdentity:
    task_id: TaskId
    source_commitment: str
    codex_capability_profile_id: str
    mapping_version: str
    identity_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", task_id(self.task_id))
        validate_commitment(self.source_commitment)
        object.__setattr__(
            self,
            "codex_capability_profile_id",
            _token(self.codex_capability_profile_id),
        )
        object.__setattr__(self, "mapping_version", _token(self.mapping_version))
        _digest(self.identity_digest)


@dataclass(frozen=True, slots=True)
class ImportCommand:
    session_id: SessionId
    requesting_writer_id: WriterId
    request_id: RequestId
    request_digest: str
    source_identity: ImportSourceIdentity
    mapping_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(
            self,
            "requesting_writer_id",
            writer_id(self.requesting_writer_id),
        )
        object.__setattr__(self, "request_id", request_id(self.request_id))
        _digest(self.request_digest)
        if type(self.source_identity) is not ImportSourceIdentity:
            raise _invalid("import_source_identity_invalid")
        object.__setattr__(self, "mapping_version", _token(self.mapping_version))
        if self.mapping_version != self.source_identity.mapping_version:
            raise _invalid("import_source_identity_invalid")


@dataclass(frozen=True, slots=True)
class ImportLineOutcome:
    line_ordinal: int
    byte_start: int
    byte_end: int
    status: ImportLineStatus
    source_category: str | None
    candidate_indexes: tuple[int, ...]
    gap_code: str | None

    def __post_init__(self) -> None:
        _positive(self.line_ordinal, maximum=_MAX_LINES)
        _nonnegative(self.byte_start, maximum=_MAX_SOURCE_BYTES)
        _positive(self.byte_end, maximum=_MAX_SOURCE_BYTES)
        if self.byte_end <= self.byte_start:
            raise _invalid("import_line_invalid")
        if type(self.status) is not ImportLineStatus:
            raise _invalid("import_line_invalid")
        if (
            self.status is not ImportLineStatus.OVERSIZED
            and self.byte_end - self.byte_start > _MAX_LINE_BYTES
        ):
            raise _invalid("import_line_invalid")
        if self.source_category is not None:
            object.__setattr__(self, "source_category", _token(self.source_category))
        raw_indexes = _exact_tuple(self.candidate_indexes, maximum=MAX_EVENTS_PER_BATCH)
        indexes: list[int] = []
        previous = -1
        for item in raw_indexes:
            index = _nonnegative(item)
            if index <= previous:
                raise _invalid("import_line_invalid")
            indexes.append(index)
            previous = index
        object.__setattr__(self, "candidate_indexes", tuple(indexes))
        if self.gap_code is not None:
            object.__setattr__(self, "gap_code", _gap_code(self.gap_code))
        if self.status is ImportLineStatus.MAPPED and not indexes:
            raise _invalid("import_line_invalid")
        if self.status is not ImportLineStatus.MAPPED and self.gap_code is None:
            raise _invalid("import_line_invalid")


@dataclass(frozen=True, slots=True)
class ImportEventCandidate:
    candidate_index: int
    event_id: EventId
    payload_logical_ids: tuple[str, ...]
    source_line_ordinal: int
    byte_start: int
    byte_end: int
    target_schema: EventSchema
    source_category: str
    intended_refs: tuple[str, ...]
    coverage: Coverage
    plan_object: ObjectRef

    def __post_init__(self) -> None:
        _nonnegative(self.candidate_index)
        object.__setattr__(self, "event_id", event_id(self.event_id))
        object.__setattr__(
            self,
            "payload_logical_ids",
            _sorted_ids(self.payload_logical_ids, maximum=64),
        )
        _positive(self.source_line_ordinal, maximum=_MAX_LINES)
        _nonnegative(self.byte_start, maximum=_MAX_SOURCE_BYTES)
        _positive(self.byte_end, maximum=_MAX_SOURCE_BYTES)
        if self.byte_end <= self.byte_start:
            raise _invalid("import_candidate_invalid")
        if type(self.target_schema) is not EventSchema:
            raise _invalid("invalid_event_schema")
        object.__setattr__(self, "source_category", _token(self.source_category))
        object.__setattr__(self, "intended_refs", _sorted_ids(self.intended_refs, maximum=64))
        if type(self.coverage) is not Coverage:
            raise _invalid("invalid_coverage_value")
        _object_ref(self.plan_object, ObjectKind.IMPORT_PLAN)


@dataclass(frozen=True, slots=True)
class ImportGap:
    code: str
    source_object_id: str
    line_ordinal: int
    byte_start: int
    byte_end: int
    coverage: Coverage

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _gap_code(self.code))
        validate_id(IdKind.OBJECT, self.source_object_id)
        _positive(self.line_ordinal, maximum=_MAX_LINES)
        _nonnegative(self.byte_start, maximum=_MAX_SOURCE_BYTES)
        _positive(self.byte_end, maximum=_MAX_SOURCE_BYTES)
        if self.byte_end <= self.byte_start:
            raise _invalid("import_gap_invalid")
        if type(self.coverage) is not Coverage:
            raise _invalid("invalid_coverage_value")


@dataclass(frozen=True, slots=True)
class PreparedImportPlan:
    source_identity: ImportSourceIdentity
    mapping_version: str
    line_outcomes: tuple[ImportLineOutcome, ...]
    candidates: tuple[ImportEventCandidate, ...]
    gaps: tuple[ImportGap, ...]
    candidate_count: int
    gap_count: int
    batch_plan_objects: tuple[ObjectRef, ...]
    batch_request_ids: tuple[RequestId, ...]
    report_request_id: RequestId
    report_event_id: EventId
    report_evidence_id: EvidenceId
    plan_digest: str

    def __post_init__(self) -> None:
        if type(self.source_identity) is not ImportSourceIdentity:
            raise _invalid("import_source_identity_invalid")
        object.__setattr__(self, "mapping_version", _token(self.mapping_version))
        if self.mapping_version != self.source_identity.mapping_version:
            raise _invalid("import_plan_invalid")
        raw_lines = _exact_tuple(self.line_outcomes, maximum=_MAX_LINES)
        lines: list[ImportLineOutcome] = []
        previous_ordinal = 0
        previous_end = 0
        for item in raw_lines:
            if type(item) is not ImportLineOutcome:
                raise _invalid("import_plan_invalid")
            if item.line_ordinal != previous_ordinal + 1 or item.byte_start < previous_end:
                raise _invalid("import_plan_invalid")
            lines.append(item)
            previous_ordinal = item.line_ordinal
            previous_end = item.byte_end
        object.__setattr__(self, "line_outcomes", tuple(lines))
        raw_candidates = _exact_tuple(
            self.candidates,
            maximum=MAX_EVENTS_PER_BATCH * _MAX_BATCHES,
        )
        candidates: list[ImportEventCandidate] = []
        for index, item in enumerate(raw_candidates):
            if type(item) is not ImportEventCandidate or item.candidate_index != index:
                raise _invalid("import_plan_invalid")
            candidates.append(item)
        object.__setattr__(self, "candidates", tuple(candidates))
        raw_gaps = _exact_tuple(self.gaps, maximum=_MAX_LINES)
        gaps: list[ImportGap] = []
        for item in raw_gaps:
            if type(item) is not ImportGap:
                raise _invalid("import_plan_invalid")
            gaps.append(item)
        object.__setattr__(self, "gaps", tuple(gaps))
        if self.candidate_count != len(candidates) or self.gap_count != len(gaps):
            raise _invalid("import_plan_invalid")
        raw_objects = _exact_tuple(self.batch_plan_objects, maximum=_MAX_BATCHES)
        objects = tuple(_object_ref(item, ObjectKind.IMPORT_PLAN) for item in raw_objects)
        object.__setattr__(self, "batch_plan_objects", objects)
        request_ids = _ordered_ids(
            self.batch_request_ids,
            kind=IdKind.REQUEST,
            maximum=_MAX_BATCHES,
        )
        if len(objects) != len(request_ids):
            raise _invalid("import_plan_invalid")
        object.__setattr__(self, "batch_request_ids", cast(tuple[RequestId, ...], request_ids))
        object.__setattr__(self, "report_request_id", request_id(self.report_request_id))
        object.__setattr__(self, "report_event_id", event_id(self.report_event_id))
        object.__setattr__(self, "report_evidence_id", evidence_id(self.report_evidence_id))
        _digest(self.plan_digest)


@dataclass(frozen=True, slots=True)
class ImportBatch:
    batch_index: int
    batch_count: int
    request_id: RequestId
    event_ids: tuple[EventId, ...]
    event_drafts: tuple[EventDraft, ...]
    plan_object: ObjectRef
    plan_digest: str
    gaps: tuple[ImportGap, ...]

    def __post_init__(self) -> None:
        _nonnegative(self.batch_index, maximum=_MAX_BATCHES - 1)
        _positive(self.batch_count, maximum=_MAX_BATCHES)
        if self.batch_index >= self.batch_count:
            raise _invalid("import_batch_invalid")
        object.__setattr__(self, "request_id", request_id(self.request_id))
        ids = _ordered_ids(self.event_ids, kind=IdKind.EVENT, maximum=MAX_EVENTS_PER_BATCH)
        object.__setattr__(self, "event_ids", cast(tuple[EventId, ...], ids))
        raw_drafts = _exact_tuple(self.event_drafts, maximum=MAX_EVENTS_PER_BATCH)
        drafts: list[EventDraft] = []
        for item in raw_drafts:
            if type(item) is not EventDraft:
                raise _invalid("import_batch_invalid")
            drafts.append(item)
        if tuple(draft.event_id for draft in drafts) != ids:
            raise _invalid("import_batch_invalid")
        object.__setattr__(self, "event_drafts", tuple(drafts))
        _object_ref(self.plan_object, ObjectKind.IMPORT_PLAN)
        _digest(self.plan_digest)
        raw_gaps = _exact_tuple(self.gaps, maximum=_MAX_LINES)
        if any(type(item) is not ImportGap for item in raw_gaps):
            raise _invalid("import_batch_invalid")
        object.__setattr__(self, "gaps", cast(tuple[ImportGap, ...], raw_gaps))


@dataclass(frozen=True, slots=True)
class EncryptedImportReportRef:
    report_object: ObjectRef
    report_digest: str
    terminal_result_bytes: bytes
    terminal_result_digest: str

    def __post_init__(self) -> None:
        _object_ref(self.report_object, ObjectKind.IMPORT_REPORT)
        _digest(self.report_digest)
        raw, parsed = _canonical_structural_bytes(self.terminal_result_bytes)
        if canonical_digest(parsed) != self.terminal_result_digest:
            raise _invalid("import_structural_result_invalid")
        object.__setattr__(self, "terminal_result_bytes", raw)
        _digest(self.terminal_result_digest)


@dataclass(frozen=True, slots=True)
class ImportAllocation:
    outcome: ImportAllocationOutcome
    source_identity: ImportSourceIdentity
    session_id: SessionId
    requesting_writer_id: WriterId
    request_id: RequestId
    publishing_writer_id: WriterId
    state: ImportState
    phase: ImportPhase
    owner_generation: int
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: Timestamp | None
    captured_source: CapturedImportSource
    source_object: ObjectRef
    source_commitment: str
    plan_digest: str | None
    plan_object_refs: tuple[ObjectRef, ...]
    batch_count: int
    completed_batch_count: int
    report_object: ObjectRef | None
    report_digest: str | None
    terminal_result: JsonObject | None
    terminal_result_bytes: bytes | None
    terminal_result_digest: str | None
    report_request_id: RequestId | None
    report_event_id: EventId | None
    report_evidence_id: EvidenceId | None
    report_evidence_draft: EventDraft | None
    report_evidence_draft_bytes: bytes | None
    report_evidence_draft_digest: str | None
    replayed_report: EncryptedImportReportRef | None

    def __post_init__(self) -> None:
        if type(self.outcome) is not ImportAllocationOutcome:
            raise _invalid("import_allocation_invalid")
        if type(self.source_identity) is not ImportSourceIdentity:
            raise _invalid("import_allocation_invalid")
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(
            self,
            "requesting_writer_id",
            writer_id(self.requesting_writer_id),
        )
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(
            self,
            "publishing_writer_id",
            writer_id(self.publishing_writer_id),
        )
        if type(self.state) is not ImportState or type(self.phase) is not ImportPhase:
            raise _invalid("import_allocation_invalid")
        _positive(self.owner_generation, maximum=_MAX_SQLITE_INTEGER)
        if type(self.captured_source) is not CapturedImportSource:
            raise _invalid("import_allocation_invalid")
        _object_ref(self.source_object, ObjectKind.IMPORT_SOURCE)
        validate_commitment(self.source_commitment)
        if (
            self.source_object.commitment != self.source_commitment
            or self.captured_source.source_object != self.source_object
            or self.captured_source.source_commitment != self.source_commitment
            or self.captured_source.codex_capability_profile_id
            != self.source_identity.codex_capability_profile_id
        ):
            raise _invalid("import_allocation_invalid")
        plan_digest = _digest_or_none(self.plan_digest)
        object.__setattr__(self, "plan_digest", plan_digest)
        raw_plan_refs = _exact_tuple(self.plan_object_refs, maximum=_MAX_BATCHES)
        plan_refs = tuple(_object_ref(item, ObjectKind.IMPORT_PLAN) for item in raw_plan_refs)
        object.__setattr__(self, "plan_object_refs", plan_refs)
        _nonnegative(self.batch_count, maximum=_MAX_BATCHES)
        _nonnegative(self.completed_batch_count, maximum=self.batch_count)
        if len(plan_refs) not in {0, self.batch_count}:
            raise _invalid("import_allocation_invalid")
        report_object = _object_ref_or_none(self.report_object, ObjectKind.IMPORT_REPORT)
        object.__setattr__(self, "report_object", report_object)
        report_digest = _digest_or_none(self.report_digest)
        object.__setattr__(self, "report_digest", report_digest)
        terminal = self._validated_terminal_result()
        report_ids = self._validated_report_ids()
        self._validate_lease_and_phase(
            plan_digest, report_object, report_digest, terminal, report_ids
        )

    def _validated_terminal_result(self) -> bool:
        values = (
            self.terminal_result,
            self.terminal_result_bytes,
            self.terminal_result_digest,
        )
        present = tuple(value is not None for value in values)
        if any(present) and not all(present):
            raise _invalid("import_allocation_invalid")
        if not all(present):
            return False
        if type(self.terminal_result) is not JsonObject:
            raise _invalid("import_allocation_invalid")
        raw, parsed = _canonical_structural_bytes(self.terminal_result_bytes)
        if (
            parsed != self.terminal_result
            or canonical_digest(parsed) != self.terminal_result_digest
        ):
            raise _invalid("import_allocation_invalid")
        object.__setattr__(self, "terminal_result_bytes", raw)
        _digest(self.terminal_result_digest)
        return True

    def _validated_report_ids(self) -> bool:
        values = (self.report_request_id, self.report_event_id, self.report_evidence_id)
        present = tuple(value is not None for value in values)
        if any(present) and not all(present):
            raise _invalid("import_allocation_invalid")
        if not all(present):
            return False
        object.__setattr__(self, "report_request_id", request_id(self.report_request_id))
        object.__setattr__(self, "report_event_id", event_id(self.report_event_id))
        object.__setattr__(self, "report_evidence_id", evidence_id(self.report_evidence_id))
        return True

    def _validate_lease_and_phase(
        self,
        plan_digest: str | None,
        report_object: ObjectRef | None,
        report_digest: str | None,
        terminal: bool,
        report_ids: bool,
    ) -> None:
        lease_values = (self.lease_owner_id, self.lease_generation, self.lease_expires_at)
        lease_present = tuple(value is not None for value in lease_values)
        if any(lease_present) and not all(lease_present):
            raise _invalid("import_allocation_invalid")
        if all(lease_present):
            validate_id(IdKind.SERVICE_INSTANCE, self.lease_owner_id)
            _positive(self.lease_generation, maximum=_MAX_SQLITE_INTEGER)
            _timestamp_or_none(self.lease_expires_at)
        if self.state is ImportState.PENDING:
            if self.phase is ImportPhase.TERMINAL or not all(lease_present):
                raise _invalid("import_allocation_invalid")
        elif self.phase is not ImportPhase.TERMINAL or any(lease_present):
            raise _invalid("import_allocation_invalid")
        has_plan = plan_digest is not None or report_ids
        if has_plan != (plan_digest is not None and report_ids):
            raise _invalid("import_allocation_invalid")
        if plan_digest is None and (self.plan_object_refs or self.batch_count != 0):
            raise _invalid("import_allocation_invalid")
        planned_phase = self.phase in {
            ImportPhase.PLAN_READY,
            ImportPhase.PUBLISHING,
            ImportPhase.REPORT_READY,
            ImportPhase.REPORT_PUBLISHED,
        }
        if self.state is ImportState.PENDING and planned_phase != has_plan:
            raise _invalid("import_allocation_invalid")
        report_data = report_object is not None or report_digest is not None
        if report_data != (report_object is not None and report_digest is not None):
            raise _invalid("import_allocation_invalid")
        report_phase = self.phase in {
            ImportPhase.REPORT_READY,
            ImportPhase.REPORT_PUBLISHED,
        }
        if self.state is ImportState.PENDING and report_phase != report_data:
            raise _invalid("import_allocation_invalid")
        evidence_values = (
            self.report_evidence_draft,
            self.report_evidence_draft_bytes,
            self.report_evidence_draft_digest,
        )
        evidence_present = tuple(value is not None for value in evidence_values)
        if any(evidence_present) and not all(evidence_present):
            raise _invalid("import_allocation_invalid")
        if report_data != all(evidence_present):
            raise _invalid("import_allocation_invalid")
        if report_data:
            if (
                type(self.report_evidence_draft) is not EventDraft
                or self.report_evidence_draft.event_id != self.report_event_id
            ):
                raise _invalid("import_allocation_invalid")
            raw, _ = _canonical_structural_bytes(self.report_evidence_draft_bytes)
            if canonical_digest(strict_json_parse(raw)) != self.report_evidence_draft_digest:
                raise _invalid("import_allocation_invalid")
            _digest(self.report_evidence_draft_digest)
        if self.state is ImportState.COMPLETE and (not has_plan or not report_data or not terminal):
            raise _invalid("import_allocation_invalid")
        if self.state is ImportState.QUARANTINED and not terminal:
            raise _invalid("import_allocation_invalid")
        if self.outcome is ImportAllocationOutcome.REPLAYED:
            if self.state is ImportState.PENDING:
                raise _invalid("import_allocation_invalid")
            if self.state is ImportState.COMPLETE:
                if type(self.replayed_report) is not EncryptedImportReportRef:
                    raise _invalid("import_allocation_invalid")
            elif self.replayed_report is not None:
                raise _invalid("import_allocation_invalid")
        elif self.replayed_report is not None:
            raise _invalid("import_allocation_invalid")


@dataclass(frozen=True, slots=True)
class ImportBatchSelection:
    allocation: ImportAllocation
    batch: ImportBatch | None

    def __post_init__(self) -> None:
        if type(self.allocation) is not ImportAllocation:
            raise _invalid("import_batch_invalid")
        if self.batch is not None and type(self.batch) is not ImportBatch:
            raise _invalid("import_batch_invalid")


@dataclass(frozen=True, slots=True)
class ImportStatusSnapshot:
    session_id: SessionId
    active_job_count: int
    terminal_job_count: int
    active_jobs: tuple[JsonObject, ...]
    terminal_report_locators: tuple[JsonObject, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", session_id(self.session_id))
        _nonnegative(self.active_job_count)
        _nonnegative(self.terminal_job_count)
        active = _exact_tuple(self.active_jobs, maximum=_MAX_STATUS_JOBS)
        terminals = _exact_tuple(self.terminal_report_locators, maximum=_MAX_STATUS_JOBS)
        if len(active) > self.active_job_count or len(terminals) > self.terminal_job_count:
            raise _invalid("import_status_invalid")
        object.__setattr__(self, "active_jobs", _status_rows(active, active=True))
        object.__setattr__(self, "terminal_report_locators", _status_rows(terminals, active=False))


def _status_rows(value: tuple[object, ...], *, active: bool) -> tuple[JsonObject, ...]:
    rows: list[JsonObject] = []
    previous: str | None = None
    expected = (
        frozenset({"identity_digest", "phase", "completed_batch_count", "batch_count"})
        if active
        else frozenset({"identity_digest", "report_evidence_id"})
    )
    for item in value:
        row = item if type(item) is JsonObject else JsonObject(item)
        if frozenset(row) != expected:
            raise _invalid("import_status_invalid")
        identity = row["identity_digest"]
        if type(identity) is not str:
            raise _invalid("import_status_invalid")
        _digest(identity)
        if previous is not None and identity.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("import_status_invalid")
        if active:
            phase = row["phase"]
            if type(phase) is not str or phase not in {
                member.value for member in ImportPhase if member is not ImportPhase.TERMINAL
            }:
                raise _invalid("import_status_invalid")
            completed = _nonnegative(row["completed_batch_count"], maximum=_MAX_BATCHES)
            count = _nonnegative(row["batch_count"], maximum=_MAX_BATCHES)
            if completed > count:
                raise _invalid("import_status_invalid")
        else:
            validate_id(IdKind.EVIDENCE, row["report_evidence_id"])
        rows.append(row)
        previous = identity
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class ImportReviewSource:
    identity: ImportSourceIdentity
    through: Frontier
    state: ImportState
    phase: ImportPhase
    publishing_writer_id: WriterId
    source_object: ObjectRef
    source_commitment: str
    plan_object_refs: tuple[ObjectRef, ...]
    plan_digest: str | None
    report_object: ObjectRef | None
    report_digest: str | None
    completed_batch_results: tuple[AppendResult, ...]
    mapped_event_ids: tuple[EventId, ...]
    line_outcomes: tuple[ImportLineOutcome, ...]
    gaps: tuple[ImportGap, ...]
    coverage: Coverage
    codex_capability_profile_id: str
    mapping_version: str
    import_incomplete: bool

    def __post_init__(self) -> None:
        if type(self.identity) is not ImportSourceIdentity or type(self.through) is not Frontier:
            raise _invalid("import_review_source_invalid")
        if type(self.state) is not ImportState or type(self.phase) is not ImportPhase:
            raise _invalid("import_review_source_invalid")
        if self.state is ImportState.QUARANTINED:
            raise _invalid("import_review_source_invalid")
        object.__setattr__(self, "publishing_writer_id", writer_id(self.publishing_writer_id))
        _object_ref(self.source_object, ObjectKind.IMPORT_SOURCE)
        validate_commitment(self.source_commitment)
        if self.source_object.commitment != self.source_commitment:
            raise _invalid("import_review_source_invalid")
        raw_plan_refs = _exact_tuple(self.plan_object_refs, maximum=_MAX_BATCHES)
        object.__setattr__(
            self,
            "plan_object_refs",
            tuple(_object_ref(item, ObjectKind.IMPORT_PLAN) for item in raw_plan_refs),
        )
        object.__setattr__(self, "plan_digest", _digest_or_none(self.plan_digest))
        object.__setattr__(
            self,
            "report_object",
            _object_ref_or_none(self.report_object, ObjectKind.IMPORT_REPORT),
        )
        object.__setattr__(self, "report_digest", _digest_or_none(self.report_digest))
        results = _exact_tuple(self.completed_batch_results, maximum=_MAX_BATCHES)
        if any(type(item) is not AppendResult for item in results):
            raise _invalid("import_review_source_invalid")
        object.__setattr__(
            self,
            "completed_batch_results",
            cast(tuple[AppendResult, ...], results),
        )
        ids = _ordered_ids(
            self.mapped_event_ids,
            kind=IdKind.EVENT,
            maximum=MAX_EVENTS_PER_BATCH * _MAX_BATCHES,
        )
        object.__setattr__(self, "mapped_event_ids", cast(tuple[EventId, ...], ids))
        lines = _exact_tuple(self.line_outcomes, maximum=_MAX_LINES)
        if any(type(item) is not ImportLineOutcome for item in lines):
            raise _invalid("import_review_source_invalid")
        object.__setattr__(self, "line_outcomes", cast(tuple[ImportLineOutcome, ...], lines))
        gaps = _exact_tuple(self.gaps, maximum=_MAX_LINES)
        if any(type(item) is not ImportGap for item in gaps):
            raise _invalid("import_review_source_invalid")
        object.__setattr__(self, "gaps", cast(tuple[ImportGap, ...], gaps))
        if type(self.coverage) is not Coverage or type(self.import_incomplete) is not bool:
            raise _invalid("import_review_source_invalid")
        object.__setattr__(
            self,
            "codex_capability_profile_id",
            _token(self.codex_capability_profile_id),
        )
        object.__setattr__(self, "mapping_version", _token(self.mapping_version))
        if self.codex_capability_profile_id != self.identity.codex_capability_profile_id:
            raise _invalid("import_review_source_invalid")
        if self.mapping_version != self.identity.mapping_version:
            raise _invalid("import_review_source_invalid")
        if self.import_incomplete != (self.state is ImportState.PENDING):
            raise _invalid("import_review_source_invalid")


@dataclass(frozen=True, slots=True)
class ImportSafeReason:
    code: str

    def __post_init__(self) -> None:
        if type(self.code) is not str or self.code not in _QUARANTINE_CODES:
            raise _invalid("import_safe_reason_invalid")


class ImporterPort(Protocol):
    async def capture(self, value: ImportCaptureInput) -> CapturedImportSource: ...

    async def reserve_or_resume(
        self,
        command: ImportCommand,
        source: CapturedImportSource,
    ) -> ImportAllocation: ...

    async def prepare_plan(self, allocation: ImportAllocation) -> PreparedImportPlan: ...

    async def publish_plan(
        self,
        allocation: ImportAllocation,
        plan: PreparedImportPlan,
    ) -> ImportAllocation: ...

    async def release_lease_for_authorization(self, allocation: ImportAllocation) -> None: ...

    async def next_batch(self, allocation: ImportAllocation) -> ImportBatchSelection: ...

    async def record_batch(
        self,
        allocation: ImportAllocation,
        batch: ImportBatch,
        result: AppendResult,
    ) -> ImportAllocation: ...

    async def prepare_report(
        self,
        allocation: ImportAllocation,
        report: EncryptedImportReportRef,
    ) -> ImportAllocation: ...

    async def publish_report(
        self,
        allocation: ImportAllocation,
        report: EncryptedImportReportRef,
        evidence_result: AppendResult,
    ) -> ImportAllocation: ...

    async def status(self, session_id: str) -> ImportStatusSnapshot: ...

    async def complete(self, allocation: ImportAllocation) -> ImportAllocation: ...

    async def quarantine(
        self,
        allocation: ImportAllocation,
        reason: ImportSafeReason,
    ) -> None: ...

    async def load_review_source(
        self,
        identity_digest: str,
        through: Frontier,
    ) -> ImportReviewSource | None: ...


# Older callers and serialized values resolve these types through the public facade.
for _public_name in __all__:
    _public_value = globals().get(_public_name)
    if isinstance(_public_value, type) and _public_value.__module__ == __name__:
        _public_value.__module__ = "finishup.ports.importer"
