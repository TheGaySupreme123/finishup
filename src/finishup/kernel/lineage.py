"""Pure evaluation of recorded parent-to-child dependency manifests.

The lineage lane has one deliberately narrow responsibility: turn the immutable
``child-dependencies-recorded`` rows in a parent ledger into the structural facts a check or
receipt can use.  This module never opens a child bundle, consults the catalog, or asks a child
for its current state.  The application layer may build a :class:`LineageManifest` from those
rows, but once the value reaches this module evaluation is a pure function.

The wire/domain event types are owned by the protocol slice and are intentionally adapted through
``from_recorded_payload`` instead of imported at module import time.  That keeps replay of old
ledgers possible while the additive lineage schemas are being introduced and gives storage
adapters one stable boundary to call.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final, cast

from finishup.domain.coordination import (
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from finishup.domain.events import LedgerRecord, is_lineage_service_stamped
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    FindingKind,
    FindingOrigin,
)
from finishup.domain.values import (
    EventId,
    FindingId,
    Frontier,
    ReceiptId,
    TaskId,
    event_id,
    finding_id,
    frontier_from_json,
    receipt_id,
    task_id,
    validate_sha256_digest,
)
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.coverage import (
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_from_json,
    coverage_to_json,
    weakest,
)
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CHILD_SELF_VERIFIED_GAP",
    "ChildDependencySnapshot",
    "ChildFindingSnapshot",
    "ChildRollup",
    "LineageEvaluation",
    "LineageGap",
    "LineageManifest",
    "LineageRollupState",
    "evaluate_lineage",
    "evaluate_recorded_lineage",
    "lineage_manifest_from_records",
    "manifest_from_payload",
    "with_later_manifest",
]


_TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$", re.ASCII)
_GAP_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_CHILDREN: Final = 64
_MAX_FINDINGS: Final = 100
_READ_GAP_REASONS: Final = frozenset(
    {"missing", "unreadable", "quarantined", "revoked", "not_authorized", "unknown"}
)
_PROVENANCE_RESTRICTIONS: Final = frozenset(
    {"category_restricted", "never_send", "task_scope", "minimization", "authorization_missing"}
)
_MISSING: Final = object()
# Issue #984: the same standing code the child's own readiness uses
# (``closure_readiness.FINDING_SELF_VERIFIED_GAP``), so parent and child receipts agree.
CHILD_SELF_VERIFIED_GAP: Final = "finding_self_verified"


class LineageRollupState(str, Enum):  # noqa: UP042 - stable evaluator vocabulary
    """How one recorded child contributes to a parent conclusion."""

    CLEAN = "clean"
    ANNOTATION = "annotation"
    BLOCKED = "blocked"
    OPEN_GAP = "open_gap"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


def _invalid() -> ValueError:
    return ValueError("lineage_evaluation_invalid")


def _enum[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is enum_type:
        return cast(T, value)
    raw = getattr(value, "value", value)
    if type(raw) is not str:
        raise _invalid()
    try:
        return enum_type(raw)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _sorted_unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(sorted(set(values), key=str.encode))
    if any(type(value) is not str or not _GAP_RE.fullmatch(value) for value in result):
        raise _invalid()
    return result


def _closed_strings(values: Iterable[object], allowed: frozenset[str]) -> tuple[str, ...]:
    if type(values) not in {tuple, list}:
        raise _invalid()
    normalized = tuple(getattr(value, "value", value) for value in cast(Sequence[object], values))
    if any(type(value) is not str for value in normalized):
        raise _invalid()
    result = tuple(sorted(set(cast(Sequence[str], normalized)), key=str.encode))
    if any(type(value) is not str or value not in allowed for value in result):
        raise _invalid()
    return result


def _token(value: object) -> str:
    if type(value) is int:
        if not 1 <= value <= _MAX_SAFE_INTEGER:
            raise _invalid()
        return str(value)
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _field(value: object, name: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return source.get(name, default)
    return getattr(value, name, default)


def _frontier(value: object, *, optional: bool = False) -> Frontier | None:
    if value is None:
        if optional:
            return None
        raise _invalid()
    if type(value) is Frontier:
        return value
    if isinstance(value, Mapping):
        try:
            return frontier_from_json(cast(Mapping[str, object], value))
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
    raise _invalid()


def _coverage(value: object) -> Coverage:
    if type(value) is Coverage:
        return value
    if isinstance(value, Mapping):
        try:
            return coverage_from_json(cast(JsonValue, value))
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
    raise _invalid()


def _optional_event(value: object) -> EventId | None:
    if value is None:
        return None
    try:
        return event_id(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _optional_receipt(value: object) -> ReceiptId | None:
    if value is None:
        return None
    try:
        return receipt_id(value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise _invalid()
    return value


def _finding_ids(value: object) -> tuple[FindingId, ...]:
    if value is None:
        return ()
    if type(value) not in {tuple, list}:
        raise _invalid()
    try:
        result = tuple(finding_id(item) for item in cast(Sequence[object], value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc
    if result != tuple(sorted(set(result), key=str.encode)) or len(result) > _MAX_FINDINGS:
        raise _invalid()
    return result


@dataclass(frozen=True, slots=True)
class ChildFindingSnapshot:
    """A bounded finding summary copied into a parent manifest.

    ``kind`` and ``origin`` are retained so actionability follows the same finding traits as the
    child ledger.  Priority is checked against the kind's canonical priority; it is never used as
    a proxy for actionability (``ledger_stale_or_incomplete`` is intentionally informational).
    """

    finding_id: FindingId
    kind: FindingKind
    origin: FindingOrigin
    priority: int
    resolved: bool
    resolution_event_id: EventId | None = None
    actionable: bool | None = None
    # Issue #984 (ADR-034): the child agent self-verified this repair; FinishUP could not prove it.
    self_verified: bool = False

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "finding_id", finding_id(self.finding_id))
            kind = _enum(self.kind, FindingKind)
            origin = _enum(self.origin, FindingOrigin)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "origin", origin)
        if type(self.priority) is not int or not 1 <= self.priority <= 3:
            raise _invalid()
        expected_priority = FINDING_KIND_TRAITS[kind][0]
        if self.priority != expected_priority:
            raise _invalid()
        expected_actionable = FINDING_KIND_TRAITS[kind][1]
        if self.actionable is None:
            # Direct construction is useful to pure evaluator callers. Recorded payloads go
            # through ``from_recorded`` below, which requires the service stamp explicitly.
            actionable = expected_actionable
        else:
            actionable = _bool(self.actionable)
            if actionable is not expected_actionable:
                raise _invalid()
        object.__setattr__(self, "actionable", actionable)
        resolved = _bool(self.resolved)
        object.__setattr__(self, "resolved", resolved)
        resolution = _optional_event(self.resolution_event_id)
        if resolved is not (resolution is not None):
            raise _invalid()
        object.__setattr__(self, "resolution_event_id", resolution)
        self_verified = _bool(self.self_verified)
        # A non-actionable kind cannot carry self_verified (the kind trait is the stamp), so a
        # process note never reaches the parent's self-verified id list (#1243).
        if self_verified and (resolved or not actionable):
            raise _invalid()
        object.__setattr__(self, "self_verified", self_verified)

    @classmethod
    def from_recorded(cls, value: object) -> ChildFindingSnapshot:
        """Adapt a protocol/domain child finding without trusting caller supplied aliases."""

        raw_id = _field(value, "finding_id")
        raw_kind = _field(value, "kind")
        raw_origin = _field(value, "origin")
        raw_priority = _field(value, "priority")
        raw_actionable = _field(value, "actionable", _MISSING)
        raw_resolved = _field(value, "resolved")
        # The protocol may use ``resolution_event_id`` or the older explicit null spelling.  Both
        # map to the same closed domain field; an arbitrary alias is never accepted.
        raw_resolution = _field(value, "resolution_event_id")
        # Absent (or null on a protocol model) means "not self-verified" (issue #984).
        raw_self_verified = _field(value, "self_verified")
        if raw_actionable is _MISSING:
            # Actionability is service-stamped and may not be inferred from an untrusted
            # payload. Incomplete/old manifests become a named read gap at the adapter boundary.
            raise _invalid()
        return cls(
            finding_id=cast(FindingId, raw_id),
            kind=cast(FindingKind, raw_kind),
            origin=cast(FindingOrigin, raw_origin),
            priority=cast(int, raw_priority),
            resolved=cast(bool, raw_resolved),
            resolution_event_id=cast(EventId | None, raw_resolution),
            actionable=cast(bool, raw_actionable),
            self_verified=False if raw_self_verified is None else cast(bool, raw_self_verified),
        )


@dataclass(frozen=True, slots=True)
class ChildDependencySnapshot:
    """One child state captured by the service in a parent ledger event."""

    child_task_id: TaskId
    origin: LineageOrigin
    acceptance: LineageAcceptance
    work_state: WorkState
    session_health: SessionHealth
    child_frontier: Frontier | None
    child_check_id: EventId | None
    child_receipt_id: ReceiptId | None
    coverage: Coverage
    findings: tuple[ChildFindingSnapshot, ...]
    lineage_authority_revision: str
    membership_generation: int | None = None
    read_gap_reasons: tuple[str, ...] = ()
    provenance_restrictions: tuple[str, ...] = ()
    child_check_subject_frontier: Frontier | None = None
    manifest_event_id: EventId | None = None
    manifest_sequence: int | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
            object.__setattr__(self, "origin", _enum(self.origin, LineageOrigin))
            object.__setattr__(self, "acceptance", _enum(self.acceptance, LineageAcceptance))
            object.__setattr__(self, "work_state", _enum(self.work_state, WorkState))
            object.__setattr__(self, "session_health", _enum(self.session_health, SessionHealth))
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        child_frontier = _frontier(self.child_frontier, optional=True)
        object.__setattr__(self, "child_frontier", child_frontier)
        check_id = _optional_event(self.child_check_id)
        receipt = _optional_receipt(self.child_receipt_id)
        object.__setattr__(self, "child_check_id", check_id)
        object.__setattr__(self, "child_receipt_id", receipt)
        object.__setattr__(self, "coverage", _coverage(self.coverage))
        if type(self.findings) is not tuple or len(self.findings) > _MAX_FINDINGS:
            raise _invalid()
        findings = tuple(
            item if type(item) is ChildFindingSnapshot else ChildFindingSnapshot.from_recorded(item)
            for item in self.findings
        )
        if findings != tuple(sorted(findings, key=lambda item: str(item.finding_id).encode())):
            raise _invalid()
        if len({item.finding_id for item in findings}) != len(findings):
            raise _invalid()
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self, "lineage_authority_revision", _token(self.lineage_authority_revision)
        )
        if self.membership_generation is not None and (
            type(self.membership_generation) is not int
            or not 0 <= self.membership_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        object.__setattr__(
            self,
            "read_gap_reasons",
            _closed_strings(self.read_gap_reasons, _READ_GAP_REASONS),
        )
        object.__setattr__(
            self,
            "provenance_restrictions",
            _closed_strings(self.provenance_restrictions, _PROVENANCE_RESTRICTIONS),
        )
        checked_frontier = _frontier(self.child_check_subject_frontier, optional=True)
        if (
            checked_frontier is not None
            and child_frontier is not None
            and checked_frontier > child_frontier
        ):
            raise _invalid()
        if check_id is not None and checked_frontier is None:
            # A check id without the frontier it tested cannot establish freshness.
            raise _invalid()
        object.__setattr__(self, "child_check_subject_frontier", checked_frontier)
        object.__setattr__(self, "manifest_event_id", _optional_event(self.manifest_event_id))
        if self.manifest_sequence is not None and (
            type(self.manifest_sequence) is not int
            or not 1 <= self.manifest_sequence <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        if self.read_gap_reasons and child_frontier is not None:
            raise _invalid()
        if child_frontier is None and not self.read_gap_reasons:
            # A service may not manufacture an unknown child frontier.  Missing/unreadable data
            # must carry a closed read-gap reason so the parent can surface it.
            raise _invalid()

    @property
    def tested_frontier(self) -> Frontier | None:
        """Compatibility alias for callers using the protocol's tested-frontier terminology."""

        return self.child_check_subject_frontier

    @classmethod
    def from_recorded(
        cls,
        value: object,
        *,
        manifest_event_id: object = None,
        manifest_sequence: int | None = None,
    ) -> ChildDependencySnapshot:
        """Build a snapshot from a decoded ``ChildDependencySnapshot`` payload."""

        raw_findings = _field(value, "findings", ())
        if type(raw_findings) not in {tuple, list}:
            raise _invalid()
        raw_revision = _field(value, "lineage_authority_revision")
        # READY service payloads are decoded into the domain event object, whose authority
        # revision is an integer.  Replayed wire fixtures carry the canonical decimal token.
        # Normalize both representations at this adapter boundary before the pure evaluator's
        # opaque revision field is validated.
        if type(raw_revision) is int and raw_revision >= 1:
            revision = str(raw_revision)
        elif type(raw_revision) is str:
            revision = raw_revision
        else:
            raise _invalid()
        return cls(
            child_task_id=cast(TaskId, _field(value, "child_task_id")),
            origin=cast(LineageOrigin, _field(value, "origin")),
            acceptance=cast(LineageAcceptance, _field(value, "acceptance")),
            work_state=cast(WorkState, _field(value, "work_state")),
            session_health=cast(SessionHealth, _field(value, "session_health")),
            child_frontier=cast(Frontier | None, _field(value, "child_frontier")),
            child_check_id=cast(EventId | None, _field(value, "child_check_id")),
            child_receipt_id=cast(ReceiptId | None, _field(value, "child_receipt_id")),
            coverage=cast(Coverage, _field(value, "coverage")),
            findings=tuple(
                ChildFindingSnapshot.from_recorded(item)
                for item in cast(Sequence[object], raw_findings)
            ),
            lineage_authority_revision=revision,
            membership_generation=cast(int | None, _field(value, "membership_generation")),
            read_gap_reasons=tuple(
                cast(str, item)
                for item in cast(Sequence[object], _field(value, "read_gap_reasons", ()))
            ),
            provenance_restrictions=tuple(
                cast(str, item)
                for item in cast(Sequence[object], _field(value, "provenance_restrictions", ()))
            ),
            child_check_subject_frontier=cast(
                Frontier | None, _field(value, "child_check_subject_frontier")
            ),
            manifest_event_id=cast(EventId | None, manifest_event_id),
            manifest_sequence=manifest_sequence,
        )

    def canonical_json(self) -> dict[str, JsonValue]:
        """Return the structural digest input used to compare service manifests."""

        def frontier_json(value: Frontier | None) -> JsonValue:
            return None if value is None else dict(value.as_wire().items())

        return {
            "child_task_id": self.child_task_id,
            "origin": self.origin.value,
            "acceptance": self.acceptance.value,
            "work_state": self.work_state.value,
            "session_health": self.session_health.value,
            "child_frontier": frontier_json(self.child_frontier),
            "child_check_id": self.child_check_id,
            "child_receipt_id": self.child_receipt_id,
            "coverage": coverage_to_json(self.coverage),
            "findings": [
                {
                    "finding_id": item.finding_id,
                    "kind": item.kind.value,
                    "origin": item.origin.value,
                    "priority": item.priority,
                    "actionable": item.actionable,
                    "resolved": item.resolved,
                    "resolution_event_id": item.resolution_event_id,
                    # Present only when true so every earlier manifest digest is unchanged.
                    **({"self_verified": True} if item.self_verified else {}),
                }
                for item in self.findings
            ],
            "lineage_authority_revision": self.lineage_authority_revision,
            "membership_generation": self.membership_generation,
            "read_gap_reasons": list(self.read_gap_reasons),
            "provenance_restrictions": list(self.provenance_restrictions),
            "child_check_subject_frontier": frontier_json(self.child_check_subject_frontier),
        }


@dataclass(frozen=True, slots=True)
class LineageManifest:
    """Latest recorded direct-child snapshots at one parent ledger frontier."""

    children: tuple[ChildDependencySnapshot, ...] = ()
    source_event_id: EventId | None = None
    source_sequence: int | None = None
    read_gap_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.children) is not tuple or len(self.children) > _MAX_CHILDREN:
            raise _invalid()
        children = tuple(
            item
            if type(item) is ChildDependencySnapshot
            else ChildDependencySnapshot.from_recorded(item)
            for item in self.children
        )
        if children != tuple(sorted(children, key=lambda item: str(item.child_task_id).encode())):
            raise _invalid()
        if len({item.child_task_id for item in children}) != len(children):
            raise _invalid()
        object.__setattr__(self, "children", children)
        object.__setattr__(self, "source_event_id", _optional_event(self.source_event_id))
        if self.source_sequence is not None and (
            type(self.source_sequence) is not int
            or not 1 <= self.source_sequence <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        object.__setattr__(
            self,
            "read_gap_reasons",
            _closed_strings(self.read_gap_reasons, _READ_GAP_REASONS),
        )

    @property
    def digest(self) -> str:
        """Digest only the manifest facts, excluding the parent event's location metadata."""

        return canonical_digest(
            {
                "children": [child.canonical_json() for child in self.children],
                "read_gap_reasons": list(self.read_gap_reasons),
            }
        )


@dataclass(frozen=True, slots=True)
class LineageGap:
    code: str
    child_task_id: TaskId | None = None
    finding_ids: tuple[FindingId, ...] = ()
    manifest_event_id: EventId | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not str or _GAP_RE.fullmatch(self.code) is None:
            raise _invalid()
        if self.child_task_id is not None:
            try:
                object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
            except (TypeError, ValueError) as exc:
                raise _invalid() from exc
        object.__setattr__(self, "finding_ids", _finding_ids(self.finding_ids))
        object.__setattr__(self, "manifest_event_id", _optional_event(self.manifest_event_id))
        if self.detail is not None:
            object.__setattr__(self, "detail", _token(self.detail))


@dataclass(frozen=True, slots=True)
class ChildRollup:
    """The evaluator's bounded per-child conclusion."""

    child_task_id: TaskId
    state: LineageRollupState
    freshness: str
    blockers: tuple[str, ...] = ()
    finding_ids: tuple[FindingId, ...] = ()
    manifest_event_id: EventId | None = None
    tested_manifest_ref: EventId | None = None
    later_manifest_ref: EventId | None = None
    # Issue #984 (ADR-034): child findings the child agent self-verified. They are not parent
    # work (never in ``finding_ids``), but they keep the parent from reading clean.
    self_verified_finding_ids: tuple[FindingId, ...] = ()

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
            object.__setattr__(self, "state", _enum(self.state, LineageRollupState))
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if self.freshness not in {"known", "unknown"}:
            raise _invalid()
        object.__setattr__(self, "blockers", _sorted_unique_strings(self.blockers))
        object.__setattr__(self, "finding_ids", _finding_ids(self.finding_ids))
        object.__setattr__(self, "manifest_event_id", _optional_event(self.manifest_event_id))
        object.__setattr__(self, "tested_manifest_ref", _optional_event(self.tested_manifest_ref))
        object.__setattr__(self, "later_manifest_ref", _optional_event(self.later_manifest_ref))
        self_verified = _finding_ids(self.self_verified_finding_ids)
        if set(self_verified) & set(self.finding_ids):
            raise _invalid()
        object.__setattr__(self, "self_verified_finding_ids", self_verified)

    @property
    def outcome(self) -> str:
        return self.state.value

    @property
    def blocks_clean_completion(self) -> bool:
        return bool(self.self_verified_finding_ids) or self.state in {
            LineageRollupState.BLOCKED,
            LineageRollupState.OPEN_GAP,
            LineageRollupState.INCOMPLETE,
            LineageRollupState.UNAVAILABLE,
        }


@dataclass(frozen=True, slots=True)
class LineageEvaluation:
    """Pure aggregate used by checks and receipts."""

    children: tuple[ChildRollup, ...]
    coverage: Coverage
    gaps: tuple[LineageGap, ...]
    manifest_digest: str | None = None
    snapshots: tuple[ChildDependencySnapshot, ...] = ()

    def __post_init__(self) -> None:
        if type(self.children) is not tuple or len(self.children) > _MAX_CHILDREN:
            raise _invalid()
        if self.children != tuple(
            sorted(self.children, key=lambda item: str(item.child_task_id).encode())
        ):
            raise _invalid()
        if len({item.child_task_id for item in self.children}) != len(self.children):
            raise _invalid()
        if type(self.coverage) is not Coverage or type(self.gaps) is not tuple:
            raise _invalid()
        if type(self.snapshots) is not tuple or any(
            type(item) is not ChildDependencySnapshot for item in self.snapshots
        ):
            raise _invalid()
        if self.snapshots != tuple(
            sorted(self.snapshots, key=lambda item: str(item.child_task_id).encode())
        ) or len({item.child_task_id for item in self.snapshots}) != len(self.snapshots):
            raise _invalid()
        if self.gaps != tuple(
            sorted(
                self.gaps,
                key=lambda item: (
                    item.code.encode(),
                    b"" if item.child_task_id is None else str(item.child_task_id).encode(),
                    b"" if item.manifest_event_id is None else str(item.manifest_event_id).encode(),
                    tuple(str(value).encode() for value in item.finding_ids),
                ),
            )
        ):
            raise _invalid()
        if len(
            {(item.code, item.child_task_id, item.manifest_event_id) for item in self.gaps}
        ) != len(self.gaps):
            raise _invalid()
        if self.manifest_digest is not None:
            try:
                validate_sha256_digest(self.manifest_digest)
            except (TypeError, ValueError, ProtocolValueError) as exc:
                raise _invalid() from exc

    @property
    def blocks_clean_completion(self) -> bool:
        return any(item.blocks_clean_completion for item in self.children) or any(
            gap.code == "lineage_manifest_uncovered" for gap in self.gaps
        )

    @property
    def actionable_finding_ids(self) -> tuple[FindingId, ...]:
        ids = {
            finding_id_value
            for child in self.children
            if child.state is LineageRollupState.BLOCKED
            for finding_id_value in child.finding_ids
        }
        return tuple(sorted(ids, key=str.encode))

    @property
    def self_verified_finding_ids(self) -> tuple[FindingId, ...]:
        """Child findings carried as self-verified by the child agent (issue #984)."""

        ids = {item for child in self.children for item in child.self_verified_finding_ids}
        return tuple(sorted(ids, key=str.encode))


def _snapshot_rollup(
    snapshot: ChildDependencySnapshot,
) -> tuple[ChildRollup, tuple[LineageGap, ...]]:
    """Evaluate one recorded child according to #500's severity and lifecycle rules."""

    blockers: set[str] = set()
    finding_ids: set[FindingId] = set()
    gaps: list[LineageGap] = []
    read_gaps = set(snapshot.read_gap_reasons)
    restrictions = set(snapshot.provenance_restrictions)
    # Issue #984 (ADR-034): a child's self-verified repair rolls up as "self-verified by the child
    # agent; FinishUP could not prove it". It is not parent work, so it never enters the actionable
    # set, but an accepted child carrying one never reads clean.
    self_verified = tuple(
        finding for finding in snapshot.findings if not finding.resolved and finding.self_verified
    )
    unresolved_actionable = tuple(
        finding
        for finding in snapshot.findings
        if not finding.resolved and finding.actionable and not finding.self_verified
    )
    unresolved_informational = tuple(
        finding for finding in snapshot.findings if not finding.resolved and not finding.actionable
    )
    finding_ids.update(finding.finding_id for finding in unresolved_actionable)
    invalid_rejection = snapshot.acceptance is LineageAcceptance.REJECTED and bool(
        unresolved_actionable
    )
    # Acceptance is decided before parent-blocking tokens are accumulated. Pending and
    # ordinary rejected relationships are lifecycle annotations: their gaps stay on the
    # child row, but they are not accepted dependencies. The service records
    # NOT_AUTHORIZED because it refuses to open an unaccepted bundle, so every rejected
    # child carries that read gap. Selecting UNAVAILABLE from it, as the original
    # feature commit did, was not a documented fail-closed default: it contradicted the
    # annotation rule and made rejection itself block the parent. An impossible rejected
    # snapshot that still carries actionable work stays blocking on the branch below.
    annotation_only = (
        snapshot.acceptance is not LineageAcceptance.ACCEPTED and not invalid_rejection
    )
    self_verified_ids = (
        () if annotation_only else tuple(finding.finding_id for finding in self_verified)
    )

    def note_blocker(token: str) -> None:
        if not annotation_only:
            blockers.add(token)

    if read_gaps:
        note_blocker("lineage_child_read_gap")
        gaps.append(
            LineageGap(
                "lineage_child_unavailable",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
                detail=next(iter(sorted(read_gaps)), "unknown"),
            )
        )
    if restrictions:
        note_blocker("lineage_child_provenance_restricted")
        gaps.append(
            LineageGap(
                "lineage_child_provenance_restricted",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
                detail=next(iter(sorted(restrictions)), "unknown"),
            )
        )
    if snapshot.child_frontier is None:
        note_blocker("lineage_child_frontier_unknown")
        gaps.append(
            LineageGap(
                "lineage_child_frontier_unknown",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )

    if unresolved_actionable:
        note_blocker("lineage_child_actionable_finding")
        gaps.append(
            LineageGap(
                "lineage_child_actionable_finding",
                snapshot.child_task_id,
                tuple(sorted(finding_ids, key=str.encode)),
                snapshot.manifest_event_id,
            )
        )
    if self_verified_ids:
        # A standing disclosure, not a blocker token: the parent agent has no action to take.
        gaps.append(
            LineageGap(
                CHILD_SELF_VERIFIED_GAP,
                snapshot.child_task_id,
                tuple(sorted(self_verified_ids, key=str.encode)),
                snapshot.manifest_event_id,
            )
        )
    if invalid_rejection:
        # C4 permits pending -> rejected only.  A rejected snapshot carrying a later actionable
        # child finding is therefore evidence of an impossible accepted -> rejected transition;
        # retain the finding ids, but refuse to let the parent describe the dependency as a clean
        # annotation that escaped responsibility.
        note_blocker("lineage_invalid_acceptance_transition")
        gaps.append(
            LineageGap(
                "lineage_invalid_acceptance_transition",
                snapshot.child_task_id,
                tuple(sorted(finding_ids, key=str.encode)),
                snapshot.manifest_event_id,
            )
        )

    # A child's own coverage is part of the frozen dependency fact.  Carry its limitations into
    # the parent outcome instead of allowing a child with a digest-only or otherwise partial
    # check to look clean merely because it has a receipt id.
    child_coverage_gaps = tuple(snapshot.coverage.known_gaps)
    if child_coverage_gaps:
        note_blocker("lineage_child_coverage_gap")
        gaps.append(
            LineageGap(
                "lineage_child_coverage_gap",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
                detail="coverage",
            )
        )

    check_frontier_unknown = (
        snapshot.child_check_id is not None and snapshot.child_check_subject_frontier is None
    )
    check_stale = (
        snapshot.child_frontier is not None
        and snapshot.child_check_subject_frontier is not None
        and snapshot.child_check_subject_frontier != snapshot.child_frontier
    )
    missing_check = snapshot.child_check_id is None
    missing_receipt = snapshot.child_receipt_id is None
    if check_stale:
        note_blocker("lineage_child_check_stale")
        gaps.append(
            LineageGap(
                "lineage_child_check_stale",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )
    if check_frontier_unknown:
        note_blocker("lineage_child_check_frontier_unknown")
        gaps.append(
            LineageGap(
                "lineage_child_check_frontier_unknown",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )
    if missing_check or missing_receipt:
        note_blocker("lineage_child_verification_unknown")
        gaps.append(
            LineageGap(
                "lineage_child_verification_unknown",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )

    freshness = "known"
    if (
        snapshot.child_frontier is None
        or missing_check
        or missing_receipt
        or check_frontier_unknown
    ):
        freshness = "unknown"
    if invalid_rejection:
        state = (
            LineageRollupState.UNAVAILABLE
            if read_gaps or restrictions or snapshot.child_frontier is None
            else LineageRollupState.BLOCKED
        )
    elif annotation_only:
        # Read and provenance gaps remain named in the child gap row. They are not parent
        # blocker tokens and they do not select UNAVAILABLE.
        state = LineageRollupState.ANNOTATION
    elif read_gaps or restrictions or snapshot.child_frontier is None:
        state = LineageRollupState.UNAVAILABLE
    elif unresolved_actionable:
        state = LineageRollupState.BLOCKED
    elif snapshot.session_health is SessionHealth.CONTACT_LOST or snapshot.work_state in {
        WorkState.ABANDONED,
        WorkState.CANCELLED,
        WorkState.WRITTEN_OFF,
    }:
        blockers.add("lineage_child_incomplete")
        gaps.append(
            LineageGap(
                "lineage_child_incomplete",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )
        state = LineageRollupState.INCOMPLETE
    elif snapshot.session_health is SessionHealth.ENDED and snapshot.work_state is WorkState.OPEN:
        blockers.add("lineage_child_incomplete")
        gaps.append(
            LineageGap(
                "lineage_child_incomplete",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )
        state = LineageRollupState.INCOMPLETE
    elif snapshot.session_health is SessionHealth.ACTIVE and snapshot.work_state is WorkState.OPEN:
        blockers.add("lineage_child_open")
        gaps.append(
            LineageGap(
                "lineage_child_open",
                snapshot.child_task_id,
                manifest_event_id=snapshot.manifest_event_id,
            )
        )
        state = LineageRollupState.OPEN_GAP
    elif blockers:
        # Coverage and verification blockers stay ahead of an informational annotation.
        state = LineageRollupState.OPEN_GAP
    elif self_verified_ids:
        # Not clean and not parent work: the receipt row shows each self-verified finding and
        # ``blocks_clean_completion`` holds the parent at best at insufficient_coverage.
        state = LineageRollupState.ANNOTATION
    elif unresolved_informational:
        # Informational findings stay on the receipt child row. They annotate a fully
        # verified terminal child and do not select unresolved_findings_remain. They never
        # replace an accepted lifecycle gap, which is decided above.
        state = LineageRollupState.ANNOTATION
    else:
        state = LineageRollupState.CLEAN

    rollup = ChildRollup(
        child_task_id=snapshot.child_task_id,
        state=state,
        freshness=freshness,
        blockers=tuple(sorted(blockers, key=str.encode)),
        finding_ids=tuple(sorted(finding_ids, key=str.encode)),
        manifest_event_id=snapshot.manifest_event_id,
        tested_manifest_ref=(
            None if state is LineageRollupState.UNAVAILABLE else snapshot.manifest_event_id
        ),
        self_verified_finding_ids=tuple(sorted(self_verified_ids, key=str.encode)),
    )
    return rollup, tuple(gaps)


def evaluate_lineage(
    manifest: LineageManifest | object | None,
    *,
    base_coverage: Coverage | None = None,
) -> LineageEvaluation:
    """Evaluate the latest *recorded* direct-child snapshots.

    ``base_coverage`` is the parent case coverage.  A standalone call uses the conservative
    engine-derived baseline, while receipt/check callers pass their existing case coverage and
    therefore preserve every parent-side limitation.
    """

    if manifest is None:
        manifest_value = LineageManifest()
    elif type(manifest) is LineageManifest:
        manifest_value = manifest
    else:
        manifest_value = manifest_from_payload(manifest)
    coverage = base_coverage or coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
    gaps: list[LineageGap] = []
    for reason in manifest_value.read_gap_reasons:
        gaps.append(
            LineageGap(
                f"lineage_manifest_{reason}", manifest_event_id=manifest_value.source_event_id
            )
        )
        coverage = weakest(
            coverage,
            Coverage(
                coverage.publication_channels,
                coverage.authorship_assurance,
                coverage.artifact_observation,
                coverage.evidence_immutability,
                LedgerFreshness.PARTIAL,
                coverage.check_types,
                tuple(
                    sorted(
                        set((*coverage.known_gaps, f"lineage_manifest_{reason}")), key=str.encode
                    )
                ),
            ),
        )
    rollups: list[ChildRollup] = []
    for snapshot in manifest_value.children:
        rollup, child_gaps = _snapshot_rollup(snapshot)
        rollups.append(rollup)
        gaps.extend(child_gaps)
        # Pending/rejected relationships are annotations by contract.  Their child-side missing
        # check, frontier, receipt, or coverage must remain visible in the child row while never
        # weakening the parent's clean-completion coverage.  Accepted children, in contrast, may
        # contribute every frozen coverage limitation and evaluator gap.
        annotation_coverage = snapshot.coverage
        if not rollup.blocks_clean_completion and annotation_coverage.known_gaps:
            # Pending/rejected relationships remain visible annotations.  Preserve their
            # non-gap assurance dimensions, but do not turn a child-side gap into a parent
            # completion blocker until the relationship is accepted.
            annotation_coverage = replace(annotation_coverage, known_gaps=())
        coverage = weakest(coverage, annotation_coverage)
        if rollup.blocks_clean_completion:
            child_gap_codes = {gap.code for gap in child_gaps}
            for code in child_gap_codes:
                if code not in coverage.known_gaps:
                    freshness = coverage.ledger_freshness
                    if freshness is LedgerFreshness.CURRENT:
                        freshness = LedgerFreshness.PARTIAL
                    coverage = Coverage(
                        coverage.publication_channels,
                        coverage.authorship_assurance,
                        coverage.artifact_observation,
                        coverage.evidence_immutability,
                        freshness,
                        coverage.check_types,
                        tuple(sorted(set((*coverage.known_gaps, code)), key=str.encode)),
                    )
    ordered_gaps = tuple(
        sorted(
            set(gaps),
            key=lambda item: (
                item.code.encode(),
                b"" if item.child_task_id is None else str(item.child_task_id).encode(),
                () if item.manifest_event_id is None else (str(item.manifest_event_id).encode(),),
            ),
        )
    )
    return LineageEvaluation(
        tuple(sorted(rollups, key=lambda item: str(item.child_task_id).encode())),
        coverage,
        ordered_gaps,
        manifest_value.digest,
        manifest_value.children,
    )


def _coverage_with_gap(coverage: Coverage, code: str) -> Coverage:
    """Return ``coverage`` weakened by one structural lineage gap."""

    if code in coverage.known_gaps:
        return coverage
    freshness = coverage.ledger_freshness
    if freshness is LedgerFreshness.CURRENT:
        freshness = LedgerFreshness.PARTIAL
    return Coverage(
        coverage.publication_channels,
        coverage.authorship_assurance,
        coverage.artifact_observation,
        coverage.evidence_immutability,
        freshness,
        coverage.check_types,
        tuple(sorted((*coverage.known_gaps, code), key=str.encode)),
    )


def with_later_manifest(
    evaluation: LineageEvaluation,
    later_manifest: LineageManifest | object | None,
) -> LineageEvaluation:
    """Annotate an evaluation with a newer recorded manifest that its check did not cover.

    This function receives only two immutable manifest values.  It does not query a child and it
    does not change the tested outcome; it adds the later event reference and a bounded coverage
    gap so a receipt can explain why a previously clean check no longer supports clean wording.
    """

    if type(evaluation) is not LineageEvaluation:
        raise _invalid()
    if later_manifest is None:
        return evaluation
    later = (
        later_manifest
        if type(later_manifest) is LineageManifest
        else manifest_from_payload(later_manifest)
    )
    if evaluation.manifest_digest == later.digest:
        return evaluation

    later_by_child = {child.child_task_id: child for child in later.children}
    tested_ids = {child.child_task_id for child in evaluation.children}
    children: list[ChildRollup] = []
    later_gaps: list[LineageGap] = []
    for rollup in evaluation.children:
        if rollup.child_task_id in later_by_child:
            children.append(replace(rollup, later_manifest_ref=later.source_event_id))
        else:
            # A later aggregate can remove a child.  Keep the tested row because that is what the
            # check evaluated; the aggregate event itself remains named by the global gap.
            children.append(rollup)
    for child in later.children:
        _later_rollup, child_gaps = _snapshot_rollup(child)
        later_gaps.extend(child_gaps)
        if child.child_task_id in tested_ids:
            continue
        children.append(
            replace(
                _later_rollup,
                tested_manifest_ref=None,
                later_manifest_ref=later.source_event_id,
            )
        )
    gaps_to_add = [
        LineageGap(
            "lineage_manifest_uncovered",
            manifest_event_id=later.source_event_id,
        )
    ]
    gaps_to_add.extend(
        LineageGap(
            f"lineage_manifest_{reason}",
            manifest_event_id=later.source_event_id,
        )
        for reason in later.read_gap_reasons
    )
    gaps_to_add.extend(later_gaps)
    gap = gaps_to_add[0]
    gaps = tuple(
        sorted(
            {*evaluation.gaps, *gaps_to_add},
            key=lambda item: (
                item.code.encode(),
                b"" if item.child_task_id is None else str(item.child_task_id).encode(),
                b"" if item.manifest_event_id is None else str(item.manifest_event_id).encode(),
            ),
        )
    )
    coverage = _coverage_with_gap(evaluation.coverage, gap.code)
    for later_gap in gaps_to_add[1:]:
        # Manifest-level read failures weaken the parent coverage directly.  Child-specific
        # gaps belong to the later, untested snapshot; the receipt keeps them in the structured
        # gap list while the global uncovered marker carries the conclusion-level limitation.
        if later_gap.child_task_id is not None:
            continue
        coverage = _coverage_with_gap(coverage, later_gap.code)
    return LineageEvaluation(
        tuple(sorted(children, key=lambda item: str(item.child_task_id).encode())),
        coverage,
        gaps,
        evaluation.manifest_digest,
        tuple(
            sorted(
                (
                    *evaluation.snapshots,
                    *(
                        child
                        for child in later.children
                        if child.child_task_id
                        not in {item.child_task_id for item in evaluation.snapshots}
                    ),
                ),
                key=lambda item: str(item.child_task_id).encode(),
            )
        ),
    )


def evaluate_recorded_lineage(
    records: Iterable[object],
    *,
    tested_through_sequence: int | None = None,
    base_coverage: Coverage | None = None,
) -> LineageEvaluation:
    """Evaluate manifests replayed from parent records at an optional checked frontier.

    ``tested_through_sequence`` is the parent ledger sequence the applicable check examined.  A
    later aggregate is attached as uncovered metadata; all state still comes from recorded
    parent rows.  With no sequence, the latest recorded aggregate is the evaluated subject.
    """

    accepted = tuple(records)
    if tested_through_sequence is None:
        return evaluate_lineage(
            lineage_manifest_from_records(accepted), base_coverage=base_coverage
        )
    if (
        type(tested_through_sequence) is not int
        or not 0 <= tested_through_sequence <= _MAX_SAFE_INTEGER
    ):
        raise _invalid()

    def _sequence(record: object) -> int | None:
        value = _field(_field(record, "ledger"), "ingestion_sequence")
        return value if type(value) is int else None

    tested_records = tuple(
        record
        for record in accepted
        if (sequence := _sequence(record)) is not None and sequence <= tested_through_sequence
    )
    tested = lineage_manifest_from_records(tested_records)
    latest = lineage_manifest_from_records(accepted)
    result = evaluate_lineage(tested, base_coverage=base_coverage)
    if latest.source_event_id is not None and latest.digest != tested.digest:
        result = with_later_manifest(result, latest)
    return result


def manifest_from_payload(payload: object) -> LineageManifest:
    """Adapt a decoded child-dependency event payload into a canonical aggregate."""

    children_raw = _field(payload, "children")
    if children_raw is None:
        # A transitional decoder may expose one child directly.  Accepting this shape here keeps
        # the evaluator replay-compatible; publication still emits the aggregate contract.
        if _field(payload, "child_task_id") is None:
            raise _invalid()
        children_raw = (payload,)
    if type(children_raw) not in {tuple, list}:
        raise _invalid()
    children = tuple(
        ChildDependencySnapshot.from_recorded(item) for item in cast(Sequence[object], children_raw)
    )
    return LineageManifest(children)


def lineage_manifest_from_records(records: Iterable[object]) -> LineageManifest:
    """Fold parent-ledger manifest events without reading child state.

    The latest aggregate event wins.  An unreadable manifest payload contributes a generic
    manifest read gap because no child identity may be inferred from redacted bytes.  Earlier
    aggregate members are never retained after a newer event, so a removed child cannot remain
    accidentally covered.
    """

    latest_manifest: LineageManifest | None = None
    latest_key: tuple[int, int] | None = None
    for index, record in enumerate(records):
        schema = _field(record, "schema")
        name = _field(schema, "name")
        if name not in {"child_dependencies_recorded", "child-dependencies-recorded"}:
            continue
        event_id_value = _optional_event(_field(record, "event_id"))
        ledger = _field(record, "ledger")
        sequence_raw = _field(ledger, "ingestion_sequence")
        sequence = (
            sequence_raw
            if type(sequence_raw) is int and 1 <= sequence_raw <= _MAX_SAFE_INTEGER
            else None
        )
        order_key = (sequence if sequence is not None else -1, index)
        if latest_key is not None and order_key < latest_key:
            continue
        try:
            service_stamped = is_lineage_service_stamped(cast(LedgerRecord, record))
        except (AttributeError, TypeError, ValueError):
            service_stamped = False
        if not service_stamped:
            # A closed lineage payload is not sufficient provenance.  Keep the latest event
            # visible as an authorization gap and discard its children so a fabricated/imported
            # event cannot influence a parent conclusion.
            latest_manifest = LineageManifest((), event_id_value, sequence, ("not_authorized",))
            latest_key = order_key
            continue
        payload = _field(record, "payload")
        if payload is None:
            latest_manifest = LineageManifest((), event_id_value, sequence, ("unreadable",))
            latest_key = order_key
            continue
        payload_children = _field(payload, "children")
        if payload_children is None:
            # A transitional single-child object remains replayable, but a random payload with
            # no child identity is unreadable and must not manufacture a child.
            payload_children = (payload,) if _field(payload, "child_task_id") is not None else ()
        if type(payload_children) not in {tuple, list}:
            latest_manifest = LineageManifest((), event_id_value, sequence, ("unreadable",))
            latest_key = order_key
            continue
        children: list[ChildDependencySnapshot] = []
        read_gaps: set[str] = set()
        for child_payload in cast(Sequence[object], payload_children):
            try:
                child = ChildDependencySnapshot.from_recorded(
                    child_payload,
                    manifest_event_id=event_id_value,
                    manifest_sequence=sequence,
                )
            except ValueError:
                # A malformed recorded child is a named unreadable dependency, never silently
                # dropped.  Keep the parent manifest usable for other children.
                read_gaps.add("unreadable")
                continue
            children.append(child)
        try:
            latest_manifest = LineageManifest(
                tuple(sorted(children, key=lambda item: str(item.child_task_id).encode())),
                event_id_value,
                sequence,
                tuple(sorted(read_gaps, key=str.encode)),
            )
        except ValueError:
            # Duplicate/unsorted aggregate data is a malformed recorded manifest.  Preserve the
            # event identity and surface an unreadable gap rather than falling back to an older
            # child state that the latest event may have superseded.
            latest_manifest = LineageManifest((), event_id_value, sequence, ("unreadable",))
        latest_key = order_key
    return latest_manifest or LineageManifest()
