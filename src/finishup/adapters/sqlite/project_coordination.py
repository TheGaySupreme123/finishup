"""Durable project-coordination detections and delivery records.

The project registry itself is owned by ``start_catalog``.  This adapter owns the additional
coordination rows required by issue #503: one detection identity, two structural participant
records, idempotent per-target deliveries, and per-target obligation state.  The catalog
migration that creates these tables is intentionally owned by the storage-inventory lane; this
module fails closed when it is composed before that migration.

Every JSON column written here is canonical and structural.  Raw resource names and structured
plan values are kept in the encrypted detail object referenced by ``ProjectTextRef``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, cast

import apsw

from finishup.application.coordination import (
    CoordinationAdvice,
    CoordinationDelivery,
    CoordinationDeliveryStore,
    CoordinationObligationState,
    CoordinationParticipant,
)
from finishup.domain.coordination import (
    CoordinationCoverage,
    CoordinationDetection,
    CoordinationError,
    CoordinationErrorCode,
    CoordinationGapCode,
    OverlapKind,
    ProjectTextRef,
)
from finishup.domain.coordination import (
    project_id as validate_project_id,
)
from finishup.domain.values import obligation_id
from finishup.protocol.canonical import (
    JsonValue as CanonicalJsonValue,
)
from finishup.protocol.canonical import (
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["SqliteCoordinationStore"]


def _invalid() -> CoordinationError:
    return CoordinationError(CoordinationErrorCode.INVALID)


def _json(value: object) -> str:
    try:
        return canonical_encode(cast(CanonicalJsonValue, value)).decode("utf-8")
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise _invalid() from exc


def _parse_json(value: object) -> object:
    if type(value) is not str:
        raise _invalid()
    try:
        encoded = value.encode("utf-8")
        parsed = strict_json_parse(encoded)
        if canonical_encode(parsed) != encoded:
            raise ValueError("coordination_json_noncanonical")
        return parsed
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise _invalid() from exc


def _bool(value: object) -> bool:
    if type(value) is not int or value not in {0, 1}:
        raise _invalid()
    return bool(value)


def _text_ref(value: object) -> ProjectTextRef | None:
    if value is None:
        return None
    parsed = _parse_json(value)
    if not isinstance(parsed, Mapping):
        raise _invalid()
    parsed_map = cast(Mapping[str, CanonicalJsonValue], parsed)
    required = {
        "object_id",
        "content_digest",
        "plaintext_size",
        "owner_task_id",
        "route_generation",
    }
    keys = set(parsed_map)
    if keys not in (required, required | {"envelope_digest"}):
        raise _invalid()
    route_generation = parsed_map.get("route_generation")
    plaintext_size = parsed_map.get("plaintext_size")
    if type(route_generation) is not str or type(plaintext_size) is not int:
        raise _invalid()
    try:
        parsed_generation = int(route_generation, 10)
        if str(parsed_generation) != route_generation:
            raise ValueError("coordination_generation_invalid")
        return ProjectTextRef(
            cast(str, parsed_map["object_id"]),
            cast(str, parsed_map["content_digest"]),
            plaintext_size,
            cast(str, parsed_map["owner_task_id"]),
            parsed_generation,
            None
            if parsed_map.get("envelope_digest") is None
            else cast(str, parsed_map["envelope_digest"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid() from exc


def _detection(row: tuple[object, ...]) -> CoordinationDetection:
    if len(row) != 14:
        raise _invalid()
    resources = _parse_json(row[6])
    if not isinstance(resources, list):
        raise _invalid()
    resource_values = cast(list[CanonicalJsonValue], resources)
    try:
        return CoordinationDetection(
            cast(str, row[0]),
            cast(str, row[1]),
            cast(int, row[2]),
            cast(str, row[3]),
            cast(str, row[4]),
            OverlapKind(cast(str, row[5])),
            tuple(cast(str, item) for item in resource_values),
            cast(str, row[7]),
            _bool(row[8]),
            _bool(row[9]),
            _bool(row[10]),
            _bool(row[11]),
            _text_ref(row[12]),
            _bool(row[13]),
        )
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _coverage(row: tuple[object, ...]) -> CoordinationCoverage:
    if len(row) != 6:
        raise _invalid()
    generation = row[3]
    if type(generation) is not int:
        raise _invalid()
    try:
        return CoordinationCoverage(
            cast(str, row[0]),
            cast(str, row[1]),
            cast(str, row[2]),
            generation,
            cast(Literal["unobservable"], row[4]),
            CoordinationGapCode(cast(str, row[5])),
        )
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _participant(row: tuple[object, ...]) -> CoordinationParticipant:
    if len(row) != 6:
        raise _invalid()
    try:
        return CoordinationParticipant(
            cast(str, row[0]),
            cast(str, row[1]),
            cast(str, row[2]),
            cast(str, row[3]),
            cast(int, row[4]),
            _bool(row[5]),
        )
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


class SqliteCoordinationStore(CoordinationDeliveryStore):
    """Single-connection durable implementation of the coordination delivery port."""

    def __init__(self, db: apsw.Connection) -> None:
        if type(db) is not apsw.Connection:
            raise TypeError("coordination_db_invalid")
        self._db = db

    @staticmethod
    def _detection_select() -> str:
        return (
            "SELECT detection_id, project_id, membership_generation, left_task_id, right_task_id, "
            "overlap_kind, resource_identities_json, counterpart_task_id, advice_only, "
            "obligation_declared, addressed, generation_valid, detail_ref_json, resolved "
            "FROM coordination_detections"
        )

    async def put_detection(self, detection: CoordinationDetection) -> CoordinationDetection:
        if type(detection) is not CoordinationDetection:
            raise _invalid()
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO coordination_detections("
                "detection_id, project_id, membership_generation, left_task_id, right_task_id, "
                "overlap_kind, resource_identities_json, counterpart_task_id, advice_only, "
                "obligation_declared, addressed, generation_valid, detail_ref_json, resolved) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    detection.detection_id,
                    detection.project_id,
                    detection.membership_generation,
                    detection.left_task_id,
                    detection.right_task_id,
                    detection.overlap_kind.value,
                    _json(list(detection.resource_identities)),
                    detection.counterpart_task_id,
                    int(detection.advice_only),
                    int(detection.obligation_declared),
                    int(detection.addressed),
                    int(detection.generation_valid),
                    None if detection.detail_ref is None else _json(detection.detail_ref.as_wire()),
                    int(detection.resolved),
                ),
            )
        stored = await self.get_detection(detection.detection_id)
        if stored is None:
            raise _invalid()
        immutable = (
            "project_id",
            "membership_generation",
            "left_task_id",
            "right_task_id",
            "overlap_kind",
            "resource_identities",
            "counterpart_task_id",
        )
        if any(getattr(stored, name) != getattr(detection, name) for name in immutable):
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        # A repeated sweep may observe the same detection after a participant publishes its
        # declaration.  Flags are forward-only state owned by ``replace_detection``; returning
        # the durable row lets the caller merge that state without mistaking a legitimate
        # advice-only -> declared transition for an identity conflict.
        return stored

    async def get_detection(self, detection_id: str) -> CoordinationDetection | None:
        try:
            # Domain validation is intentionally performed before the query so malformed caller
            # selectors cannot be confused with an absent detection.
            validate_id(IdKind.EVENT, detection_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        row = self._db.execute(
            self._detection_select() + " WHERE detection_id = ? LIMIT 2", (detection_id,)
        ).fetchall()
        if len(row) > 1:
            raise _invalid()
        return None if not row else _detection(tuple(row[0]))

    async def list_detections(self, project_id: str) -> tuple[CoordinationDetection, ...]:
        try:
            project_id = validate_project_id(project_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        rows = self._db.execute(
            self._detection_select() + " WHERE project_id = ? ORDER BY detection_id ASC",
            (project_id,),
        ).fetchall()
        return tuple(_detection(tuple(row)) for row in rows)

    async def _require_advice_context(self, advice: CoordinationAdvice) -> CoordinationDetection:
        detection = await self.get_detection(advice.detection_id)
        if detection is None:
            raise CoordinationError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        if advice.target_task_id not in {detection.left_task_id, detection.right_task_id}:
            raise CoordinationError(CoordinationErrorCode.INVALID)
        if advice.counterpart_task_id not in {detection.left_task_id, detection.right_task_id}:
            raise CoordinationError(CoordinationErrorCode.INVALID)
        expected = (
            detection.project_id,
            detection.membership_generation,
            detection.overlap_kind,
            detection.resource_identities,
            len(detection.resource_identities),
        )
        actual = (
            advice.project_id,
            advice.membership_generation,
            advice.overlap_kind,
            advice.resource_identities,
            advice.resource_count,
        )
        if actual != expected:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        participants = await self.participants(advice.detection_id)
        if participants is None:
            # Advice has no durable source provenance without the pair row.  Refuse to create a
            # one-sided delivery that a restart could not authenticate or complete.
            raise CoordinationError(CoordinationErrorCode.INVALID)
        expected_counterpart = next(
            (item.task_id for item in participants if item.task_id != advice.target_task_id),
            None,
        )
        if expected_counterpart != advice.counterpart_task_id:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        return detection

    async def put_advice(self, advice: CoordinationAdvice) -> CoordinationDelivery:
        if type(advice) is not CoordinationAdvice:
            raise _invalid()
        await self._require_advice_context(advice)
        inserted = False
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO coordination_deliveries("
                "detection_id, target_task_id, outcome, expected_generation, observed_generation, "
                "reason_code, advice_json) VALUES(?,?,?,?,?,?,?)",
                (
                    advice.detection_id,
                    advice.target_task_id,
                    "delivered",
                    advice.membership_generation,
                    advice.membership_generation,
                    None,
                    _json(advice.as_wire()),
                ),
            )
            inserted = self._db.changes() == 1
        if inserted:
            return CoordinationDelivery(
                advice.detection_id,
                advice.target_task_id,
                "delivered",
                advice.membership_generation,
                advice.membership_generation,
            )
        existing = self._db.execute(
            "SELECT outcome, expected_generation, observed_generation, reason_code, advice_json "
            "FROM coordination_deliveries WHERE detection_id = ? AND target_task_id = ? LIMIT 2",
            (advice.detection_id, advice.target_task_id),
        ).fetchall()
        if len(existing) != 1:
            raise _invalid()
        row = existing[0]
        if row[0] == "delivered":
            outcome: Literal["delivered", "duplicate", "refused"] = "duplicate"
            if type(row[4]) is not str or row[4] != _json(advice.as_wire()):
                raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        elif row[0] == "refused":
            outcome = "refused"
        else:
            raise _invalid()
        return CoordinationDelivery(
            advice.detection_id,
            advice.target_task_id,
            outcome,
            cast(int, row[1]),
            cast(int, row[2]),
            None if row[3] is None else cast(str, row[3]),
        )

    async def put_delivery(self, delivery: CoordinationDelivery) -> CoordinationDelivery:
        if type(delivery) is not CoordinationDelivery:
            raise _invalid()
        detection = await self.get_detection(delivery.detection_id)
        if detection is None:
            raise CoordinationError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        if delivery.target_task_id not in {detection.left_task_id, detection.right_task_id}:
            raise CoordinationError(CoordinationErrorCode.INVALID)
        participants = await self.participants(delivery.detection_id)
        if participants is None or delivery.target_task_id not in {
            participants[0].task_id,
            participants[1].task_id,
        }:
            raise CoordinationError(CoordinationErrorCode.INVALID)
        if delivery.expected_generation != detection.membership_generation:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        if delivery.outcome == "duplicate":
            existing = self._db.execute(
                "SELECT outcome, expected_generation, observed_generation, reason_code "
                "FROM coordination_deliveries WHERE detection_id = ? AND target_task_id = ? LIMIT 2",
                (delivery.detection_id, delivery.target_task_id),
            ).fetchall()
            if len(existing) != 1 or existing[0][0] != "delivered":
                raise _invalid()
            row = existing[0]
            return CoordinationDelivery(
                delivery.detection_id,
                delivery.target_task_id,
                "duplicate",
                cast(int, row[1]),
                cast(int, row[2]),
                None if row[3] is None else cast(str, row[3]),
            )
        existing = self._db.execute(
            "SELECT outcome, expected_generation, observed_generation, reason_code "
            "FROM coordination_deliveries WHERE detection_id = ? AND target_task_id = ? LIMIT 2",
            (delivery.detection_id, delivery.target_task_id),
        ).fetchall()
        if len(existing) > 1:
            raise _invalid()
        if existing:
            row = existing[0]
            if delivery.outcome == "refused" and row[0] == "delivered":
                return CoordinationDelivery(
                    delivery.detection_id,
                    delivery.target_task_id,
                    "delivered",
                    cast(int, row[1]),
                    cast(int, row[2]),
                    None if row[3] is None else cast(str, row[3]),
                )
            if (
                row[0] != delivery.outcome
                or row[1] != delivery.expected_generation
                or row[2] != delivery.observed_generation
                or row[3] != delivery.reason_code
            ):
                raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
            raw_outcome = row[0]
            if raw_outcome not in {"delivered", "refused"}:
                raise _invalid()
            return CoordinationDelivery(
                delivery.detection_id,
                delivery.target_task_id,
                cast(Literal["delivered", "refused"], raw_outcome),
                cast(int, row[1]),
                cast(int, row[2]),
                None if row[3] is None else cast(str, row[3]),
            )
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO coordination_deliveries("
                "detection_id, target_task_id, outcome, expected_generation, observed_generation, "
                "reason_code, advice_json) VALUES(?,?,?,?,?,?,NULL)",
                (
                    delivery.detection_id,
                    delivery.target_task_id,
                    delivery.outcome,
                    delivery.expected_generation,
                    delivery.observed_generation,
                    delivery.reason_code,
                ),
            )
        row = self._db.execute(
            "SELECT outcome, expected_generation, observed_generation, reason_code "
            "FROM coordination_deliveries WHERE detection_id = ? AND target_task_id = ?",
            (delivery.detection_id, delivery.target_task_id),
        ).fetchone()
        if row is None:
            raise _invalid()
        raw_outcome = row[0]
        if raw_outcome not in {"delivered", "refused"}:
            raise _invalid()
        return CoordinationDelivery(
            delivery.detection_id,
            delivery.target_task_id,
            cast(Literal["delivered", "refused"], raw_outcome),
            cast(int, row[1]),
            cast(int, row[2]),
            None if row[3] is None else cast(str, row[3]),
        )

    async def deliveries(self, detection_id: str) -> tuple[CoordinationDelivery, ...]:
        try:
            validate_id(IdKind.EVENT, detection_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        rows = self._db.execute(
            "SELECT detection_id, target_task_id, outcome, expected_generation, "
            "observed_generation, reason_code FROM coordination_deliveries "
            "WHERE detection_id = ? ORDER BY target_task_id ASC",
            (detection_id,),
        ).fetchall()
        return tuple(
            CoordinationDelivery(
                cast(str, row[0]),
                cast(str, row[1]),
                cast(Literal["delivered", "duplicate", "refused"], row[2]),
                cast(int, row[3]),
                cast(int, row[4]),
                None if row[5] is None else cast(str, row[5]),
            )
            for row in rows
        )

    async def advice_for(self, detection_id: str, target_task_id: str) -> CoordinationAdvice | None:
        try:
            validate_id(IdKind.EVENT, detection_id)
            validate_id(IdKind.TASK, target_task_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        rows = self._db.execute(
            "SELECT advice_json FROM coordination_deliveries "
            "WHERE detection_id = ? AND target_task_id = ? LIMIT 2",
            (detection_id, target_task_id),
        ).fetchall()
        if len(rows) > 1:
            raise _invalid()
        if not rows or rows[0][0] is None:
            return None
        parsed = _parse_json(rows[0][0])
        if not isinstance(parsed, Mapping):
            raise _invalid()
        source = cast(Mapping[str, CanonicalJsonValue], parsed)
        expected = {
            "detection_id",
            "target_task_id",
            "counterpart_task_id",
            "project_id",
            "membership_generation",
            "overlap_kind",
            "resource_identities",
            "resource_count",
            "coverage",
        }
        if set(source) != expected:
            raise _invalid()
        generation = source["membership_generation"]
        resources = source["resource_identities"]
        count = source["resource_count"]
        if type(generation) is not str or type(count) is not int or not isinstance(resources, list):
            raise _invalid()
        try:
            parsed_generation = int(generation, 10)
            if str(parsed_generation) != generation:
                raise ValueError("coordination_generation_invalid")
            return CoordinationAdvice(
                cast(str, source["detection_id"]),
                cast(str, source["target_task_id"]),
                cast(str, source["counterpart_task_id"]),
                cast(str, source["project_id"]),
                parsed_generation,
                OverlapKind(cast(str, source["overlap_kind"])),
                tuple(cast(str, item) for item in resources),
                count,
                cast(Literal["complete", "unobservable", "truncated"], source["coverage"]),
            )
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc

    async def put_participants(
        self,
        detection_id: str,
        participants: tuple[CoordinationParticipant, CoordinationParticipant],
    ) -> None:
        try:
            validate_id(IdKind.EVENT, detection_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if type(participants) is not tuple or len(participants) != 2:
            raise _invalid()
        if participants[0].task_id == participants[1].task_id:
            raise _invalid()
        if any(type(item) is not CoordinationParticipant for item in participants):
            raise _invalid()
        detection = await self.get_detection(detection_id)
        if detection is None:
            raise CoordinationError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        if {item.task_id for item in participants} != {
            detection.left_task_id,
            detection.right_task_id,
        }:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        if any(
            item.project_id != detection.project_id or item.route_generation < 1
            for item in participants
        ):
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        participants = cast(
            tuple[CoordinationParticipant, CoordinationParticipant],
            tuple(sorted(participants, key=lambda item: item.task_id.encode("ascii"))),
        )
        with self._db:
            for participant in participants:
                self._db.execute(
                    "INSERT OR IGNORE INTO coordination_participants("
                    "detection_id, task_id, project_id, repository_commitment, workspace_commitment, "
                    "route_generation, source_has_attributable_paths) VALUES(?,?,?,?,?,?,?)",
                    (
                        detection_id,
                        participant.task_id,
                        participant.project_id,
                        participant.repository_commitment,
                        participant.workspace_commitment,
                        participant.route_generation,
                        int(participant.source_has_attributable_paths),
                    ),
                )

        stored = await self.participants(detection_id)
        expected = participants
        if stored != expected:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)

    async def participants(
        self, detection_id: str
    ) -> tuple[CoordinationParticipant, CoordinationParticipant] | None:
        try:
            validate_id(IdKind.EVENT, detection_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        rows = self._db.execute(
            "SELECT task_id, project_id, repository_commitment, workspace_commitment, "
            "route_generation, source_has_attributable_paths FROM coordination_participants "
            "WHERE detection_id = ? ORDER BY task_id ASC",
            (detection_id,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 2:
            raise _invalid()
        return cast(
            tuple[CoordinationParticipant, CoordinationParticipant],
            tuple(_participant(tuple(row)) for row in rows),
        )

    async def put_coverage(self, coverage: CoordinationCoverage) -> CoordinationCoverage:
        if type(coverage) is not CoordinationCoverage:
            raise _invalid()
        existing_scope = self._db.execute(
            "SELECT coverage_id, project_id, task_id, membership_generation, coverage, gap_code "
            "FROM coordination_coverage WHERE project_id = ? AND task_id = ? "
            "AND membership_generation = ? LIMIT 2",
            (coverage.project_id, coverage.task_id, coverage.membership_generation),
        ).fetchall()
        if len(existing_scope) > 1:
            raise _invalid()
        if existing_scope:
            stored = _coverage(tuple(existing_scope[0]))
            if stored != coverage:
                raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
            return stored
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO coordination_coverage("
                "coverage_id, project_id, task_id, membership_generation, coverage, gap_code) "
                "VALUES(?,?,?,?,?,?)",
                (
                    coverage.coverage_id,
                    coverage.project_id,
                    coverage.task_id,
                    coverage.membership_generation,
                    coverage.coverage,
                    coverage.gap_code.value,
                ),
            )
        rows = self._db.execute(
            "SELECT coverage_id, project_id, task_id, membership_generation, coverage, gap_code "
            "FROM coordination_coverage WHERE coverage_id = ? LIMIT 2",
            (coverage.coverage_id,),
        ).fetchall()
        if len(rows) != 1:
            raise _invalid()
        stored = _coverage(tuple(rows[0]))
        if stored != coverage:
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        return stored

    async def coverage_for(
        self, project_id: str, membership_generation: int
    ) -> tuple[CoordinationCoverage, ...]:
        try:
            project = validate_project_id(project_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if type(membership_generation) is not int or membership_generation < 1:
            raise _invalid()
        rows = self._db.execute(
            "SELECT coverage_id, project_id, task_id, membership_generation, coverage, gap_code "
            "FROM coordination_coverage WHERE project_id = ? AND membership_generation = ? "
            "ORDER BY task_id ASC, coverage_id ASC",
            (project, membership_generation),
        ).fetchall()
        return tuple(_coverage(tuple(row)) for row in rows)

    async def obligation(
        self, detection_id: str, task_id: str
    ) -> CoordinationObligationState | None:
        try:
            validate_id(IdKind.EVENT, detection_id)
            validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        row = self._db.execute(
            "SELECT detection_id, task_id, obligation_id, declared, addressed, resolved "
            "FROM coordination_obligations WHERE detection_id = ? AND task_id = ? LIMIT 2",
            (detection_id, task_id),
        ).fetchall()
        if len(row) > 1:
            raise _invalid()
        if not row:
            return None
        value = row[0]
        return CoordinationObligationState(
            cast(str, value[0]),
            cast(str, value[1]),
            _bool(value[3]),
            _bool(value[4]),
            _bool(value[5]),
            None if value[2] is None else obligation_id(value[2]),
        )

    async def set_obligation(
        self, state: CoordinationObligationState
    ) -> CoordinationObligationState:
        if type(state) is not CoordinationObligationState:
            raise _invalid()
        existing = await self.obligation(state.detection_id, state.task_id)
        if existing is not None:
            # Obligations are forward-only facts.  A retry may return the exact row, while a
            # caller attempting to erase an acknowledgement/resolution is a conflict.
            if existing.obligation_id != state.obligation_id:
                raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
            if (
                existing.declared
                and not state.declared
                or existing.addressed
                and not state.addressed
                or existing.resolved
                and not state.resolved
            ):
                raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
            if existing == state:
                return existing
        with self._db:
            self._db.execute(
                "INSERT INTO coordination_obligations("
                "detection_id, task_id, obligation_id, declared, addressed, resolved) "
                "VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(detection_id, task_id) DO UPDATE SET declared=excluded.declared, "
                "addressed=excluded.addressed, resolved=excluded.resolved",
                (
                    state.detection_id,
                    state.task_id,
                    state.obligation_id,
                    int(state.declared),
                    int(state.addressed),
                    int(state.resolved),
                ),
            )
        return state

    async def replace_detection(self, detection: CoordinationDetection) -> CoordinationDetection:
        if type(detection) is not CoordinationDetection:
            raise _invalid()
        existing = await self.get_detection(detection.detection_id)
        if existing is None:
            raise _invalid()
        immutable = (
            "detection_id",
            "project_id",
            "membership_generation",
            "left_task_id",
            "right_task_id",
            "overlap_kind",
            "resource_identities",
            "counterpart_task_id",
        )
        if any(getattr(existing, name) != getattr(detection, name) for name in immutable):
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        # The detector state machine is forward-only.  In particular, an old retry cannot reopen
        # a finding or make a revoked generation appear live after a newer durable transition.
        if (
            (existing.obligation_declared and not detection.obligation_declared)
            or (existing.addressed and not detection.addressed)
            or (existing.resolved and not detection.resolved)
            or (not existing.generation_valid and detection.generation_valid)
            or (not existing.advice_only and detection.advice_only)
        ):
            raise CoordinationError(CoordinationErrorCode.SELECTOR_CONFLICT)
        with self._db:
            self._db.execute(
                "UPDATE coordination_detections SET advice_only=?, obligation_declared=?, "
                "addressed=?, generation_valid=?, resolved=?, detail_ref_json=? WHERE detection_id=?",
                (
                    int(detection.advice_only),
                    int(detection.obligation_declared),
                    int(detection.addressed),
                    int(detection.generation_valid),
                    int(detection.resolved),
                    None if detection.detail_ref is None else _json(detection.detail_ref.as_wire()),
                    detection.detection_id,
                ),
            )
            if self._db.changes() != 1:
                raise _invalid()
        stored = await self.get_detection(detection.detection_id)
        if stored is None:
            raise _invalid()
        return stored
