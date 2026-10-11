"""What stands between the latest recorded check and the current ledger (tb4n3 RC-6).

Four surfaces used to repeat the same walk over the records that follow the latest check: the
receipt context (``check_not_applicable`` and ``check_current_as_of_earlier_frontier``), receipt
capacity admission, compact status coverage and closure readiness. Each walk asked
``invalidates_recorded_check`` and then, separately, whether any material record followed. That is
how the standing code came to mean four things. ``check_standing`` is the one walk. It returns the
facts every surface renders, with the record that decided them:

* ``superseded_by`` - the first later record that superseded the check (a cooperative material
  record, an observation-authored finding, or an observed deliverable/workspace edit), or ``None``;
* ``counted`` - the later material records Yoetz cannot prove harmless, which keep the standing
  ``check_current_as_of_earlier_frontier`` disclosure;
* ``ignored`` - how many later records ``later_material_class`` proved harmless, by class, so a
  receipt can say what it did not count.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from yoetz.domain.events import LedgerRecord, is_observation_authored
from yoetz.domain.values import EventId
from yoetz.kernel.later_material import (
    LaterMaterial,
    LaterMaterialClass,
    classify_later_material,
    observed_actions_by_event,
    supersession_exempt,
)
from yoetz.kernel.projections import (
    LatestTestedState,
    ProjectionState,
    observation_limitation_finding_ids,
)
from yoetz.kernel.reducers import invalidates_recorded_check, is_material_event_family

__all__ = [
    "CheckCause",
    "CheckStanding",
    "LaterRecord",
    "check_standing",
]

_NO_COUNTS: Final[Mapping[LaterMaterialClass, int]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class LaterRecord:
    """One record that follows the check, with the closed rule that classified it."""

    event_id: EventId
    ingestion_sequence: int
    family: str
    observation_authored: bool
    material: LaterMaterial


@dataclass(frozen=True, slots=True)
class CheckCause:
    """The record that decided the check's standing, with the check it follows (lineage).

    ``superseded``: the check no longer covers the current state (``check_not_applicable``).
    ``bounds_conclusion``: the check still counts but the earlier-frontier disclosure bounds the
    receipt because of the first counted record.
    """

    effect: Literal["superseded", "bounds_conclusion"]
    record: LaterRecord
    check_event_id: EventId
    check_subject_sequence: int


@dataclass(frozen=True, slots=True)
class CheckStanding:
    """The latest check's standing at one ledger prefix."""

    latest: LatestTestedState | None
    check_record: LedgerRecord | None
    superseded_by: LaterRecord | None
    counted: tuple[LedgerRecord, ...]
    counted_first: LaterRecord | None
    ignored: Mapping[LaterMaterialClass, int]
    # The first counted observation-authored record (the one that bounds), and the first of those
    # that names the tool call it observed. A cooperative response never stands in for either.
    bounding_first: LaterRecord | None = None
    clearing_first: LaterRecord | None = None

    @property
    def superseded(self) -> bool:
        return self.superseded_by is not None

    @property
    def cause(self) -> CheckCause | None:
        """The decisive later record when the check is superseded or the suffix bounds."""

        if self.check_record is None or self.latest is None:
            return None
        if self.superseded_by is not None:
            effect: Literal["superseded", "bounds_conclusion"] = "superseded"
            record = self.superseded_by
        elif self.clearing_first is not None:
            effect = "bounds_conclusion"
            record = self.clearing_first
        else:
            return None
        return CheckCause(
            effect, record, self.check_record.event_id, self.latest.subject_frontier.sequence
        )

    @property
    def bounds_conclusion(self) -> bool:
        """Whether the counted suffix keeps ``check_current_as_of_earlier_frontier`` bounding.

        Only the agent's answers to the check's own findings are advisory (ADR-040 section 7).
        Any counted observation-authored record is work Yoetz could not prove harmless.
        """

        return any(is_observation_authored(record) for record in self.counted)

    @property
    def recheck_clears(self) -> bool:
        """Whether one more check would remove the earlier-frontier disclosure for good.

        True only when a counted observation names the tool call it saw: the next check's own
        observation is an identified Yoetz call, so the disclosure cannot regenerate. Records with
        no tool identity (a post-only host result, a lineage manifest) are made again by every
        check on a host that observes that way: readiness must not ask for a recheck for them.
        """

        return self.clearing_first is not None


def _later(record: LedgerRecord, material: LaterMaterial) -> LaterRecord:
    return LaterRecord(
        record.event_id,
        record.ledger.ingestion_sequence,
        record.schema.name,
        is_observation_authored(record),
        material,
    )


def check_standing(projection: ProjectionState, records: tuple[LedgerRecord, ...]) -> CheckStanding:
    """Walk the records after the latest check once and classify every one of them."""

    latest = projection.latest_tested_state
    if latest is None:
        return CheckStanding(None, None, None, (), None, _NO_COUNTS)
    check_record = next((r for r in records if r.event_id == latest.source_check_event_id), None)
    if check_record is None:
        return CheckStanding(latest, None, None, (), None, _NO_COUNTS)
    sequence = check_record.ledger.ingestion_sequence
    limitations = observation_limitation_finding_ids(projection, records)
    exempt = supersession_exempt(projection)
    actions = observed_actions_by_event(records)
    superseded: LaterRecord | None = None
    counted: list[LedgerRecord] = []
    counted_first: LaterRecord | None = None
    bounding_first: LaterRecord | None = None
    clearing_first: LaterRecord | None = None
    ignored: Counter[LaterMaterialClass] = Counter()
    for record in records:
        if record.ledger.ingestion_sequence <= sequence:
            continue
        if superseded is None and invalidates_recorded_check(
            record,
            sequence,
            latest.returned_finding_ids,
            limitation_finding_ids=limitations,
            projection=projection,
        ):
            superseded = _later(
                record,
                classify_later_material(
                    record, projection, exempt=exempt, actions_by_event=actions
                ),
            )
        if not is_material_event_family(record.schema.name):
            continue
        material = classify_later_material(
            record, projection, exempt=exempt, actions_by_event=actions
        )
        if material.ignored:
            ignored[material.material_class] += 1
            continue
        counted.append(record)
        later = _later(record, material)
        if counted_first is None:
            counted_first = later
        if later.observation_authored:
            if bounding_first is None:
                bounding_first = later
            if clearing_first is None and material.names_a_call:
                clearing_first = later
    return CheckStanding(
        latest,
        check_record,
        superseded,
        tuple(counted),
        counted_first,
        MappingProxyType(dict(sorted(ignored.items(), key=lambda item: item[0].value))),
        bounding_first,
        clearing_first,
    )
