"""Bounded historical loss identity, independent of any later host envelope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from finishup.domain.observation import ObservationSource, observation_selection_route
from finishup.domain.values import JsonObject, validate_commitment, validate_sha256_digest
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import ProtocolValueError


@dataclass(frozen=True)
class ObservationSelectionLoss:
    lane: str
    source: ObservationSource
    session_commitment: str
    source_generation: int
    task_id: str
    session_id: str
    writer_id: str
    authority_generation: str
    unreconciled: bool = False
    # Closed admission refusal causes recorded for this lane (tb4n1 B3, #998). Not part of the
    # lane identity or the marker's operation identity; disclosure only.
    causes: tuple[str, ...] = ()

    @classmethod
    def from_local_range(cls, value: JsonObject) -> ObservationSelectionLoss:
        lane = value.get("lane")
        source = value.get("source")
        session = value.get("session")
        generation = value.get("source_generation")
        route = observation_selection_route(value.get("route"))
        if (
            type(lane) is not str
            or type(source) is not str
            or type(session) is not str
            or type(generation) is not int
            or generation <= 0
            or route is None
        ):
            raise ValueError("selection_loss_invalid")
        validate_sha256_digest(lane)
        validate_commitment(session)
        if lane != canonical_digest(
            JsonObject(
                {
                    "source": source,
                    "session": session,
                    "generation": generation,
                    "route": value["route"],
                }
            )
        ):
            raise ValueError("selection_loss_invalid")
        return cls(
            lane,
            ObservationSource(source),
            session,
            generation,
            *route,
            causes=_loss_causes(value.get("loss_causes")),
        )

    @classmethod
    def from_local_range_for_recovery(cls, value: JsonObject) -> ObservationSelectionLoss:
        """Recover a route-valid lane when only its historical digest is malformed.

        The route, source, session commitment, and generation remain authenticated
        structural fields. If the stored lane digest does not validate or no longer
        matches them, derive a new service-marker identity from those validated
        fields and mark the report unreconciled. A malformed route or source is
        rejected instead of being assigned to a task.
        """

        route = observation_selection_route(value.get("route"))
        source = value.get("source")
        session = value.get("session")
        generation = value.get("source_generation")
        if (
            route is None
            or type(source) is not str
            or type(session) is not str
            or type(generation) is not int
            or isinstance(generation, bool)
            or generation <= 0
        ):
            raise ValueError("selection_loss_invalid")
        try:
            source_value = ObservationSource(source)
            validate_commitment(session)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ValueError("selection_loss_invalid") from exc
        route_value = JsonObject(
            {
                "selection_task_id": route[0],
                "selection_session_id": route[1],
                "selection_writer_id": route[2],
                "selection_authority_generation": route[3],
            }
        )
        expected_lane = canonical_digest(
            JsonObject(
                {
                    "source": source,
                    "session": session,
                    "generation": generation,
                    "route": route_value,
                }
            )
        )
        lane = value.get("lane")
        lane_valid = False
        if type(lane) is str:
            try:
                validate_sha256_digest(lane)
            except ProtocolValueError, TypeError, ValueError:
                pass
            else:
                lane_valid = lane == expected_lane
        causes = _loss_causes(value.get("loss_causes"))
        if lane_valid:
            return cls(cast(str, lane), source_value, session, generation, *route, causes=causes)
        recovery_lane = canonical_digest(
            JsonObject(
                {
                    "format": "yoetz.selection-loss-unreconciled/1",
                    "source": source,
                    "session": session,
                    "generation": generation,
                    "route": route_value,
                }
            )
        )
        return cls(recovery_lane, source_value, session, generation, *route, True, causes=causes)

    def identity(self) -> JsonObject:
        identity: dict[str, str | int] = {
            "lane": self.lane,
            "source": self.source.value,
            "session_commitment": self.session_commitment,
            "source_generation": self.source_generation,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "writer_id": self.writer_id,
            "authority_generation": self.authority_generation,
        }
        if self.unreconciled:
            identity["reconciliation"] = "unreconciled"
        return JsonObject(identity)


def _loss_causes(value: object) -> tuple[str, ...]:
    """Closed admission refusal causes from a local loss report; anything else is dropped."""

    from finishup.domain.observation_budget import AdmissionLossCause

    if not isinstance(value, (list, tuple)):
        return ()
    items: tuple[object, ...] = tuple(cast(list[object] | tuple[object, ...], value))
    allowed = {item.value for item in AdmissionLossCause}
    return tuple(sorted({item for item in items if type(item) is str} & allowed))
