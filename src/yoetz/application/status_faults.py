"""Typed classification for status read failures that are not the caller's fault.

A status request reaches the application already validated against its frozen schema. Caller
shape problems (a cursor, frontier, selector, or filter this request cannot use) are rejected at
explicit sites as ``INVALID_REQUEST``. A ``TypeError`` or ``ValueError`` raised after that is a
fault in stored state or in the service's own projection, and reporting it as invalid caller input
sends the agent to fix a request that was valid while discarding the only evidence of the real
defect (issue #840).

Each fault is therefore tagged with the stage that raised it and classified once:

- ``replay`` — a recorded ledger, lineage manifest, or stored row failed strict decoding. The data
  must not be retried and is escalated to the operator: ``STORAGE_CORRUPT``.
- ``model`` — a projected row failed its closed public wire model.
- ``digest`` — the snapshot identity could not be canonically digested.
- ``projection`` — any other internal failure while assembling the page.

The last three are the service's own defect: ``INTERNAL_ERROR``. Every classification records one
bounded diagnostic whose correlation id the public error carries, so the id an agent reports
resolves to the reviewed exception-class token and the innermost ``yoetz`` source origin. The
record never contains ``str(exc)``, a validation payload, a path, or any user content.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from yoetz.observability.logging import (
    record_classified_exception_without_raising,
    record_public_error_without_raising,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "StatusFault",
    "StatusFaultStage",
    "classify_status_fault",
    "fault_source",
    "record_status_member_unavailable",
    "status_stage",
]

_COMPONENT: Final = "application.status"


class StatusFaultStage(StrEnum):
    REPLAY = "replay"
    MODEL = "model"
    DIGEST = "digest"
    PROJECTION = "projection"


_CODES: Final = MappingProxyType(
    {
        StatusFaultStage.REPLAY: PublicErrorCode.STORAGE_CORRUPT,
        StatusFaultStage.MODEL: PublicErrorCode.INTERNAL_ERROR,
        StatusFaultStage.DIGEST: PublicErrorCode.INTERNAL_ERROR,
        StatusFaultStage.PROJECTION: PublicErrorCode.INTERNAL_ERROR,
    }
)
_MESSAGES: Final = MappingProxyType(
    {
        StatusFaultStage.REPLAY: "The stored task state could not be read for status.",
        StatusFaultStage.MODEL: "The status projection produced an invalid row.",
        StatusFaultStage.DIGEST: "The status snapshot identity could not be computed.",
        StatusFaultStage.PROJECTION: "The status projection failed.",
    }
)


class StatusFault(Exception):
    """Internal marker for a ``TypeError``/``ValueError`` raised inside one named status stage.

    It deliberately is not a ``ValueError``: an enclosing stage or the outer status boundary must
    not reclassify a fault an inner stage already named. The original exception is its cause.
    ``message`` keeps an existing site's more specific fixed wording; it is never derived from the
    exception.
    """

    def __init__(self, stage: StatusFaultStage, message: str | None = None) -> None:
        super().__init__(stage.value)
        self.stage = stage
        self.public_message = message


@contextmanager
def status_stage(stage: StatusFaultStage, message: str | None = None) -> Generator[None]:
    """Tag a ``TypeError``/``ValueError`` raised in this block with ``stage``.

    Public errors and already-tagged faults pass through untouched.
    """

    try:
        yield
    except (TypeError, ValueError) as exc:
        raise StatusFault(stage, message) from exc


def fault_source(exc: BaseException) -> BaseException:
    """Return the exception a diagnostic should describe: the original under a stage marker.

    The marker is raised at the stage boundary, so its own class and innermost ``yoetz`` frame
    would name the boundary rather than the defect.
    """

    if isinstance(exc, StatusFault) and exc.__cause__ is not None:
        return exc.__cause__
    return exc


def classify_status_fault(
    exc: BaseException,
    *,
    view: str,
    request_id: str | None,
) -> PublicOperationError:
    """Record one joinable diagnostic and return the typed public error for ``exc``.

    ``view`` is the schema-validated status view literal, so the diagnostic operation is a closed
    structural token. An untagged exception is an unclassified internal projection fault.
    """

    stage = StatusFaultStage.PROJECTION
    message: str | None = None
    if isinstance(exc, StatusFault):
        stage = exc.stage
        message = exc.public_message
    correlation_id = record_classified_exception_without_raising(
        fault_source(exc),
        component=_COMPONENT,
        operation=f"status_{view}_{stage.value}_failed",
        request_id=request_id,
        phase=stage.value,
    )
    return PublicOperationError(
        _CODES[stage],
        _MESSAGES[stage] if message is None else message,
        False,
        correlation_id=correlation_id,
        safe_details={"phase": stage.value},
    )


def record_status_member_unavailable(
    exc: BaseException,
    *,
    request_id: str | None,
) -> None:
    """Keep one project member's degraded read diagnosable after it becomes a coverage gap.

    A member that cannot be read is disclosed as ``project_member_unavailable`` instead of failing
    every member's view. A classified public error already recorded its diagnostic when it was
    built; any other public error, or an untagged fault, is recorded here so the gap still joins
    to a bounded record by ``request_id``.
    """

    if isinstance(exc, PublicOperationError):
        if exc.correlation_id is None:
            record_public_error_without_raising(
                component=_COMPONENT,
                operation="status_project_member_unavailable",
                reason=exc.code.value.lower(),
                request_id=request_id,
            )
        return
    classify_status_fault(exc, view="project", request_id=request_id)
