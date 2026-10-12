"""Typed service startup failures: the stage, a reviewed exception-class token and one id (#1040).

A service that could not start used to leave ``internal_error: the command could not be
completed`` and nothing else, and a bridge that spawned it waited out its whole budget before
reporting the service as merely not running. Every startup failure now writes one durable
diagnostic record (component ``service.daemon``, operation ``service_startup_failed``) whose
``phase`` is the startup stage, ``reason`` the reviewed exception-class token, ``origin`` the
innermost ``yoetz`` frame and ``reason_code`` the exception's own closed refusal token when it
carries one. The foreground command prints the same facts and the record's ``correlation_id``; a
process that spawned the service passes the id it will look the record up under, so its own
error names the same failure.

Kept import-light (no service composition): the CLI records an import-stage failure with it
before the daemon module could be loaded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from yoetz.observability.exception_reasons import (
    EXCEPTION_REASON_TOKENS,
    UNKNOWN_EXCEPTION_REASON,
    exception_reason,
)
from yoetz.observability.logging import (
    exception_origin,
    record_classified_exception_without_raising,
    record_unexpected_exception_without_raising,
)
from yoetz.observability.privacy import redact_diagnostic_value
from yoetz.protocol.errors import SERVICE_STARTUP_PHASES

__all__ = [
    "SERVICE_STARTUP_STAGES",
    "STARTUP_FAILURE_COMPONENT",
    "STARTUP_FAILURE_OPERATION",
    "ServiceStartupError",
    "StartupFailure",
    "read_startup_failure",
    "record_startup_failure",
    "spawned_startup_failure",
]

# Closed stage vocabulary, in startup order. ``import`` loads the service modules, ``configuration``
# reads configuration and installs the log sink, ``composition`` checks the instance identity and
# takes the singleton and vault, ``activation`` publishes the endpoints (after ready activation when
# the vault unlocks), and ``serving`` is a failure after the service had started.
SERVICE_STARTUP_STAGES: Final = ("import", "configuration", "composition", "activation", "serving")
if frozenset(SERVICE_STARTUP_STAGES) != SERVICE_STARTUP_PHASES:
    raise RuntimeError("service_startup_stages_disagree_with_protocol_phases")
STARTUP_FAILURE_COMPONENT: Final = "service.daemon"
STARTUP_FAILURE_OPERATION: Final = "service_startup_failed"
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class StartupFailure:
    """One recorded startup failure. Every field is a closed token or a source location."""

    stage: str
    reason: str
    correlation_id: str
    reason_code: str | None = None
    origin: str | None = None

    def describe(self) -> str:
        """Render ``stage: <stage>; <exception token>[; <refusal token>][; at <origin>]``."""

        parts = [f"stage: {self.stage}", self.reason]
        if self.reason_code is not None:
            parts.append(self.reason_code)
        if self.origin is not None:
            parts.append(f"at {self.origin}")
        return "; ".join(parts)

    def line(self) -> str:
        """The foreground ``yoetz service run`` failure line (service.log)."""

        outcome = "stopped unexpectedly" if self.stage == "serving" else "could not start"
        return (
            f"internal_error: the service {outcome} ({self.describe()}); "
            f"correlation_id {self.correlation_id}; "
            f"read it with 'yoetz service diagnostics --correlation-id {self.correlation_id}'"
        )


class ServiceStartupError(Exception):
    """An unexpected startup failure, already recorded under ``failure.correlation_id``."""

    __slots__ = ("failure",)

    failure: StartupFailure

    def __init__(self, failure: StartupFailure) -> None:
        if type(failure) is not StartupFailure:
            raise TypeError("startup_failure_invalid")
        self.failure = failure
        super().__init__(failure.stage)


def _ensure_structural_sink() -> None:
    """Install the default structural stderr sink when configuration never got to install one.

    An import- or configuration-stage failure happens before the service installs its sink; an
    unconfigured logger would print a blank line where the structural record belongs.
    """

    try:
        import logging

        if logging.getLogger().handlers:
            return
        from yoetz.config.models import LoggingConfig
        from yoetz.observability.logging import LogMode, configure_logging

        configure_logging(LoggingConfig(), LogMode.SERVICE)
    except Exception:
        return


def record_startup_failure(
    exc: BaseException,
    *,
    stage: str,
    correlation_id: str | None = None,
    reason_code: str | None = None,
) -> StartupFailure:
    """Record ``exc`` as a startup failure at ``stage`` and return what was recorded.

    ``reason_code`` is the exception's own closed refusal token (a lifecycle, path-safety,
    instance-identity or configuration reason); without one the failure is unexpected and is
    recorded as such. ``correlation_id`` is the id a spawning process will look the record up
    under; a missing or invalid one is replaced by a fresh id. Never raises.
    """

    if stage not in SERVICE_STARTUP_STAGES:
        stage = "activation"
    code = reason_code if type(reason_code) is str and _TOKEN.fullmatch(reason_code) else None
    _ensure_structural_sink()
    if code is None:
        recorded = record_unexpected_exception_without_raising(
            exc,
            component=STARTUP_FAILURE_COMPONENT,
            operation=STARTUP_FAILURE_OPERATION,
            phase=stage,
            correlation_id=correlation_id,
        )
    else:
        recorded = record_classified_exception_without_raising(
            exc,
            component=STARTUP_FAILURE_COMPONENT,
            operation=STARTUP_FAILURE_OPERATION,
            phase=stage,
            reason_code=code,
            correlation_id=correlation_id,
        )
    return StartupFailure(
        stage=stage,
        reason=exception_reason(exc),
        correlation_id=recorded,
        reason_code=code,
        origin=_gated_origin(exception_origin(exc)),
    )


def _gated_origin(origin: object) -> str | None:
    """Keep a value only when it is the one-``yoetz``-source-location shape the sinks admit."""

    if type(origin) is not str:
        return None
    return origin if redact_diagnostic_value("origin", origin) == origin else None


def read_startup_failure(correlation_id: str) -> StartupFailure | None:
    """Return the startup failure recorded under ``correlation_id``, or None.

    Every field is re-gated against its closed vocabulary or pattern: the ring is owner-only, but
    what is read back is still never rendered unless it is one of the tokens the writer can write.
    """

    try:
        from yoetz.observability.diagnostics import lookup_diagnostic_records

        records = lookup_diagnostic_records(correlation_id)
    except Exception:
        return None
    for record in reversed(records):
        if (
            record.get("component") != STARTUP_FAILURE_COMPONENT
            or record.get("operation") != STARTUP_FAILURE_OPERATION
        ):
            continue
        stage = record.get("phase")
        reason = record.get("reason")
        if stage not in SERVICE_STARTUP_STAGES or reason not in EXCEPTION_REASON_TOKENS:
            continue
        code = record.get("reason_code")
        origin = record.get("origin")
        return StartupFailure(
            stage=str(stage),
            reason=str(reason),
            correlation_id=correlation_id,
            reason_code=code if type(code) is str and _TOKEN.fullmatch(code) else None,
            origin=_gated_origin(origin),
        )
    return None


def spawned_startup_failure(phase: object, correlation_id: object) -> StartupFailure | None:
    """The startup failure a ``service_unavailable`` control error names, or None.

    On-demand start raises that error with ``phase`` set to the spawned service's stage and its
    record's ``correlation_id`` (``yoetz.service.client``); every other ``service_unavailable``
    carries no startup stage. A record that can no longer be read still yields the stage.
    """

    if phase not in SERVICE_STARTUP_STAGES or type(correlation_id) is not str:
        return None
    recorded = read_startup_failure(correlation_id)
    if recorded is not None:
        return recorded
    return StartupFailure(
        stage=str(phase), reason=UNKNOWN_EXCEPTION_REASON, correlation_id=correlation_id
    )
