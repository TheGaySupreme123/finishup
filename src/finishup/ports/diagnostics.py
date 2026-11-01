"""Bounded startup diagnostics and the pure capability write gate."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Literal, Protocol, cast

from finishup.domain.values import (
    JsonScalar,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    task_id,
    validate_sha256_digest,
)
from finishup.protocol.canonical import JsonValue as CanonicalJsonValue
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "DiagnosticsPort",
    "MaintenanceDiagnostic",
    "MaintenanceDiagnosticSink",
    "RuntimeCapability",
    "StartupCheckArea",
    "StartupCheckOutcome",
    "StartupCheckResult",
    "StartupGateReport",
    "evaluate_startup_gate",
]


class StartupCheckArea(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    RUNTIME = "runtime"
    PACKAGE = "package"
    RESOURCES = "resources"
    PATH = "path"
    SERVICE_CONTROL = "service_control"
    SERVICE_LIFECYCLE = "service_lifecycle"
    SQLITE_BUILD = "sqlite_build"
    SQLITE_SCHEMA = "sqlite_schema"
    OWNERSHIP = "ownership"
    LEDGER = "ledger"
    OBJECTS = "objects"
    KEYS = "keys"
    VAULT = "vault"
    SECRET_MEMORY = "secret_memory"
    PROJECTION = "projection"
    PRIVACY_POLICY = "privacy_policy"
    EGRESS_GATEWAY = "egress_gateway"
    PROVIDER = "provider"


class StartupCheckOutcome(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    OK = "ok"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class RuntimeCapability(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    STRUCTURAL_READ = "structural_read"
    PAYLOAD_READ = "payload_read"
    WRITE = "write"
    SEMANTIC = "semantic"


_CHECK_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31})?$",
    re.ASCII,
)
_SAFE_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_DETAIL_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_DETAIL_STRING_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$", re.ASCII)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_SAFE_DETAILS = 16
_MAINTENANCE_OPERATIONS = frozenset({"backup", "migration", "restore"})
_MAINTENANCE_PHASES = frozenset({"execute", "preview"})
_MAINTENANCE_OUTCOMES = frozenset({"cancelled", "failed", "success"})

type MaintenanceOperation = Literal["backup", "migration", "restore"]
type MaintenancePhase = Literal["execute", "preview"]
type MaintenanceOutcome = Literal["cancelled", "failed", "success"]


def _invalid(reason: str) -> ValueError:
    return ValueError(reason)


def _is_actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _freeze_safe_details(value: object) -> Mapping[str, JsonScalar]:
    if not _is_actual_mapping(value):
        raise _invalid("startup_safe_details_invalid")
    source = cast(Mapping[object, object], value)
    try:
        raw_items = tuple(source.items())
    except Exception as exc:
        raise _invalid("startup_safe_details_invalid") from exc
    if len(raw_items) > _MAX_SAFE_DETAILS:
        raise _invalid("startup_safe_details_invalid")

    normalized: list[tuple[str, JsonScalar]] = []
    seen: set[str] = set()
    for raw_key, raw_value in raw_items:
        if (
            type(raw_key) is not str
            or _DETAIL_KEY_PATTERN.fullmatch(raw_key) is None
            or raw_key in seen
        ):
            raise _invalid("startup_safe_details_invalid")
        seen.add(raw_key)
        if type(raw_value) is bool:
            safe_value: JsonScalar = raw_value
        elif type(raw_value) is int:
            if not 0 <= raw_value <= _MAX_SAFE_INTEGER:
                raise _invalid("startup_safe_details_invalid")
            safe_value = raw_value
        elif type(raw_value) is str:
            if _DETAIL_STRING_PATTERN.fullmatch(raw_value) is None:
                raise _invalid("startup_safe_details_invalid")
            safe_value = raw_value
        else:
            raise _invalid("startup_safe_details_invalid")
        normalized.append((raw_key, safe_value))
    normalized.sort(key=lambda item: item[0].encode("ascii"))
    return MappingProxyType(dict(normalized))


def _validate_capabilities(value: object) -> frozenset[RuntimeCapability]:
    if type(value) is not frozenset:
        raise _invalid("startup_capabilities_invalid")
    items = cast(frozenset[object], value)
    if any(type(item) is not RuntimeCapability for item in items):
        raise _invalid("startup_capabilities_invalid")
    return cast(frozenset[RuntimeCapability], value)


def _validate_reason_codes(value: object, *, field: str) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _invalid(field)
    result = cast(tuple[object, ...], value)
    if any(type(item) is not str or _SAFE_TOKEN_PATTERN.fullmatch(item) is None for item in result):
        raise _invalid(field)
    strings = cast(tuple[str, ...], result)
    if strings != tuple(sorted(set(strings), key=str.encode)):
        raise _invalid(field)
    return strings


@dataclass(frozen=True, slots=True)
class StartupCheckResult:
    check_id: str
    area: StartupCheckArea
    outcome: StartupCheckOutcome
    reason_code: str | None
    capabilities: frozenset[RuntimeCapability]
    safe_details: Mapping[str, JsonScalar]
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or _CHECK_ID_PATTERN.fullmatch(self.check_id) is None:
            raise _invalid("startup_check_id_invalid")
        if type(self.area) is not StartupCheckArea:
            raise _invalid("startup_check_area_invalid")
        if type(self.outcome) is not StartupCheckOutcome:
            raise _invalid("startup_check_outcome_invalid")
        if self.outcome is StartupCheckOutcome.OK:
            if self.reason_code is not None:
                raise _invalid("startup_reason_code_invalid")
        elif (
            type(self.reason_code) is not str
            or _SAFE_TOKEN_PATTERN.fullmatch(self.reason_code) is None
        ):
            raise _invalid("startup_reason_code_invalid")

        object.__setattr__(self, "capabilities", _validate_capabilities(self.capabilities))
        object.__setattr__(self, "safe_details", _freeze_safe_details(self.safe_details))
        normalized_time = parse_rfc3339_millis(format_rfc3339_millis(self.observed_at))
        object.__setattr__(self, "observed_at", normalized_time)


@dataclass(frozen=True, slots=True)
class StartupGateReport:
    results_digest: str
    capabilities: frozenset[RuntimeCapability]
    blocked_reasons: tuple[str, ...]
    degraded_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_sha256_digest(self.results_digest)
        object.__setattr__(self, "capabilities", _validate_capabilities(self.capabilities))
        object.__setattr__(
            self,
            "blocked_reasons",
            _validate_reason_codes(self.blocked_reasons, field="startup_blocked_reasons_invalid"),
        )
        object.__setattr__(
            self,
            "degraded_reasons",
            _validate_reason_codes(self.degraded_reasons, field="startup_degraded_reasons_invalid"),
        )


class DiagnosticsPort(Protocol):
    """Consume an already validated structural startup result."""

    def record(self, result: StartupCheckResult) -> None: ...


@dataclass(frozen=True, slots=True)
class MaintenanceDiagnostic:
    """Bounded path-free observation for one maintenance preview or execution."""

    operation: MaintenanceOperation
    phase: MaintenancePhase
    outcome: MaintenanceOutcome
    request_id: str
    task_id: str | None
    plan_digest: str | None
    result_digest: str | None
    from_version: str | None
    to_version: str | None
    count: int | None
    duration_ms: int
    reason_code: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.operation) is not str
            or self.operation not in _MAINTENANCE_OPERATIONS
            or type(self.phase) is not str
            or self.phase not in _MAINTENANCE_PHASES
            or type(self.outcome) is not str
            or self.outcome not in _MAINTENANCE_OUTCOMES
        ):
            raise _invalid("maintenance_diagnostic_invalid")
        try:
            validate_id(IdKind.REQUEST, self.request_id)
            if self.task_id is not None:
                task_id(self.task_id)
            for digest in (self.plan_digest, self.result_digest):
                if digest is not None:
                    validate_sha256_digest(digest)
        except ValueError as exc:
            raise _invalid("maintenance_diagnostic_invalid") from exc
        for version in (self.from_version, self.to_version):
            if version is not None and (
                type(version) is not str or _DETAIL_STRING_PATTERN.fullmatch(version) is None
            ):
                raise _invalid("maintenance_diagnostic_invalid")
        for value in (self.count, self.duration_ms):
            if value is not None and (
                type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER
            ):
                raise _invalid("maintenance_diagnostic_invalid")
        if self.reason_code is not None and (
            type(self.reason_code) is not str
            or _SAFE_TOKEN_PATTERN.fullmatch(self.reason_code) is None
        ):
            raise _invalid("maintenance_diagnostic_invalid")
        if self.outcome == "success" and self.reason_code is not None:
            raise _invalid("maintenance_diagnostic_invalid")
        if self.outcome != "success" and self.reason_code is None:
            raise _invalid("maintenance_diagnostic_invalid")
        normalized_time = parse_rfc3339_millis(format_rfc3339_millis(self.observed_at))
        object.__setattr__(self, "observed_at", normalized_time)


class MaintenanceDiagnosticSink(Protocol):
    """Consume only already-redacted maintenance observations."""

    def record_maintenance(self, diagnostic: MaintenanceDiagnostic) -> None: ...


def _result_json(result: StartupCheckResult) -> Mapping[str, CanonicalJsonValue]:
    return {
        "area": result.area.value,
        "capabilities": [
            capability.value
            for capability in sorted(result.capabilities, key=lambda item: item.value)
        ],
        "check_id": result.check_id,
        "observed_at": format_rfc3339_millis(result.observed_at),
        "outcome": result.outcome.value,
        "reason_code": result.reason_code,
        "safe_details": dict(result.safe_details),
    }


def evaluate_startup_gate(results: Iterable[StartupCheckResult]) -> StartupGateReport:
    """Evaluate the complete positive-proof startup capability gate once."""

    try:
        supplied = tuple(results)
    except Exception as exc:
        raise _invalid("startup_results_invalid") from exc
    if any(type(result) is not StartupCheckResult for result in supplied):
        raise _invalid("startup_results_invalid")

    by_id: dict[str, StartupCheckResult] = {}
    conflicts: set[str] = set()
    removed: set[RuntimeCapability] = set()
    blocked: set[str] = set()
    degraded: set[str] = set()

    for result in supplied:
        previous = by_id.get(result.check_id)
        if previous is None:
            by_id[result.check_id] = result
        elif previous != result:
            conflicts.add(result.check_id)
            removed.update(previous.capabilities)
            removed.update(result.capabilities)

        if result.outcome is StartupCheckOutcome.BLOCKED:
            blocked.add(cast(str, result.reason_code))
            removed.update(result.capabilities)
        elif result.outcome is StartupCheckOutcome.DEGRADED:
            degraded.add(cast(str, result.reason_code))
            removed.update(result.capabilities)

    if conflicts:
        blocked.add("startup_check_conflict")

    present_areas = {result.area for result in by_id.values()}
    missing_areas = set(StartupCheckArea).difference(present_areas)
    if missing_areas:
        blocked.add("startup_check_missing")

    proven: set[RuntimeCapability] = set()
    for result in by_id.values():
        if result.outcome is StartupCheckOutcome.OK and result.check_id not in conflicts:
            proven.update(result.capabilities)

    if blocked:
        # A missing or contradictory mandatory proof cannot authorize any capability. Individual
        # blocked results otherwise remove exactly the capabilities named by their producer.
        if missing_areas or conflicts:
            removed.update(RuntimeCapability)

    capabilities = frozenset(proven.difference(removed))
    blocked_reasons = tuple(sorted(blocked, key=str.encode))
    degraded_reasons = tuple(sorted(degraded, key=str.encode))
    canonical_results: list[CanonicalJsonValue] = [
        _result_json(by_id[key]) for key in sorted(by_id, key=str.encode)
    ]
    digest_input: Mapping[str, CanonicalJsonValue] = {
        "blocked_reasons": list(blocked_reasons),
        "degraded_reasons": list(degraded_reasons),
        "results": canonical_results,
    }
    results_digest = canonical_digest(digest_input)
    return StartupGateReport(
        results_digest=results_digest,
        capabilities=capabilities,
        blocked_reasons=blocked_reasons,
        degraded_reasons=degraded_reasons,
    )
