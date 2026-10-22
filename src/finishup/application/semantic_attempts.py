"""Durable AI-powered review operation attempt budget, retry matrix, and accounting.

ADR-006: one durable AI-powered review operation, at most two retries (``max_retries``), one total
deadline (``timeout_seconds``), and one physical attempt identity per dispatch. The ledger's
``semantic_jobs`` / ``semantic_attempts`` tables are the recovery authority — never a
memory-only coordinator object.

Two retry classes share that budget. Transient classes (timeout, transport, rate limit) may use
every remaining slot. The repair class — a response that reached the provider and came back
``invalid / response_content_invalid`` (incomplete or overlong output) — may use exactly one slot
per job (issue #348), resubmitting the same frozen case as a fresh physical attempt. Every other
invalid, refusal, policy, human, stale, quota, and secret class is terminal on first sight.

A declared fallback endpoint (issue #582) adds a second, separately budgeted endpoint behind the
primary. The primary is given up only for the closed fallback-licensing classes — it could not
serve at all (timeout, transport, rate limit, quota) — after ``FALLBACK_PRIMARY_FAILURE_LIMIT``
such failures, one quota exhaustion, or its own exhausted budget. Every content-shaped outcome
stays with the primary exactly as before. Which endpoint an attempt used is a pure function of
the durable rows before it, so crash and ``awaiting_human`` replay resume the same endpoint.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol

from finishup.domain.findings import RuntimeTokenUsage, SemanticFailureClass
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.ledger import (
    AttemptOutcome,
    OperationLease,
    SemanticAttemptHandle,
    SemanticAttemptRecord,
    SemanticJobRecord,
)
from finishup.ports.objects import ObjectRef
from finishup.ports.semantic import Deadline
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import VALID_SEMANTIC_REASONS, SemanticReason, SemanticStatus

__all__ = [
    "FALLBACK_PRIMARY_FAILURE_LIMIT",
    "EndpointRole",
    "SemanticAttemptAccounting",
    "SemanticAttemptDispatch",
    "SemanticAttemptUsage",
    "SemanticEndpointAttempts",
    "SemanticEndpointPlan",
    "SemanticFallbackPlan",
    "attempt_accounting_from_rows",
    "attempt_accounting_to_json",
    "backoff_seconds",
    "endpoint_role_for_ordinal",
    "final_status_after_exhaustion",
    "is_fallback_licensing_outcome",
    "one_conversation_plan",
    "is_repairable_semantic_outcome",
    "is_retriable_semantic_outcome",
    "max_physical_attempts",
    "physical_attempt_budget",
    "repair_retries_from_rows",
    "run_durable_semantic_attempts",
    "should_retry_after",
    "status_for_semantic_reason",
]

# ADR-006 approved transient classes only. Contract-invalid is not a transient class.
_RETRIABLE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.PROVIDER_TIMEOUT,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        SemanticReason.PROVIDER_RATE_LIMITED,
    }
)

# Issue #348 repair class: the provider was reached and answered, but the answer was incomplete
# or overlong (``failure_class=response_content``). One bounded resubmission of the same frozen
# case may recover a usable judgment. ``response_schema_invalid`` (non-JSON / wrong shape) and
# ``semantic_judgment_rejected`` (post-validation) are deliberately absent: they are not fixed by
# asking again.
_REPAIRABLE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {SemanticReason.RESPONSE_CONTENT_INVALID}
)

# At most one repair retry per durable AI-powered review job, whatever ``max_retries`` allows.
_REPAIR_RETRY_LIMIT: Final = 1

_RETRIABLE_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {
        SemanticStatus.TIMEOUT,
        SemanticStatus.UNAVAILABLE,
    }
)

# Terminal job states that must not re-enter claim_semantic_job (recovery authority).
_TERMINAL_JOB_STATES: Final[frozenset[str]] = frozenset({"succeeded", "failed", "quarantined"})

# ADR-006: at most two retries → at most three physical attempts.
_ADR_MAX_RETRIES: Final = 2

# Reverse map: each closed SemanticReason belongs to exactly one SemanticStatus.
_STATUS_BY_REASON: Final[dict[SemanticReason, SemanticStatus]] = {
    reason: status for status, reasons in VALID_SEMANTIC_REASONS.items() for reason in reasons
}

# Issue #582: the primary is abandoned for its fallback after this many fallback-licensing
# failures. Two, not one: a single transient fault is what the ordinary retry budget already
# absorbs, and switching destinations on the first blip would send the same case to a second
# provider for nothing. Not owner-configurable — a knob here is a hidden retry budget.
FALLBACK_PRIMARY_FAILURE_LIMIT: Final = 2

# The closed set of primary outcomes that license a fallback dispatch: the primary could not
# serve. Everything the provider actually answered (content-invalid, schema-invalid, refused,
# rejected judgment), every policy or human outcome, and ``outcome_unknown`` — where the primary
# may in fact have served — stay with the primary. Quota exhaustion is here although the retry
# matrix refuses to re-ask the same endpoint: the fallback is a different endpoint.
_FALLBACK_LICENSING_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.PROVIDER_TIMEOUT,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        SemanticReason.PROVIDER_RATE_LIMITED,
        SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
    }
)

EndpointRole = Literal["primary", "fallback"]


@dataclass(frozen=True, slots=True)
class SemanticEndpointPlan:
    """Structural identity and retry budget of one bound endpoint (no URL, no credential)."""

    role: EndpointRole
    provider_id: str
    model_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    max_retries: int

    def __post_init__(self) -> None:
        if self.role not in {"primary", "fallback"}:
            raise ValueError("semantic_endpoint_plan_invalid")
        for value in (
            self.provider_id,
            self.model_id,
            self.endpoint_profile_id,
            self.endpoint_profile_version,
        ):
            if type(value) is not str or not value:
                raise ValueError("semantic_endpoint_plan_invalid")
        physical_attempt_budget(self.max_retries)

    @property
    def budget(self) -> int:
        return physical_attempt_budget(self.max_retries)


@dataclass(frozen=True, slots=True)
class SemanticFallbackPlan:
    """One primary endpoint and the one fallback licensed to serve when it cannot.

    ``primary_predispatch_reason`` is set when the primary could not even be resolved before any
    attempt (its credential or registry entry is absent); every attempt then goes to the
    fallback and the accounting names that closed reason against zero primary attempts.
    """

    primary: SemanticEndpointPlan
    fallback: SemanticEndpointPlan
    primary_predispatch_reason: SemanticReason | None = None
    # #1118: a reviewer conversation may have disclosed on any exchange, so a failure of the
    # dispatched primary never engages the fallback; only ``primary_predispatch_reason`` does.
    predispatch_only: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.primary) is not SemanticEndpointPlan
            or type(self.fallback) is not SemanticEndpointPlan
            or self.primary.role != "primary"
            or self.fallback.role != "fallback"
        ):
            raise ValueError("semantic_fallback_plan_invalid")
        if self.primary_predispatch_reason is not None and (
            type(self.primary_predispatch_reason) is not SemanticReason
        ):
            raise ValueError("semantic_fallback_plan_invalid")
        if type(self.predispatch_only) is not bool:
            raise ValueError("semantic_fallback_plan_invalid")

    def endpoint(self, role: EndpointRole) -> SemanticEndpointPlan:
        return self.primary if role == "primary" else self.fallback


@dataclass(frozen=True, slots=True)
class SemanticEndpointAttempts:
    """Per-endpoint slice of the accounting: what one destination was asked and answered."""

    role: EndpointRole
    provider_id: str
    model_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    attempted_count: int
    terminal_reason_counts: tuple[tuple[str, int], ...]
    last_terminal_reason: str | None
    predispatch_reason: str | None

    def __post_init__(self) -> None:
        if self.role not in {"primary", "fallback"}:
            raise ValueError("semantic_attempt_accounting_invalid")
        if type(self.attempted_count) is not int or self.attempted_count < 0:
            raise ValueError("semantic_attempt_accounting_invalid")
        for token, count in self.terminal_reason_counts:
            if type(token) is not str or type(count) is not int or count < 1:
                raise ValueError("semantic_attempt_accounting_invalid")
        if self.predispatch_reason is not None and self.attempted_count != 0:
            raise ValueError("semantic_attempt_accounting_invalid")


@dataclass(frozen=True, slots=True)
class SemanticAttemptAccounting:
    """Bounded structural attempt accounting reconstructible from durable rows."""

    attempted_count: int
    selected_attempt_id: str | None
    exhausted: bool
    terminal_reason_counts: tuple[tuple[str, int], ...]
    # Empty for a single-endpoint job; primary then fallback for a declared pairing (#582).
    endpoint_attempts: tuple[SemanticEndpointAttempts, ...] = ()
    # One bounded numeric usage sample for every physical attempt, including failed/retried rows.
    attempt_usages: tuple[SemanticAttemptUsage, ...] = ()

    def __post_init__(self) -> None:
        if type(self.attempted_count) is not int or self.attempted_count < 0:
            raise ValueError("semantic_attempt_accounting_invalid")
        if self.selected_attempt_id is not None and (
            type(self.selected_attempt_id) is not str
            or not self.selected_attempt_id.startswith("att_")
        ):
            raise ValueError("semantic_attempt_accounting_invalid")
        if type(self.exhausted) is not bool:
            raise ValueError("semantic_attempt_accounting_invalid")
        if type(self.terminal_reason_counts) is not tuple:
            raise ValueError("semantic_attempt_accounting_invalid")
        for token, count in self.terminal_reason_counts:
            if type(token) is not str or type(count) is not int or count < 1:
                raise ValueError("semantic_attempt_accounting_invalid")
        if type(self.endpoint_attempts) is not tuple or any(
            type(item) is not SemanticEndpointAttempts for item in self.endpoint_attempts
        ):
            raise ValueError("semantic_attempt_accounting_invalid")
        if type(self.attempt_usages) is not tuple or any(
            type(item) is not SemanticAttemptUsage for item in self.attempt_usages
        ):
            raise ValueError("semantic_attempt_accounting_invalid")

    def endpoint(self, role: EndpointRole) -> SemanticEndpointAttempts | None:
        return next((item for item in self.endpoint_attempts if item.role == role), None)


@dataclass(frozen=True, slots=True)
class SemanticAttemptUsage:
    """Bounded per-attempt usage recovered from the AI-powered review attempt ledger row."""

    attempt_id: str
    attempt_ordinal: int
    token_usage: RuntimeTokenUsage | None

    def __post_init__(self) -> None:
        if type(self.attempt_id) is not str or not self.attempt_id.startswith("att_"):
            raise ValueError("semantic_attempt_usage_invalid")
        if type(self.attempt_ordinal) is not int or self.attempt_ordinal < 1:
            raise ValueError("semantic_attempt_usage_invalid")
        if self.token_usage is not None and type(self.token_usage) is not RuntimeTokenUsage:
            raise ValueError("semantic_attempt_usage_invalid")


@dataclass(frozen=True, slots=True)
class _EndpointWalk:
    """Where the endpoint state machine stands after a sequence of completed attempts."""

    engaged: bool
    primary_attempts: int
    fallback_attempts: int
    licensing_failures: int

    @property
    def role(self) -> EndpointRole:
        return "fallback" if self.engaged else "primary"


def one_conversation_plan(plan: SemanticFallbackPlan) -> SemanticFallbackPlan:
    """``plan`` for one reviewer conversation (#1118): one attempt per endpoint, and the fallback
    engaged only for a primary that was never dispatched."""

    return replace(
        plan,
        primary=replace(plan.primary, max_retries=0),
        fallback=replace(plan.fallback, max_retries=0),
        predispatch_only=True,
    )


def is_fallback_licensing_outcome(status: SemanticStatus, reason: SemanticReason) -> bool:
    """Whether a terminal primary outcome licenses dispatching the fallback endpoint (#582)."""

    return status in _RETRIABLE_STATUSES and reason in _FALLBACK_LICENSING_REASONS


def _walk_endpoints(
    codes: tuple[SemanticReason | None, ...], plan: SemanticFallbackPlan
) -> _EndpointWalk:
    """Replay the closed engagement rule over completed attempt codes, in ordinal order.

    ``None`` is an attempt that has no terminal code yet (a ``started`` row on replay); it holds
    a slot on its endpoint without deciding anything. Once engaged, every later attempt belongs
    to the fallback: the rule never returns to the primary inside one job.
    """

    engaged = plan.primary_predispatch_reason is not None
    primary_attempts = 0
    fallback_attempts = 0
    licensing_failures = 0
    primary_budget = plan.primary.budget
    for code in codes:
        if engaged:
            fallback_attempts += 1
            continue
        primary_attempts += 1
        if code is None or code not in _FALLBACK_LICENSING_REASONS or plan.predispatch_only:
            continue
        licensing_failures += 1
        if (
            code is SemanticReason.PROVIDER_QUOTA_EXHAUSTED
            or licensing_failures >= FALLBACK_PRIMARY_FAILURE_LIMIT
            or primary_attempts >= primary_budget
        ):
            engaged = True
    return _EndpointWalk(engaged, primary_attempts, fallback_attempts, licensing_failures)


def _ordered_codes(
    attempts: tuple[SemanticAttemptRecord, ...], *, before_ordinal: int | None = None
) -> tuple[SemanticReason | None, ...]:
    ordered = sorted(attempts, key=lambda attempt: attempt.attempt_ordinal)
    return tuple(
        attempt.terminal_code
        for attempt in ordered
        if before_ordinal is None or attempt.attempt_ordinal < before_ordinal
    )


def endpoint_role_for_ordinal(
    attempts: tuple[SemanticAttemptRecord, ...],
    plan: SemanticFallbackPlan | None,
    ordinal: int,
) -> EndpointRole:
    """Which endpoint the attempt at ``ordinal`` uses, from the durable rows before it only.

    Reading it from rows rather than coordinator memory is what makes a resumed ``started``
    attempt go to the same endpoint it was claimed for, on every replay.
    """

    if plan is None:
        return "primary"
    if type(ordinal) is not int or ordinal < 1:
        raise ValueError("attempt_ordinal_invalid")
    return _walk_endpoints(_ordered_codes(attempts, before_ordinal=ordinal), plan).role


def _total_budget(walk: _EndpointWalk, plan: SemanticFallbackPlan) -> int:
    """Physical attempts the whole job may spend, given how far the walk has come."""

    if walk.engaged:
        return walk.primary_attempts + plan.fallback.budget
    return plan.primary.budget


def physical_attempt_budget(max_retries: int) -> int:
    """Return the maximum physical attempts for a configured retry count (capped by ADR-006)."""

    if type(max_retries) is not int or max_retries < 0:
        raise ValueError("max_retries_invalid")
    capped = min(max_retries, _ADR_MAX_RETRIES)
    return 1 + capped


def max_physical_attempts(max_retries: int) -> int:
    """Alias used by tests and composition; same as :func:`physical_attempt_budget`."""

    return physical_attempt_budget(max_retries)


_NON_RETRIABLE_FAILURE_CLASSES: Final[frozenset[SemanticFailureClass]] = frozenset(
    {
        SemanticFailureClass.AUTHENTICATION,
        SemanticFailureClass.AUTHORIZATION,
    }
)


def is_retriable_semantic_outcome(
    status: SemanticStatus,
    reason: SemanticReason,
    *,
    failure_class: SemanticFailureClass | None = None,
) -> bool:
    """Whether a terminal attempt outcome may consume another physical attempt slot."""

    if failure_class in _NON_RETRIABLE_FAILURE_CLASSES:
        return False
    if status not in _RETRIABLE_STATUSES or reason not in _RETRIABLE_REASONS:
        return False
    # Quota exhaustion is not a transient 429-class retry; refuse silent multi-dispatch.
    if reason is SemanticReason.PROVIDER_QUOTA_EXHAUSTED:
        return False
    return True


def is_repairable_semantic_outcome(status: SemanticStatus, reason: SemanticReason) -> bool:
    """Whether a terminal attempt outcome is the issue #348 repair class (one retry, ever)."""

    return status is SemanticStatus.INVALID and reason in _REPAIRABLE_REASONS


def repair_retries_from_rows(attempts: tuple[SemanticAttemptRecord, ...]) -> int:
    """Count repair retries already spent on a job from its durable attempt rows.

    A repaired attempt is closed as ``expired`` with the repair-class terminal code, so the count
    is simply the rows carrying such a code. Reading it from rows rather than coordinator memory
    is what keeps the one-repair cap true across a crash or an ``awaiting_human`` replay, where
    the loop restarts with fresh locals but the ledger still remembers the first attempt.
    """

    return sum(1 for attempt in attempts if attempt.terminal_code in _REPAIRABLE_REASONS)


def should_retry_after(
    *,
    status: SemanticStatus,
    reason: SemanticReason,
    attempts_completed: int,
    max_retries: int,
    deadline_expired: bool,
    repair_retries_used: int = 0,
    failure_class: SemanticFailureClass | None = None,
) -> bool:
    """Decide whether another physical attempt is admitted inside the total deadline.

    ``repair_retries_used`` is the number of repair retries the job has already spent (from
    durable rows). A repair-class outcome is admitted only while that count is below the
    one-retry cap; transient classes ignore it. Both classes share the physical-attempt budget.
    A rejected credential is not a transport retry even when the public reason is the
    transport catch-all (issue #742).
    """

    if deadline_expired:
        return False
    if type(repair_retries_used) is not int or repair_retries_used < 0:
        raise ValueError("repair_retries_used_invalid")
    if is_retriable_semantic_outcome(status, reason, failure_class=failure_class):
        pass
    elif is_repairable_semantic_outcome(status, reason):
        if repair_retries_used >= _REPAIR_RETRY_LIMIT:
            return False
    else:
        return False
    budget = physical_attempt_budget(max_retries)
    return attempts_completed < budget


def _reason_counts(
    codes: tuple[SemanticReason | None, ...],
) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for code in codes:
        if code is None:
            continue
        counts[code.value] = counts.get(code.value, 0) + 1
    return tuple(sorted(counts.items(), key=lambda item: item[0].encode("ascii")))


def _endpoint_attempts(
    codes: tuple[SemanticReason | None, ...], plan: SemanticFallbackPlan
) -> tuple[SemanticEndpointAttempts, ...]:
    walk = _walk_endpoints(codes, plan)
    primary_codes = codes[: walk.primary_attempts]
    fallback_codes = codes[walk.primary_attempts :]
    primary_last = next((code for code in reversed(primary_codes) if code is not None), None)
    fallback_last = next((code for code in reversed(fallback_codes) if code is not None), None)
    predispatch = plan.primary_predispatch_reason
    return (
        SemanticEndpointAttempts(
            "primary",
            plan.primary.provider_id,
            plan.primary.model_id,
            plan.primary.endpoint_profile_id,
            plan.primary.endpoint_profile_version,
            walk.primary_attempts,
            _reason_counts(primary_codes),
            None if primary_last is None else primary_last.value,
            None if predispatch is None else predispatch.value,
        ),
        SemanticEndpointAttempts(
            "fallback",
            plan.fallback.provider_id,
            plan.fallback.model_id,
            plan.fallback.endpoint_profile_id,
            plan.fallback.endpoint_profile_version,
            walk.fallback_attempts,
            _reason_counts(fallback_codes),
            None if fallback_last is None else fallback_last.value,
            None,
        ),
    )


def attempt_accounting_from_rows(
    job: SemanticJobRecord | None,
    attempts: tuple[SemanticAttemptRecord, ...],
    *,
    max_retries: int,
    fallback: SemanticFallbackPlan | None = None,
) -> SemanticAttemptAccounting:
    """Rebuild bounded accounting from durable job/attempt rows.

    With a fallback plan the budget is the primary's own until the walk engages the fallback,
    then the primary attempts actually spent plus the fallback's own budget; the per-endpoint
    slices are derived from the same walk so they always agree with the roles dispatch used.
    """

    codes = _ordered_codes(attempts)
    if fallback is None:
        budget = physical_attempt_budget(max_retries)
        endpoint_attempts: tuple[SemanticEndpointAttempts, ...] = ()
    else:
        budget = _total_budget(_walk_endpoints(codes, fallback), fallback)
        endpoint_attempts = _endpoint_attempts(codes, fallback)
    attempted = len(attempts)
    selected = None if job is None else job.selected_attempt_id
    exhausted = (
        job is not None
        and job.state in {"failed", "quarantined"}
        and (attempted >= budget or (job.terminal_code is SemanticReason.RETRY_BUDGET_EXHAUSTED))
    )
    attempt_usages = tuple(
        SemanticAttemptUsage(
            attempt.attempt_id,
            attempt.attempt_ordinal,
            attempt.token_usage,
        )
        for attempt in sorted(attempts, key=lambda item: item.attempt_ordinal)
    )
    return SemanticAttemptAccounting(
        attempted_count=attempted,
        selected_attempt_id=selected,
        exhausted=exhausted,
        terminal_reason_counts=_reason_counts(codes),
        endpoint_attempts=endpoint_attempts,
        attempt_usages=attempt_usages,
    )


def attempt_accounting_to_json(value: SemanticAttemptAccounting) -> dict[str, JsonValue]:
    """Encode accounting as structural JSON with no user-controlled content."""

    body: dict[str, JsonValue] = {
        "attempted_count": value.attempted_count,
        "selected_attempt_id": value.selected_attempt_id,
        "exhausted": value.exhausted,
        "terminal_reason_counts": tuple(
            {"reason": reason, "count": count} for reason, count in value.terminal_reason_counts
        ),
    }
    if value.endpoint_attempts:
        body["endpoint_attempts"] = tuple(
            {
                "role": item.role,
                "provider_id": item.provider_id,
                "model_id": item.model_id,
                "endpoint_profile_id": item.endpoint_profile_id,
                "endpoint_profile_version": item.endpoint_profile_version,
                "attempted_count": item.attempted_count,
                "terminal_reason_counts": tuple(
                    {"reason": reason, "count": count}
                    for reason, count in item.terminal_reason_counts
                ),
                "last_terminal_reason": item.last_terminal_reason,
                "predispatch_reason": item.predispatch_reason,
            }
            for item in value.endpoint_attempts
        )
    if value.attempt_usages:
        body["attempt_usages"] = tuple(
            {
                "attempt_id": item.attempt_id,
                "attempt_ordinal": item.attempt_ordinal,
                "token_usage": (
                    None
                    if item.token_usage is None
                    else {
                        "input_tokens": str(item.token_usage.input_tokens),
                        "cached_input_tokens": str(item.token_usage.cached_input_tokens),
                        "cache_write_input_tokens": str(item.token_usage.cache_write_input_tokens),
                        "output_tokens": str(item.token_usage.output_tokens),
                        "reasoning_output_tokens": str(item.token_usage.reasoning_output_tokens),
                        "total_tokens": str(item.token_usage.total_tokens),
                    }
                ),
            }
            for item in value.attempt_usages
        )
    return body


def final_status_after_exhaustion(
    last_status: SemanticStatus,
    last_reason: SemanticReason,
    *,
    attempts_completed: int,
    max_retries: int,
) -> tuple[SemanticStatus, SemanticReason]:
    """Map multi-attempt exhaustion to the closed public status/reason pair.

    A single physical attempt that fails with a retriable class keeps its exact reason
    (``max_retries=0``). Exhaustion after using the full budget surfaces
    ``unavailable/retry_budget_exhausted``. A repair-class last outcome is a real provider
    answer, not transport exhaustion: it keeps ``invalid/response_content_invalid`` however many
    attempts preceded it, so a second invalid answer reads as what it was.
    """

    if is_repairable_semantic_outcome(last_status, last_reason):
        return last_status, last_reason
    budget = physical_attempt_budget(max_retries)
    if attempts_completed >= budget and attempts_completed > 1:
        return SemanticStatus.UNAVAILABLE, SemanticReason.RETRY_BUDGET_EXHAUSTED
    if (
        attempts_completed >= budget
        and is_retriable_semantic_outcome(last_status, last_reason)
        and max_retries > 0
    ):
        return SemanticStatus.UNAVAILABLE, SemanticReason.RETRY_BUDGET_EXHAUSTED
    return last_status, last_reason


def status_for_semantic_reason(reason: SemanticReason) -> SemanticStatus:
    """Map a closed SemanticReason to its unique SemanticStatus (no coercion of unknown pairs)."""

    status = _STATUS_BY_REASON.get(reason)
    if status is None:
        raise ValueError("semantic_reason_unmapped")
    return status


BackoffKind = Literal["none", "transient"]


def backoff_seconds(attempt_ordinal: int, *, kind: BackoffKind = "transient") -> float:
    """Deterministic bounded backoff before the next physical attempt (ADR-006 jittered budget)."""

    if kind == "none" or attempt_ordinal <= 1:
        return 0.0
    # Small deterministic backoff: 0.05s, 0.1s — stays well under typical total deadlines.
    base = 0.05 * float(1 << min(attempt_ordinal - 1, 2))
    # Stable pseudo-jitter from ordinal (no clock/random dependency).
    jitter = 0.01 * float((attempt_ordinal * 17) % 5)
    return min(1.0, base + jitter)


class _SemanticAttemptLedger(Protocol):
    async def claim_semantic_job(
        self, lease: OperationLease, job_id: str
    ) -> SemanticAttemptHandle: ...

    async def record_attempt_outcome(
        self,
        handle: SemanticAttemptHandle,
        outcome: AttemptOutcome,
        result_object_ref: ObjectRef | None = None,
        terminal_code: SemanticReason | None = None,
        token_usage: RuntimeTokenUsage | None = None,
    ) -> None: ...

    async def fail_semantic_job(
        self,
        lease: OperationLease,
        job_id: str,
        terminal_code: SemanticReason,
    ) -> SemanticJobRecord: ...

    async def select_attempt(
        self,
        lease: OperationLease,
        handle: SemanticAttemptHandle,
        selected_result_object_ref: ObjectRef,
    ) -> object: ...

    async def load_semantic_job(
        self, writer_id: str, operation_id: str, case_digest: str | None = None
    ) -> SemanticJobRecord | None: ...

    async def list_semantic_attempts(self, job_id: str) -> tuple[SemanticAttemptRecord, ...]: ...

    async def record_disclosure_wait(
        self,
        handle: SemanticAttemptHandle,
        pending_id: str,
        pending_expires_at: datetime,
    ) -> object: ...

    async def load_disclosure_wait(self, writer_id: str, operation_id: str) -> object | None: ...

    async def resolve_disclosure_wait(self, job_id: str) -> object: ...

    async def renew_leases(self, lease: OperationLease) -> OperationLease: ...


async def _resolve_disclosure_wait_after_terminal(
    ledger: _SemanticAttemptLedger,
    lease: OperationLease,
    job_id: str,
    attempt_id: str | None = None,
) -> None:
    """Close an exact one-use wait only after its bound attempt is terminal.

    The attempt write is the authoritative transition. Resolving the side-table wait afterwards
    keeps crash recovery safe: a crash before this cleanup still recovers the terminal attempt,
    while resolving first could expose a started attempt as though it were no longer waiting. The
    job may itself be terminal or queued for a separately authorized physical retry.
    """

    try:
        wait = await ledger.load_disclosure_wait(lease.writer_id, lease.operation_id)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="semantic_attempts",
            operation="semantic_disclosure_wait_load_after_terminal_failed",
            request_id=lease.operation_id,
        )
        return
    if (
        wait is None
        or getattr(wait, "job_id", None) != job_id
        or getattr(wait, "state", None) != "awaiting"
        or (attempt_id is not None and getattr(wait, "attempt_id", None) != attempt_id)
    ):
        return
    try:
        await ledger.resolve_disclosure_wait(job_id)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="semantic_attempts",
            operation="semantic_disclosure_wait_resolve_after_terminal_failed",
            request_id=lease.operation_id,
        )


class _AttemptEvaluation(Protocol):
    @property
    def status(self) -> SemanticStatus: ...

    @property
    def reason(self) -> SemanticReason: ...

    @property
    def judgment(self) -> object | None: ...

    @property
    def provenance(self) -> object | None: ...


def _attempt_token_usage(evaluation: _AttemptEvaluation) -> RuntimeTokenUsage | None:
    """Extract only bounded numeric provider usage for the durable attempt row."""

    provenance = evaluation.provenance
    if provenance is None:
        return None
    runtime = getattr(provenance, "runtime_evidence", None)
    runtime_usage = getattr(runtime, "token_usage", None)
    if type(runtime_usage) is RuntimeTokenUsage:
        return runtime_usage
    # Aggregate TokenUsage does not prove that cache-write or reasoning counters were zero. Keep
    # those detailed fields unknown for providers that do not emit RuntimeTokenUsage rather than
    # manufacturing a complete-looking sample.
    return None


SemanticAttemptDispatch = Callable[
    [SemanticAttemptHandle, Deadline],
    Awaitable[_AttemptEvaluation],
]


async def _accounting_for(
    ledger: _SemanticAttemptLedger,
    lease: OperationLease,
    job_id: str,
    *,
    max_retries: int,
    fallback: SemanticFallbackPlan | None = None,
    case_digest: str | None = None,
) -> SemanticAttemptAccounting:
    rows = await ledger.list_semantic_attempts(job_id)
    # One operation may own several jobs, one per case it sent (issue #1047): read this one.
    job_final = await ledger.load_semantic_job(
        lease.writer_id, lease.operation_id, case_digest=case_digest
    )
    return attempt_accounting_from_rows(job_final, rows, max_retries=max_retries, fallback=fallback)


def _role_exhaustion(
    last_status: SemanticStatus,
    last_reason: SemanticReason,
    *,
    codes: tuple[SemanticReason | None, ...],
    max_retries: int,
    fallback: SemanticFallbackPlan | None,
) -> tuple[SemanticStatus, SemanticReason]:
    """Exhaustion mapping for the endpoint that produced the last of ``codes``.

    ``codes`` ends with the last attempt's own reason. Without a fallback plan this is exactly
    :func:`final_status_after_exhaustion` over the whole job; with one, the budget and the
    attempt count are those of the endpoint the last attempt used, so a single fallback failure
    keeps its exact reason instead of reading as an exhausted retry budget it never had.
    """

    if fallback is None:
        return final_status_after_exhaustion(
            last_status, last_reason, attempts_completed=len(codes), max_retries=max_retries
        )
    role = _walk_endpoints(codes[:-1], fallback).role
    walk = _walk_endpoints(codes, fallback)
    attempts = walk.primary_attempts if role == "primary" else walk.fallback_attempts
    return final_status_after_exhaustion(
        last_status,
        last_reason,
        attempts_completed=attempts,
        max_retries=fallback.endpoint(role).max_retries,
    )


async def _recover_terminal_job(
    *,
    ledger: _SemanticAttemptLedger,
    lease: OperationLease,
    job: SemanticJobRecord,
    max_retries: int,
    fallback: SemanticFallbackPlan | None,
    recover_selected: Callable[[SemanticJobRecord], Awaitable[_AttemptEvaluation | None]] | None,
    recover_response: Callable[[ObjectRef], Awaitable[_AttemptEvaluation | None]] | None,
    build_final: Callable[
        [SemanticStatus, SemanticReason, _AttemptEvaluation | None, SemanticAttemptAccounting],
        object,
    ],
) -> object:
    """Rebuild the final evaluation from a durable terminal job without re-claiming."""

    await _resolve_disclosure_wait_after_terminal(ledger, lease, job.job_id)
    accounting = await _accounting_for(
        ledger,
        lease,
        job.job_id,
        max_retries=max_retries,
        fallback=fallback,
        case_digest=job.case_digest,
    )
    if job.state == "succeeded":
        evaluation: _AttemptEvaluation | None = None
        if recover_selected is not None:
            evaluation = await recover_selected(job)
        reason = (
            job.terminal_code
            if type(job.terminal_code) is SemanticReason
            else SemanticReason.SEMANTIC_COMPLETED
        )
        return build_final(SemanticStatus.SUCCEEDED, reason, evaluation, accounting)

    reason = (
        job.terminal_code
        if type(job.terminal_code) is SemanticReason
        else SemanticReason.COORDINATOR_FAILURE
    )
    try:
        status = status_for_semantic_reason(reason)
    except ValueError:
        status = SemanticStatus.FAILED
        reason = SemanticReason.COORDINATOR_FAILURE
    evaluation: _AttemptEvaluation | None = None
    if recover_response is not None:
        # A terminal failed job may carry a response object even though it was never selected.
        # This is the durable carrier for privacy omission identities on non-success outcomes;
        # only the latest attempt can be relevant because the terminal write is its authority.
        attempts = await ledger.list_semantic_attempts(job.job_id)
        latest = max(attempts, key=lambda attempt: attempt.attempt_ordinal, default=None)
        if latest is not None and latest.result_object_ref is not None:
            evaluation = await recover_response(latest.result_object_ref)
    return build_final(status, reason, evaluation, accounting)


async def _terminalize_after_failure(
    *,
    ledger: _SemanticAttemptLedger,
    renew: Callable[[], Awaitable[OperationLease]],
    lease_holder: Callable[[], OperationLease],
    job_id: str,
    handle: SemanticAttemptHandle | None,
    token_usage: RuntimeTokenUsage | None = None,
    max_retries: int,
    fallback: SemanticFallbackPlan | None = None,
    case_digest: str | None = None,
) -> SemanticAttemptAccounting:
    """Drive a failed attempt and its job to a terminal state, whatever went wrong.

    Total by construction: every step is individually guarded and recorded, because a second
    fault while cleaning up after the first must not re-raise and strand the very state this is
    trying to release. Returns whatever accounting could be read, empty if none.

    ``record_attempt_outcome(FAILED)`` terminalizes the job as well as the attempt, so it is the
    right call whenever an attempt was claimed. ``fail_semantic_job`` is for the other case only —
    it rejects a job that still has an active attempt.
    """

    try:
        await renew()
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="semantic_attempts",
            operation="semantic_terminalize_renew_failed",
            request_id=lease_holder().operation_id,
        )
    if handle is not None:
        try:
            await ledger.record_attempt_outcome(
                handle,
                AttemptOutcome.FAILED,
                terminal_code=SemanticReason.COORDINATOR_FAILURE,
                token_usage=token_usage,
            )
        except Exception as exc:
            # The attempt may already have left "started" if the raise came after the outcome
            # write; that is the state we wanted, so it is not worth escalating.
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_attempts",
                operation="semantic_terminalize_attempt_failed",
                request_id=lease_holder().operation_id,
            )
    else:
        try:
            await ledger.fail_semantic_job(
                lease_holder(), job_id, SemanticReason.COORDINATOR_FAILURE
            )
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_attempts",
                operation="semantic_terminalize_job_failed",
                request_id=lease_holder().operation_id,
            )
    await _resolve_disclosure_wait_after_terminal(
        ledger,
        lease_holder(),
        job_id,
        None if handle is None else handle.attempt_id,
    )
    try:
        return await _accounting_for(
            ledger,
            lease_holder(),
            job_id,
            max_retries=max_retries,
            fallback=fallback,
            case_digest=case_digest,
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="semantic_attempts",
            operation="semantic_terminalize_accounting_failed",
            request_id=lease_holder().operation_id,
        )
        return attempt_accounting_from_rows(None, (), max_retries=max_retries, fallback=fallback)


async def _terminalize_cancellation_safe(
    *,
    ledger: _SemanticAttemptLedger,
    renew: Callable[[], Awaitable[OperationLease]],
    lease_holder: Callable[[], OperationLease],
    job_id: str,
    handle: SemanticAttemptHandle | None,
    token_usage: RuntimeTokenUsage | None = None,
    max_retries: int,
    fallback: SemanticFallbackPlan | None = None,
    case_digest: str | None = None,
) -> tuple[SemanticAttemptAccounting, bool]:
    """Finish terminal writes even if cancellation is delivered again during cleanup.

    The cleanup runs in its own task so cancelling this coordinator task cannot cancel a ledger
    write through the await chain. ``shield`` still reports each new cancellation to this task;
    remember that fact, keep waiting for cleanup, then let the caller restore cancellation by
    raising after durability and accounting have finished.
    """

    cleanup = asyncio.create_task(
        _terminalize_after_failure(
            ledger=ledger,
            renew=renew,
            lease_holder=lease_holder,
            job_id=job_id,
            handle=handle,
            token_usage=token_usage,
            max_retries=max_retries,
            fallback=fallback,
            case_digest=case_digest,
        )
    )
    cancellation_received = False
    while True:
        try:
            accounting = await asyncio.shield(cleanup)
            return accounting, cancellation_received
        except asyncio.CancelledError:
            cancellation_received = True
            if cleanup.done():
                if not cleanup.cancelled():
                    return cleanup.result(), True
                # A cleanup implementation that cancelled itself cannot be resumed. Preserve
                # the signal and return bounded fallback accounting to the caller.
                return (
                    attempt_accounting_from_rows(
                        None, (), max_retries=max_retries, fallback=fallback
                    ),
                    True,
                )


async def run_durable_semantic_attempts(
    *,
    ledger: _SemanticAttemptLedger,
    lease: OperationLease,
    job: SemanticJobRecord,
    deadline: Deadline,
    max_retries: int,
    now_monotonic: Callable[[], float],
    dispatch: SemanticAttemptDispatch,
    publish_success_response: Callable[
        [SemanticAttemptHandle, _AttemptEvaluation], Awaitable[ObjectRef]
    ],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    build_final: Callable[
        [SemanticStatus, SemanticReason, _AttemptEvaluation | None, SemanticAttemptAccounting],
        object,
    ],
    recover_selected: (
        Callable[[SemanticJobRecord], Awaitable[_AttemptEvaluation | None]] | None
    ) = None,
    recover_response: Callable[[ObjectRef], Awaitable[_AttemptEvaluation | None]] | None = None,
    on_lease_renewed: Callable[[OperationLease], None] | None = None,
    fallback: SemanticFallbackPlan | None = None,
    dispatch_fallback: SemanticAttemptDispatch | None = None,
    primary_deadline: Deadline | None = None,
    fallback_timeout_seconds: float | None = None,
    now_utc: Callable[[], datetime] | None = None,
) -> object:
    """Run the physical attempt loop for one durable AI-powered review job.

    Each iteration claims (or resumes) one attempt, dispatches once, and records a durable
    outcome. Retries the ADR-006 transient classes, plus at most one issue #348 repair retry
    after ``invalid/response_content_invalid``, within the total deadline and ``max_retries``
    budget. Exactly one selected attempt or one terminal failed job results.

    With ``fallback`` (issue #582) the endpoint of every attempt is read from the durable rows
    before it (:func:`endpoint_role_for_ordinal`); ``dispatch`` serves the primary and
    ``dispatch_fallback`` the fallback, each inside its own retry budget. ``max_retries`` must
    equal the primary's budget so the single-endpoint accounting stays the same function.

    Crash/replay after a terminal job row already exists recovers from durable state without
    re-claiming. The check operation lease is renewed before each claim and after each provider
    result; its bounded expiry is derived by the ledger from the frozen AI-powered review execution.
    """

    if fallback is not None:
        if type(fallback) is not SemanticFallbackPlan or dispatch_fallback is None:
            raise ValueError("semantic_fallback_dispatch_missing")
        if fallback.primary.max_retries != max_retries:
            raise ValueError("semantic_fallback_budget_mismatch")

    current_lease = lease

    async def _renew() -> OperationLease:
        nonlocal current_lease
        current_lease = await ledger.renew_leases(current_lease)
        if on_lease_renewed is not None:
            on_lease_renewed(current_lease)
        return current_lease

    async def _accounting() -> SemanticAttemptAccounting:
        return await _accounting_for(
            ledger,
            current_lease,
            job.job_id,
            max_retries=max_retries,
            fallback=fallback,
            case_digest=job.case_digest,
        )

    async def _publish_terminal_response(
        handle: SemanticAttemptHandle, evaluation: _AttemptEvaluation
    ) -> tuple[ObjectRef | None, bool]:
        """Persist privacy omission identities and private read usage for a non-success attempt.

        Successful attempts already publish their response object before selection. A blocked,
        exhausted, retryable, or otherwise non-success attempt is never selected, but its
        withheld item identities are still part of the public result. Store that bounded metadata
        in the same authenticated response object so retry and terminal replay can recover it
        without re-dispatching. Publishing is best effort here; callers decide whether a failed
        write is retryable or an explicit persistence-unknown terminal outcome.
        """

        # Omission identities are part of the public result; private read usage (#1173) is
        # owner-local telemetry only, so losing it never changes the outcome or stops a retry.
        public = bool(
            getattr(evaluation, "semantic_withheld_item_ids", ())
            or getattr(evaluation, "semantic_redacted_values", ())
        )
        if not public and not getattr(evaluation, "reviewer_read_usage", None):
            return None, False
        try:
            return await publish_success_response(handle, evaluation), False
        except asyncio.CancelledError:
            # Cancellation must reach the coordinator's durable cleanup path. Swallowing it
            # here could return a terminal result whose omission metadata was never persisted.
            raise
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_attempts",
                operation=(
                    "semantic_attempt_terminal_response_persistence_failed"
                    if public
                    else "semantic_attempt_read_usage_persistence_failed"
                ),
                request_id=current_lease.operation_id,
            )
            return None, public

    async def _exhaustion_from_rows(
        last_status: SemanticStatus, last_reason: SemanticReason
    ) -> tuple[SemanticStatus, SemanticReason]:
        # The last attempt's row is already durable here (it was closed ``expired`` when its
        # retry was admitted), so the rows end with its own reason.
        codes = _ordered_codes(await ledger.list_semantic_attempts(job.job_id))
        if not codes or codes[-1] is not last_reason:
            codes = (*codes, last_reason)
        return _role_exhaustion(
            last_status, last_reason, codes=codes, max_retries=max_retries, fallback=fallback
        )

    # Always refresh the check lease before recovery or the first claim so a long AI-powered review
    # deadline is not truncated by the 60-second operation-lease TTL. Once the authenticated
    # execution bound has passed, a reclaimed operation may still have a short local
    # lease for closing a started attempt. That lease is cleanup-only: the immutable provider
    # deadline below remains expired and the dispatch branch refuses to send anything.
    local_cleanup_only = False
    try:
        await _renew()
    except PublicOperationError as exc:
        if not (
            exc.code is PublicErrorCode.OPERATION_PENDING
            and deadline.expired(now_monotonic())
            and job.state == "leased"
            and job.active_attempt_id is not None
        ):
            raise
        current_job = await ledger.load_semantic_job(
            current_lease.writer_id, current_lease.operation_id, case_digest=job.case_digest
        )
        if (
            current_job is None
            or current_job.state != "leased"
            or current_job.active_attempt_id is None
        ):
            raise exc
        current_attempt = next(
            (
                row
                for row in await ledger.list_semantic_attempts(current_job.job_id)
                if row.attempt_id == current_job.active_attempt_id
            ),
            None,
        )
        if current_attempt is None or current_attempt.state not in {"started", "response_durable"}:
            raise exc
        # The caller's job snapshot may be stale after a concurrent terminalization. Use the
        # durable row that justified cleanup so a queued replacement cannot be claimed here.
        job = current_job
        local_cleanup_only = True

    # Recover previously terminal jobs (crash after select_attempt / final FAILED before commit).
    if job.state in _TERMINAL_JOB_STATES:
        return await _recover_terminal_job(
            ledger=ledger,
            lease=current_lease,
            job=job,
            max_retries=max_retries,
            fallback=fallback,
            recover_selected=recover_selected,
            recover_response=recover_response,
            build_final=build_final,
        )

    if fallback is None:
        budget = physical_attempt_budget(max_retries)
    else:
        # Replay may resume a job that already engaged its fallback; the budget is then the
        # primary attempts actually spent plus the fallback's own, not the primary's alone.
        budget = _total_budget(
            _walk_endpoints(
                _ordered_codes(await ledger.list_semantic_attempts(job.job_id)), fallback
            ),
            fallback,
        )
    last: _AttemptEvaluation | None = None
    attempts_completed = 0
    pending_claim_error: PublicOperationError | None = None

    while attempts_completed < budget:
        if deadline.expired(now_monotonic()) and not (
            job.state == "leased" and last is None and pending_claim_error is None
        ):
            if last is None and pending_claim_error is not None:
                # Another live owner still has authority over the job. Do not falsify that
                # recoverable state as a coordinator failure or mutate its active attempt.
                raise pending_claim_error
            if last is None:
                await ledger.fail_semantic_job(
                    current_lease,
                    job.job_id,
                    SemanticReason.PROVIDER_TIMEOUT,
                )
                await _resolve_disclosure_wait_after_terminal(ledger, current_lease, job.job_id)
                return build_final(
                    SemanticStatus.TIMEOUT,
                    SemanticReason.PROVIDER_TIMEOUT,
                    None,
                    await _accounting(),
                )
            status, reason = await _exhaustion_from_rows(last.status, last.reason)
            await ledger.fail_semantic_job(current_lease, job.job_id, reason)
            await _resolve_disclosure_wait_after_terminal(ledger, current_lease, job.job_id)
            return build_final(status, reason, last, await _accounting())

        # Keep the operation lease alive across provider latency and backoff. A lease that was
        # reclaimed after the provider deadline is usable only for the one local terminal write;
        # renewing it would turn cleanup authority into a new provider lifetime.
        if not local_cleanup_only:
            await _renew()
        handle: SemanticAttemptHandle | None = None
        role: EndpointRole = "primary"
        codes_before: tuple[SemanticReason | None, ...] = ()
        failure_stage = "claim"
        try:
            try:
                handle = await ledger.claim_semantic_job(current_lease, job.job_id)
            except PublicOperationError as exc:
                if not exc.retryable:
                    raise
                # A live lease held elsewhere is durable pending state, not a failed physical
                # attempt. Poll inside the total deadline without consuming an attempt slot.
                pending_claim_error = exc
                remaining = deadline.remaining_seconds(now_monotonic())
                if remaining > 0.0:
                    await sleep(min(0.05, remaining))
                continue
            pending_claim_error = None
            failure_stage = "attempt_recovery"
            attempts = await ledger.list_semantic_attempts(job.job_id)
            durable_response = next(
                (
                    row
                    for row in attempts
                    if row.attempt_id == handle.attempt_id and row.state == "response_durable"
                ),
                None,
            )
            if durable_response is not None:
                if durable_response.result_object_ref is None:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "AI-powered review response durable row is missing its result object.",
                        False,
                    )
                # The provider response was already authenticated and published before the
                # crash. Select that exact object under the rebound lease and recover its
                # judgment; no provider dispatch or new request identity is permitted here.
                await ledger.select_attempt(
                    current_lease, handle, durable_response.result_object_ref
                )
                recovered_job = await ledger.load_semantic_job(
                    current_lease.writer_id,
                    current_lease.operation_id,
                    case_digest=job.case_digest,
                )
                if recovered_job is None:
                    raise PublicOperationError(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "AI-powered review job disappeared during response recovery.",
                        False,
                    )
                return await _recover_terminal_job(
                    ledger=ledger,
                    lease=current_lease,
                    job=recovered_job,
                    max_retries=max_retries,
                    fallback=fallback,
                    recover_selected=recover_selected,
                    recover_response=recover_response,
                    build_final=build_final,
                )
            if fallback is not None:
                # The endpoint is a function of the rows before this ordinal, so a resumed
                # ``started`` attempt goes back to the endpoint it was claimed for.
                codes_before = _ordered_codes(
                    await ledger.list_semantic_attempts(job.job_id),
                    before_ordinal=handle.attempt_ordinal,
                )
                role = _walk_endpoints(codes_before, fallback).role
            dispatch_deadline = (
                primary_deadline if role == "primary" and primary_deadline is not None else deadline
            )
            if role == "fallback" and fallback_timeout_seconds is not None:
                if now_utc is None or fallback is None:
                    raise ValueError("semantic_fallback_clock_missing")
                rows = await ledger.list_semantic_attempts(job.job_id)
                first = next(
                    row
                    for row in sorted(rows, key=lambda item: item.attempt_ordinal)
                    if endpoint_role_for_ordinal(rows, fallback, row.attempt_ordinal) == "fallback"
                )
                # Claim time is durable across retries, disclosure waits, and service restart.
                # Missing legacy metadata gets the conservative primary cutoff, never a new
                # fallback lifetime starting at this replay.
                cutoff = (
                    first.started_at + timedelta(seconds=fallback_timeout_seconds)
                    if first.started_at is not None
                    else (primary_deadline or deadline).expires_at_utc
                )
                cutoff = min(cutoff, deadline.expires_at_utc)
                remaining = min(
                    deadline.remaining_seconds(now_monotonic()),
                    max(0.0, (cutoff - now_utc()).total_seconds()),
                )
                dispatch_deadline = Deadline(cutoff, now_monotonic() + remaining)
            remaining = dispatch_deadline.remaining_seconds(now_monotonic())
            attempt_deadline = Deadline(
                dispatch_deadline.expires_at_utc,
                now_monotonic() + remaining,
            )
            attempt_dispatch = dispatch
            if role == "fallback":
                assert dispatch_fallback is not None  # validated at entry
                attempt_dispatch = dispatch_fallback
            if remaining <= 0.0:
                # A resumed started attempt must not be sent after its frozen endpoint cutoff.
                # A task-local awaiting row may be stale after the independent privacy audit
                # consumed admission. It cannot prove that a resumed started attempt never
                # dispatched. Preserve uncertainty without re-entering provider authorization;
                # only a newly claimed attempt is a known pre-admission timeout here.
                # Neither outcome licenses a retry or fallback dispatch.
                uncertain = job.state == "leased" and last is None
                terminal_reason = (
                    SemanticReason.OUTCOME_UNKNOWN if uncertain else SemanticReason.PROVIDER_TIMEOUT
                )
                await ledger.record_attempt_outcome(
                    handle, AttemptOutcome.FAILED, terminal_code=terminal_reason
                )
                await _resolve_disclosure_wait_after_terminal(
                    ledger, current_lease, job.job_id, handle.attempt_id
                )
                return build_final(
                    SemanticStatus.UNAVAILABLE if uncertain else SemanticStatus.TIMEOUT,
                    terminal_reason,
                    # A fallback endpoint can reach its frozen cutoff while the total operation
                    # deadline remains live. Keep the prior evaluation as the bounded carrier for
                    # omission identities; ``build_final`` copies only those identities when the
                    # terminal status/reason cannot reuse its provider provenance.
                    last,
                    await _accounting(),
                )
            failure_stage = "dispatch_entered"
            evaluation = await attempt_dispatch(handle, attempt_deadline)
        except BaseException as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_attempts",
                operation=f"semantic_attempt_{failure_stage}_failed",
                request_id=current_lease.operation_id,
            )
            # A raise between claim and the terminal write used to unwind past every
            # terminalizing call, leaving the attempt "started" and the job "leased" forever —
            # and, because claim resumes the same attempt on replay, the operation could never
            # recover. This frame is the only one that knows the durable state, so it finalizes
            # here rather than letting the exception reach the coordinator's catch-all.
            accounting, cancellation_received = await _terminalize_cancellation_safe(
                ledger=ledger,
                renew=_renew,
                lease_holder=lambda: current_lease,
                job_id=job.job_id,
                case_digest=job.case_digest,
                handle=handle,
                max_retries=max_retries,
                fallback=fallback,
            )
            if cancellation_received:
                raise asyncio.CancelledError
            if isinstance(exc, Exception):
                return build_final(
                    SemanticStatus.FAILED,
                    SemanticReason.COORDINATOR_FAILURE,
                    None,
                    accounting,
                )
            # Cancellation and other BaseExceptions still propagate — but only after the durable
            # state has been made terminal.
            raise
        attempts_completed = handle.attempt_ordinal
        last = evaluation

        final_stage = "dispatch_result_received"
        try:
            # Provider dispatch may consume most of a lease TTL; renew before ledger mutations.
            await _renew()

            if evaluation.status is SemanticStatus.SUCCEEDED:
                final_stage = "response_persistence"
                try:
                    response_ref = await publish_success_response(handle, evaluation)
                except BaseException as exc:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="semantic_attempts",
                        operation="semantic_attempt_response_persistence_failed",
                        request_id=current_lease.operation_id,
                    )
                    accounting, cancellation_received = await _terminalize_cancellation_safe(
                        ledger=ledger,
                        renew=_renew,
                        lease_holder=lambda: current_lease,
                        job_id=job.job_id,
                        case_digest=job.case_digest,
                        handle=handle,
                        token_usage=_attempt_token_usage(evaluation),
                        max_retries=max_retries,
                        fallback=fallback,
                    )
                    if cancellation_received:
                        raise asyncio.CancelledError
                    if isinstance(exc, Exception):
                        return build_final(
                            SemanticStatus.FAILED,
                            SemanticReason.COORDINATOR_FAILURE,
                            None,
                            accounting,
                        )
                    raise
                await ledger.record_attempt_outcome(
                    handle,
                    AttemptOutcome.RESPONSE_DURABLE,
                    response_ref,
                    token_usage=_attempt_token_usage(evaluation),
                )
                final_stage = "result_commit"
                await ledger.select_attempt(current_lease, handle, response_ref)
                await _resolve_disclosure_wait_after_terminal(
                    ledger, current_lease, job.job_id, handle.attempt_id
                )
                return build_final(
                    evaluation.status, evaluation.reason, evaluation, await _accounting()
                )

            # awaiting_human is the one nonterminal dispatch outcome. It is not a failure and not a
            # retry: no provider was reached, the case was never sent, and the same attempt must be
            # resumable once the human answers. Falling through to the exhaustion path below would
            # write the attempt FAILED, terminalize the job, and commit a terminal check result —
            # leaving an approved decision with nothing left to resume.
            if evaluation.status is SemanticStatus.AWAITING_HUMAN:
                continuation = getattr(evaluation, "continuation", None)
                if continuation is None:
                    # Without a pending id the caller cannot act and the job cannot be resumed;
                    # that is a coordinator failure, not a wait.
                    accounting = await _terminalize_after_failure(
                        ledger=ledger,
                        renew=_renew,
                        lease_holder=lambda: current_lease,
                        job_id=job.job_id,
                        case_digest=job.case_digest,
                        handle=handle,
                        max_retries=max_retries,
                        fallback=fallback,
                    )
                    return build_final(
                        SemanticStatus.FAILED,
                        SemanticReason.COORDINATOR_FAILURE,
                        None,
                        accounting,
                    )
                await ledger.record_disclosure_wait(
                    handle,
                    continuation.pending_id,
                    continuation.expires_at.as_datetime(),
                )
                # The attempt stays `started` and the job stays `leased` on purpose: this is the
                # durable record that the check is open, not finished.
                return build_final(
                    evaluation.status, evaluation.reason, evaluation, await _accounting()
                )

            # The repair cap is read from durable rows, not a local counter: after an
            # ``awaiting_human`` replay this loop starts over with ``attempts_completed`` rebuilt
            # from the claimed ordinal, and the one-repair rule has to survive that the same way.
            repair_retries_used = repair_retries_from_rows(
                await ledger.list_semantic_attempts(job.job_id)
            )
            deadline_expired = deadline.expired(now_monotonic())
            codes_after = (*codes_before, evaluation.reason)
            switching = False
            raw_failure_class = (
                getattr(evaluation.provenance, "failure_class", None)
                if evaluation.provenance is not None
                else None
            )
            failure_class = (
                raw_failure_class if type(raw_failure_class) is SemanticFailureClass else None
            )
            if fallback is None:
                can_retry = should_retry_after(
                    status=evaluation.status,
                    reason=evaluation.reason,
                    attempts_completed=attempts_completed,
                    max_retries=max_retries,
                    deadline_expired=deadline_expired,
                    repair_retries_used=repair_retries_used,
                    failure_class=failure_class,
                )
            else:
                walk_after = _walk_endpoints(codes_after, fallback)
                # A rejected credential is not a licensed transition either: the durable code may
                # be the transport catch-all, but the adapter's class says the provider refused
                # this binding, and the ``semantic_credential_rejected`` directive promises that
                # the job stops. The veto only ever ends a job, so replay never needs the class.
                switching = (
                    role == "primary"
                    and walk_after.engaged
                    and failure_class not in _NON_RETRIABLE_FAILURE_CLASSES
                )
                if switching:
                    # The primary just crossed the closed engagement rule. The fallback's own
                    # budget is untouched, so the only thing that can refuse it is the deadline.
                    can_retry = not deadline_expired
                else:
                    role_attempts = (
                        walk_after.primary_attempts
                        if role == "primary"
                        else walk_after.fallback_attempts
                    )
                    can_retry = should_retry_after(
                        status=evaluation.status,
                        reason=evaluation.reason,
                        attempts_completed=role_attempts,
                        max_retries=fallback.endpoint(role).max_retries,
                        deadline_expired=deadline_expired
                        or attempt_deadline.expired(now_monotonic()),
                        repair_retries_used=repair_retries_used,
                        failure_class=failure_class,
                    )
                budget = _total_budget(walk_after, fallback)
            if can_retry:
                retry_response_ref, retry_response_failed = await _publish_terminal_response(
                    handle, evaluation
                )
                if retry_response_failed:
                    # Retrying after losing the only durable carrier would let an immediate
                    # result expose omission identities that terminal replay cannot reconstruct.
                    # Stop with the same bounded persistence-unknown outcome used by terminal
                    # attempts instead of clearing the facts and pretending the retry is safe.
                    await ledger.record_attempt_outcome(
                        handle,
                        AttemptOutcome.FAILED,
                        terminal_code=SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
                        token_usage=_attempt_token_usage(evaluation),
                    )
                    await _resolve_disclosure_wait_after_terminal(
                        ledger, current_lease, job.job_id, handle.attempt_id
                    )
                    return build_final(
                        SemanticStatus.UNAVAILABLE,
                        SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
                        None,
                        await _accounting(),
                    )
                # ``expired`` keeps the job claimable and leaves this attempt's terminal code in the
                # row, so the repaired attempt stays visible in accounting next to its successor.
                await ledger.record_attempt_outcome(
                    handle,
                    AttemptOutcome.EXPIRED,
                    result_object_ref=retry_response_ref,
                    terminal_code=evaluation.reason,
                    token_usage=_attempt_token_usage(evaluation),
                )
                await _resolve_disclosure_wait_after_terminal(
                    ledger, current_lease, job.job_id, handle.attempt_id
                )
                # A repair is not waiting out a transport fault, and a fallback is a different
                # endpoint: neither resubmits with backoff.
                repair = is_repairable_semantic_outcome(evaluation.status, evaluation.reason)
                delay = backoff_seconds(
                    handle.attempt_ordinal, kind="none" if repair or switching else "transient"
                )
                if delay > 0.0 and not deadline.expired(now_monotonic() + delay):
                    await sleep(delay)
                continue

            terminal_status, terminal_reason = _role_exhaustion(
                evaluation.status,
                evaluation.reason,
                codes=codes_after if fallback is not None else (None,) * attempts_completed,
                max_retries=max_retries,
                fallback=fallback,
            )
            try:
                terminal_response_ref, terminal_response_failed = await _publish_terminal_response(
                    handle, evaluation
                )
            except asyncio.CancelledError:
                # Complete the terminal ledger write under shielding, then restore cancellation
                # to the caller. The cancellation path intentionally does not manufacture a
                # replayable response object after its write was interrupted.
                await _terminalize_cancellation_safe(
                    ledger=ledger,
                    renew=_renew,
                    lease_holder=lambda: current_lease,
                    job_id=job.job_id,
                    case_digest=job.case_digest,
                    handle=handle,
                    token_usage=_attempt_token_usage(evaluation),
                    max_retries=max_retries,
                    fallback=fallback,
                )
                raise
            if terminal_response_failed:
                # A non-success result with omitted items is only replayable when its bounded
                # omission identities reach durable storage. Surface a bounded persistence
                # uncertainty instead of claiming the original policy outcome is replay-safe.
                terminal_status = SemanticStatus.UNAVAILABLE
                terminal_reason = SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN
                terminal_evaluation: _AttemptEvaluation | None = None
            else:
                terminal_evaluation = evaluation
            await ledger.record_attempt_outcome(
                handle,
                AttemptOutcome.FAILED,
                result_object_ref=terminal_response_ref,
                terminal_code=terminal_reason,
                token_usage=_attempt_token_usage(evaluation),
            )
            await _resolve_disclosure_wait_after_terminal(
                ledger, current_lease, job.job_id, handle.attempt_id
            )
            return build_final(
                terminal_status,
                terminal_reason,
                terminal_evaluation,
                await _accounting(),
            )

        except BaseException as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_attempts",
                operation=f"semantic_attempt_{final_stage}_failed",
                request_id=current_lease.operation_id,
            )
            raise

    if last is None:
        await ledger.fail_semantic_job(
            current_lease,
            job.job_id,
            SemanticReason.RETRY_BUDGET_EXHAUSTED,
        )
        await _resolve_disclosure_wait_after_terminal(ledger, current_lease, job.job_id)
        return build_final(
            SemanticStatus.UNAVAILABLE,
            SemanticReason.RETRY_BUDGET_EXHAUSTED,
            None,
            await _accounting(),
        )
    status, reason = await _exhaustion_from_rows(last.status, last.reason)
    await ledger.fail_semantic_job(current_lease, job.job_id, reason)
    await _resolve_disclosure_wait_after_terminal(ledger, current_lease, job.job_id)
    return build_final(status, reason, last, await _accounting())
