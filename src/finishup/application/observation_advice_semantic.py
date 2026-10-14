"""Bounded asynchronous AI-powered review for observation advice (issue #619).

Hook ingest never calls a provider. The advice builder asks the scheduler for the durable
attempt that matches the current advice-candidate identity; when eligible it enqueues one
minimized packet and reports ``advice_semantic_pending``. A generation-fenced background worker later
claims the row, resolves repository-scoped provider authority at dispatch time, performs the
privacy-gated attempt, and records the outcome. Only a ``succeeded`` row with validated output
may add AI-powered advice; every other state stays a truthful bounded coverage gap.

Frequency bound (#888): reuse is keyed by the stable candidate identity (rule, kind, next action,
summary, and scoped gaps; never the rolling evidence basis or per-rule evidence counts). A
terminal non-success for that identity is re-admitted after an exponential backoff. A new
admission is
refused while the session's last provider-reaching attempt is younger than the configured
minimum interval; the refusal is reported as ``deferred`` and a revisit is scheduled for when
the interval elapses, so suppressed work is retried without waiting for another hook.

Reachability (#923): admission first asks whether a usable provider exists right now (an endpoint
bound, LLM-inference egress admitted by the machine policy, the configured credential present) and
whether the session's task route can reach it (ACTIVE, with a granted repository authority that
admits LLM inference). Without both, nothing is written and no revisit is scheduled; an
already-succeeded review of the same identity is still reused, and every other state reports
``provider_unreachable`` (the ``advice_semantic_unavailable`` gap), never ``pending``. The probes
run on every build, so a stored credential, an enabled channel, a granted repository, or a newly
bound provider (which recomposes the service) admits the next eligible condition without
restarting the host session. A row that still ends ``authorization_missing`` (authority lost
between admission and dispatch) waits out the base backoff like any pre-provider failure, so a
disagreement between probe and dispatch can never re-admit on every build.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast

from finishup.application.observation_advice import (
    ADVICE_SEMANTIC_DEFERRED_REASON,
    ADVICE_SEMANTIC_UNREACHABLE_REASON,
    ObservationAdviceCandidate,
    ObservationAdviceSemanticAddon,
    minimized_semantic_evidence_packet,
)
from finishup.domain.findings import FindingId
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.semantic_budget import (
    semantic_background_scope,
    semantic_budget_profile_scope,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

if TYPE_CHECKING:
    from finishup.application.egress import SemanticEgressAttemptUnknown

__all__ = [
    "ADVICE_SEMANTIC_CANCEL_RECOVERY_SECONDS",
    "ADVICE_SEMANTIC_FAILURE_REASONS",
    "ADVICE_SEMANTIC_PENDING_REASON",
    "DEFAULT_ADVICE_SEMANTIC_MAX_PENDING",
    "DEFAULT_ADVICE_SEMANTIC_MIN_INTERVAL_SECONDS",
    "DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS",
    "MAX_ADVICE_SEMANTIC_BACKOFF_FACTOR",
    "MAX_ADVICE_SEMANTIC_ATTEMPTS",
    "AdviceSemanticCancellationReconciler",
    "AdviceSemanticDispatch",
    "AdviceSemanticDrainHandle",
    "AdviceSemanticProviderReady",
    "ObservationAdviceSemanticAttempt",
    "ObservationAdviceSemanticDeferral",
    "ObservationAdviceSemanticOutcome",
    "ObservationAdviceSemanticRepository",
    "ObservationAdviceSemanticScheduler",
    "ObservationAdviceSemanticSupervisor",
    "ObservationAdviceSemanticWorker",
    "addon_from_attempt",
    "advice_candidate_identity",
    "advice_semantic_retry_delay_seconds",
    "reconcile_cancelled_advice_request",
]

type AttemptStatus = Literal[
    "pending", "running", "succeeded", "failed", "unavailable", "cancelled"
]
type TerminalStatus = Literal["succeeded", "failed", "unavailable", "cancelled"]

# Closed vocabulary shared with the migration CHECK constraint. ``pending`` is not a stored
# failure reason: it is the addon marker for a row that has not reached a terminal state.
ADVICE_SEMANTIC_PENDING_REASON: Final = "pending"
ADVICE_SEMANTIC_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "queue_full",
        "superseded",
        "authorization_missing",
        "provider_unavailable",
        "provider_failed",
        "output_invalid",
        "cancelled",
        "interrupted",
    }
)
# At most this many pending rows per task bundle; the next schedule records ``queue_full``
# without a provider attempt so the bound is visible instead of silent.
DEFAULT_ADVICE_SEMANTIC_MAX_PENDING: Final = 16
# A row reclaimed this many times without a terminal outcome is recorded ``interrupted``.
MAX_ADVICE_SEMANTIC_ATTEMPTS: Final = 3
# Minimum spacing between provider-reaching background reviews of one FinishUP session (#888).
DEFAULT_ADVICE_SEMANTIC_MIN_INTERVAL_SECONDS: Final = 180
# Retries of one failed candidate identity back off exponentially from the minimum interval and
# stop growing at this multiple of it (180 s -> 360 s -> ... -> 48 min at the default).
MAX_ADVICE_SEMANTIC_BACKOFF_FACTOR: Final = 16
# Upper bound on the shielded post-cancellation reconciliation, so it can never hold a foreground
# rebind open. A reconciler that needs a slower lookup must bound it below this itself.
DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS: Final = 5.0
# The cancelled-request egress lookup waits on the privacy admission lock, which a foreground check
# may hold for its whole provider call, so it is bounded inside the worker's bound above: a lookup
# that cannot finish still records the usage-unknown provider identity (#923).
ADVICE_SEMANTIC_CANCEL_RECOVERY_SECONDS: Final = (
    DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS * 0.8
)
_MAX_REVISIT_TIMERS: Final = 256
# Failure reasons recorded before any provider request: they neither consume the session's rate
# limit nor wait on a provider-failure backoff longer than the base interval.
_PRE_PROVIDER_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {"authorization_missing", "provider_unavailable", "queue_full", "superseded"}
)


def advice_semantic_retry_delay_seconds(
    attempt: ObservationAdviceSemanticAttempt,
    *,
    generation: int,
    base_seconds: int,
) -> int:
    """Backoff before a terminal non-success row for one identity may be admitted again.

    ``generation`` is how many rows this identity already has in the session (1 for the first).
    A superseded row was never attempted, so it is immediately eligible (subject to the session
    rate limit). Pre-provider unavailability retries at the base interval; provider-reaching
    failures double per generation up to the cap.
    """

    if base_seconds <= 0:
        return 0
    if attempt.failure_reason == "superseded":
        return 0
    if attempt.failure_reason in _PRE_PROVIDER_FAILURE_REASONS:
        return base_seconds
    factor = min(2 ** max(generation - 1, 0), MAX_ADVICE_SEMANTIC_BACKOFF_FACTOR)
    return base_seconds * factor


def advice_candidate_identity(packet: Mapping[str, object]) -> str:
    """Stable identity of the reviewable advice candidates in one minimized packet.

    The identity is the set of distinct candidates (kind, rule, next action, summary) plus the
    scoped gaps and packet format. It excludes the rolling evidence basis, each rule's evidence
    count, and how many times the same candidate repeats, all of which change on almost every
    observation. A new or removed candidate kind, a changed next action, or a changed scoped gap
    is a different identity and therefore genuinely new advice.
    """

    rules = packet.get("deterministic_rules", ())
    distinct: dict[bytes, JsonValue] = {}
    for rule in cast(Sequence[object], rules):
        if not isinstance(rule, Mapping):
            continue
        stable = cast(
            JsonValue,
            {
                str(key): value
                for key, value in cast(Mapping[str, object], rule).items()
                if key != "evidence_ref_count"
            },
        )
        distinct[canonical_encode(stable)] = stable
    summaries = packet.get("finding_summaries", ())
    condition: dict[str, object] = {
        "format": packet.get("format"),
        "policy": packet.get("policy"),
        "coverage_gaps": packet.get("coverage_gaps", ()),
        "finding_summaries": tuple(
            sorted({str(item) for item in cast(Sequence[object], summaries)}, key=str.encode)
        ),
        "deterministic_rules": tuple(distinct[key] for key in sorted(distinct)),
    }
    return canonical_digest(cast(JsonValue, condition))


@dataclass(frozen=True, slots=True)
class ObservationAdviceSemanticAttempt:
    """One durable attempt keyed by session and candidate identity (legacy rows use basis).

    Retries of the same identity are stored as ``<identity>#<generation>`` so every earlier
    receipt and failure reason is retained.
    """

    attempt_id: str
    workspace_commitment: str
    yoetz_session_id: str
    basis_digest: str
    subject_digest: str
    coverage_gaps: tuple[str, ...]
    packet_json: bytes
    status: AttemptStatus
    state_token: int
    attempt_count: int = 0
    failure_reason: str | None = None
    attempt_receipt: str | None = None
    provider_identity: str | None = None
    finding_ids: tuple[str, ...] = ()
    evidence_digest: str | None = None
    summaries: tuple[str, ...] = ()
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ObservationAdviceSemanticOutcome:
    """Terminal result of one dispatch, as recorded on the durable row."""

    status: TerminalStatus
    failure_reason: str | None = None
    attempt_receipt: str | None = None
    provider_identity: str | None = None
    finding_ids: tuple[str, ...] = ()
    evidence_digest: str | None = None
    summaries: tuple[str, ...] = ()
    details: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status == "succeeded":
            if self.failure_reason is not None:
                raise ValueError("advice_semantic_outcome_invalid")
        elif self.failure_reason not in ADVICE_SEMANTIC_FAILURE_REASONS:
            raise ValueError("advice_semantic_outcome_invalid")
        if self.status != "succeeded" and self.finding_ids:
            raise ValueError("advice_semantic_outcome_invalid")


@dataclass(frozen=True, slots=True)
class ObservationAdviceSemanticDeferral:
    """An admission the frequency bound refused without writing a row or contacting a provider.

    ``rate_limited``: the session's last provider-reaching attempt is too recent.
    ``retry_backoff``: this identity's last attempt failed and its backoff has not elapsed.
    """

    reason: Literal["rate_limited", "retry_backoff"]
    retry_after_seconds: float
    previous: ObservationAdviceSemanticAttempt | None = None


class ObservationAdviceSemanticRepository(Protocol):
    """Generation-fenced durable attempt repository (one per task bundle)."""

    def schedule(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        basis_digest: str,
        subject_digest: str,
        coverage_gaps: tuple[str, ...],
        packet_json: bytes,
        enqueued_at: str,
        max_pending: int,
        min_interval_seconds: int = 0,
        retry_base_seconds: int = 0,
    ) -> ObservationAdviceSemanticAttempt | ObservationAdviceSemanticDeferral: ...

    def lookup(
        self, *, yoetz_session_id: str, basis_digest: str
    ) -> ObservationAdviceSemanticAttempt | None: ...

    def latest_for_identity(
        self, *, yoetz_session_id: str, identity: str
    ) -> ObservationAdviceSemanticAttempt | None: ...

    def claim_next(
        self,
        *,
        service_generation: int,
        lease_owner: str,
        lease_expires_at: str,
        now: str,
    ) -> ObservationAdviceSemanticAttempt | None: ...

    def complete(
        self,
        *,
        attempt: ObservationAdviceSemanticAttempt,
        service_generation: int,
        lease_owner: str,
        outcome: ObservationAdviceSemanticOutcome,
        recorded_at: str,
    ) -> None: ...

    def list_pending_workspaces(self) -> tuple[str, ...]: ...


type AdviceSemanticDispatch = Callable[
    [ObservationAdviceSemanticAttempt], Awaitable[ObservationAdviceSemanticOutcome]
]
# Shielded, bounded post-cancellation reconciliation for one claimed row. ``None`` means the
# attempt never consumed a disclosure authorization, so the ordinary ``cancelled`` outcome stands.
type AdviceSemanticCancellationReconciler = Callable[
    [ObservationAdviceSemanticAttempt], Awaitable[ObservationAdviceSemanticOutcome | None]
]
type NowProvider = Callable[[], str]
# ``(yoetz_session_id) -> the task route can reach a provider`` (#923): the route is ACTIVE, and
# its repository authority is granted and admits LLM-inference egress. Read from the policy store,
# never through the privacy admission lock; gates admission together with provider readiness.
type AdviceSemanticRouteReady = Callable[[str], Awaitable[bool]]
# ``() -> a usable provider exists now`` (#923): an endpoint is bound, the machine privacy policy
# admits LLM-inference egress, and the configured credential is present. Read from current facts
# on every build, never from the READY snapshot; a probe failure counts as not ready.
type AdviceSemanticProviderReady = Callable[[], Awaitable[bool]]
# ``(workspace, yoetz_session_id, delay_seconds)``: ask for an advice rebuild once a deferred or
# backed-off admission becomes eligible. Must not block; the supervisor owns the timer.
type AdviceSemanticRevisit = Callable[[str, str, float], None]


def addon_from_attempt(
    attempt: ObservationAdviceSemanticAttempt | None,
) -> ObservationAdviceSemanticAddon | None:
    """Project a durable row onto the additive advice addon without inventing success."""

    if attempt is None:
        return None
    if attempt.status == "succeeded":
        return ObservationAdviceSemanticAddon(
            finding_ids=cast(tuple[FindingId, ...], attempt.finding_ids),
            evidence_digest=attempt.evidence_digest,
            next_action=None,
            summaries=attempt.summaries,
            details=attempt.details,
            provider_identity=attempt.provider_identity,
            attempt_receipt=attempt.attempt_receipt,
            failure_reason=None,
        )
    if attempt.status in {"pending", "running"}:
        return ObservationAdviceSemanticAddon(
            finding_ids=(),
            evidence_digest=None,
            next_action=None,
            summaries=(),
            details=(),
            provider_identity=None,
            attempt_receipt=None,
            failure_reason=ADVICE_SEMANTIC_PENDING_REASON,
        )
    reason = (
        attempt.failure_reason
        if attempt.failure_reason in ADVICE_SEMANTIC_FAILURE_REASONS
        else "provider_failed"
    )
    return ObservationAdviceSemanticAddon(
        finding_ids=(),
        evidence_digest=None,
        next_action=None,
        summaries=(),
        details=(),
        provider_identity=attempt.provider_identity,
        attempt_receipt=attempt.attempt_receipt,
        failure_reason=reason,
    )


async def reconcile_cancelled_advice_request(
    minted: tuple[str, str] | None,
    recover: Callable[[str], Awaitable[SemanticEgressAttemptUnknown | None]] | None,
    *,
    timeout_seconds: float = ADVICE_SEMANTIC_CANCEL_RECOVERY_SECONDS,
) -> ObservationAdviceSemanticOutcome | None:
    """Outcome for an advisory dispatch cancelled by a foreground rebind (#755, #923).

    ``minted`` is the ``(request_id, provider_id)`` the dispatch minted before entering the
    privacy-gated provider path, or ``None`` when it was cancelled earlier. ``None`` is returned
    only when no provider call can have started: nothing was minted, or the audit proves the
    request's disclosure authorization was never consumed. Otherwise the call's usage is unknown
    and the row names the provider, plus the consumed attempt's terminal receipt (else its
    privacy proposal) when the bounded lookup finds it. The provider is never re-entered.
    """

    if minted is None:
        return None
    request_id, provider_id = minted
    usage_unknown = ObservationAdviceSemanticOutcome(
        status="cancelled", failure_reason="cancelled", provider_identity=provider_id
    )
    if recover is None:
        return usage_unknown
    try:
        recovered = await asyncio.wait_for(recover(request_id), timeout_seconds)
    except TimeoutError:
        return usage_unknown
    except Exception as exc:  # noqa: BLE001 - an unreadable audit cannot prove no call started
        record_unexpected_exception_without_raising(
            exc,
            component="application.observation_advice_semantic",
            operation="cancelled_request_recovery_failed",
        )
        return usage_unknown
    if recovered is None:
        return None
    return ObservationAdviceSemanticOutcome(
        status="cancelled",
        failure_reason="cancelled",
        attempt_receipt=recovered.receipt_id or recovered.privacy_proposal_id,
        provider_identity=provider_id,
    )


@dataclass(frozen=True, slots=True)
class ObservationAdviceSemanticScheduler:
    """Advice-build side of the worker: look up or enqueue, never dispatch.

    ``review`` runs inside the advice build on the hook path, so it performs only local
    repository reads and one bounded insert. The scoped observation gaps are stored with the
    row and reach the provider packet byte-for-byte; the old inline callback dropped them.
    """

    now: NowProvider
    max_pending: int = DEFAULT_ADVICE_SEMANTIC_MAX_PENDING
    enabled: bool = True
    min_interval_seconds: int = DEFAULT_ADVICE_SEMANTIC_MIN_INTERVAL_SECONDS
    route_ready: AdviceSemanticRouteReady | None = field(default=None, compare=False)
    revisit: AdviceSemanticRevisit | None = field(default=None, compare=False)
    provider_ready: AdviceSemanticProviderReady | None = field(default=None, compare=False)

    async def review(
        self,
        *,
        store: object,
        workspace: str,
        candidates: Sequence[ObservationAdviceCandidate],
        basis: str,
        gaps: Sequence[str],
        yoetz_session_id: str | None,
    ) -> ObservationAdviceSemanticAddon | None:
        if not self.enabled or yoetz_session_id is None or not candidates:
            return None
        repository = _repository_for(store)
        if repository is None:
            return None
        sorted_gaps = tuple(sorted({gap for gap in gaps if gap}, key=str.encode))
        packet = minimized_semantic_evidence_packet(
            candidates,
            basis,
            coverage_gaps=sorted_gaps,
            finding_summaries=tuple(str(item.rule_code) for item in candidates),
        )
        # The packet contains rule summaries, not source content. Key reuse by the stable
        # candidate identity, excluding the rolling stream digest and evidence counts. Keep the
        # original basis in the frozen packet and hash those exact bytes for disclosure provenance.
        identity = advice_candidate_identity(packet)
        latest = repository.latest_for_identity(
            yoetz_session_id=yoetz_session_id, identity=identity
        )
        if not (
            await self._probe(self.provider_ready, "provider_ready_probe_failed")
            and await self._probe(self.route_ready, "route_ready_probe_failed", yoetz_session_id)
        ):
            # Advice that cannot reach a provider never enqueues (#923): no row, no revisit, no
            # pending gap. A review this identity already completed stays a recorded fact.
            if latest is not None and latest.status == "succeeded":
                return addon_from_attempt(latest)
            return ObservationAdviceSemanticAddon(
                finding_ids=(),
                evidence_digest=None,
                failure_reason=ADVICE_SEMANTIC_UNREACHABLE_REASON,
            )
        payload = canonical_encode(cast(JsonValue, dict(packet)))
        subject = canonical_digest(cast(JsonValue, dict(packet)))
        scheduled = repository.schedule(
            workspace=workspace,
            yoetz_session_id=yoetz_session_id,
            basis_digest=identity,
            subject_digest=subject,
            coverage_gaps=sorted_gaps,
            packet_json=payload,
            enqueued_at=self.now(),
            max_pending=self.max_pending,
            min_interval_seconds=self.min_interval_seconds,
            retry_base_seconds=self.min_interval_seconds,
        )
        if isinstance(scheduled, ObservationAdviceSemanticDeferral):
            self._request_revisit(workspace, yoetz_session_id, scheduled.retry_after_seconds)
            if scheduled.reason == "retry_backoff" and scheduled.previous is not None:
                # The last attempt's own closed reason stays visible until the retry runs.
                return addon_from_attempt(scheduled.previous)
            return ObservationAdviceSemanticAddon(
                finding_ids=(),
                evidence_digest=None,
                failure_reason=ADVICE_SEMANTIC_DEFERRED_REASON,
            )
        return addon_from_attempt(scheduled)

    async def _probe(
        self,
        probe: Callable[..., Awaitable[bool]] | None,
        operation: str,
        *arguments: str,
    ) -> bool:
        if probe is None:
            return True
        try:
            return bool(await probe(*arguments))
        except Exception as exc:  # noqa: BLE001 - an unreadable fact admits nothing this build
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_advice_semantic",
                operation=operation,
            )
            return False

    def _request_revisit(self, workspace: str, yoetz_session_id: str, delay: float) -> None:
        revisit = self.revisit
        if revisit is None:
            return
        try:
            revisit(workspace, yoetz_session_id, max(float(delay), 1.0))
        except Exception as exc:  # noqa: BLE001 - a missed revisit only waits for the next hook
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_advice_semantic",
                operation="revisit_schedule_failed",
            )


def _repository_for(store: object) -> ObservationAdviceSemanticRepository | None:
    factory = getattr(store, "advice_semantic_repository", None)
    if not callable(factory):
        return None
    repository = factory()
    if repository is None:
        return None
    return cast(ObservationAdviceSemanticRepository, repository)


@dataclass
class ObservationAdviceSemanticWorker:
    """Run one serialized, generation-fenced durable AI-powered review attempt at a time."""

    repository: ObservationAdviceSemanticRepository
    dispatch: AdviceSemanticDispatch
    service_generation: int
    lease_owner: str
    now: NowProvider
    lease_expires_at: NowProvider
    reconcile_cancelled: AdviceSemanticCancellationReconciler | None = None
    reconcile_timeout_seconds: float = DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self._active_task: asyncio.Task[object] | None = None
        self._rebind_requested = False

    def begin_rebind_scope(self) -> None:
        """Bind foreground-yield cancellation to the whole supervisor drain turn."""

        self._active_task = asyncio.current_task()

    def end_rebind_scope(self) -> None:
        if self._active_task is asyncio.current_task():
            self._active_task = None

    def request_rebind(self) -> None:
        """Ask the current provider attempt to yield for an explicit foreground start.

        The provider outcome is not converted into success. ``run_once`` records the normal
        ``cancelled`` terminal outcome before propagating cancellation so the supervisor can
        release its task runtime and let the foreground session rebind.
        """

        if self._rebind_requested:
            return
        self._rebind_requested = True
        active = self._active_task
        if active is not None and active is not asyncio.current_task():
            active.cancel()

    async def run_once(self) -> ObservationAdviceSemanticAttempt | None:
        if self._rebind_requested:
            return None
        attempt = self.repository.claim_next(
            service_generation=self.service_generation,
            lease_owner=self.lease_owner,
            lease_expires_at=self.lease_expires_at(),
            now=self.now(),
        )
        if attempt is None:
            return None
        if self._rebind_requested:
            self._complete(
                attempt,
                ObservationAdviceSemanticOutcome(status="cancelled", failure_reason="cancelled"),
            )
            return attempt
        try:
            # Background advice is never a completion gate: routine output limit plus the
            # adapter's lower background effort, independent of any explicit ``check`` profile.
            with semantic_budget_profile_scope("routine"), semantic_background_scope():
                outcome = await self.dispatch(attempt)
        except asyncio.CancelledError:
            self._complete(attempt, await self._cancelled_outcome(attempt))
            raise
        except Exception:
            outcome = ObservationAdviceSemanticOutcome(
                status="failed", failure_reason="provider_failed"
            )
        self._complete(attempt, outcome)
        return attempt

    async def _cancelled_outcome(
        self, attempt: ObservationAdviceSemanticAttempt
    ) -> ObservationAdviceSemanticOutcome:
        """Record cancellation, plus the reconciled egress provenance when authority was spent.

        A cancelled row is never a semantic success. It is also not proof that no physical
        provider call started: if the privacy audit consumed the disclosure authorization before
        the yield landed, the reconciliation reports the terminal ``outcome_unknown`` receipt for
        that consumed attempt and this row carries it as provenance. The reconciliation is
        shielded and bounded so it cannot be cancelled away and cannot hold the foreground rebind
        open; it never redispatches.
        """

        cancelled = ObservationAdviceSemanticOutcome(status="cancelled", failure_reason="cancelled")
        reconcile = self.reconcile_cancelled
        if reconcile is None:
            return cancelled
        try:
            reconciled = await asyncio.wait_for(
                asyncio.shield(reconcile(attempt)), self.reconcile_timeout_seconds
            )
        except asyncio.CancelledError:
            return cancelled
        except Exception as exc:  # noqa: BLE001 - a bounded reconciliation never blocks the rebind
            record_unexpected_exception_without_raising(
                exc,
                component="application.observation_advice_semantic",
                operation="cancelled_egress_reconciliation_failed",
            )
            return cancelled
        return cancelled if reconciled is None else reconciled

    def _complete(
        self,
        attempt: ObservationAdviceSemanticAttempt,
        outcome: ObservationAdviceSemanticOutcome,
    ) -> None:
        with contextlib.suppress(Exception):
            self.repository.complete(
                attempt=attempt,
                service_generation=self.service_generation,
                lease_owner=self.lease_owner,
                outcome=outcome,
                recorded_at=self.now(),
            )


@dataclass(frozen=True, slots=True)
class AdviceSemanticDrainHandle:
    """One workspace's durable AI-powered worker plus optional post-attempt hook."""

    workspace_commitment: str
    worker: ObservationAdviceSemanticWorker
    after_complete: Callable[[], Awaitable[None]] | None = None
    on_idle: Callable[[], Awaitable[None]] | None = None


@dataclass
class ObservationAdviceSemanticSupervisor:
    """Generation-fenced background AI-powered advice owned by the ready lifecycle.

    Mirrors ``ObservationVerificationSupervisor``: the hook path only enqueues and wakes it;
    provider attempts never execute inside a hook RPC budget. Restart recovery registers
    handles for workspaces that still hold pending rows, and ``claim_next`` reclaims leases
    left by a previous service generation.
    """

    service_generation: int

    def __post_init__(self) -> None:
        self._handles: dict[str, AdviceSemanticDrainHandle] = {}
        self._wake = asyncio.Event()
        self._closed = False
        self._loop_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._active_handle: AdviceSemanticDrainHandle | None = None
        self._retirements: dict[int, asyncio.Task[None]] = {}
        self._revisit_handler: Callable[[str, str], Awaitable[None]] | None = None
        self._revisit_timers: dict[tuple[str, str], asyncio.TimerHandle] = {}
        self._revisit_tasks: set[asyncio.Task[None]] = set()

    def set_revisit_handler(self, handler: Callable[[str, str], Awaitable[None]] | None) -> None:
        """Install the advice rebuild used when a deferred background review becomes eligible."""

        self._revisit_handler = handler

    def schedule_revisit(self, workspace: str, yoetz_session_id: str, delay: float) -> None:
        """Rebuild one session's advice after ``delay`` seconds (trailing edge, #888).

        At most one timer per session; an existing earlier timer is kept because the rebuild
        simply defers again, rescheduling itself, if it fires before eligibility. The table is
        bounded, in memory, and cleared on stop; after a restart the next hook rebuild re-derives
        the same deferral from durable rows.
        """

        if self._closed or self._revisit_handler is None:
            return
        key = (workspace, yoetz_session_id)
        if key in self._revisit_timers or len(self._revisit_timers) >= _MAX_REVISIT_TIMERS:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._revisit_timers[key] = loop.call_later(
            max(delay, 1.0), self._fire_revisit, workspace, yoetz_session_id
        )

    def _fire_revisit(self, workspace: str, yoetz_session_id: str) -> None:
        self._revisit_timers.pop((workspace, yoetz_session_id), None)
        handler = self._revisit_handler
        if self._closed or handler is None:
            return

        async def run() -> None:
            try:
                await handler(workspace, yoetz_session_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a failed revisit waits for the next hook
                record_unexpected_exception_without_raising(
                    exc,
                    component="application.observation_advice_semantic",
                    operation="revisit_failed",
                )

        task = asyncio.get_running_loop().create_task(run(), name="observation-advice-revisit")
        self._revisit_tasks.add(task)
        task.add_done_callback(self._revisit_tasks.discard)

    def pending_revisits(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted(self._revisit_timers))

    def register(self, handle: AdviceSemanticDrainHandle) -> bool:
        if self._closed:
            return False
        if handle.workspace_commitment in self._handles:
            self._wake.set()
            return False
        self._handles[handle.workspace_commitment] = handle
        self._wake.set()
        return True

    def has_handle(self, workspace_commitment: str) -> bool:
        return workspace_commitment in self._handles

    @property
    def closed(self) -> bool:
        return self._closed

    def unregister(self, workspace_commitment: str) -> None:
        self._handles.pop(workspace_commitment, None)

    def notify(self, workspace_commitment: str | None = None) -> None:
        del workspace_commitment
        if not self._closed:
            self._wake.set()

    def request_rebind(self, workspace_commitment: str) -> None:
        """Yield one advisory handle for an explicit foreground runtime rebind.

        The supervisor keeps provider work serialized. A handle that is waiting behind another
        provider attempt can be retired immediately; the active handle is cancelled through its
        whole drain turn and lets the normal loop perform the release. This callback is called
        synchronously by the runtime admission lock, so queued retirement is scheduled and never
        awaits while the runtime lock is held.
        """

        handle = self._handles.get(workspace_commitment)
        if handle is None:
            return
        handle.worker.request_rebind()
        if self._active_handle is handle:
            return
        self._schedule_retirement(handle)

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._closed = False
        self._wake.set()
        self._loop_task = asyncio.create_task(self._run_loop(), name="observation-advice-semantic")

    async def rediscover(
        self,
        builders: Mapping[str, Callable[[], AdviceSemanticDrainHandle | None]],
    ) -> None:
        for workspace, builder in sorted(builders.items(), key=lambda item: item[0].encode()):
            if self._closed:
                return
            if workspace in self._handles:
                continue
            handle = builder()
            if handle is None:
                continue
            self.register(handle)
        self.notify()

    async def stop(self) -> None:
        self._closed = True
        self._wake.set()
        for timer in self._revisit_timers.values():
            timer.cancel()
        self._revisit_timers.clear()
        for revisit in tuple(self._revisit_tasks):
            revisit.cancel()
        if self._revisit_tasks:
            await asyncio.gather(*self._revisit_tasks, return_exceptions=True)
        task = self._loop_task
        self._loop_task = None
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        pending = [self._schedule_retirement(handle) for handle in tuple(self._handles.values())]
        pending.extend(self._retirements.values())
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def drain_once(self) -> None:
        """Run every registered worker to idle once; tests drive this without the loop."""

        await self._drain_once()

    async def _run_loop(self) -> None:
        while not self._closed:
            self._wake.clear()
            await self._drain_once()
            if self._closed:
                break
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=2.0)
            except TimeoutError:
                pass

    async def _drain_once(self) -> None:
        async with self._lock:
            handles = tuple(self._handles.values())
        for handle in handles:
            if self._closed:
                return
            if handle.worker.service_generation != self.service_generation:
                continue
            while not self._closed:
                self._active_handle = handle
                handle.worker.begin_rebind_scope()
                try:
                    attempt = await handle.worker.run_once()
                    if attempt is None:
                        await self._retire_handle(handle)
                        break
                    if handle.after_complete is not None:
                        await handle.after_complete()
                except asyncio.CancelledError:
                    # A foreground start may cooperatively cancel one in-flight provider attempt
                    # or its post-attempt advice rebuild so its runtime lease can yield. The
                    # worker already recorded ``cancelled`` when dispatch was active; retire this
                    # handle and release the runtime without rerunning the packet.
                    await self._retire_handle(handle)
                    break
                except Exception as exc:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="application.observation_advice_semantic",
                        operation="drain_failed",
                    )
                    with contextlib.suppress(asyncio.CancelledError):
                        await self._retire_handle(handle)
                    break
                finally:
                    handle.worker.end_rebind_scope()
                    if self._active_handle is handle:
                        self._active_handle = None

    def _schedule_retirement(self, handle: AdviceSemanticDrainHandle) -> asyncio.Task[None]:
        token = id(handle)
        existing = self._retirements.get(token)
        if existing is not None:
            return existing
        task = asyncio.create_task(self._release_handle(handle), name="observation-advice-retire")
        self._retirements[token] = task

        def completed(finished: asyncio.Task[None]) -> None:
            self._retirements.pop(token, None)
            if not finished.cancelled() and (failure := finished.exception()) is not None:
                record_unexpected_exception_without_raising(
                    failure,
                    component="application.observation_advice_semantic",
                    operation="retire_failed",
                )

        task.add_done_callback(completed)
        return task

    async def _retire_handle(self, handle: AdviceSemanticDrainHandle) -> None:
        # The runtime release must finish even if another host cancels the drain waiter.
        await asyncio.shield(self._schedule_retirement(handle))

    async def _release_handle(self, handle: AdviceSemanticDrainHandle) -> None:
        if self._handles.get(handle.workspace_commitment) is not handle:
            return
        self.unregister(handle.workspace_commitment)
        if handle.on_idle is not None:
            await handle.on_idle()
