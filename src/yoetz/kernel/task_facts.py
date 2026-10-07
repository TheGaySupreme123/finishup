"""Deterministic task facts derived from hook observations and the ledger (issue #977).

Yoetz's local checks used to describe only relations between ledger records ("no published
action names this item"). This module computes facts about the task's own work that the hooks
and the ledger already establish, so the agent can act on them:

* **Planned verification.** An effective obligation's ``requested_items`` of kind ``command`` is
  a verification the agent said it would run. Its exact identity is the installation-keyed
  command commitment the hook computes for every observed shell call (#909): the requested
  value gets the same light normalization and the same keyed commitment, so command text is
  never compared, stored or shown. A planned command is reported as never observed, as failing
  on its latest observed run, or as stale when an observed edit follows that run. A wrapped or
  reformatted variant is a different identity: the remedy is to run the planned command as
  recorded, or to correct the requested item to the command actually run.
* **Edits after the last verification.** An observed edit after the latest observed run the hook
  classified as ``test``, ``lint``, ``typecheck`` or ``build``.
* **Runtime facts** the hook classified at the host boundary (closed suffixes on the observed
  action description): a package install that resolved to Yoetz's own runtime or to a private
  virtual environment outside the workspace, an edit-tool write outside the workspace root, and
  verification that only ever ran as root.
* **Blockers.** A readable, unsuperseded ``decision_recorded`` whose statement holds the exact
  line ``yoetz-blocker:<kind>`` for a closed kind (authority, consent, credential,
  dependency_unavailable) and names ``affected_obligation_ids`` records that those obligations
  are blocked by something outside the agent's control. Yoetz cannot verify the claim; it
  honours it for the Stop-time closure gate and discloses it, and nothing else qualifies (missing
  data the task says is recoverable is not a blocker kind).

Self-generated evidence stays admissible here: no rule asks who produced a verification, only
whether the hooks observed it run, and when.

Every code is a closed token classified in ``kernel.closure_readiness.GAP_CLASSIFICATION``.
Requested-output facts need a check-time workspace read and live in ``requested_output_facts``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from yoetz.domain.events import (
    AcceptedEvent,
    ActionKind,
    DecisionRecordedPayload,
    LedgerRecord,
    ObligationChangeKind,
    ObligationStatus,
    RequestedItemKind,
    ResultOutcome,
    is_observation_authored,
)
from yoetz.domain.observation import normalize_observed_command, observed_command_commitment
from yoetz.domain.values import EventId, ObligationId
from yoetz.kernel.command_attempts import attempted_items_for_obligation
from yoetz.kernel.observed_failures import (
    command_identity,
    observed_action_runner_class,
    observed_action_runtime_tokens,
    observed_event_ids_from_records,
)
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import ProjectionState
from yoetz.protocol.coverage import Coverage, PublicationChannel

__all__ = [
    "AGENT_ACTIONABLE_TASK_FACT_GAPS",
    "BLOCKER_KINDS",
    "BLOCKER_MARKER",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "EDITED_AFTER_LAST_VERIFICATION_GAP",
    "INSTALL_INTO_PRIVATE_ENV_GAP",
    "INSTALL_INTO_YOETZ_RUNTIME_GAP",
    "OBLIGATION_BLOCKED_GAP",
    "PLANNED_VERIFICATION_FAILED_GAP",
    "PLANNED_VERIFICATION_NOT_OBSERVED_GAP",
    "PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP",
    "PLANNED_VERIFICATION_STALE_GAP",
    "PLANNED_VERIFICATION_UNOBSERVABLE_GAP",
    "REQUESTED_OUTPUT_GIT_IGNORED_GAP",
    "REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP",
    "REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP",
    "REQUESTED_OUTPUT_UNCHANGED_GAP",
    "REQUESTED_OUTPUT_UNVERIFIED_GAP",
    "STANDING_TASK_FACT_GAPS",
    "STOP_GATE_TOKENS",
    "TASK_FACT_GAPS",
    "VERIFICATION_ONLY_AS_ROOT_GAP",
    "WRITE_OUTSIDE_WORKSPACE_GAP",
    "RequestedOutputState",
    "TaskFactSignals",
    "BlockerDeclaration",
    "acting_started",
    "blocked_obligations",
    "blocker_declarations",
    "cooperative_event_ids_from_coverage",
    "cooperative_event_ids_from_records",
    "command_identity_key_registered",
    "effective_obligations",
    "open_effective_obligations",
    "register_command_identity_key",
    "requested_command_identity",
    "requested_output_facts",
    "task_fact_signals",
]

PLANNED_VERIFICATION_NOT_OBSERVED_GAP: Final = "planned_verification_not_observed"
PLANNED_VERIFICATION_FAILED_GAP: Final = "planned_verification_failed"
PLANNED_VERIFICATION_STALE_GAP: Final = "planned_verification_stale"
PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP: Final = "planned_verification_outcome_unknown"
PLANNED_VERIFICATION_UNOBSERVABLE_GAP: Final = "planned_verification_unobservable"
EDITED_AFTER_LAST_VERIFICATION_GAP: Final = "edited_after_last_verification"
INSTALL_INTO_YOETZ_RUNTIME_GAP: Final = "install_into_yoetz_runtime"
INSTALL_INTO_PRIVATE_ENV_GAP: Final = "install_into_private_env"
WRITE_OUTSIDE_WORKSPACE_GAP: Final = "write_outside_workspace"
VERIFICATION_ONLY_AS_ROOT_GAP: Final = "verification_only_as_root"
OBLIGATION_BLOCKED_GAP: Final = "obligation_blocked_outside_agent_control"
REQUESTED_OUTPUT_GIT_IGNORED_GAP: Final = "requested_output_git_ignored"
REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP: Final = "requested_output_ignored_by_repository"
REQUESTED_OUTPUT_UNCHANGED_GAP: Final = "requested_output_unchanged"
REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP: Final = "requested_output_outside_workspace"
REQUESTED_OUTPUT_UNVERIFIED_GAP: Final = "requested_output_unverified"
# A declared deliverable deleted or renamed away (ADR-035; computed in ``kernel.delivered_set``).
DECLARED_OUTPUT_REMOVED_GAP: Final = "declared_output_removed"

# Facts the agent removes by its own action: run the planned verification after the last edit
# (or correct the requested item to the command it runs), or stop excluding a requested output.
AGENT_ACTIONABLE_TASK_FACT_GAPS: Final = frozenset(
    {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
        EDITED_AFTER_LAST_VERIFICATION_GAP,
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,
        DECLARED_OUTPUT_REMOVED_GAP,
    }
)
# Disclosures: recorded history (an install or write already happened), a heuristic the
# observer cannot confirm, a read Yoetz could not make, or a declared blocker.
STANDING_TASK_FACT_GAPS: Final = frozenset(
    {
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
        PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
        INSTALL_INTO_YOETZ_RUNTIME_GAP,
        INSTALL_INTO_PRIVATE_ENV_GAP,
        WRITE_OUTSIDE_WORKSPACE_GAP,
        VERIFICATION_ONLY_AS_ROOT_GAP,
        OBLIGATION_BLOCKED_GAP,
        REQUESTED_OUTPUT_UNCHANGED_GAP,
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
        REQUESTED_OUTPUT_UNVERIFIED_GAP,
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    }
)
TASK_FACT_GAPS: Final = AGENT_ACTIONABLE_TASK_FACT_GAPS | STANDING_TASK_FACT_GAPS
# The closure-readiness items that make the Stop-time gate continue the agent once: work the
# agent owes (open obligations, a receipt-blocking finding) and the task facts it can repair.
STOP_GATE_TOKENS: Final = (
    "obligations_open",
    "receipt_findings_unresolved",
    # The closing AI-powered review the closure checklist requires after the last material change.
    "closing_review_required",
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
)

BLOCKER_MARKER: Final = "yoetz-blocker"
BLOCKER_KINDS: Final = ("authority", "consent", "credential", "dependency_unavailable")
_BLOCKER_LINES: Final = MappingProxyType(
    {f"{BLOCKER_MARKER}:{kind}": kind for kind in BLOCKER_KINDS}
)
_VERIFICATION_RUNNERS: Final = frozenset({"test", "lint", "typecheck", "build"})
_COOPERATIVE_CHANNELS: Final = frozenset(
    {PublicationChannel.COOPERATIVE_MCP, PublicationChannel.LOCAL_CLI}
)
# Observed commands that show work under way by themselves. Exploration, version control, and
# the unclassified ``other``/``compound`` shells (where TB4 agents read and probed before any
# change) do not; an edit or a published action does.
_ACTING_RUNNERS: Final = _VERIFICATION_RUNNERS

# ---------------------------------------------------------------------------------------------
# Installation command identity
# ---------------------------------------------------------------------------------------------

_KEY_LOCK: Final = threading.Lock()
_COMMAND_IDENTITY_KEY: list[bytes | None] = [None]


def register_command_identity_key(key_material: bytes | None) -> None:
    """Install (or clear) the installation key the hooks commit commands with.

    The service registers the local observation store's key at composition. Without it the
    planned-verification facts are not computed at all, which is reported by omission rather
    than guessed: a process that cannot compute the identity never claims a command was not run.
    """

    if key_material is not None and (
        type(key_material) is not bytes or not 16 <= len(key_material) <= 64
    ):
        raise ValueError("command_identity_key_invalid")
    with _KEY_LOCK:
        _COMMAND_IDENTITY_KEY[0] = key_material


def command_identity_key_registered() -> bool:
    return _COMMAND_IDENTITY_KEY[0] is not None


def requested_command_identity(value: str) -> str | None:
    """The keyed identity a hook would record for exactly this command, or ``None``."""

    key = _COMMAND_IDENTITY_KEY[0]
    if key is None:
        return None
    normalized = normalize_observed_command(value)
    if normalized is None:
        return None
    try:
        return observed_command_commitment(key, normalized)
    except ValueError:
        return None


# ---------------------------------------------------------------------------------------------
# Ledger facts
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlockerDeclaration:
    """One obligation's recorded blocker: the closed kind and the decision that declared it."""

    kind: str
    decision_event_id: EventId

    def __post_init__(self) -> None:
        if self.kind not in BLOCKER_KINDS:
            raise ValueError("blocker_kind_invalid")


def blocker_declarations(projection: ProjectionState) -> Mapping[ObligationId, BlockerDeclaration]:
    """Obligations a readable, unsuperseded blocker decision names, with its kind and event id.

    Only the exact statement line ``yoetz-blocker:<kind>`` for a closed kind counts, and only for
    the ids in ``affected_obligation_ids``. The first kind in ``BLOCKER_KINDS`` order wins when a
    decision names more than one; the earliest such decision in ledger order wins when several
    name the same obligation. Yoetz cannot verify the claim: the Stop gate re-asks it once and the
    closing review checks it against the task (#977, #976).
    """

    blocked: dict[ObligationId, BlockerDeclaration] = {}
    for event_id, row in projection.decisions.items():
        payload = row.payload
        if type(payload) is not DecisionRecordedPayload or row.superseded_by_event_id is not None:
            continue
        kinds = {
            _BLOCKER_LINES[line.strip()]
            for line in payload.statement.splitlines()
            if line.strip() in _BLOCKER_LINES
        }
        if not kinds:
            continue
        kind = next(item for item in BLOCKER_KINDS if item in kinds)
        for obligation in payload.affected_obligation_ids:
            blocked.setdefault(obligation, BlockerDeclaration(kind, event_id))
    return MappingProxyType(blocked)


def blocked_obligations(projection: ProjectionState) -> Mapping[ObligationId, str]:
    """Obligations a readable, unsuperseded blocker decision names, with the blocker kind."""

    return MappingProxyType(
        {obligation: item.kind for obligation, item in blocker_declarations(projection).items()}
    )


def effective_obligations(projection: ProjectionState) -> tuple[ObligationId, ...]:
    """Effective, readable, unwaived obligations of the current plan chain."""

    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if scope.effective_obligation_refs is None:
        return ()
    return tuple(
        obligation
        for obligation in scope.effective_obligation_refs
        if (record := projection.obligations.get(obligation)) is not None
        and record.payload is not None
        and record.plan_change is not ObligationChangeKind.WAIVED
    )


def open_effective_obligations(projection: ProjectionState) -> tuple[ObligationId, ...]:
    """Effective, unwaived obligations whose latest readable status is ``open``."""

    return tuple(
        obligation
        for obligation in effective_obligations(projection)
        if (payload := projection.obligations[obligation].payload) is not None
        and payload.status is ObligationStatus.OPEN
    )


@dataclass(frozen=True, slots=True)
class _ObservedRun:
    position: int
    outcome: ResultOutcome
    identity: str | None
    runner: str | None
    tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ObservedState:
    runs: tuple[_ObservedRun, ...]
    latest_edit: int | None
    edit_tokens: frozenset[str]
    command_tokens: frozenset[str]
    acting: bool


def cooperative_event_ids_from_records(records: Iterable[LedgerRecord]) -> frozenset[EventId]:
    """Agent-published (MCP or local CLI) events of one accepted prefix."""

    return frozenset(
        record.event_id
        for record in records
        if type(record) is AcceptedEvent
        and record.publication_channel in _COOPERATIVE_CHANNELS
        and not is_observation_authored(record)
    )


def cooperative_event_ids_from_coverage[Ref: str](
    coverage_by_ref: Mapping[Ref, Coverage],
) -> frozenset[EventId]:
    """Agent-published events of a frozen case, read from their service-derived channels."""

    return frozenset(
        EventId(ref)
        for ref, coverage in coverage_by_ref.items()
        if ref.startswith("evt_")
        and _COOPERATIVE_CHANNELS & set(coverage.publication_channels)
        and PublicationChannel.HOOK_OBSERVED not in set(coverage.publication_channels)
    )


def _observed_state(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
) -> _ObservedState:
    runs: list[_ObservedRun] = []
    latest_edit: int | None = None
    edit_tokens: set[str] = set()
    command_tokens: set[str] = set()
    acting = False
    edits_with_result: set[str] = set()
    commands_with_result: set[str] = set()
    for result in projection.results.values():
        payload = result.payload
        if payload is None or result.source_event_id not in observed:
            continue
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None or action.source_event_id not in observed:
            continue
        description = action.payload.description
        if action.payload.action_kind is ActionKind.EDIT:
            edits_with_result.add(str(payload.action_id))
            if payload.outcome is ResultOutcome.FAILURE:
                continue
            latest_edit = max(latest_edit or 0, result.source_frontier)
            edit_tokens.update(observed_action_runtime_tokens(description))
            acting = True
        elif action.payload.action_kind is ActionKind.COMMAND:
            commands_with_result.add(str(payload.action_id))
            runner = observed_action_runner_class(description)
            tokens = observed_action_runtime_tokens(description)
            command_tokens.update(tokens)
            if runner in _ACTING_RUNNERS:
                acting = True
            runs.append(
                _ObservedRun(
                    result.source_frontier,
                    payload.outcome,
                    command_identity(action.payload.command),
                    runner,
                    tokens,
                )
            )
    for action_ref, action in projection.actions.items():
        payload = action.payload
        if payload is None:
            continue
        if action.source_event_id in cooperative:
            # A published action is the agent's own record of acting.
            acting = True
            continue
        if action.source_event_id not in observed:
            continue
        if payload.action_kind is ActionKind.EDIT and str(action_ref) not in edits_with_result:
            # An observed edit whose outcome has not arrived yet still changed the state under
            # test as far as the observer can tell; a stated failure above never counts.
            latest_edit = max(latest_edit or 0, action.source_frontier)
            edit_tokens.update(observed_action_runtime_tokens(payload.description))
            acting = True
        elif (
            payload.action_kind is ActionKind.COMMAND
            and str(action_ref) not in commands_with_result
        ):
            # A command seen starting whose result never arrived (a lost post-event, or a run
            # still going) did run as far as the observer knows: its outcome is unknown, never
            # "not observed".
            tokens = observed_action_runtime_tokens(payload.description)
            command_tokens.update(tokens)
            runs.append(
                _ObservedRun(
                    action.source_frontier,
                    ResultOutcome.UNKNOWN,
                    command_identity(payload.command),
                    observed_action_runner_class(payload.description),
                    tokens,
                )
            )
    runs.sort(key=lambda run: run.position)
    return _ObservedState(
        tuple(runs), latest_edit, frozenset(edit_tokens), frozenset(command_tokens), acting
    )


def acting_started(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
) -> bool:
    """Whether the agent has started acting on the task.

    An observed edit, an observed test, lint, typecheck or build run, or any published action.
    Plans, obligations, guidance reads and investigation commands are not acting, so a requested
    item is not "never attempted" before work could have begun (TB4 tb4f1: 86% of all findings
    were raised before the first edit).
    """

    return _observed_state(projection, observed, cooperative).acting


@dataclass(frozen=True, slots=True)
class TaskFactSignals:
    """Closed task-fact codes for one accepted prefix.

    ``codes`` are bare codes (status gaps); ``markers`` pair a code with the obligation it names
    (``<code>:<obligation id>``) for the check case, or with nothing for a task-wide fact.
    """

    codes: tuple[str, ...]
    markers: tuple[tuple[str, ObligationId | None], ...]
    acting_started: bool
    blocked: Mapping[ObligationId, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not set(self.codes) <= TASK_FACT_GAPS:
            raise ValueError("task_fact_code_invalid")


def task_fact_signals(
    projection: ProjectionState, records: Iterable[LedgerRecord]
) -> TaskFactSignals:
    """Derive the ledger-backed task facts for exactly this prefix.

    ``records`` must be the accepted prefix that produced ``projection``: it is read only to
    establish which events are service-stamped hook observations (ADR-022).
    """

    if type(projection) is not ProjectionState:
        raise TypeError("task_facts_projection_invalid")
    prefix = tuple(records)
    observed = observed_event_ids_from_records(prefix)
    state = _observed_state(projection, observed, cooperative_event_ids_from_records(prefix))
    blocked = blocked_obligations(projection)
    markers: set[tuple[str, ObligationId | None]] = set()

    # Planned verification.
    keyed_runs = [run for run in state.runs if run.identity is not None]
    if command_identity_key_registered():
        for obligation in effective_obligations(projection):
            if obligation in blocked:
                continue
            payload = projection.obligations[obligation].payload
            assert payload is not None
            for item in payload.requested_items:
                if item.item_kind is not RequestedItemKind.COMMAND:
                    continue
                if not keyed_runs:
                    markers.add((PLANNED_VERIFICATION_UNOBSERVABLE_GAP, obligation))
                    continue
                identity = requested_command_identity(item.value)
                matching = [run for run in keyed_runs if run.identity == identity]
                if identity is None or not matching:
                    markers.add((PLANNED_VERIFICATION_NOT_OBSERVED_GAP, obligation))
                    continue
                latest = matching[-1]
                if latest.outcome in {ResultOutcome.FAILURE, ResultOutcome.PARTIAL}:
                    markers.add((PLANNED_VERIFICATION_FAILED_GAP, obligation))
                elif latest.outcome is ResultOutcome.UNKNOWN:
                    markers.add((PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP, obligation))
                if state.latest_edit is not None and state.latest_edit > latest.position:
                    markers.add((PLANNED_VERIFICATION_STALE_GAP, obligation))

    # Edits after the last verification-class run.
    verification_runs = [run for run in state.runs if run.runner in _VERIFICATION_RUNNERS]
    if (
        verification_runs
        and state.latest_edit is not None
        and state.latest_edit > verification_runs[-1].position
    ):
        markers.add((EDITED_AFTER_LAST_VERIFICATION_GAP, None))

    # Runtime facts.
    if "install yoetz_runtime" in state.command_tokens:
        markers.add((INSTALL_INTO_YOETZ_RUNTIME_GAP, None))
    if "install private_env" in state.command_tokens:
        markers.add((INSTALL_INTO_PRIVATE_ENV_GAP, None))
    if "write outside_workspace" in state.edit_tokens | state.command_tokens:
        markers.add((WRITE_OUTSIDE_WORKSPACE_GAP, None))
    if verification_runs and all("user root" in run.tokens for run in verification_runs):
        markers.add((VERIFICATION_ONLY_AS_ROOT_GAP, None))

    # Declared blockers on obligations that are still open.
    for obligation in open_effective_obligations(projection):
        if obligation in blocked:
            markers.add((OBLIGATION_BLOCKED_GAP, obligation))

    ordered = tuple(sorted(markers, key=lambda item: (item[0].encode(), (item[1] or "").encode())))
    return TaskFactSignals(
        codes=tuple(sorted({code for code, _ in ordered}, key=str.encode)),
        markers=ordered,
        acting_started=state.acting,
        blocked=blocked,
    )


# ---------------------------------------------------------------------------------------------
# Requested outputs (check-time workspace read)
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestedOutputState:
    """What one check-time, metadata-only workspace read established for a requested file.

    ``location`` is ``inside`` for a path under the checked repository root, ``outside`` for any
    other absolute path, and ``unverified`` when the read could not run. Inside the root:
    ``exists`` (no link followed), ``ignored`` (Git would not add it: ``.gitignore``,
    ``.git/info/exclude``, a configured excludes file), ``changed`` (in the working-tree change
    from the task base), and ``deleted`` (a tracked file the change deletes).
    ``ignored_by_task`` is true when the ignoring rule is ``.git/info/exclude`` (a local exclude
    that never travels with the repository) or a ``.gitignore`` the task's own change created.
    """

    location: str
    exists: bool | None = None
    ignored: bool | None = None
    changed: bool | None = None
    deleted: bool = False
    ignored_by_task: bool = False

    def __post_init__(self) -> None:
        if self.location not in {"inside", "outside", "unverified"}:
            raise ValueError("requested_output_state_invalid")


def requested_output_facts(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
) -> tuple[
    tuple[tuple[ObligationId, int], ...],
    tuple[tuple[str, ObligationId], ...],
]:
    """Split requested-file states into absent outputs and closed gap markers.

    Returns ``(absent, markers)``: ``absent`` lists (obligation, item index) pairs whose file does
    not exist and was not deleted from the task base (a receipt-blocking requested item), and
    ``markers`` the ``(code, obligation)`` gap pairs. Obligations a blocker decision names are
    skipped. A deleted tracked file is the change the request may have asked for, so it is never
    reported as missing.

    A requested ``file`` item names any file the request names, inputs included (the task's data,
    a policy to read). An existing file the change leaves untouched, or a path outside the
    checked repository, is exactly what such an input looks like, so ``requested_output_unchanged``
    and ``requested_output_outside_workspace`` are reported only for an item the record asserts
    was written: an ``edit`` action whose ``attempted_items`` names that exact value (#977, tb4v1).
    """

    blocked = blocked_obligations(projection)
    edited: dict[ObligationId, frozenset[str]] = {}
    absent: list[tuple[ObligationId, int]] = []
    markers: set[tuple[str, ObligationId]] = set()
    for (obligation, index), state in sorted(
        states.items(), key=lambda item: (item[0][0].encode(), item[0][1])
    ):
        if obligation in blocked:
            continue
        if obligation not in edited:
            edited[obligation] = attempted_items_for_obligation(
                projection, obligation, action_kind=ActionKind.EDIT
            )
        # Exact value match, as for requested_item_never_attempted: no path normalization.
        written = _requested_value(projection, obligation, index) in edited[obligation]
        if state.location == "outside":
            if written:
                markers.add((REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP, obligation))
            continue
        if state.location == "unverified" or state.exists is None:
            markers.add((REQUESTED_OUTPUT_UNVERIFIED_GAP, obligation))
            continue
        if not state.exists:
            if not state.deleted:
                absent.append((obligation, index))
            continue
        if state.ignored and state.ignored_by_task:
            markers.add((REQUESTED_OUTPUT_GIT_IGNORED_GAP, obligation))
        elif state.ignored:
            # The repository already ignores it (a build or checkpoint directory, say): delivery
            # by diff would omit it, but the task did not choose that, so it is a disclosure.
            markers.add((REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP, obligation))
        elif state.changed is False and written:
            markers.add((REQUESTED_OUTPUT_UNCHANGED_GAP, obligation))
    return tuple(absent), tuple(
        sorted(markers, key=lambda item: (item[0].encode(), item[1].encode()))
    )


def _requested_value(
    projection: ProjectionState, obligation: ObligationId, index: int
) -> str | None:
    row = projection.obligations.get(obligation)
    payload = None if row is None else row.payload
    if payload is None or not 0 <= index < len(payload.requested_items):
        return None
    return payload.requested_items[index].value
