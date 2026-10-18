"""Deterministic task facts derived from hook observations and the ledger (issue #977).

FinishUP's local checks used to describe only relations between ledger records ("no published
action names this item"). This module computes facts about the task's own work that the hooks
and the ledger already establish, so the agent can act on them:

* **Planned verification.** An effective obligation's ``requested_items`` of kind ``command`` is
  a verification the agent said it would run. Its identity is the installation-keyed command
  commitment the hook computes for every observed shell call (#909): the requested value gets
  the same light normalization and the same keyed commitment, so command text is never
  compared, stored or shown. A run also matches when the planned command is one of the simple
  commands the run composed (``cd /app && X && git diff --check``, ``X > log 2>&1``,
  ``time X``, ``FOO=1 X``, ``X | tee log``, a line of a ``bash <<'EOF'`` script): the hook
  commits to each segment beside the whole command (``domain.command_segments``). A segment
  match takes the run's outcome only when the run is that one command with prefixes or
  redirections; a successful ``&&`` chain is a success of every part; otherwise the outcome is
  unknown. A planned command is reported as not matched to an observed run, as failing on its
  latest matched run, or as stale when an observed edit follows that run. A requested value
  with a ``<placeholder>`` or one that is plain prose (``Broad GSEA CLI``) names no command a
  hook could observe and is reported as unobservable instead.
* **Edits after the last verification.** An observed edit after the latest observed run the hook
  classified as ``test``, ``lint``, ``typecheck`` or ``build``.
* **Runtime facts** the hook classified at the host boundary (closed suffixes on the observed
  action description): a package install that resolved to FinishUP's own runtime or to a private
  virtual environment outside the workspace, an edit-tool write outside the workspace root, and
  verification that only ever ran as root.
* **Blockers.** A readable, unsuperseded ``decision_recorded`` whose statement holds the exact
  line ``finishup-blocker:<kind>`` for a closed kind (authority, consent, credential,
  dependency_unavailable) and names ``affected_obligation_ids`` claims that those obligations
  are blocked by something outside the agent's control. FinishUP cannot verify the claim. The first
  such decision is only *claimed* (``obligation_blocker_unconfirmed``, agent work: repair first,
  or confirm); it becomes a standing ``obligation_blocked_outside_agent_control`` only once a
  later decision repeats the same line for the same obligation after the publish-time challenge
  and the Stop-time re-ask (#985). A FinishUP limit is never a blocker, and missing data the task
  says is recoverable is not a blocker kind.
* **Disclosures (#995).** An exact decision statement line ``finishup-assumption:<obligation id>``
  or ``finishup-verification-limit:<obligation id>`` discloses a best-effort assumption or an
  inherent verification limit. It is never a blocker and never a fact: readiness lists it as a
  standing code and the receipt names it.
* **Acknowledged obligations (#997).** An obligation published as ``acknowledged_not_done`` gets no
  task fact and no requested-item finding; readiness and the receipt disclose it as not done.

Self-generated evidence stays admissible here: no rule asks who produced a verification, only
whether the hooks observed it run, and when.

Every code is a closed token classified in ``kernel.closure_readiness.GAP_CLASSIFICATION``.
Requested-output facts need a check-time workspace read and live in ``requested_output_facts``.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import posixpath
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Final, cast

from finishup.domain.command_segments import (
    PlannedSegment,
    exact_segment_commitments,
    planned_segments,
    requested_command_shape,
)
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    DecisionRecordedPayload,
    LedgerRecord,
    ObligationChangeKind,
    ObligationStatus,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    SessionOpenedPayload,
    is_observation_authored,
)
from finishup.domain.observation import normalize_observed_command, observed_command_commitment
from finishup.domain.task_fact_tokens import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS as AGENT_ACTIONABLE_TASK_FACT_GAPS,
)
from finishup.domain.task_fact_tokens import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP as DECLARED_OUTPUT_CONTENT_MOVED_GAP,
)
from finishup.domain.task_fact_tokens import (
    DECLARED_OUTPUT_EMPTIED_GAP as DECLARED_OUTPUT_EMPTIED_GAP,
)
from finishup.domain.task_fact_tokens import (
    DECLARED_OUTPUT_NOT_REVIEWABLE_GAP as DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
)
from finishup.domain.task_fact_tokens import (
    DECLARED_OUTPUT_REMOVED_GAP as DECLARED_OUTPUT_REMOVED_GAP,
)
from finishup.domain.task_fact_tokens import (
    DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP as DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP,
)
from finishup.domain.task_fact_tokens import (
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP as DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
)
from finishup.domain.task_fact_tokens import (
    EDITED_AFTER_LAST_VERIFICATION_GAP as EDITED_AFTER_LAST_VERIFICATION_GAP,
)
from finishup.domain.task_fact_tokens import (
    INSTALL_INTO_FINISHUP_RUNTIME_GAP as INSTALL_INTO_FINISHUP_RUNTIME_GAP,
)
from finishup.domain.task_fact_tokens import (
    INSTALL_INTO_PRIVATE_ENV_GAP as INSTALL_INTO_PRIVATE_ENV_GAP,
)
from finishup.domain.task_fact_tokens import (
    OBLIGATION_BLOCKED_GAP as OBLIGATION_BLOCKED_GAP,
)
from finishup.domain.task_fact_tokens import (
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP as OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_AGENT_LINKED_GAP as PLANNED_VERIFICATION_AGENT_LINKED_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_FAILED_GAP as PLANNED_VERIFICATION_FAILED_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP as PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP as PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP as PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_STALE_GAP as PLANNED_VERIFICATION_STALE_GAP,
)
from finishup.domain.task_fact_tokens import (
    PLANNED_VERIFICATION_UNOBSERVABLE_GAP as PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
)
from finishup.domain.task_fact_tokens import (
    REQUESTED_OUTPUT_GIT_IGNORED_GAP as REQUESTED_OUTPUT_GIT_IGNORED_GAP,
)
from finishup.domain.task_fact_tokens import (
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP as REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
)
from finishup.domain.task_fact_tokens import (
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP as REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
)
from finishup.domain.task_fact_tokens import (
    REQUESTED_OUTPUT_UNCHANGED_GAP as REQUESTED_OUTPUT_UNCHANGED_GAP,
)
from finishup.domain.task_fact_tokens import (
    REQUESTED_OUTPUT_UNVERIFIED_GAP as REQUESTED_OUTPUT_UNVERIFIED_GAP,
)
from finishup.domain.task_fact_tokens import (
    STANDING_TASK_FACT_GAPS as STANDING_TASK_FACT_GAPS,
)
from finishup.domain.task_fact_tokens import (
    STOP_GATE_TOKENS as STOP_GATE_TOKENS,
)
from finishup.domain.task_fact_tokens import (
    TASK_FACT_GAPS as TASK_FACT_GAPS,
)
from finishup.domain.task_fact_tokens import (
    VERIFICATION_ONLY_AS_ROOT_GAP as VERIFICATION_ONLY_AS_ROOT_GAP,
)
from finishup.domain.task_fact_tokens import (
    WRITE_OUTSIDE_WORKSPACE_GAP as WRITE_OUTSIDE_WORKSPACE_GAP,
)
from finishup.domain.values import EventId, ObligationId, obligation_id
from finishup.domain.workspace_effect import path_beyond_workspace_fingerprint
from finishup.domain.write_scope import finishup_artifact_name, notes_artifact_name, scratch_overlap
from finishup.kernel.command_attempts import attempted_items_for_obligation
from finishup.kernel.fact_lineage import (
    RULE_COMMAND_MATCH,
    RULE_COMMAND_UNMATCHED,
    RULE_EDIT_AFTER_RUN,
    FactLineage,
)
from finishup.kernel.observed_failures import (
    NON_COUNTING_WRITE_TOKENS,
    SHELL_EDIT_TOKENS,
    command_identity,
    command_segment_identities,
    observed_action_runner_class,
    observed_action_runtime_tokens,
    observed_edit_counts,
    observed_event_ids_from_records,
    observed_shell_write_counts,
    success_certified_identities,
)
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import (
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionState,
)
from finishup.protocol.coverage import Coverage, PublicationChannel

__all__ = [
    "AGENT_ACTIONABLE_TASK_FACT_GAPS",
    "BLOCKER_KINDS",
    "BLOCKER_MARKER",
    "LEGACY_BLOCKER_MARKER",
    "LEGACY_DISCLOSURE_MARKERS",
    "DECLARED_OUTPUT_CONTENT_MOVED_GAP",
    "DECLARED_OUTPUT_EMPTIED_GAP",
    "DECLARED_OUTPUT_NOT_REVIEWABLE_GAP",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP",
    "DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP",
    "EDITED_AFTER_LAST_VERIFICATION_GAP",
    "INSTALL_INTO_PRIVATE_ENV_GAP",
    "INSTALL_INTO_FINISHUP_RUNTIME_GAP",
    "OBLIGATION_BLOCKED_GAP",
    "PLANNED_VERIFICATION_AGENT_LINKED_GAP",
    "OBLIGATION_BLOCKER_UNCONFIRMED_GAP",
    "PLANNED_VERIFICATION_FAILED_GAP",
    "PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP",
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
    "ObservedCommandRun",
    "PlannedCommand",
    "PlannedMatch",
    "RequestedOutputState",
    "TaskFactSignals",
    "BlockerDeclaration",
    "acting_started",
    "declared_path_beyond_fingerprint",
    "task_workspace_root",
    "acknowledged_obligation_ids",
    "agent_linked_run_events",
    "observed_planned_commands",
    "observed_run_from_command",
    "BLOCKER_NOTICE_CLAIMED",
    "BLOCKER_NOTICE_CODES",
    "BLOCKER_NOTICE_CONFIRMED",
    "BLOCKER_NOTICE_WITHOUT_EFFECT",
    "BlockerNotice",
    "DISCLOSURE_KINDS",
    "DISCLOSURE_MARKERS",
    "DisclosureDeclaration",
    "disclosure_declarations",
    "disclosure_line_obligations",
    "blocked_obligations",
    "blocker_declarations",
    "blocker_publication_notices",
    "confirmed_blocked_obligation_ids",
    "decision_batches",
    "cooperative_event_ids_from_coverage",
    "cooperative_event_ids_from_records",
    "command_identity_key_registered",
    "declared_output_items",
    "deliverable_path_identity",
    "effective_obligation_ids",
    "effective_obligations",
    "material_edit_recorded",
    "open_effective_obligations",
    "register_command_identity_key",
    "planned_match",
    "planned_verification_commands",
    "planned_verification_passed",
    "requested_command_identities",
    "requested_command_identity",
    "requested_planned_command",
    "requested_output_facts",
    "requested_verification_run_events",
    "superseded_unnamed_outputs",
    "task_fact_signals",
    "non_counting_edits_exempt",
    "passing_verification_observed",
]

BLOCKER_MARKER: Final = "finishup-blocker"
# Frozen legacy identifier (ADR-048): decision statements recorded before the rename carry this
# spelling and are re-parsed on every projection rebuild, so the reader accepts it permanently.
LEGACY_BLOCKER_MARKER: Final = "yoetz-blocker"
BLOCKER_KINDS: Final = ("authority", "consent", "credential", "dependency_unavailable")
# Both spellings of one kind are the same line to every rule, the confirmation rule included.
_BLOCKER_LINES: Final = MappingProxyType(
    {
        f"{marker}:{kind}": kind
        for marker in (BLOCKER_MARKER, LEGACY_BLOCKER_MARKER)
        for kind in BLOCKER_KINDS
    }
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
# Bumped on every registration, so a memo of keyed command facts (tb4n5: the acceptance-risk and
# command-mismatch per-read memos) never outlives the key its rows were derived with.
_COMMAND_IDENTITY_KEY_GENERATION: list[int] = [0]


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
        _COMMAND_IDENTITY_KEY_GENERATION[0] += 1


def command_identity_key_registered() -> bool:
    return _COMMAND_IDENTITY_KEY[0] is not None


def command_identity_key_generation() -> int:
    """How many times the installation key was (re)registered in this process."""

    return _COMMAND_IDENTITY_KEY_GENERATION[0]


# Frozen legacy identifier (ADR-048): domain separator inside stored digests.
_PATH_IDENTITY_DOMAIN: Final = b"yoetz/deliverable-path/v1\x00"


def deliverable_path_identity(relative: str) -> str | None:
    """The installation-keyed commitment to one root-relative deliverable path, or ``None``.

    The same key that commits observed commands, with its own domain. History of a declared
    output is keyed on this (ADR-045), so the obligation that declares the path can change or be
    republished without starting a new history. Without the key (a process that has not
    registered it) there is no history and the caller falls back to the task-base proof alone.
    """

    key = _COMMAND_IDENTITY_KEY[0]
    if key is None or type(relative) is not str or not relative or "\x00" in relative:
        return None
    digest = hmac.new(key, _PATH_IDENTITY_DOMAIN + relative.encode("utf-8"), hashlib.sha256)
    return "hmac-sha256:" + digest.hexdigest()


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


def requested_command_identities(value: str) -> tuple[str, frozenset[str], str | None] | None:
    """The whole keyed identity of a requested command, its segment identities and composition.

    The segments are what ``domain.command_segments`` would commit for the same text, so a
    planned ``X > log`` or ``cd /app && X`` also matches a run that shares those parts. The
    composition (``single``, ``and_chain``, ``masked``; ``None`` for a simple command) says
    whether the planned command's own outcome is its one segment's (``! X`` or ``X &`` is not).
    """

    key = _COMMAND_IDENTITY_KEY[0]
    if key is None:
        return None
    normalized = normalize_observed_command(value)
    if normalized is None:
        return None
    try:
        whole = observed_command_commitment(key, normalized)
        segments = exact_segment_commitments(key, normalized)
    except ValueError:
        return None
    if segments is None:
        return whole, frozenset(), None
    return whole, frozenset(segments[0]), segments[1]


@dataclass(frozen=True, slots=True)
class PlannedCommand:
    """A requested command ready to be matched against observed runs (ADR-045).

    ``whole``, ``segments`` and ``composition`` are ``requested_command_identities``;
    ``probes`` holds, for each simple command the planned text runs, its canonical probes
    (wrappers and ``python3`` normalised away, leading-argument prefixes and flag sets).
    """

    whole: str
    segments: frozenset[str]
    composition: str | None
    probes: tuple[PlannedSegment, ...]


# How a planned command matched an observed run, strongest first. ``exact`` and ``normalized``
# are clean (the same commands, up to wrappers); ``prefix`` and ``flags`` count as a run but are
# disclosed (``planned_verification_matched_by_prefix``): the run did the planned work and more,
# or in another order, and FinishUP cannot tell whether that is what the plan meant.
MATCH_EXACT: Final = "exact"
MATCH_NORMALIZED: Final = "normalized"
MATCH_PREFIX: Final = "prefix"
MATCH_FLAGS: Final = "flags"
_MATCH_RANK: Final = {MATCH_EXACT: 0, MATCH_NORMALIZED: 1, MATCH_PREFIX: 2, MATCH_FLAGS: 3}
LOOSE_MATCH_KINDS: Final = frozenset({MATCH_PREFIX, MATCH_FLAGS})


def requested_planned_command(value: str) -> PlannedCommand | None:
    """The identities and canonical probes of a requested command, or ``None``."""

    key = _COMMAND_IDENTITY_KEY[0]
    identities = requested_command_identities(value)
    if key is None or identities is None:
        return None
    normalized = normalize_observed_command(value)
    if normalized is None:
        return None
    try:
        probes = planned_segments(key, normalized) or ()
    except ValueError:
        probes = ()
    return PlannedCommand(identities[0], identities[1], identities[2], probes)


# ---------------------------------------------------------------------------------------------
# Ledger facts
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlockerDeclaration:
    """One obligation's recorded blocker: the closed kind, the decision that claimed it, and the
    later decision that confirmed it (``None`` while the blocker is only claimed, #985)."""

    kind: str
    decision_event_id: EventId
    confirmation_event_id: EventId | None = None

    def __post_init__(self) -> None:
        if self.kind not in BLOCKER_KINDS:
            raise ValueError("blocker_kind_invalid")
        if self.confirmation_event_id == self.decision_event_id:
            raise ValueError("blocker_confirmation_invalid")

    @property
    def confirmed(self) -> bool:
        return self.confirmation_event_id is not None


def _blocker_kinds(payload: DecisionRecordedPayload) -> frozenset[str]:
    return frozenset(
        _BLOCKER_LINES[line.strip()]
        for line in payload.statement.splitlines()
        if line.strip() in _BLOCKER_LINES
    )


def decision_batches(records: Iterable[LedgerRecord]) -> Mapping[EventId, str]:
    """The publish batch (operation id) each recorded ``decision_recorded`` event arrived in."""

    return MappingProxyType(
        {
            record.event_id: str(record.operation_id)
            for record in records
            if record.schema.name == "decision_recorded"
        }
    )


def blocker_declarations(
    projection: ProjectionState, batches: Mapping[EventId, str]
) -> Mapping[ObligationId, BlockerDeclaration]:
    """Obligations a readable, unsuperseded blocker decision names, with its kind and event ids.

    Only the exact statement line ``finishup-blocker:<kind>`` (or its legacy ``yoetz-blocker:<kind>``
    spelling, ADR-048) for a closed kind counts, and only for the ids in
    ``affected_obligation_ids``. The first kind in ``BLOCKER_KINDS`` order wins when a
    decision names more than one; the earliest such decision in ledger order claims the
    obligation. The claim is confirmed by the earliest later decision that repeats the same
    ``finishup-blocker:<kind>`` line for the same obligation *in a later publish batch* (issue #985):
    the publish-time challenge is delivered in the claiming batch's result, so only a later batch
    is necessarily the agent's answer to it. A repeat in the same batch (or a second line in the
    same decision) never confirms, and a dry run records nothing. ``batches`` maps decision event
    ids to their batch (``decision_batches`` of the accepted prefix); a decision whose batch is
    unknown confirms nothing. A later decision naming the obligation with a different kind starts
    a new claim of that kind, even over a confirmed one; a superseded decision does not count, so
    superseding the claim makes the next unsuperseded blocker decision the claim. FinishUP still
    cannot verify the claim; the closing review checks it against the task (#978). Ledger order and
    batch are recorded facts, so the answer is replay-stable.
    """

    rows = sorted(
        (
            (row.source_frontier, event_id, row.payload)
            for event_id, row in projection.decisions.items()
            if type(row.payload) is DecisionRecordedPayload and row.superseded_by_event_id is None
        ),
        key=lambda item: (item[0], str(item[1]).encode()),
    )
    blocked: dict[ObligationId, BlockerDeclaration] = {}
    for _position, event_id, payload in rows:
        assert payload is not None
        kinds = _blocker_kinds(payload)
        if not kinds:
            continue
        kind = next(item for item in BLOCKER_KINDS if item in kinds)
        for obligation in payload.affected_obligation_ids:
            current = blocked.get(obligation)
            if current is None or current.kind not in kinds:
                # A first claim, or a different kind: the new kind is a new claim that must face
                # its own challenge, so a confirmed blocker of another kind does not carry over.
                blocked[obligation] = BlockerDeclaration(kind, event_id)
                continue
            claimed_batch = batches.get(current.decision_event_id)
            this_batch = batches.get(event_id)
            if (
                not current.confirmed
                and claimed_batch is not None
                and this_batch is not None
                and this_batch != claimed_batch
            ):
                blocked[obligation] = BlockerDeclaration(
                    current.kind, current.decision_event_id, event_id
                )
    return MappingProxyType(blocked)


def blocked_obligations(
    projection: ProjectionState, batches: Mapping[EventId, str]
) -> Mapping[ObligationId, str]:
    """Obligations a *confirmed* blocker names, with the blocker kind (#977, #985).

    Only a confirmed blocker suppresses the per-obligation facts and findings (planned
    verification, requested outputs, ``requested_item_never_attempted``). A claimed one leaves
    the obligation's ordinary facts in place: until the agent confirms it, it is still work.
    """

    return MappingProxyType(
        {
            obligation: item.kind
            for obligation, item in blocker_declarations(projection, batches).items()
            if item.confirmed
        }
    )


def confirmed_blocked_obligation_ids(
    markers: Iterable[tuple[str, Iterable[str]]],
) -> frozenset[ObligationId]:
    """Open obligations a frozen case's task-fact markers record as confirmed blocked.

    ``markers`` are ``(code, subject refs)`` pairs (a deterministic case's gaps). The markers were
    derived from the accepted prefix with its publish batches, so a case-only reader (a local
    pack, the check-time output read) applies the same confirmation rule without the records.
    """

    return frozenset(
        cast(ObligationId, ref)
        for code, refs in markers
        if code == OBLIGATION_BLOCKED_GAP
        for ref in refs
        if ref.startswith("obl_")
    )


@dataclass(frozen=True, slots=True)
class BlockerNotice:
    """One publish-time notice for a ``finishup-blocker`` line (#985): a closed notice code."""

    obligation_id: ObligationId
    kind: str
    notice: str

    def __post_init__(self) -> None:
        if self.kind not in BLOCKER_KINDS or self.notice not in BLOCKER_NOTICE_CODES:
            raise ValueError("blocker_notice_invalid")


BLOCKER_NOTICE_CLAIMED: Final = "blocker_claimed"
BLOCKER_NOTICE_CONFIRMED: Final = "blocker_confirmed"
BLOCKER_NOTICE_WITHOUT_EFFECT: Final = "blocker_without_effect"
BLOCKER_NOTICE_CODES: Final = (
    BLOCKER_NOTICE_CLAIMED,
    BLOCKER_NOTICE_CONFIRMED,
    BLOCKER_NOTICE_WITHOUT_EFFECT,
)


def blocker_publication_notices(
    projection: ProjectionState,
    decisions: Iterable[tuple[EventId, DecisionRecordedPayload]],
) -> tuple[BlockerNotice, ...]:
    """Closed notices for the ``finishup-blocker`` lines one publish batch carries (#985).

    ``projection`` already includes the batch: the accepted result frontier of a publish, or the
    provisional fold of a dry run. ``decisions`` are the batch's ``(event id, payload)`` pairs.
    Each ``(obligation, kind)`` gets one notice: ``blocker_without_effect`` when the obligation is
    not open (a blocker on finished work changes nothing; a FinishUP limit is ``respond
    self_verified``, a refusal ``acknowledged_not_done``), ``blocker_confirmed`` when the
    obligation's blocker of that kind was claimed in an earlier batch (this batch confirms it, or
    it already was), and ``blocker_claimed`` otherwise (the challenge: repair first; confirm only
    by repeating the line in a later publish). An obligation id the projection does not know is
    not open either, so it gets ``blocker_without_effect`` too (admission also reports it).
    """

    batch = tuple(decisions)
    batch_ids = frozenset(event for event, _payload in batch)
    open_now = set(open_effective_obligations(projection))
    # Within this batch every decision shares one batch key, and every earlier decision is in a
    # different batch than this one; that is all the confirmation rule needs here.
    batches = {
        event_id: ("this" if event_id in batch_ids else str(event_id))
        for event_id in projection.decisions
    }
    declared = blocker_declarations(projection, batches)
    notices: dict[tuple[ObligationId, str], str] = {}
    for _event_id, payload in batch:
        if type(payload) is not DecisionRecordedPayload:
            continue
        kinds = _blocker_kinds(payload)
        if not kinds:
            continue
        kind = next(item for item in BLOCKER_KINDS if item in kinds)
        for obligation in payload.affected_obligation_ids:
            key = (obligation, kind)
            if key in notices:
                continue
            if obligation not in open_now:
                notices[key] = BLOCKER_NOTICE_WITHOUT_EFFECT
                continue
            current = declared.get(obligation)
            confirmed = current is not None and current.confirmed and current.kind in kinds
            notices[key] = BLOCKER_NOTICE_CONFIRMED if confirmed else BLOCKER_NOTICE_CLAIMED
    return tuple(
        BlockerNotice(obligation, kind, notice)
        for (obligation, kind), notice in sorted(
            notices.items(), key=lambda item: (item[0][0].encode(), item[0][1].encode())
        )
    )


# ---------------------------------------------------------------------------------------------
# Disclosures (#995, ADR-033): an assumption or an inherent verification limit, never a blocker
# ---------------------------------------------------------------------------------------------

# ``finishup-assumption:<obligation id>`` discloses a best-effort choice the agent made for that
# obligation; ``finishup-verification-limit:<obligation id>`` discloses a check the agent inherently
# cannot run (a hidden verifier, a private trace). The decision's rationale carries the text.
DISCLOSURE_MARKERS: Final = MappingProxyType(
    {"finishup-assumption": "assumption", "finishup-verification-limit": "verification_limit"}
)
# Frozen legacy identifiers (ADR-048): decision statements recorded before the rename carry these
# spellings and are re-parsed on every projection rebuild, so the reader accepts them permanently.
LEGACY_DISCLOSURE_MARKERS: Final = MappingProxyType(
    {"yoetz-assumption": "assumption", "yoetz-verification-limit": "verification_limit"}
)
_DISCLOSURE_LINE_MARKERS: Final = MappingProxyType(
    {**DISCLOSURE_MARKERS, **LEGACY_DISCLOSURE_MARKERS}
)
DISCLOSURE_KINDS: Final = ("assumption", "verification_limit")


@dataclass(frozen=True, slots=True)
class DisclosureDeclaration:
    """One obligation's recorded disclosure: the closed kind and the decision that records it."""

    obligation_id: ObligationId
    kind: str
    decision_event_id: EventId

    def __post_init__(self) -> None:
        if self.kind not in DISCLOSURE_KINDS:
            raise ValueError("disclosure_kind_invalid")


def disclosure_line_obligations(statement: str) -> tuple[tuple[str, ObligationId], ...]:
    """The ``(kind, obligation id)`` pairs a decision statement's disclosure lines name.

    Only a line ``finishup-assumption:<obligation id>`` or ``finishup-verification-limit:<obligation
    id>`` with a well-formed obligation id counts, or the same line with its legacy ``yoetz-``
    spelling (ADR-048); whitespace around the line and around the colon is ignored, and anything
    else on the line makes it ordinary prose. Pairs are
    unique, in first-seen order. The reducer reads the same pairs to report an id that names no
    recorded obligation as ``missing_ref``.
    """

    pairs: dict[tuple[str, ObligationId], None] = {}
    for line in statement.splitlines():
        marker, separator, value = line.strip().partition(":")
        kind = _DISCLOSURE_LINE_MARKERS.get(marker.strip())
        if kind is None or not separator:
            continue
        try:
            obligation = obligation_id(value.strip())
        except ValueError:
            continue
        pairs.setdefault((kind, obligation), None)
    return tuple(pairs)


def disclosure_declarations(projection: ProjectionState) -> tuple[DisclosureDeclaration, ...]:
    """Disclosures readable, unsuperseded decisions record for recorded obligations (#995).

    One row per ``(obligation, kind)``: the earliest such decision in ledger order records it. A
    disclosure never blocks, never resolves and never changes an obligation's status or readiness
    state; readiness lists it as a standing code and the receipt names it by id. A decision
    superseded by a later one (``supersedes_event_id``) no longer discloses anything, so the
    agent withdraws a disclosure exactly as it withdraws a blocker. An id that names no recorded
    obligation discloses nothing (the reducer reports it as ``missing_ref``). Sorted by
    obligation, then kind.
    """

    rows = sorted(
        (
            (row.source_frontier, event_id, row.payload)
            for event_id, row in projection.decisions.items()
            if type(row.payload) is DecisionRecordedPayload and row.superseded_by_event_id is None
        ),
        key=lambda item: (item[0], str(item[1]).encode()),
    )
    declared: dict[tuple[ObligationId, str], EventId] = {}
    for _position, event_id, payload in rows:
        assert payload is not None
        for kind, obligation in disclosure_line_obligations(payload.statement):
            record = projection.obligations.get(obligation)
            if record is None or record.payload is None:
                continue
            declared.setdefault((obligation, kind), event_id)
    return tuple(
        DisclosureDeclaration(obligation, kind, event)
        for (obligation, kind), event in sorted(
            declared.items(), key=lambda item: (item[0][0].encode(), item[0][1].encode())
        )
    )


def effective_obligations(projection: ProjectionState) -> tuple[ObligationId, ...]:
    """Effective, readable, unwaived obligations of the current plan chain."""

    return effective_obligation_ids(
        projection.plans, projection.obligations, projection.coverage_gaps
    )


def effective_obligation_ids(
    plans: Mapping[int, PlanProjectionRecord],
    obligations: Mapping[ObligationId, ObligationProjectionRecord],
    coverage_gaps: tuple[str, ...],
) -> tuple[ObligationId, ...]:
    """``effective_obligations`` over the collections the reducer folds (#1104)."""

    scope = current_plan_scope(plans, coverage_gaps)
    if scope.effective_obligation_refs is None:
        return ()
    return tuple(
        obligation
        for obligation in scope.effective_obligation_refs
        if (record := obligations.get(obligation)) is not None
        and record.payload is not None
        and record.plan_change is not ObligationChangeKind.WAIVED
    )


_PATH_TOKEN_EDGES: Final = " \t\r\n`'\"()[]{}<>,;:"
_CONDITION_WORD: Final = re.compile(r"\b(?:when|whenever|if|unless)\b", re.IGNORECASE)


def _spells_path(spelled: str, value: str) -> bool:
    """Whether ``spelled`` names the declared path ``value``: the same path, a longer (absolute)
    spelling of it, or, for an absolute declaration, its tail with at least one directory. A
    bare file name never names a declared path in another directory (checker R2 #3)."""

    spelled = spelled.removeprefix("./").rstrip("/")
    wanted = value.removeprefix("./").rstrip("/")
    if not spelled or not wanted:
        return False
    return (
        spelled == wanted
        or spelled.endswith("/" + wanted)
        or (wanted.startswith("/") and "/" in spelled and wanted.endswith("/" + spelled))
    )


def _change_paths(text: str) -> tuple[str, ...]:
    """The whitespace-separated tokens of a ``change`` value, trimmed of quoting and punctuation."""

    return tuple(
        token
        for raw in text.split()
        if (token := raw.strip(_PATH_TOKEN_EDGES).rstrip(".").strip(_PATH_TOKEN_EDGES))
    )


def _preserves_output(item: RequestedItem, value: str, outputs: tuple[str, ...]) -> bool:
    """Whether a replacement's item keeps or explicitly re-models the output ``value`` (tb4n5).

    A ``file`` or ``directory`` item that is not ``role: input`` re-declares it (an input item
    is no delivery promise). A ``change`` item releases it only in the documented correction
    form: the item spells that declared path, names none of the superseded obligation's other
    ``outputs``, states a condition (``when``, ``if``, ``unless``) and never calls it
    unconditional. Anything else is ambiguous and keeps the output required (checker R2 #3).
    """

    if item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}:
        return item.role is not RequestedItemRole.INPUT and _spells_path(item.value, value)
    if item.item_kind is not RequestedItemKind.CHANGE:
        return False
    text = item.value
    if "unconditional" in text.lower() or _CONDITION_WORD.search(text) is None:
        return False
    tokens = _change_paths(text)
    named = [output for output in outputs if any(_spells_path(token, output) for token in tokens)]
    return named == [value]


def superseded_unnamed_outputs(
    projection: ProjectionState,
) -> tuple[tuple[ObligationId, int], ...]:
    """Requested outputs a plan correction dropped without naming them (tb4n5, ADR-033).

    An obligation a ``plan_revised`` superseded with replacements leaves the effective plan, and
    with it its requested files. The documented correction of a conditional output re-declares
    each file the replacements still deliver as a ``file`` item (not ``role: input``) and names a
    conditional one, by its declared path, in a ``change`` item of its own that states its
    condition (``_preserves_output``). A requested ``file`` or ``directory`` item (role ``output``
    or none) that no replacement preserves, transitively, either way, is still requested: the
    correction cannot launder a missing deliverable, and incidental or ambiguous prose keeps it
    required. Returns its ``(obligation, item index)`` pairs, which the check probes and reports
    exactly like an effective obligation's.
    """

    effective = frozenset(effective_obligations(projection))
    dropped: list[tuple[ObligationId, int]] = []
    for obligation, record in sorted(projection.obligations.items(), key=lambda row: row[0]):
        if (
            obligation in effective
            or record.payload is None
            or record.plan_change is not ObligationChangeKind.SUPERSEDED
            or not record.superseded_by_obligation_ids
        ):
            continue
        replacements: set[ObligationId] = set()
        pending = list(record.superseded_by_obligation_ids)
        while pending:
            current = pending.pop()
            if current in replacements:
                continue
            replacements.add(current)
            following = projection.obligations.get(current)
            if following is not None:
                pending.extend(following.superseded_by_obligation_ids)
        named_by = tuple(
            item
            for replacement in replacements
            if (row := projection.obligations.get(replacement)) is not None
            and row.payload is not None
            for item in row.payload.requested_items
        )
        outputs = tuple(
            item.value
            for item in record.payload.requested_items
            if item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}
            and item.role is not RequestedItemRole.INPUT
        )
        for index, item in enumerate(record.payload.requested_items):
            if (
                item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}
                and item.role is not RequestedItemRole.INPUT
                and not any(_preserves_output(other, item.value, outputs) for other in named_by)
            ):
                dropped.append((obligation, index))
    return tuple(dropped)


def acknowledged_obligation_ids(projection: ProjectionState) -> frozenset[ObligationId]:
    """Effective obligations the agent acknowledged as not done (#997): no task fact or
    requested-item finding is reported for them; readiness and the receipt disclose them."""

    return frozenset(
        obligation
        for obligation in effective_obligations(projection)
        if (payload := projection.obligations[obligation].payload) is not None
        and payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
    )


def open_effective_obligations(projection: ProjectionState) -> tuple[ObligationId, ...]:
    """Effective, unwaived obligations whose latest readable status is ``open``.

    ``acknowledged_not_done`` (obligation_published 1.1.0, #997) is neither open nor resolved:
    readiness and the receipt count it once, as not done (``acknowledged_obligation_ids``).
    """

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
    segments: frozenset[str] = frozenset()
    composition: str | None = None
    action_event: EventId | None = None


# Public name for the observed run the matchers take (``planned_match``, ``observed_run_from_command``).
ObservedCommandRun = _ObservedRun


@dataclass(frozen=True, slots=True)
class _ObservedState:
    runs: tuple[_ObservedRun, ...]
    latest_edit: int | None
    edit_tokens: frozenset[str]
    command_tokens: frozenset[str]
    acting: bool
    latest_edit_event: EventId | None = None


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


def _segment_fields(command: str | None) -> tuple[frozenset[str], str | None]:
    parsed = command_segment_identities(command)
    return (frozenset(), None) if parsed is None else parsed


def _planned_outcome(
    run: _ObservedRun, whole: str, segments: frozenset[str], composition: str | None = None
) -> ResultOutcome | None:
    """The outcome ``run`` establishes for one planned command, or ``None`` when unmatched.

    An identical command, or a planned command whose only simple command is the run (``X > log``
    planned, ``X`` run), takes the run's outcome. A planned command that is one simple command
    of the run, or whose simple commands all are, takes it only when the run is that one command
    with prefixes or redirections (``single``); a successful ``&&`` chain proves every part
    succeeded, and every other case (a failed chain, a pipe, ``;``, ``||``, a script) names no
    outcome for the part, so it is unknown.
    """

    if run.identity is None:
        return None
    if run.identity == whole or (
        # ``X > log`` planned, ``X`` run: the planned outcome is its one segment's, but only for a
        # ``single`` composition; a planned ``! X`` or ``X &`` inverts or detaches it.
        len(segments) == 1 and composition == "single" and run.identity in segments
    ):
        return run.outcome
    if whole not in run.segments and not (segments and segments <= run.segments | {run.identity}):
        return None
    return _attributed_outcome(run, composition)


def _attributed_outcome(run: _ObservedRun, planned_composition: str | None) -> ResultOutcome:
    """The outcome a run establishes for a planned part it matched (not the whole command).

    A planned command that masks its own outcome (``! X``, ``X &``, ``X | tee``, ``X; Y``) names
    no outcome for its part. Otherwise the run's composition decides: a ``single`` run is that
    command, a successful ``&&`` chain succeeded in every part, anything else is unknown.
    """

    if planned_composition == "masked":
        return ResultOutcome.UNKNOWN
    if run.composition == "single":
        return run.outcome
    if run.composition == "and_chain" and run.outcome is ResultOutcome.SUCCESS:
        return ResultOutcome.SUCCESS
    return ResultOutcome.UNKNOWN


@dataclass(frozen=True, slots=True)
class PlannedMatch:
    """One observed run's match to one planned command: the outcome it establishes and how."""

    outcome: ResultOutcome
    kind: str


def planned_match(run: _ObservedRun, planned: PlannedCommand) -> PlannedMatch | None:
    """How *run* matches *planned*, or ``None`` (ADR-045).

    The recorded rule first (``exact``: the same command, or the planned one is a segment of the
    run). Then the canonical rule: every simple command the plan runs must be found among the
    run's, as ``normalized`` (same command up to wrappers, ``python3``, absolute paths), else as a
    ``prefix`` (the run began with the planned arguments and went on) or as ``flags`` (the planned
    program and all its flags are present, in any order). A command that only sets the scene
    (``cd /app``) may be missing from the run, which makes the match a ``prefix`` one. The weakest
    command decides the kind; a single-token command only ever matches whole.
    """

    exact = _planned_outcome(run, planned.whole, planned.segments, planned.composition)
    if exact is not None:
        return PlannedMatch(exact, MATCH_EXACT)
    if run.identity is None or not planned.probes:
        return None
    held = run.segments | {run.identity}
    kinds: list[str] = []
    skipped_scene = False
    for probe in planned.probes:
        if probe.exact in held:
            kinds.append(MATCH_EXACT)
        elif (probe.full is not None and probe.full in held) or (
            probe.canonical_text is not None and probe.canonical_text in held
        ):
            kinds.append(MATCH_NORMALIZED)
        elif probe.prefix is not None and probe.prefix in held:
            kinds.append(MATCH_PREFIX)
        elif probe.flags and all(flag in held for flag in probe.flags):
            kinds.append(MATCH_FLAGS)
        elif probe.scene and len(planned.probes) > 1:
            skipped_scene = True
        else:
            return None
    if not kinds:
        return None
    kind = max(kinds, key=_MATCH_RANK.__getitem__)
    if skipped_scene and kind in {MATCH_EXACT, MATCH_NORMALIZED}:
        kind = MATCH_PREFIX
    if (
        len(planned.probes) == 1
        and planned.probes[0].canonical_text == run.identity
        and planned.composition != "masked"
    ):
        # The run's whole text is the planned command's canonical form (``pytest`` for a planned
        # ``python -m pytest``): one simple command, so its own outcome is the part's.
        return PlannedMatch(run.outcome, kind)
    return PlannedMatch(_attributed_outcome(run, planned.composition), kind)


def _agent_linked_runs(
    projection: ProjectionState,
    prefix: tuple[LedgerRecord, ...],
    state: _ObservedState,
    observed: frozenset[EventId],
) -> Mapping[tuple[ObligationId, str], tuple[_ObservedRun, ...]]:
    """Observed runs the agent linked to a requested command value, per obligation.

    A cooperative ``action_recorded`` of kind ``command`` whose ``attempted_items`` holds the
    exact requested value and whose ``causal_parents`` names a hook-observed command action links
    that observed run to the value (the ``command_attempts`` relevance rule). Attribution follows
    ``attempted_items_for_obligation``: an action naming obligations links only for those ids, an
    action naming none for every obligation. Only an observed command action parent counts, so a
    cooperative result or an unrelated cooperative action never links anything; the linked run's
    own observed outcome and position decide. Keys are ``(obligation, exact value)``.
    """

    runs_by_action = {run.action_event: run for run in state.runs if run.action_event is not None}
    if not runs_by_action:
        return {}
    cooperative = cooperative_event_ids_from_records(prefix)
    parents_of = {
        record.event_id: record.causal_parents
        for record in prefix
        if type(record) is AcceptedEvent and record.event_id in cooperative
    }
    linked: dict[tuple[ObligationId, str], list[_ObservedRun]] = {}
    obligations = tuple(effective_obligations(projection))
    for action in projection.actions.values():
        payload = action.payload
        if (
            payload is None
            or payload.action_kind is not ActionKind.COMMAND
            or not payload.attempted_items
            or action.source_event_id not in cooperative
        ):
            continue
        parents = [
            runs_by_action[parent]
            for parent in parents_of.get(action.source_event_id, ())
            if parent in observed and parent in runs_by_action
        ]
        if not parents:
            continue
        targets = payload.obligation_refs or obligations
        for obligation in targets:
            for value in payload.attempted_items:
                bucket = linked.setdefault((obligation, value), [])
                bucket.extend(run for run in parents if all(run is not seen for seen in bucket))
    return {
        key: tuple(sorted(value, key=lambda run: run.position)) for key, value in linked.items()
    }


def agent_linked_run_events(
    projection: ProjectionState, records: Iterable[LedgerRecord]
) -> frozenset[EventId]:
    """The observed command actions the agent linked to a requested command value (PL6-3).

    The links ``task_fact_signals`` accepts as an obligation's planned verification (see
    ``_agent_linked_runs``), for the requested command values of every effective obligation,
    keyed by the linked run's hook-observed ``action_recorded`` event. A run in this set is the
    task's declared verification by the agent's own declaration, never a run beyond it (review of
    #1043 x #1049). ``records`` must be the accepted prefix that produced ``projection``.
    """

    prefix = tuple(records)
    observed = observed_event_ids_from_records(prefix)
    state = _observed_state(projection, observed, cooperative_event_ids_from_records(prefix))
    linked = _agent_linked_runs(projection, prefix, state, observed)
    if not linked:
        return frozenset()
    events: set[EventId] = set()
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if item.item_kind is not RequestedItemKind.COMMAND:
                continue
            events.update(
                run.action_event
                for run in linked.get((obligation, item.value), ())
                if run.action_event is not None
            )
    return frozenset(events)


def requested_verification_run_events(
    projection: ProjectionState, records: Iterable[LedgerRecord]
) -> frozenset[EventId] | None:
    """The observed command actions that ran a command an effective obligation requests.

    A run of the task's own requested verification command (ADR-045 matching, or the agent's
    explicit link) is a verification run whatever its runner class, so the closing review keeps
    treating it as new input even when the workspace stayed the same (PR #1080). ``None`` means
    the task requests a command but no installation key is registered to match runs against it:
    the caller cannot tell which runs verify and must treat every run as possibly verifying.
    ``records`` must be the accepted prefix that produced ``projection``.
    """

    values: list[tuple[ObligationId, str]] = []
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        values.extend(
            (obligation, item.value)
            for item in payload.requested_items
            if item.item_kind is RequestedItemKind.COMMAND
        )
    if not values:
        return frozenset()
    if not command_identity_key_registered():
        return None
    prefix = tuple(records)
    observed = observed_event_ids_from_records(prefix)
    state = _observed_state(projection, observed, cooperative_event_ids_from_records(prefix))
    keyed = [run for run in state.runs if run.identity is not None and run.action_event]
    linked = _agent_linked_runs(projection, prefix, state, observed)
    events: set[EventId] = set()
    for obligation, value in values:
        events.update(
            run.action_event for run in linked.get((obligation, value), ()) if run.action_event
        )
        if requested_command_shape(value) != "command":
            continue
        planned = requested_planned_command(value)
        if planned is None:
            continue
        events.update(
            run.action_event
            for run in keyed
            if run.action_event is not None and planned_match(run, planned) is not None
        )
    return frozenset(events)


def task_workspace_root(records: Iterable[LedgerRecord]) -> str | None:
    """The one absolute workspace root this task's sessions name, or ``None`` when it is not known.

    ``session_opened`` keeps the ``workspace_ref`` its session started with: hook auto-attach sends
    the canonical absolute root the workspace fingerprint walks, and guidance asks an agent's
    ``start`` for the same root. A session without an absolute ref (absent, redacted, or not a
    path) or two different roots leave the root unknown. Lexical: the value is never resolved.
    """

    roots: set[str] = set()
    for record in records:
        if type(record) is not AcceptedEvent or record.schema.name != "session_opened":
            continue
        payload = record.payload
        ref = payload.workspace_ref if type(payload) is SessionOpenedPayload else None
        if ref is None or not ref.startswith("/"):
            return None
        roots.add(posixpath.normpath(ref))
    return next(iter(roots)) if len(roots) == 1 else None


def declared_path_beyond_fingerprint(
    projection: ProjectionState, *, workspace_root: str | None = None
) -> bool:
    """Whether an effective obligation names a deliverable the workspace fingerprint cannot vouch for.

    A requested non-input ``file`` or ``directory`` inside the workspace where the walk does not
    compare it: a VCS store recorded by identity only or a skipped VCS bookkeeping file, below the
    first level of a dependency environment or tool cache, a bytecode file, or a saved receipt or
    export name (``path_beyond_workspace_fingerprint``, PR #1080 round 6). The hook does not read
    obligations; the kernel then withholds ``unchanged`` from every command rather than trust a
    comparison that may not have seen the delivery. ``workspace_root`` is the task's absolute root
    (``task_workspace_root``): an absolute declaration outside it is out of the walk's scope, and
    with no known root an absolute one is judged against each of its ancestors. Pure: no
    filesystem is read.
    """

    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if item.item_kind not in _DECLARED_OUTPUT_KINDS or item.role is RequestedItemRole.INPUT:
                continue
            if path_beyond_workspace_fingerprint(
                item.value,
                directory=item.item_kind is RequestedItemKind.DIRECTORY,
                workspace_root=workspace_root,
            ):
                return True
    return False


def non_counting_edits_exempt(projection: ProjectionState) -> frozenset[str]:
    """The write tokens whose edits are exempt from the stale rule for this task (ADR-042).

    Deliverables take precedence over the lexical write classes, per class:

    * ``write scratch`` is not exempt when a requested non-input file or directory lies under a
      fixed temporary root or contains one (a deliverable under ``/tmp``);
    * ``write yoetz_owned`` is not exempt when a requested non-input file has a FinishUP receipt or
      export name, or any requested non-input directory exists (a receipt saved into a declared
      output directory changes that delivery);
    * ``write notes`` (the agent's own notes or logs, ADR-045) is not exempt when a requested
      non-input file has a notes-like name or any requested non-input directory exists.

    Fixed roots only, so replay never depends on the environment.
    """

    exempt = set(NON_COUNTING_WRITE_TOKENS)
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if item.item_kind not in _DECLARED_OUTPUT_KINDS or item.role is RequestedItemRole.INPUT:
                continue
            if scratch_overlap(item.value):
                exempt.discard("write scratch")
            if item.item_kind is RequestedItemKind.DIRECTORY or finishup_artifact_name(item.value):
                # Frozen legacy identifier (ADR-048): recorded wire token value.
                exempt.discard("write yoetz_owned")
            if item.item_kind is RequestedItemKind.DIRECTORY or notes_artifact_name(item.value):
                # A declared output named like a notes file, or any declared directory (which may
                # hold one), is a deliverable: writes to notes-like names keep counting (ADR-045).
                exempt.discard("write notes")
    return frozenset(exempt)


def _non_counting_edit(description: str, exempt: frozenset[str]) -> bool:
    """An observed edit whose every path was scratch or FinishUP-owned (ADR-042, tb4n2 R4).

    It changes nothing under test: it never advances the latest edit (so it never makes a planned
    or recorded verification stale) and is not acting on the task. Deliverable, workspace and
    real outside-workspace edits keep counting.
    """

    return not observed_edit_counts(description, exempt)


def _observed_state(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
) -> _ObservedState:
    exempt = non_counting_edits_exempt(projection)
    runs: list[_ObservedRun] = []
    latest_edit: int | None = None
    latest_edit_event: EventId | None = None
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
            if payload.outcome is ResultOutcome.FAILURE or _non_counting_edit(description, exempt):
                continue
            latest_edit = max(latest_edit or 0, result.source_frontier)
            latest_edit_event = action.source_event_id
            edit_tokens.update(observed_action_runtime_tokens(description))
            acting = True
        elif action.payload.action_kind is ActionKind.COMMAND:
            commands_with_result.add(str(payload.action_id))
            runner = observed_action_runner_class(description)
            tokens = observed_action_runtime_tokens(description)
            command_tokens.update(tokens)
            if runner in _ACTING_RUNNERS:
                acting = True
            if observed_shell_write_counts(description, exempt):
                # ADR-045: a shell command that visibly wrote files (``cat > f``, ``sed -i``,
                # ``cp a f``) changed the work as surely as an edit tool would, and it did so
                # whatever its exit status (``: > f; false`` emptied ``f``). A write to the
                # agent's notes counts only when the task declares a notes-like output.
                latest_edit = max(latest_edit or 0, result.source_frontier)
                latest_edit_event = action.source_event_id
                edit_tokens.update(tokens & (SHELL_EDIT_TOKENS | NON_COUNTING_WRITE_TOKENS))
                acting = True
            runs.append(
                _ObservedRun(
                    result.source_frontier,
                    payload.outcome,
                    command_identity(action.payload.command),
                    runner,
                    tokens,
                    *_segment_fields(action.payload.command),
                    action.source_event_id,
                )
            )
    for action_ref, action in projection.actions.items():
        payload = action.payload
        if payload is None:
            continue
        if action.source_event_id in cooperative:
            # A published action is the agent's own record of acting; a research or review
            # action only reads, so it is not acting (tb4n2 E4, P1-7: lake S got "no recorded
            # attempt" after one research action).
            if payload.action_kind not in {ActionKind.RESEARCH, ActionKind.REVIEW}:
                acting = True
            continue
        if action.source_event_id not in observed:
            continue
        if payload.action_kind is ActionKind.EDIT and str(action_ref) not in edits_with_result:
            if _non_counting_edit(payload.description, exempt):
                continue
            # An observed edit whose outcome has not arrived yet still changed the state under
            # test as far as the observer can tell; a stated failure above never counts.
            latest_edit = max(latest_edit or 0, action.source_frontier)
            latest_edit_event = action.source_event_id
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
            if observed_shell_write_counts(payload.description, exempt):
                # ADR-045: a shell write counts whatever its outcome, so one whose result never
                # arrives counts like a pending edit. A Codex shell ``apply_patch <<EOF`` is
                # always one: Codex applies the patch itself and fires only the pre-event
                # (#1041), so its write token is the ledger's only record of the edit (#1046).
                latest_edit = max(latest_edit or 0, action.source_frontier)
                latest_edit_event = action.source_event_id
                edit_tokens.update(tokens & (SHELL_EDIT_TOKENS | NON_COUNTING_WRITE_TOKENS))
                acting = True
            runs.append(
                _ObservedRun(
                    action.source_frontier,
                    ResultOutcome.UNKNOWN,
                    command_identity(payload.command),
                    observed_action_runner_class(payload.description),
                    tokens,
                    *_segment_fields(payload.command),
                    action.source_event_id,
                )
            )
    runs.sort(key=lambda run: run.position)
    return _ObservedState(
        tuple(runs),
        latest_edit,
        frozenset(edit_tokens),
        frozenset(command_tokens),
        acting,
        latest_edit_event,
    )


def passing_verification_observed(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
) -> bool:
    """Whether a hook-observed ``test``, ``lint``, ``typecheck`` or ``build`` run succeeded.

    ADR-045 reads it as the "passing recorded verification" half of a deliverable's basis: a file
    that held content while such a run was on the record counts as delivered work even when no
    obligation had been resolved yet.
    """

    state = _observed_state(projection, observed, cooperative)
    # A composition that masks its own status (``pytest -q; true``, ``pytest | tail``) says
    # nothing about the verifying part, so only a plain command or a successful ``&&`` chain is a
    # passing run.
    return any(
        run.runner in _VERIFICATION_RUNNERS
        and run.outcome is ResultOutcome.SUCCESS
        and run.composition in {None, "single", "and_chain"}
        for run in state.runs
    )


def observed_run_from_command(
    command: str | None, *, outcome: ResultOutcome = ResultOutcome.UNKNOWN
) -> _ObservedRun | None:
    """A minimal observed run read off an action's ``command`` field, or ``None`` (unkeyed).

    Only the identity and segment commitments are known from a bare command field; the outcome
    is unknown unless the caller read it off the run's own result. ``command_attempts`` uses it
    to ask whether an observed action the agent linked to a planned command is a run of that
    command, with no position or outcome claimed.
    """

    identity = command_identity(command)
    if identity is None:
        return None
    segments, composition = _segment_fields(command)
    return _ObservedRun(0, outcome, identity, None, frozenset(), segments, composition)


@functools.lru_cache(maxsize=512)
def _cached_planned_command(value: str, generation: int) -> PlannedCommand | None:
    # ``generation`` is part of the cache key only: a re-registered key never reuses a row.
    del generation
    return requested_planned_command(value)


def planned_verification_commands(
    plans: Mapping[int, PlanProjectionRecord],
    obligations: Mapping[ObligationId, ObligationProjectionRecord],
    coverage_gaps: tuple[str, ...],
) -> tuple[PlannedCommand, ...]:
    """The planned verifications of the effective plan, ready to match observed runs (#1104).

    Every effective obligation's requested item of kind ``command`` that names an observable
    command, in plan order, each once. An obligation the agent acknowledged as not done
    (``acknowledged_not_done``) requests nothing here, as the planned-verification task facts
    skip it; an obligation with a recorded blocker still does (a blocker decision is not a plan
    event, and its command passing is still the planned verification passing). Empty without the
    installation key: a process that cannot compute the identity never treats a run as the
    planned verification.
    """

    if not command_identity_key_registered():
        return ()
    generation = command_identity_key_generation()
    seen: set[str] = set()
    planned: list[PlannedCommand] = []
    for obligation in effective_obligation_ids(plans, obligations, coverage_gaps):
        payload = obligations[obligation].payload
        assert payload is not None
        if payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE:
            continue
        for item in payload.requested_items:
            if (
                item.item_kind is not RequestedItemKind.COMMAND
                or item.value in seen
                or requested_command_shape(item.value) != "command"
            ):
                continue
            seen.add(item.value)
            command = _cached_planned_command(item.value, generation)
            if command is not None:
                planned.append(command)
    return tuple(planned)


def planned_verification_passed(command: str | None, planned: Iterable[PlannedCommand]) -> bool:
    """Whether a passing run of the observed ``command`` passed a planned verification (#1104).

    Only the recorded rule counts (``planned_match`` kind ``exact``: the ADR-033 keyed command
    commitment, or the planned command as a segment of the run), and the outcome it establishes
    for the planned command must be a success: a ``single`` run or a successful ``&&`` chain. A
    canonical, prefix or flag match, an agent link, a masked composition and a masked planned
    command never count. The caller supplies a run whose own recorded outcome is a success.

    Retirement reads segments the way the same-command rule does: only a segment the success
    certifies (``observed_failures.success_certified_identities``, one that ran exactly as
    listed) can be the planned command, so ``PYTEST_ADDOPTS=--co pytest -q``, ``exec pytest -q``
    or ``pytest -q < answers.txt`` never passes a planned ``pytest -q``. A planned command whose
    own composition masks its outcome (``X | tail``, ``! X``, ``X || true``, ``X &``, ``X; Y``)
    never counts either, even run exactly as planned: its recorded exit is not the planned
    work's. The task facts keep their looser ADR-033 reading.
    """

    run = observed_run_from_command(command, outcome=ResultOutcome.SUCCESS)
    if run is None:
        return False
    run = replace(run, segments=success_certified_identities(command))
    return any(
        item.composition != "masked"
        and (match := planned_match(run, item)) is not None
        and match.kind == MATCH_EXACT
        and match.outcome is ResultOutcome.SUCCESS
        for item in planned
    )


def observed_planned_commands(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
    values: Iterable[str],
) -> frozenset[str]:
    """The requested command values some hook-observed run matched, by any outcome (ADR-045).

    ``requested_item_never_attempted`` used to ask only whether the agent's own published action
    named the exact value in ``attempted_items``; a run the hook saw execute the planned command
    (exactly, up to wrappers, or by its leading arguments or flags) is an attempt too. The
    outcome is not asked here: a failed run still attempted it.
    """

    if not command_identity_key_registered():
        return frozenset()
    state = _observed_state(projection, observed, cooperative)
    runs = [run for run in state.runs if run.identity is not None]
    if not runs:
        return frozenset()
    matched: set[str] = set()
    for value in values:
        if requested_command_shape(value) != "command":
            continue
        planned = requested_planned_command(value)
        if planned is not None and any(planned_match(run, planned) is not None for run in runs):
            matched.add(value)
    return frozenset(matched)


def material_edit_recorded(
    projection: ProjectionState,
    observed: frozenset[EventId],
    cooperative: frozenset[EventId],
) -> bool:
    """Whether the prefix records a material edit of the work (issue #1046).

    An observed edit or shell write that counts (ADR-042: not only scratch or FinishUP-owned paths;
    ADR-045: ``cat > f``, ``sed -i``), the same edits that make a later check stale, or an edit
    action the agent published. Plans, reads, runs and FinishUP's own calls are not edits. The check's
    workspace capture is the other half of the answer; callers combine the two.
    """

    if _observed_state(projection, observed, cooperative).latest_edit is not None:
        return True
    return any(
        row.payload is not None
        and row.payload.action_kind is ActionKind.EDIT
        and row.source_event_id in cooperative
        for row in projection.actions.values()
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
    # ADR-045: where each fact came from (rule, the obligation item, the observed runs or edit it
    # rests on). Derived with the markers, from the same prefix.
    lineage: tuple[FactLineage, ...] = ()

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
    batches = decision_batches(prefix)
    blocked = blocked_obligations(projection, batches)
    acknowledged = acknowledged_obligation_ids(projection)
    markers: set[tuple[str, ObligationId | None]] = set()

    # Planned verification.
    lineage: list[FactLineage] = []
    keyed_runs = [run for run in state.runs if run.identity is not None]
    linked_runs = _agent_linked_runs(projection, prefix, state, observed)
    planned_runs: list[_ObservedRun] = []
    if command_identity_key_registered():
        for obligation in effective_obligations(projection):
            if obligation in blocked or obligation in acknowledged:
                continue
            payload = projection.obligations[obligation].payload
            assert payload is not None
            for index, item in enumerate(payload.requested_items):
                if item.item_kind is not RequestedItemKind.COMMAND:
                    continue
                if requested_command_shape(item.value) != "command":
                    # A requested value no hook could observe (a ``<placeholder>`` admitted
                    # before publication rejected it, or prose); no agent link changes that.
                    markers.add((PLANNED_VERIFICATION_UNOBSERVABLE_GAP, obligation))
                    continue
                planned = requested_planned_command(item.value)
                matching = (
                    []
                    if planned is None
                    else [
                        (run, match.outcome, match.kind)
                        for run in keyed_runs
                        if (match := planned_match(run, planned)) is not None
                    ]
                )
                planned_runs.extend(run for run, _outcome, _kind in matching)
                linked = [
                    (run, run.outcome, "agent_link")
                    for run in linked_runs.get((obligation, item.value), ())
                    if all(run is not other for other, _outcome, _kind in matching)
                ]
                if not matching and not linked:
                    code = (
                        PLANNED_VERIFICATION_NOT_OBSERVED_GAP
                        if keyed_runs
                        else PLANNED_VERIFICATION_UNOBSERVABLE_GAP
                    )
                    markers.add((code, obligation))
                    lineage.append(
                        FactLineage(
                            code=code,
                            rule=RULE_COMMAND_UNMATCHED,
                            state="unmatched",
                            obligation_id=obligation,
                            item_index=index,
                            frontier=projection.frontier,
                        )
                    )
                    continue
                if not matching:
                    markers.add((PLANNED_VERIFICATION_AGENT_LINKED_GAP, obligation))
                latest, outcome, kind = max(matching + linked, key=lambda row: row[0].position)
                match_state = {
                    MATCH_EXACT: "matched_exact",
                    MATCH_NORMALIZED: "matched_normalized",
                    MATCH_PREFIX: "matched_prefix",
                    MATCH_FLAGS: "matched_flags",
                }.get(kind, "matched_agent_link")
                sources = (latest.action_event,) if latest.action_event is not None else ()
                if kind in LOOSE_MATCH_KINDS:
                    # The run that decides the outcome matched only by its leading arguments or by
                    # its program and flags: it counts as run, and the match is disclosed.
                    markers.add((PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP, obligation))
                    lineage.append(
                        FactLineage(
                            code=PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
                            rule=RULE_COMMAND_MATCH,
                            state=match_state,
                            obligation_id=obligation,
                            item_index=index,
                            frontier=latest.position,
                            proof="observed_run",
                            source_event_ids=sources,
                        )
                    )
                if outcome in {ResultOutcome.FAILURE, ResultOutcome.PARTIAL}:
                    markers.add((PLANNED_VERIFICATION_FAILED_GAP, obligation))
                    lineage.append(
                        FactLineage(
                            code=PLANNED_VERIFICATION_FAILED_GAP,
                            rule=RULE_COMMAND_MATCH,
                            state="failed",
                            obligation_id=obligation,
                            item_index=index,
                            frontier=latest.position,
                            proof="observed_run",
                            source_event_ids=sources,
                        )
                    )
                elif outcome is ResultOutcome.UNKNOWN:
                    markers.add((PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP, obligation))
                if state.latest_edit is not None and state.latest_edit > latest.position:
                    markers.add((PLANNED_VERIFICATION_STALE_GAP, obligation))
                    lineage.append(
                        FactLineage(
                            code=PLANNED_VERIFICATION_STALE_GAP,
                            rule=RULE_COMMAND_MATCH,
                            state="stale",
                            obligation_id=obligation,
                            item_index=index,
                            frontier=latest.position,
                            prior_frontier=state.latest_edit,
                            proof="observed_run",
                            source_event_ids=tuple(
                                sorted(
                                    {
                                        *sources,
                                        *(
                                            (state.latest_edit_event,)
                                            if state.latest_edit_event is not None
                                            else ()
                                        ),
                                    },
                                    key=str.encode,
                                )
                            ),
                        )
                    )

    # Edits after the last verification-class run. A run of a command the task itself asked for
    # is a verification run whatever its class (``sage solve.sage ... && cmp`` is composed, so it
    # classes ``compound``), so the planned matches count with the classed runs (ADR-045).
    verification_runs = sorted(
        {
            id(run): run
            for run in (
                *(run for run in state.runs if run.runner in _VERIFICATION_RUNNERS),
                *planned_runs,
            )
        }.values(),
        key=lambda run: run.position,
    )
    if (
        verification_runs
        and state.latest_edit is not None
        and state.latest_edit > verification_runs[-1].position
    ):
        markers.add((EDITED_AFTER_LAST_VERIFICATION_GAP, None))
        last_run = verification_runs[-1]
        lineage.append(
            FactLineage(
                code=EDITED_AFTER_LAST_VERIFICATION_GAP,
                rule=RULE_EDIT_AFTER_RUN,
                state="edited_after",
                frontier=state.latest_edit,
                prior_frontier=last_run.position,
                proof="observed_run",
                source_event_ids=tuple(
                    sorted(
                        {
                            *(
                                (last_run.action_event,)
                                if last_run.action_event is not None
                                else ()
                            ),
                            *(
                                (state.latest_edit_event,)
                                if state.latest_edit_event is not None
                                else ()
                            ),
                        },
                        key=str.encode,
                    )
                ),
            )
        )

    # Runtime facts.
    # Frozen legacy identifier (ADR-048): recorded wire token value.
    if "install yoetz_runtime" in state.command_tokens:
        markers.add((INSTALL_INTO_FINISHUP_RUNTIME_GAP, None))
    if "install private_env" in state.command_tokens:
        markers.add((INSTALL_INTO_PRIVATE_ENV_GAP, None))
    if "write outside_workspace" in state.edit_tokens | state.command_tokens:
        markers.add((WRITE_OUTSIDE_WORKSPACE_GAP, None))
    if verification_runs and all("user root" in run.tokens for run in verification_runs):
        markers.add((VERIFICATION_ONLY_AS_ROOT_GAP, None))

    # Declared blockers on obligations that are still open: confirmed ones are disclosed, a
    # claimed one is still agent work until a later decision confirms it (#985).
    declarations = blocker_declarations(projection, batches)
    for obligation in open_effective_obligations(projection):
        declaration = declarations.get(obligation)
        if declaration is None:
            continue
        markers.add(
            (
                OBLIGATION_BLOCKED_GAP
                if declaration.confirmed
                else OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
                obligation,
            )
        )

    ordered = tuple(sorted(markers, key=lambda item: (item[0].encode(), (item[1] or "").encode())))
    return TaskFactSignals(
        codes=tuple(sorted({code for code, _ in ordered}, key=str.encode)),
        markers=ordered,
        acting_started=state.acting,
        blocked=blocked,
        lineage=tuple(sorted(dict.fromkeys(lineage), key=lambda item: item.sort_key)),
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

    For a declared delivered file the change modified (ADR-035), a bounded line-count read may
    add ``base_lines`` (its lines in the task base), ``lines_lost`` (lines removed minus lines
    added by the change) and ``undeclared_lines_added`` (net lines the same change added to files
    outside the declared delivered set; a lower bound). Each is ``None`` when not read.
    """

    location: str
    exists: bool | None = None
    ignored: bool | None = None
    changed: bool | None = None
    deleted: bool = False
    ignored_by_task: bool = False
    base_lines: int | None = None
    lines_lost: int | None = None
    undeclared_lines_added: int | None = None
    # The size of an existing regular file inside the root, from the metadata-only probe
    # (tb4n2 R2: ``declared_output_emptied``); ``None`` when unknown or not a regular file.
    size_bytes: int | None = None
    # The current line count of an existing declared file the bounded line-count read could
    # count (tracked or untracked, ADR-045); ``None`` when not read, binary or too large.
    lines: int | None = None
    # The bounded line-count read left changed or untracked files out, so ``undeclared_lines_added``
    # is only a lower bound: it can prove a move, never rule one out (ADR-045).
    counts_truncated: bool = False
    # The root-relative path of an ``inside`` item (``.`` for the root), compared only in memory
    # to tell overlapping declarations of one path apart (tb4n2 R2); never stored or rendered.
    relative: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.location not in {"inside", "outside", "unverified"}:
            raise ValueError("requested_output_state_invalid")


def requested_output_facts(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId],
) -> tuple[
    tuple[tuple[ObligationId, int], ...],
    tuple[tuple[str, ObligationId], ...],
]:
    """Split requested-file states into absent outputs and closed gap markers.

    Returns ``(absent, markers)``: ``absent`` lists (obligation, item index) pairs whose file does
    not exist and was not deleted from the task base (a receipt-blocking requested item), and
    ``markers`` the ``(code, obligation)`` gap pairs. ``blocked`` obligations (a confirmed blocker
    names them: ``confirmed_blocked_obligation_ids`` of the case) are skipped. A deleted tracked file is the change the request may have asked for, so it is never
    reported as missing.

    A requested ``file`` item names any file the request names, inputs included (the task's data,
    a policy to read). An existing file the change leaves untouched, or a path outside the
    checked repository, is exactly what such an input looks like, so ``requested_output_unchanged``
    and ``requested_output_outside_workspace`` are reported only for an item the record asserts
    was written: an ``edit`` action whose ``attempted_items`` names that exact value (#977, tb4v1).

    ``obligation_published`` 1.1.0 lets the record say which it is (#1002). An item with role
    ``input`` is the task's data, never an output, so none of these facts is reported for it, not
    even ``absent`` (a missing input is the task's problem to state, not a missing delivery). An
    item with role ``output`` is a declared delivery: it counts as written without an exact
    ``edit`` match, so an untouched or out-of-workspace output is reported. A ``directory`` item is
    read like a ``file`` item; the workspace read decides when it is changed or absent.
    """

    skipped = frozenset(blocked) | acknowledged_obligation_ids(projection)
    edited: dict[ObligationId, frozenset[str]] = {}
    absent: list[tuple[ObligationId, int]] = []
    markers: set[tuple[str, ObligationId]] = set()
    for (obligation, index), state in sorted(
        states.items(), key=lambda item: (item[0][0].encode(), item[0][1])
    ):
        if obligation in skipped:
            continue
        item = _requested_item(projection, obligation, index)
        role = None if item is None else item.role
        if role is RequestedItemRole.INPUT:
            continue
        if obligation not in edited:
            edited[obligation] = attempted_items_for_obligation(
                projection, obligation, action_kind=ActionKind.EDIT
            )
        # Exact value match: no path normalization (the disclosures below stay conservative).
        written = role is RequestedItemRole.OUTPUT or (
            item is not None and item.value in edited[obligation]
        )
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


def _requested_item(
    projection: ProjectionState, obligation: ObligationId, index: int
) -> RequestedItem | None:
    row = projection.obligations.get(obligation)
    payload = None if row is None else row.payload
    if payload is None or not 0 <= index < len(payload.requested_items):
        return None
    return payload.requested_items[index]


_DECLARED_OUTPUT_KINDS: Final = frozenset({RequestedItemKind.FILE, RequestedItemKind.DIRECTORY})


def declared_output_items(
    projection: ProjectionState,
) -> tuple[tuple[ObligationId, int, RequestedItemKind, str], ...]:
    """The task's declared deliveries: requested ``file``/``directory`` items with role ``output``.

    One ``(obligation, item index, kind, value)`` row per item of every effective (readable,
    unwaived, current-plan) obligation, sorted by obligation id (ASCII) then item index. Only an
    explicit ``role: output`` (``obligation_published`` 1.1.0, #1002) declares a delivery; an item
    without a role is not guessed at. Obligations a blocker decision names are included; a caller
    that must skip them filters with ``blocked_obligations``. Values are returned for in-process
    comparison only and are never a structural table key, log field or error text.
    """

    rows: list[tuple[ObligationId, int, RequestedItemKind, str]] = []
    for obligation in sorted(effective_obligations(projection), key=str.encode):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for index, item in enumerate(payload.requested_items):
            if item.role is RequestedItemRole.OUTPUT and item.item_kind in _DECLARED_OUTPUT_KINDS:
                rows.append((obligation, index, item.item_kind, item.value))
    return tuple(rows)
