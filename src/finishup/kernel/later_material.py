"""What a record accepted after the last check can tell about the work under test (tb4n3 RC-6).

A recorded check covers the state it read. Everything appended after it is "later". Until tb4n3
every later material record read the same way (the standing ``check_current_as_of_earlier_frontier``
gap), whether it was the agent's own ``status`` poll, a stream bookkeeping row, or an edit of a
deliverable: 17 of 17 tb4n3 receipts carried that gap, the deterministic arm never reached a
clean receipt, and a real post-check edit looked exactly like a status call.

``later_material_class`` is the one predicate. It is replay-pure, reads only the record, the
projection's action rows and the declared outputs, and names *why* (``LaterMaterial.rule``):

* ``FINISHUP_OWN_CALL`` - the hook or stream observation of a call to one of FinishUP's own MCP tools.
  The call's effect is the cooperative record the service wrote; the observation is never work.
* ``EXPLORATION`` - an observed call that cannot have changed the work: a host-native read tool
  (``Read``, ``Grep``, ``Glob``), a routine-read summary, or a shell command whose result carries
  the hook's before/after workspace fingerprint ``unchanged`` (PR #1080) and that is not a
  verification run or a package install. Command *text* never makes a shell command
  exploration: rounds 3 and 4 of PR #1080 showed that read-looking spellings can write.
  ``workspace_effects`` derives the fingerprint facts from the prefix; without them every shell
  command stays ``OTHER``.
* ``NO_TOOL_ACTIVITY`` - host stream bookkeeping that names no tool call: token counts, reasoning,
  messages, a tool call's own announcement, completion signals; a host poll tool (Codex
  ``wait``) that only returns the output of work started earlier; and a host sleep (Codex
  ``clocksleep``) that only pauses the turn.
* ``NON_COUNTING_WRITE`` - an observed edit whose every path was scratch or FinishUP-owned (ADR-042).
* ``RESPONSE`` - a cooperative answer to a finding; advisory, as before (ADR-040 section 7).
* ``EDIT_OR_WRITE`` - an observed deliverable, workspace or outside-workspace edit, or a shell
  command whose runtime tokens record a workspace write (ADR-045). It supersedes
  the check: the check no longer covers the current state.
* ``OTHER`` - anything FinishUP cannot prove harmless: an unclassified command or tool, an unpaired
  result with no tool identity, a subagent, a lineage manifest. It keeps the disclosure.

The first four never touch a receipt's conclusion and add no gap. ``EDIT_OR_WRITE`` is a
supersession (``check_not_applicable``). ``RESPONSE`` and ``OTHER`` keep the standing
``check_current_as_of_earlier_frontier`` disclosure exactly as before. Wave 2's gap-effect
classifier reads this class; it does not re-derive it.

A tool that reports a result is classified by its action (``result_of_action``): a result never
looks cleaner than the call it answers.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceRecordedPayload,
    LedgerRecord,
    RequestedItemKind,
    RequestedItemRole,
    ResultRecordedPayload,
    is_observation_authored,
)
from finishup.domain.finishup_tools import finishup_tool_spelling
from finishup.domain.observation_selection import ROUTINE_READ_TOOLS
from finishup.domain.values import ActionId, EventId
from finishup.domain.workspace_effect import (
    WORKSPACE_CHANGED,
    WORKSPACE_UNAVAILABLE,
    WORKSPACE_UNCHANGED,
    workspace_effect_from_result_summary,
)
from finishup.domain.write_scope import finishup_tree_overlap
from finishup.kernel.observed_failures import (
    observed_action_runner_class,
    observed_action_runtime_tokens,
    observed_action_tool,
    observed_edit_counts,
    observed_shell_write_counts,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    effective_obligations,
    non_counting_edits_exempt,
    requested_verification_run_events,
)

__all__ = [
    "COMPLETION_SIGNAL_PREFIX",
    "IGNORED_LATER_CLASSES",
    "OPAQUE_OBSERVATION_PREFIX",
    "ROUTINE_READ_SUMMARY_PREFIX",
    "STREAM_BOOKKEEPING_KINDS",
    "LaterMaterial",
    "LaterMaterialClass",
    "WorkspaceEffects",
    "classify_later_material",
    "counted_later_material",
    "later_material_class",
    "observed_actions_by_event",
    "supersession_exempt",
    "workspace_effects",
]

# The descriptions the observation materializer writes for evidence rows that carry no tool call.
# The materializer builds them from these constants, so the reader and the writer cannot drift.
OPAQUE_OBSERVATION_PREFIX: Final = "Opaque observation kind="
COMPLETION_SIGNAL_PREFIX: Final = "Observed completion signal kind="
ROUTINE_READ_SUMMARY_PREFIX: Final = "Routine-read summary observed "
# The Codex rollout wrapper kinds the session-stream reader forwards (every supported profile's
# ``wrapper_types`` plus the ``token_usage_record`` bookkeeping row). A tool call inside them is
# named by its own tool-bearing row (``PreToolUse``/``PostToolUse``/``item_completed``), so the
# wrapper row that is left over states no tool call. An unknown kind stays ``OTHER``.
STREAM_BOOKKEEPING_KINDS: Final = frozenset(
    {
        "compacted",
        "event_msg",
        "inter_agent_communication",
        "inter_agent_communication_metadata",
        "realtime_item",
        "response_item",
        "security_risk_score",
        "session_meta",
        "token_usage_record",
        "turn_context",
        "world_state",
    }
)


# The observation-authored families whose rows state which tool ran or what a stream carried.
_CLASSIFIED_FAMILIES: Final = frozenset({"action_recorded", "result_recorded", "evidence_recorded"})


class LaterMaterialClass(str, Enum):  # noqa: UP042 - stable closed wire-adjacent token
    """The closed classes of a record that follows the last check (``later_material_class``)."""

    # Frozen legacy identifier (ADR-048): recorded wire token value.
    FINISHUP_OWN_CALL = "yoetz_own_call"
    RESPONSE = "response"
    EXPLORATION = "exploration"
    NO_TOOL_ACTIVITY = "no_tool_activity"
    NON_COUNTING_WRITE = "non_counting_write"
    EDIT_OR_WRITE = "edit_or_write"
    OTHER = "other"


# Classes that cannot have changed the work under test: no gap, no supersession, not counted.
IGNORED_LATER_CLASSES: Final = frozenset(
    {
        LaterMaterialClass.FINISHUP_OWN_CALL,
        LaterMaterialClass.EXPLORATION,
        LaterMaterialClass.NO_TOOL_ACTIVITY,
        LaterMaterialClass.NON_COUNTING_WRITE,
    }
)


@dataclass(frozen=True, slots=True)
class LaterMaterial:
    """One classification and the closed reason for it (rule, tool token, answered action)."""

    material_class: LaterMaterialClass
    rule: str
    tool: str | None = None

    @property
    def ignored(self) -> bool:
        return self.material_class in IGNORED_LATER_CLASSES

    @property
    def supersedes(self) -> bool:
        return self.material_class is LaterMaterialClass.EDIT_OR_WRITE


# Runner classes of a verification run: a new result of one is new closing-review input whatever
# it did to the workspace ("verification-run semantics", #1079 item 3).
_VERIFYING_RUNNERS: Final = frozenset({"test", "build", "lint", "typecheck"})


@dataclass(frozen=True, slots=True)
class WorkspaceEffects:
    """What the hook's before/after workspace fingerprints established for a prefix (PR #1080).

    ``quiet`` holds the observed actions a service-stamped result reports ``unchanged`` for, with
    no result of the same action reporting ``changed`` or ``unavailable``, minus every run of a
    command the task itself requests (a verification run stays new input). ``changed`` holds the
    actions a result reports ``changed`` for. An action in neither set has no usable fact: the
    pre-call snapshot was missing, the call had not ended, the workspace was beyond the walk
    bound, or the record predates the fact. It reads exactly like a change.
    """

    quiet: frozenset[ActionId] = frozenset()
    changed: frozenset[ActionId] = frozenset()


def workspace_effects(
    records: Iterable[LedgerRecord], projection: ProjectionState
) -> WorkspaceEffects:
    """Read the workspace-effect facts of the observed results in this prefix.

    Only service-stamped observation results count: an agent-published result cannot claim that
    a command left the workspace unchanged. Records past the projection frontier are ignored.
    """

    if type(projection) is not ProjectionState:
        return WorkspaceEffects()
    frontier = projection.frontier
    prefix = tuple(
        record
        for record in records
        if type(sequence := getattr(getattr(record, "ledger", None), "ingestion_sequence", None))
        is int
        and sequence <= frontier
    )
    unchanged: set[ActionId] = set()
    contradicted: set[ActionId] = set()
    changed: set[ActionId] = set()
    for record in prefix:
        if record.schema.name != "result_recorded":
            continue
        payload = record.payload
        if type(payload) is not ResultRecordedPayload or not is_observation_authored(record):
            continue
        effect = workspace_effect_from_result_summary(payload.summary)
        if effect == WORKSPACE_UNCHANGED:
            unchanged.add(payload.action_id)
        elif effect in {WORKSPACE_CHANGED, WORKSPACE_UNAVAILABLE}:
            contradicted.add(payload.action_id)
            if effect == WORKSPACE_CHANGED:
                changed.add(payload.action_id)
    quiet: set[ActionId] = unchanged - contradicted
    if quiet:
        verifying = requested_verification_run_events(projection, prefix)
        if verifying is None:
            # The task requests a command, but no run can be matched to it: any run may be that
            # verification, so none is quiet.
            quiet = set[ActionId]()
        elif verifying:
            quiet = {
                action
                for action in quiet
                if (row := projection.actions.get(action)) is None
                or row.source_event_id not in verifying
            }
    return WorkspaceEffects(frozenset(quiet), frozenset(changed))


def supersession_exempt(projection: ProjectionState) -> frozenset[str]:
    """The write tokens an observed edit may carry without superseding a check.

    ``task_facts.non_counting_edits_exempt`` keeps the lexical write classes unless a declared
    output makes them part of the delivery (a deliverable under ``/tmp``). A FinishUP receipt or
    export the agent saves is the one exception here: it is the output *about* the check, so no
    check can ever cover it. Counting it would make every receipt saved into a declared output
    directory invalidate the check that produced it, and the next receipt would do it again. The
    exception ends where a declared output is a packaged FinishUP tree (the task's product is the
    plugin or skill itself): a write there may be the deliverable, so it keeps counting.
    """

    exempt = non_counting_edits_exempt(projection)
    # Frozen legacy identifier (ADR-048): recorded wire token value.
    if "write yoetz_owned" in exempt:
        return exempt
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if (
                item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}
                and item.role is not RequestedItemRole.INPUT
                and finishup_tree_overlap(item.value)
            ):
                return exempt
    # Frozen legacy identifier (ADR-048): recorded wire token value.
    return exempt | {"write yoetz_owned"}


# Host tools that record no work of their own, by the closed rule that names why. Codex's ``wait``
# only polls: it returns the output of a code-mode cell started earlier (the work it ran has its
# own rows). In the tb4n2/tb4n3 replay a poll output followed the last check in 18 of 27
# semantic-arm attempts; left unclassified it kept the bounding disclosure, and readiness would
# then ask for a costly extra AI-powered review because the agent waited. Codex's ``clock.sleep``
# (hook spelling ``clocksleep``, a built-in control tool) only pauses the turn: tb4n5 react S
# slept while its check cell ran, and two sleeps (ledger records 442 and 689) bounded the check.
# A closed list, evidenced per tool spelling.
_HOST_NO_ACTIVITY_TOOLS: Final[Mapping[str, str]] = {
    "wait": "host_poll_tool",
    "clocksleep": "host_sleep_tool",
}


def _classify_action(
    payload: ActionRecordedPayload,
    projection: ProjectionState,
    exempt: frozenset[str] | None,
    effects: WorkspaceEffects | None = None,
) -> LaterMaterial:
    tool = observed_action_tool(payload.description)
    if tool is not None and finishup_tool_spelling(tool) is not None:
        return LaterMaterial(LaterMaterialClass.FINISHUP_OWN_CALL, "finishup_tool_call", tool)
    no_activity_rule = None if tool is None else _HOST_NO_ACTIVITY_TOOLS.get(tool.casefold())
    if no_activity_rule is not None:
        return LaterMaterial(LaterMaterialClass.NO_TOOL_ACTIVITY, no_activity_rule, tool)
    if payload.action_kind is ActionKind.EDIT:
        # Only an edit needs the declared outputs; every other record stays a string read.
        if observed_edit_counts(
            payload.description, supersession_exempt(projection) if exempt is None else exempt
        ):
            return LaterMaterial(LaterMaterialClass.EDIT_OR_WRITE, "observed_counting_edit", tool)
        return LaterMaterial(
            LaterMaterialClass.NON_COUNTING_WRITE, "observed_non_counting_write", tool
        )
    if payload.action_kind is ActionKind.COMMAND and observed_shell_write_counts(
        payload.description, supersession_exempt(projection) if exempt is None else exempt
    ):
        # ADR-045: a shell command that wrote the workspace (``cat > f``, ``sed -i``) changed the
        # work as surely as an edit tool, whatever its exit status or whether a result arrived.
        return LaterMaterial(LaterMaterialClass.EDIT_OR_WRITE, "observed_shell_write", tool)
    runner = observed_action_runner_class(payload.description)
    if payload.action_kind is ActionKind.COMMAND:
        # PR #1080: a shell command is judged by what it did, never by its text. Only the hook's
        # before/after fingerprint can make it harmless; a verification run and a package install
        # (an environment change the fingerprint does not walk) stay material.
        if (
            effects is not None
            and payload.action_id in effects.quiet
            and runner not in _VERIFYING_RUNNERS
            and not any(
                token.startswith("install ")
                for token in observed_action_runtime_tokens(payload.description)
            )
        ):
            return LaterMaterial(
                LaterMaterialClass.EXPLORATION, "observed_workspace_unchanged", tool
            )
        return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_action", tool)
    if (
        payload.action_kind is ActionKind.OTHER
        and runner == "exploration"
        and tool is not None
        and tool.casefold() in ROUTINE_READ_TOOLS
    ):
        # A host-native read tool has a closed meaning without any command text.
        return LaterMaterial(LaterMaterialClass.EXPLORATION, "observed_exploration_runner", tool)
    return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_action", tool)


def _classify_evidence(payload: EvidenceRecordedPayload) -> LaterMaterial:
    description = payload.description
    if description is None:
        return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_evidence")
    if description.startswith(ROUTINE_READ_SUMMARY_PREFIX):
        return LaterMaterial(LaterMaterialClass.EXPLORATION, "routine_read_summary")
    if description.startswith(COMPLETION_SIGNAL_PREFIX):
        return LaterMaterial(LaterMaterialClass.NO_TOOL_ACTIVITY, "completion_signal")
    if (
        description.startswith(OPAQUE_OBSERVATION_PREFIX)
        and description[len(OPAQUE_OBSERVATION_PREFIX) :] in STREAM_BOOKKEEPING_KINDS
    ):
        return LaterMaterial(LaterMaterialClass.NO_TOOL_ACTIVITY, "stream_bookkeeping")
    return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_evidence")


def classify_later_material(
    record: LedgerRecord,
    projection: ProjectionState,
    *,
    exempt: frozenset[str] | None = None,
    actions_by_event: Mapping[EventId, ActionRecordedPayload] | None = None,
    effects: WorkspaceEffects | None = None,
) -> LaterMaterial:
    """Classify one accepted record that follows a check, with the rule that decided it.

    ``projection`` is the projection the caller already holds for the same prefix: a result is
    classified by its action's row, and the declared outputs decide which writes count.
    ``exempt`` lets a caller that classifies many records compute ``supersession_exempt`` once.
    ``actions_by_event`` maps the observed action events of the prefix to their payloads: content
    the host captured for a call (tool output, a workspace diff) is evidence recorded under that
    action (``causal_parents``) and takes the action's class, never a cleaner one. Without it
    such evidence is read by its description alone and stays ``other``. ``effects`` is
    ``workspace_effects`` over the same prefix; without it no shell command is exploration.
    """

    name = record.schema.name
    if not is_observation_authored(record):
        if name == "response_recorded":
            return LaterMaterial(LaterMaterialClass.RESPONSE, "cooperative_response")
        return LaterMaterial(LaterMaterialClass.OTHER, "cooperative_material")
    if name not in _CLASSIFIED_FAMILIES:
        return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_record")
    payload = record.payload
    if name == "action_recorded" and type(payload) is ActionRecordedPayload:
        return _classify_action(payload, projection, exempt, effects)
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            return LaterMaterial(LaterMaterialClass.OTHER, "result_without_readable_action")
        answered = _classify_action(action.payload, projection, exempt, effects)
        return LaterMaterial(answered.material_class, "result_of_action", answered.tool)
    if name == "evidence_recorded" and type(payload) is EvidenceRecordedPayload:
        if actions_by_event:
            for parent in record.causal_parents:
                parent_action = actions_by_event.get(parent)
                if parent_action is not None:
                    answered = _classify_action(parent_action, projection, exempt, effects)
                    if answered.material_class is LaterMaterialClass.EDIT_OR_WRITE:
                        # The edit itself is the superseding record, at the position it was
                        # ingested; its late output is not a second change. Disclosed, never
                        # superseding (the reducer cannot see the lineage and agrees).
                        return LaterMaterial(
                            LaterMaterialClass.OTHER, "evidence_of_edit", answered.tool
                        )
                    return LaterMaterial(
                        answered.material_class, "evidence_of_action", answered.tool
                    )
        return _classify_evidence(payload)
    return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_record")


def later_material_class(record: LedgerRecord, projection: ProjectionState) -> LaterMaterialClass:
    """The class of one record accepted after a check (see the module docstring)."""

    return classify_later_material(record, projection).material_class


def observed_actions_by_event(
    records: Iterable[LedgerRecord],
) -> Mapping[EventId, ActionRecordedPayload]:
    """The observed action payloads of a prefix by their event id (for evidence lineage)."""

    return {
        record.event_id: record.payload
        for record in records
        if record.schema.name == "action_recorded"
        and is_observation_authored(record)
        and type(record.payload) is ActionRecordedPayload
    }


def counted_later_material(
    records: Iterable[LedgerRecord],
    projection: ProjectionState,
    *,
    all_records: Iterable[LedgerRecord] | None = None,
) -> tuple[LedgerRecord, ...]:
    """The records among *records* a receipt must still disclose: not ignored by class.

    ``all_records`` is the whole prefix when *records* is only its suffix after a check, so the
    evidence lineage can find the action an evidence row was recorded under.
    """

    exempt = supersession_exempt(projection)
    selected = tuple(records)
    prefix = selected if all_records is None else tuple(all_records)
    actions = observed_actions_by_event(prefix)
    effects = workspace_effects(prefix, projection)
    return tuple(
        record
        for record in selected
        if not classify_later_material(
            record, projection, exempt=exempt, actions_by_event=actions, effects=effects
        ).ignored
    )
