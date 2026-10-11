"""What a record accepted after the last check can tell about the work under test (tb4n3 RC-6).

A recorded check covers the state it read. Everything appended after it is "later". Until tb4n3
every later material record read the same way (the standing ``check_current_as_of_earlier_frontier``
gap), whether it was the agent's own ``status`` poll, a stream bookkeeping row, or an edit of a
deliverable: 17 of 17 tb4n3 receipts carried that gap, the deterministic arm never reached a
clean receipt, and a real post-check edit looked exactly like a status call.

``later_material_class`` is the one predicate. It is replay-pure, reads only the record, the
projection's action rows and the declared outputs, and names *why* (``LaterMaterial.rule``):

* ``YOETZ_OWN_CALL`` - the hook or stream observation of a call to one of Yoetz's own MCP tools.
  The call's effect is the cooperative record the service wrote; the observation is never work.
* ``EXPLORATION`` - an observed read-only run (the hook's closed ``exploration`` runner class, a
  native read tool) or a routine-read summary.
* ``NO_TOOL_ACTIVITY`` - host stream bookkeeping that names no tool call: token counts, reasoning,
  messages, a tool call's own announcement, completion signals; and a host poll tool (Codex
  ``wait``) that only returns the output of work started earlier.
* ``NON_COUNTING_WRITE`` - an observed edit whose every path was scratch or Yoetz-owned (ADR-042).
* ``RESPONSE`` - a cooperative answer to a finding; advisory, as before (ADR-040 section 7).
* ``EDIT_OR_WRITE`` - an observed deliverable, workspace or outside-workspace edit. It supersedes
  the check: the check no longer covers the current state.
* ``OTHER`` - anything Yoetz cannot prove harmless: an unclassified command or tool, an unpaired
  result with no tool identity, a subagent, a lineage manifest. It keeps the disclosure.

The first four never touch a receipt's conclusion and add no gap. ``EDIT_OR_WRITE`` is a
supersession (``check_not_applicable``). ``RESPONSE`` and ``OTHER`` keep the standing
``check_current_as_of_earlier_frontier`` disclosure exactly as before. Wave 2's gap-effect
classifier reads this class; it does not re-derive it.

A tool that reports a result is classified by its action (``result_of_action``): a result never
looks cleaner than the call it answers.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Final

from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceRecordedPayload,
    LedgerRecord,
    ResultRecordedPayload,
    is_observation_authored,
)
from yoetz.domain.yoetz_tools import yoetz_tool_spelling
from yoetz.kernel.observed_failures import (
    observed_action_runner_class,
    observed_action_tool,
    observed_edit_counts,
)
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import non_counting_edits_exempt

__all__ = [
    "COMPLETION_SIGNAL_PREFIX",
    "IGNORED_LATER_CLASSES",
    "OPAQUE_OBSERVATION_PREFIX",
    "ROUTINE_READ_SUMMARY_PREFIX",
    "STREAM_BOOKKEEPING_KINDS",
    "LaterMaterial",
    "LaterMaterialClass",
    "classify_later_material",
    "counted_later_material",
    "later_material_class",
    "supersession_exempt",
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

    YOETZ_OWN_CALL = "yoetz_own_call"
    RESPONSE = "response"
    EXPLORATION = "exploration"
    NO_TOOL_ACTIVITY = "no_tool_activity"
    NON_COUNTING_WRITE = "non_counting_write"
    EDIT_OR_WRITE = "edit_or_write"
    OTHER = "other"


# Classes that cannot have changed the work under test: no gap, no supersession, not counted.
IGNORED_LATER_CLASSES: Final = frozenset(
    {
        LaterMaterialClass.YOETZ_OWN_CALL,
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


def supersession_exempt(projection: ProjectionState) -> frozenset[str]:
    """The write tokens an observed edit may carry without superseding a check.

    ``task_facts.non_counting_edits_exempt`` keeps the lexical write classes unless a declared
    output makes them part of the delivery (a deliverable under ``/tmp``). A Yoetz receipt or
    export the agent saves is the one exception here: it is the output *about* the check, so no
    check can ever cover it. Counting it would make every receipt saved into a declared output
    directory invalidate the check that produced it, and the next receipt would do it again.
    """

    return non_counting_edits_exempt(projection) | {"write yoetz_owned"}


# Host tools that only poll something already running and record no work of their own: Codex's
# ``wait`` returns the output of a code-mode cell started earlier (the work it ran has its own
# rows). In the tb4n2 replay it was the one trailing call of 9 of 14 semantic-arm suffixes; left
# unclassified it kept the bounding disclosure, and readiness would then ask for a costly extra
# AI-powered review because the agent waited. A closed list, evidenced per tool.
_HOST_POLL_TOOLS: Final = frozenset({"wait"})


def _classify_action(
    payload: ActionRecordedPayload, projection: ProjectionState, exempt: frozenset[str] | None
) -> LaterMaterial:
    tool = observed_action_tool(payload.description)
    if tool is not None and yoetz_tool_spelling(tool) is not None:
        return LaterMaterial(LaterMaterialClass.YOETZ_OWN_CALL, "yoetz_tool_call", tool)
    if tool is not None and tool.casefold() in _HOST_POLL_TOOLS:
        return LaterMaterial(LaterMaterialClass.NO_TOOL_ACTIVITY, "host_poll_tool", tool)
    if payload.action_kind is ActionKind.EDIT:
        # Only an edit needs the declared outputs; every other record stays a string read.
        if observed_edit_counts(
            payload.description, supersession_exempt(projection) if exempt is None else exempt
        ):
            return LaterMaterial(LaterMaterialClass.EDIT_OR_WRITE, "observed_counting_edit", tool)
        return LaterMaterial(
            LaterMaterialClass.NON_COUNTING_WRITE, "observed_non_counting_write", tool
        )
    if (
        payload.action_kind in {ActionKind.COMMAND, ActionKind.OTHER}
        and observed_action_runner_class(payload.description) == "exploration"
    ):
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
) -> LaterMaterial:
    """Classify one accepted record that follows a check, with the rule that decided it.

    ``projection`` is the projection the caller already holds for the same prefix: a result is
    classified by its action's row, and the declared outputs decide which writes count.
    ``exempt`` lets a caller that classifies many records compute ``supersession_exempt`` once.
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
        return _classify_action(payload, projection, exempt)
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            return LaterMaterial(LaterMaterialClass.OTHER, "result_without_readable_action")
        answered = _classify_action(action.payload, projection, exempt)
        return LaterMaterial(answered.material_class, "result_of_action", answered.tool)
    if name == "evidence_recorded" and type(payload) is EvidenceRecordedPayload:
        return _classify_evidence(payload)
    return LaterMaterial(LaterMaterialClass.OTHER, "unclassified_observed_record")


def later_material_class(record: LedgerRecord, projection: ProjectionState) -> LaterMaterialClass:
    """The class of one record accepted after a check (see the module docstring)."""

    return classify_later_material(record, projection).material_class


def counted_later_material(
    records: Iterable[LedgerRecord], projection: ProjectionState
) -> tuple[LedgerRecord, ...]:
    """The records among *records* a receipt must still disclose: not ignored by class."""

    exempt = supersession_exempt(projection)
    return tuple(
        record
        for record in records
        if not classify_later_material(record, projection, exempt=exempt).ignored
    )
