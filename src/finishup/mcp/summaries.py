"""Privacy-safe bounded text projections of structured operation results."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, cast

from pydantic import BaseModel

from finishup.domain.bounded_text import (
    Part,
    compose_parts,
    list_variants,
)
from finishup.domain.closure import PREPARATION_REMEDIATIONS
from finishup.domain.findings import FINDING_KIND_TRAITS, FindingKind
from finishup.domain.receipts import (
    COORDINATOR_FAILURE_LIMITATION,
    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT,
    check_time_change_gap_sentence,
    historical_gaps_from_wire,
    limitations_name_coordinator_failure,
)
from finishup.domain.review_input_render import (
    has_agent_suppliable_missing,
    publish_exactly,
    render_review_input_manifest_compact,
)
from finishup.domain.review_mode_render import (
    check_review_mode_line,
    review_mode_continuation,
    status_review_mode_line,
)
from finishup.kernel.fact_lineage import FactLineage, lineage_from_wire, lineage_texts
from finishup.legacy_names import LAUNCHER_NAME, LAUNCHER_NAMES
from finishup.mcp.errors import VALIDATION_REASON_TOKENS
from finishup.protocol.canonical import JsonValue, ensure_canonical_value
from finishup.protocol.errors import (
    SERVICE_STARTUP_PHASES,
    PublicErrorCode,
    normalize_safe_details,
)
from finishup.protocol.guidance_uris import ALL_GUIDANCE_URIS, LEGACY_ALL_GUIDANCE_URIS
from finishup.protocol.ids import IdKind, is_valid_id, validate_opaque_item_id
from finishup.protocol.inspection_text import inspection_text
from finishup.protocol.readiness_text import (
    READINESS_STATES,
    awaiting_ruling_variants,
    check_cause_sentence,
    closure_counts_variants,
    obligation_resolve_recipe_variants,
    predicted_receipt_variants,
    readiness_directive,
    recheck_note,
)
from finishup.protocol.recovery import (
    REASON_REMEDIES,
    RecoveryDirective,
    continuation_for_semantic_outcome,
    correction_for_invariant,
    directive_for,
)
from finishup.protocol.redacted_values import SemanticRedactedValue

__all__ = [
    "MAX_SUMMARY_BYTES",
    "SummaryRender",
    "render_safe_compact_summary",
    "render_safe_compact_summary_detailed",
    "render_check_reviewer_output",
    "summary_for_check",
    "summary_for_check_awaiting",
    "summary_for_check_inspection",
    "summary_for_closure_prepare",
    "summary_for_public_error",
    "summary_for_read_guidance",
    "summary_for_receipt",
    "summary_for_status",
]

# tb4n3 RC-2 (#1025): 512 was too small for the closing check of a run (10 of 13 deterministic
# runs overflowed it and lost their verdict). The bound stays a bound, but every builder composes
# against it with ``compose_parts`` -- required core first, optional clauses by priority -- so
# exceeding it degrades the optional clauses and can never raise (ADR-030 "Budget priority").
MAX_SUMMARY_BYTES: Final = 4096
_MAX_SUMMARY_BYTES: Final = MAX_SUMMARY_BYTES
_MAX_REVIEW_OUTPUT_BYTES: Final = 12_288
_REVIEW_VERDICTS: Final = frozenset({"supported", "not_supported", "not_assessable"})
_REVIEW_KINDS: Final = frozenset(
    {
        "action_without_result",
        "claim_without_admissible_evidence",
        "completion_with_open_obligations",
        "contradictory_claims_unresolved",
        "coordination_overlap",
        "diff_does_not_match_account",
        "evidence_does_not_support_claim",
        "failed_work_omitted",
        "ledger_stale_or_incomplete",
        "material_limitation_omitted",
        "questionable_finding_rejection",
        "requested_item_never_attempted",
        "result_without_action",
        "stale_evidence_for_changed_state",
        "weak_or_stale_response",
        "code_defect",
        "task_requirement_unmet",
        "agent_criterion_unmet",
    }
)
# A validation location pointer as ``finishup.mcp.errors`` builds it: at most eight frozen
# presentation-schema segments or bounded indexes. Re-gated here so a list member that is not that
# exact shape is never rendered, whatever put it on the envelope.
_VALIDATION_POINTER: Final = re.compile(
    r"^(?:/(?:[a-z][a-z0-9_]{0,63}|0|[1-9][0-9]?)){1,8}$", re.ASCII
)
_MAX_NAMED_VALIDATION_LOCATIONS: Final = 2
_SAFE_TOKEN: Final = re.compile(r"^[A-Za-z0-9_+.-]{1,128}$", re.ASCII)
_GAP_CODE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
# F3: the status summary names at most this many required limitation ids, then "+N more"; the
# structured closure_readiness lists up to 64.
_MAX_SUMMARY_LIMITATION_IDS: Final = 3
_RESULT_REF: Final = re.compile(
    r"^res_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_READINESS_ITEM: Final = re.compile(r"^(?:unclassified_gap:)?[a-z][a-z0-9_]{0,127}$", re.ASCII)
_MISSING_REF: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
# Closed shape for the frozen field and family tokens the repair clause may carry (issue #266).
_FIELD_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_SAFE_COUNT: Final = re.compile(r"^(?:0|[1-9][0-9]{0,18})$", re.ASCII)
_CORRELATION_ID: Final = re.compile(
    r"^err_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
# Closed shape for the frontier head: either the genesis sentinel or a canonical digest.
_HEAD_DIGEST: Final = re.compile(r"^(?:genesis|sha256:[0-9a-f]{64})$", re.ASCII)
# Closed shape of a packaged guidance URI, the only location a guidance pointer may name. A
# caller that read in the legacy ``yoetz://`` scheme is answered in it (ADR-048).
_GUIDANCE_URI: Final = re.compile(r"^(?:finishup|yoetz)://guidance/[a-z0-9-]{1,64}\.md$", re.ASCII)
_REGISTERED_GUIDANCE_URIS: Final = frozenset((*ALL_GUIDANCE_URIS, *LEGACY_ALL_GUIDANCE_URIS))


# Priority bands for ``compose_parts`` (lower is granted room first). Every required part is
# granted before every optional one; these only order the optional clauses among themselves.
_P_ACTION: Final = 10  # an instruction the agent must act on
_P_IDENTITY: Final = 20  # ids and refs the next request must carry
_P_STATE: Final = 30  # counts and checklists that describe state
_P_DISCLOSURE: Final = 40  # disclosures of what the check did not cover
_P_DETAIL: Final = 50  # supporting detail; the structured result carries it in full
# The status text's lineage and boilerplate bands, in grant order after the core and the action
# clauses (tb4n3 RC-6, RC-5): the lineage of a listed closure token (check_cause), then the first
# derived-fact provenance sentence (fact_lineage, ADR-045), then every boilerplate sentence (the
# generic closure sentence, the named standing list, the operation-progress text), then the counts
# sentence of the full ready_with_limitations directive. None of them is required, so none can
# displace the closure state, the stop instruction or the agent-actionable items.
_P_CAUSE: Final = _P_ACTION + 1
_P_FACT_WHY: Final = _P_ACTION + 2
_P_BOILERPLATE: Final = _P_ACTION + 3
_P_COUNTS_SENTENCE: Final = _P_ACTION + 4
# The once-per-frontier re-reads a Stop will ask, in their short form (tb4n3 RC-8).
_RECHECK_SHORT: Final = "At Stop you will be asked once to re-read what you recorded."
# One id or token list never takes more than this of the bounded text, so a 100-finding check
# still leaves room for the instruction, the checklist and the disclosures beside it; the exact
# remainder is stated as "+N more" and the structured result carries every row.
_LIST_MAX_CHARS: Final = 1024


@dataclass(frozen=True, slots=True)
class SummaryRender:
    """A rendered text projection plus every clause or builder that failed to render.

    ``failures`` pairs ``<builder>[.<clause>]`` with the exception that stopped it. The text always
    names them (``summary_render_failed:...``) so the agent knows the structured result is the
    complete record; the bridge records the exceptions in the service diagnostics.
    """

    text: str
    failures: tuple[tuple[str, BaseException], ...] = ()


# The failure sink of the render in progress. Direct builder calls leave it unset; the bridge
# entry point sets it so it can record what degraded.
_FAILURE_SINK: ContextVar[list[tuple[str, BaseException]] | None] = ContextVar(
    "finishup_summary_failure_sink", default=None
)
# The bridge's host profile for the render in progress (#1050 follow-up). It only decides how the
# re-check note says a flagged acceptance re-read is answered (``recheck_note``): ``cursor`` never
# names the ``finishup-acceptance`` line its Stop cannot deliver, ``generic`` names which hosts read
# it, and ``codex``/``claude`` (or a direct builder call, which leaves it unset) keep the line.
_SUMMARY_HOST: ContextVar[str | None] = ContextVar("finishup_summary_host", default=None)


class _Render:
    """One builder run: guards each clause so one failing clause cannot blank the summary."""

    __slots__ = ("builder", "failed")

    def __init__(self, builder: str) -> None:
        self.builder = builder
        self.failed: list[str] = []

    def _note(self, clause: str, exc: Exception) -> None:
        site = f"{self.builder}.{clause}"
        if site not in self.failed:
            self.failed.append(site)
        sink = _FAILURE_SINK.get()
        if sink is not None:
            sink.append((site, exc))

    def text(self, clause: str, build: Callable[[], str]) -> str:
        try:
            return build()
        except Exception as exc:  # noqa: BLE001 - a clause is optional; the core must survive
            self._note(clause, exc)
            return ""

    def variants(self, clause: str, build: Callable[[], tuple[str, ...]]) -> tuple[str, ...]:
        try:
            return build()
        except Exception as exc:  # noqa: BLE001 - a clause is optional; the core must survive
            self._note(clause, exc)
            return ()

    def guarded_parts(self, clause: str, build: Callable[[], list[Part]]) -> list[Part]:
        try:
            return build()
        except Exception as exc:  # noqa: BLE001 - a clause is optional; the core must survive
            self._note(clause, exc)
            return []

    def guarded_one(self, clause: str, build: Callable[[], Part | None]) -> Part | None:
        try:
            return build()
        except Exception as exc:  # noqa: BLE001 - a clause is optional; the core must survive
            self._note(clause, exc)
            return None

    def failure_part(self) -> Part | None:
        if not self.failed:
            return None
        sites = ",".join(self.failed)
        return Part(
            (
                f"summary_render_failed:{sites}; those clauses are omitted and the structured "
                "result is complete.",
                f"summary_render_failed:{sites}.",
            ),
            required=True,
        )


def _req(*variants: str) -> Part:
    """A part that is always present; later variants are the shorter forms."""

    return Part(variants, required=True)


def _opt(*variants: str, priority: int = _P_DETAIL) -> Part:
    """A part kept only when the longest variant that fits beside the required text exists."""

    return Part(variants, priority=priority)


def _compose(parts: Sequence[Part | None]) -> str:
    return compose_parts([part for part in parts if part is not None], _MAX_SUMMARY_BYTES).text


def _list_part(
    prefix: str,
    values: Sequence[str],
    *,
    priority: int = _P_DETAIL,
    required: bool = False,
    max_chars: int | None = _LIST_MAX_CHARS,
) -> Part | None:
    """A bounded token list as one part: all values, then fewer with an exact ``+N more``.

    ``max_chars`` caps the longest rendering so one very long list cannot take the room a sibling
    list needs; the shortest rendering is always kept.
    """

    variants = list_variants(prefix, values, suffix=";")
    if not variants:
        return None
    if max_chars is not None:
        within = tuple(variant for variant in variants if len(variant) <= max_chars)
        variants = within or variants[-1:]
    return Part(variants, required=required, priority=priority)


def _failure_class_from_mapping(value: object) -> object | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value).get("failure_class")
    return None


def _mapping(value: object) -> Mapping[str, JsonValue]:
    if isinstance(value, BaseModel):
        dumped = cast(JsonValue, value.model_dump(mode="json", by_alias=True, exclude_unset=True))
        ensure_canonical_value(dumped)
        return cast(Mapping[str, JsonValue], dumped)
    if isinstance(value, Mapping):
        candidate = cast(JsonValue, value)
        ensure_canonical_value(candidate)
        return cast(Mapping[str, JsonValue], candidate)
    raise TypeError("summary_envelope_wrong_type")


def _safe_token(value: object, *, fallback: str = "unavailable") -> str:
    if isinstance(value, Enum):
        value = value.value
    if type(value) is str and _SAFE_TOKEN.fullmatch(value) is not None:
        return value
    return fallback


def _safe_count(value: object) -> str:
    if type(value) is int and 0 <= value <= 9_223_372_036_854_775_807:
        return str(value)
    if type(value) is str and _SAFE_COUNT.fullmatch(value) is not None:
        return value
    return "unavailable"


def _frontier_clause(envelope: Mapping[str, JsonValue]) -> str:
    """Render sequence plus head digest so the text channel alone can seed the next frontier.

    The text summary is the documented authoring fallback when a host drops structured
    content, and ``publish_work`` needs ``expected_frontier.head_digest``, not only the
    sequence, so a summary that carried the sequence alone could not construct the next
    request (issue #279).
    """

    for key in ("result_frontier", "subject_frontier", "head_frontier", "frontier"):
        frontier = envelope.get(key)
        if isinstance(frontier, Mapping):
            typed_frontier = cast(Mapping[str, JsonValue], frontier)
            sequence = _safe_count(typed_frontier.get("sequence"))
            if sequence != "unavailable":
                head = typed_frontier.get("head_digest")
                if type(head) is str and _HEAD_DIGEST.fullmatch(head) is not None:
                    return f"frontier: {sequence}; head_digest: {head}"
                return f"frontier: {sequence}"
    return "frontier: unavailable"


def _identity_clause(envelope: Mapping[str, JsonValue]) -> str:
    """Render the returned identifiers the next request must echo, when present (issue #279).

    Each value is re-gated against the strict public-id validator, so this projector admits
    the operation's own minted identifiers and nothing else.
    """

    parts: list[str] = []
    for label, key, kind in (
        ("task", "task_id", IdKind.TASK),
        ("session", "session_id", IdKind.SESSION),
        ("writer", "writer_id", IdKind.WRITER),
    ):
        value = envelope.get(key)
        if is_valid_id(kind, value):
            parts.append(f"{label}: {cast(str, value)}")
    if not parts:
        return ""
    return "; ".join(parts) + "; "


_TODO_STATES: Final = (
    "open",
    "verified_resolved",
    "acknowledged_not_done",
    "rejection_accepted",
    "self_verified",
    "disputed_after_rebuttal",
)
_CHECKLIST_NEXT: Final = frozenset(
    {
        "decide_at_budget",
        "disclose_limitations",
        "request_receipt",
        "request_ruling",
        "work_open_findings",
    }
)
_BUDGET: Final = re.compile(r"^(?:[1-9]|[1-4][0-9]|50)$", re.ASCII)
_ROUNDS: Final = re.compile(r"^(?:0|[1-9][0-9]{0,17})$", re.ASCII)


def _actionable_kind(kind: object) -> bool:
    """Whether a row's kind is a to-do; unknown or malformed kinds never count."""

    if type(kind) is not str:
        return False
    try:
        return FINDING_KIND_TRAITS[FindingKind(kind)][1]
    except ValueError:
        return False


def _checklist_clause(rows: object, budget: object, next_step: object | None) -> str:
    """Count findings by to-do state with closed tokens only (issue #905).

    Rows are re-read from the structured result; anything that is not an allowlisted state,
    a canonical count or a canonical budget is ignored, so no caller text reaches the summary.
    Coverage-limitation kinds (and unknown kinds) are not to-dos and are not counted, matching the
    check's own checklist counts.
    """

    if not isinstance(rows, list | tuple):
        return ""
    counts = dict.fromkeys(_TODO_STATES, 0)
    at_budget = 0
    linked = 0
    budget_value = int(budget) if type(budget) is str and _BUDGET.fullmatch(budget) else None
    for raw in cast(Sequence[JsonValue], rows):
        if not isinstance(raw, Mapping):
            continue
        row = cast(Mapping[str, JsonValue], raw)
        if not _actionable_kind(row.get("kind")):
            continue
        state = row.get("todo_state")
        if type(state) is not str or state not in counts:
            continue
        counts[state] += 1
        # Issue #996: a holding duplicate link; the row's state is its earlier finding's.
        linked += is_valid_id(IdKind.FINDING, row.get("duplicate_of_finding_id"))
        rounds = row.get("review_rounds")
        if (
            state == "open"
            and budget_value is not None
            and type(rounds) is str
            and _ROUNDS.fullmatch(rounds)
            and int(rounds) >= budget_value
        ):
            at_budget += 1
    if not any(counts.values()):
        return ""
    clause = (
        f"to-do: open {counts['open']}"
        + (f" ({at_budget} at budget {budget_value})" if at_budget else "")
        + f", verified {counts['verified_resolved']}"
        + f", not done {counts['acknowledged_not_done']}"
        + f", rejection accepted {counts['rejection_accepted']}"
        + _self_verified_part(counts["self_verified"])
        + _disputed_part(counts["disputed_after_rebuttal"])
        + (f", linked duplicates {linked}" if linked else "")
        + "; "
    )
    if type(next_step) is str and next_step in _CHECKLIST_NEXT:
        clause += f"next: {next_step}; "
    return clause


def _self_verified_part(count: int) -> str:
    """Issue #984: named only when present, so every earlier summary keeps its exact bytes."""

    return f", self-verified {count}" if count else ""


def _disputed_part(count: int) -> str:
    """Issue #1020: named only when present, so every earlier summary keeps its exact bytes."""

    return f", disputed after rebuttal {count}" if count else ""


def _checklist_budget_cue(budget: object, next_step: object) -> str:
    """The finding checklist's at-budget decision cue alone, for a summary without room."""

    if next_step != "decide_at_budget":
        return ""
    budget_text = budget if type(budget) is str and _BUDGET.fullmatch(budget) else None
    suffix = "" if budget_text is None else f" (at budget {budget_text})"
    return f"finding checklist next: decide_at_budget{suffix}; "


def _closure_counter_clause(counts: Mapping[str, JsonValue]) -> str:
    """The ADR-046 finding counters of a check's ``counts`` object, or ``""`` when absent."""

    keys = ("to_do", "awaiting_ruling", "unmet", "disclosed", "to_disclose")
    if not all(
        type(counts.get(key)) is str and _ROUNDS.fullmatch(cast(str, counts[key])) for key in keys
    ):
        return ""
    variants = closure_counts_variants(
        {
            "to_do": counts["to_do"],
            "awaiting_ruling": counts["awaiting_ruling"],
            "unmet": counts["unmet"],
            "disclosed": counts["disclosed"],
            "to_disclose": counts["to_disclose"],
            "self_verify_eligible": "0",
        },
        None,
    )
    return variants[0] if variants else ""


def _checklist_counts_clause(
    counts: object,
    budget: object,
    next_step: object,
    *,
    input_action_required: bool = False,
) -> str:
    """The check's to-do counts, taken from its whole-list ``counts`` object (issue #905)."""

    if not isinstance(counts, Mapping):
        return ""
    source = cast(Mapping[str, JsonValue], counts)
    values: dict[str, int] = {}
    for key in (
        "open",
        "open_at_budget",
        "verified_resolved",
        "acknowledged_not_done",
        "rejection_accepted",
    ):
        raw = source.get(key)
        if type(raw) is not str or _ROUNDS.fullmatch(raw) is None:
            return ""
        values[key] = int(raw)
    # Absent on a result an earlier build shaped (issue #984).
    raw_self_verified = source.get("self_verified", "0")
    self_verified = (
        int(raw_self_verified)
        if type(raw_self_verified) is str and _ROUNDS.fullmatch(raw_self_verified)
        else 0
    )
    raw_disputed = source.get("disputed_after_rebuttal", "0")
    disputed = (
        int(raw_disputed) if type(raw_disputed) is str and _ROUNDS.fullmatch(raw_disputed) else 0
    )
    budget_text = budget if type(budget) is str and _BUDGET.fullmatch(budget) else None
    closure = _closure_counter_clause(source)
    if closure:
        # ADR-046: the one set of finding counters (the numbers status prints), then what the
        # checklist adds: items proved absent, and the budget cue.
        clause = closure[:-1] + (
            f"; verified {values['verified_resolved']}" if values["verified_resolved"] else ""
        )
        if values["open_at_budget"] and budget_text is not None:
            clause += f"; {values['open_at_budget']} at budget {budget_text}"
        clause += "; "
        if type(next_step) is str and next_step in _CHECKLIST_NEXT:
            label = "finding checklist next" if input_action_required else "next"
            clause += f"{label}: {next_step}; "
        return clause
    clause = (
        f"to-do: open {values['open']}"
        + (
            f" ({values['open_at_budget']} at budget {budget_text})"
            if values["open_at_budget"] and budget_text is not None
            else ""
        )
        + f", verified {values['verified_resolved']}"
        + f", not done {values['acknowledged_not_done']}"
        + f", rejection accepted {values['rejection_accepted']}"
        + _self_verified_part(self_verified)
        + _disputed_part(disputed)
        + "; "
    )
    if type(next_step) is str and next_step in _CHECKLIST_NEXT:
        label = "finding checklist next" if input_action_required else "next"
        clause += f"{label}: {next_step}; "
    return clause


def _overall_next_parts(source: Mapping[str, JsonValue]) -> list[Part]:
    """Render the structured task continuation before the finding-only checklist (#963).

    The action and status are the one instruction the closing check must carry, so they are a
    required part. The acknowledged-endpoint and limitation-disclosure sentences and the target
    refs are optional parts beside it; a 64-ref list shrinks to as many refs as fit, then to a
    count, and never makes the action itself disappear.
    """

    raw = source.get("overall_next")
    if not isinstance(raw, Mapping):
        return []
    next_source = cast(Mapping[str, JsonValue], raw)
    action = next_source.get("action")
    status = next_source.get("status")
    if action not in {
        "supply_missing_input",
        "work_open_findings",
        "disclose_limitations",
        "request_ruling",
        "review_recorded_work",
        "request_receipt",
    }:
        return []
    if status not in {"action_required", "ready_with_limitations", "ready"}:
        return []
    raw_refs = next_source.get("target_refs")
    refs = (
        tuple(
            value
            for value in cast(Sequence[JsonValue], raw_refs)
            if type(value) is str and _MISSING_REF.fullmatch(value) is not None
        )
        if isinstance(raw_refs, (list, tuple))
        else ()
    )
    if (
        action
        in {"work_open_findings", "disclose_limitations", "request_ruling", "review_recorded_work"}
        and not refs
    ):
        return []
    if action == "request_receipt" and refs:
        return []
    endpoint = next_source.get("acknowledged_incomplete_endpoint")
    parts = [_req(f"overall next: {action}; status: {status};")]
    predicted = next_source.get("predicted_conclusion")
    if type(predicted) is str:
        sentence = predicted_receipt_variants(
            {"conclusion": predicted, "reasons": ()},
            state="action_required" if status == "action_required" else "ready",
        )
        if sentence:
            parts.append(_opt(*sentence, priority=_P_ACTION + 3))
    if endpoint == "receipt":
        parts.append(_opt("acknowledged incomplete endpoint: receipt;", priority=_P_ACTION))
    if status == "ready_with_limitations" and endpoint == "receipt":
        parts.append(_opt("disclose limitation at: receipt;", priority=_P_ACTION))
    if refs:
        variants = tuple(
            variant
            for variant in list_variants(
                "targets: ", refs, joiner=",", more=",...(+{n})", suffix=";", max_variants=32
            )
            if len(variant) <= _LIST_MAX_CHARS
        )
        parts.append(
            _opt(*variants, f"targets: ...(+{len(refs)});", priority=_P_ACTION)
            if len(refs) > 1
            else _opt(*variants, priority=_P_ACTION)
        )
    return parts


def _item_count(value: object) -> str:
    if isinstance(value, list | tuple):
        items = cast(Sequence[JsonValue], value)
        return str(min(len(items), 9_223_372_036_854_775_807))
    return "unavailable"


def _finding_identity_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Render as many revalidated finding IDs as the check summary can safely carry.

    A check's text projection is an authoring fallback.  When it reports actionable
    findings, the returned IDs are required to author ``respond`` (issue #324).
    """

    raw_findings = source.get("findings")
    if not isinstance(raw_findings, list | tuple):
        return None
    finding_ids = tuple(
        cast(str, raw.get("finding_id"))
        for raw in raw_findings
        if isinstance(raw, Mapping) and is_valid_id(IdKind.FINDING, raw.get("finding_id"))
    )
    return _list_part("finding IDs: ", finding_ids, priority=_P_IDENTITY)


_MISSING_KINDS: Final = frozenset(
    {
        "command_identity",
        "current_diff_for_path",
        "other",
        "plan_or_claim_text",
        "prior_finding_context",
        "task_statement",
        "verification_output",
    }
)
# Frozen legacy identifier (ADR-048): the ``yoetz_limit_*`` availability values are released.
_MISSING_AVAILABILITIES: Final = frozenset(
    {
        "agent_suppliable",
        "structurally_unavailable_on_this_host",
        "yoetz_limit_packet_room",
        "yoetz_limit_unsupported_data_type",
    }
)


def _missing_items_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Name each item an ``insufficient_packet`` review needed, from closed tokens only (#907).

    Kinds and availability classes are re-gated against their closed vocabularies; target refs
    stay in the structured result. The clause is a check limitation, never a finding.
    """

    raw = source.get("missing_for_assessment")
    if not isinstance(raw, list | tuple):
        return None
    tokens: list[str] = []
    suppliable = 0
    finishup_limit = 0
    for item in cast(Sequence[JsonValue], raw):
        if not isinstance(item, Mapping):
            continue
        item_source = cast(Mapping[str, JsonValue], item)
        kind = item_source.get("kind")
        availability = item_source.get("availability")
        if kind not in _MISSING_KINDS or availability not in _MISSING_AVAILABILITIES:
            continue
        suppliable += availability == "agent_suppliable"
        finishup_limit += type(availability) is str and availability.startswith("yoetz_limit_")
        refs = item_source.get("target_refs")
        safe_refs = (
            tuple(
                value
                for value in cast(Sequence[JsonValue], refs)
                if type(value) is str and _MISSING_REF.fullmatch(value) is not None
            )
            if isinstance(refs, (list, tuple))
            else ()
        )
        target = f"[{','.join(safe_refs)}]" if safe_refs else ""
        instruction = (
            publish_exactly(kind)
            if availability == "agent_suppliable" and type(kind) is str
            else ""
        )
        published = f": {instruction}" if instruction else ""
        tokens.append(f"{kind}={availability}{target}{published}")
    if not tokens:
        return None
    limit_note = (
        f", finishup-limit: {finishup_limit}, self-verify, not a blocker, never reshape the work"
        if finishup_limit
        else ""
    )
    return _list_part(
        f"missing for assessment: {len(tokens)} (agent-suppliable: {suppliable}{limit_note}): ",
        tokens,
        priority=_P_STATE,
    )


def _limitation_refs_required_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Name the result ids a whole-task completion claim must list in ``limitation_refs`` (F3).

    Ids and the service count only, so the first completion claim is accepted. A scoped claim
    needs only those whose action names a claimed obligation or none.
    """

    readiness = source.get("closure_readiness")
    if not isinstance(readiness, Mapping):
        return None
    typed = cast(Mapping[str, JsonValue], readiness)
    count = _safe_count(typed.get("limitation_refs_required_count"))
    raw = typed.get("limitation_refs_required")
    if count in {"unavailable", "0"} or not isinstance(raw, list | tuple):
        return None
    values = tuple(
        value
        for value in cast(Sequence[object], raw)
        if type(value) is str and _RESULT_REF.fullmatch(value) is not None
    )[:_MAX_SUMMARY_LIMITATION_IDS]
    prefix = f"limitation_refs a whole-task completion claim must name ({count}): "
    variants: list[str] = []
    for shown in range(len(values), 0, -1):
        remaining = int(count) - shown
        suffix = f"; +{remaining} more" if remaining > 0 else ""
        variants.append(f"{prefix}{', '.join(values[:shown])}{suffix};")
    if not variants:
        return None
    return Part(tuple(variants), priority=_P_ACTION)


def _obligation_ids_from_status(source: Mapping[str, JsonValue], view: str) -> tuple[str, ...]:
    page = source.get("page")
    if not isinstance(page, Mapping):
        return ()
    typed_page = cast(Mapping[str, JsonValue], page)
    raw_items: object = typed_page.get("items")
    if view == "compact":
        item = _first_page_item(source)
        raw_items = item.get("open_obligations") if item is not None else None
    if not isinstance(raw_items, list | tuple):
        return ()
    return tuple(
        cast(str, item.get("obligation_id"))
        for item in raw_items
        if isinstance(item, Mapping) and is_valid_id(IdKind.OBLIGATION, item.get("obligation_id"))
    )


def _obligation_resolve_recipe(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """The shared resolution recipe when the obligations page holds an unresolved row."""

    page = source.get("page")
    if not isinstance(page, Mapping):
        return ()
    return obligation_resolve_recipe_variants(cast(Mapping[str, JsonValue], page).get("items"))


def _finding_frontiers_from_status(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Pair each revalidated finding ID with the frontier ``respond`` accepts for it (#917).

    Only an allowlisted finding ID, a canonical sequence and a digest-shaped head leave this
    projector, so the text fallback can author ``respond`` without a frontier hunt.
    """

    page = source.get("page")
    if not isinstance(page, Mapping):
        return ()
    raw_items: object = cast(Mapping[str, JsonValue], page).get("items")
    if not isinstance(raw_items, list | tuple):
        return ()
    values: list[str] = []
    for raw in cast(Sequence[JsonValue], raw_items):
        if not isinstance(raw, Mapping):
            continue
        item = cast(Mapping[str, JsonValue], raw)
        finding = item.get("finding_id")
        frontier = item.get("finding_frontier")
        if not is_valid_id(IdKind.FINDING, finding) or not isinstance(frontier, Mapping):
            continue
        typed_frontier = cast(Mapping[str, JsonValue], frontier)
        sequence = _safe_count(typed_frontier.get("sequence"))
        head = typed_frontier.get("head_digest")
        if sequence == "unavailable" or type(head) is not str or not _HEAD_DIGEST.fullmatch(head):
            continue
        values.append(f"{cast(str, finding)} at {sequence} {head}")
    return tuple(values)


def _open_obligation_ids_from_receipt(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    raw_items = source.get("obligations")
    if not isinstance(raw_items, list | tuple):
        return ()
    return tuple(
        cast(str, item.get("obligation_id"))
        for item in raw_items
        if isinstance(item, Mapping)
        and item.get("status") == "open"
        and is_valid_id(IdKind.OBLIGATION, item.get("obligation_id"))
    )


def _safe_gap_codes(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    coverage = source.get("coverage")
    if not isinstance(coverage, Mapping):
        return ()
    raw_gaps = cast(Mapping[str, JsonValue], coverage).get("known_gaps")
    if not isinstance(raw_gaps, list | tuple):
        return ()
    return tuple(
        gap for gap in raw_gaps if type(gap) is str and _GAP_CODE.fullmatch(gap) is not None
    )


def _safe_status_gap_codes(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    raw_gaps = source.get("gaps")
    if not isinstance(raw_gaps, list | tuple):
        return ()
    return tuple(
        gap for gap in raw_gaps if type(gap) is str and _GAP_CODE.fullmatch(gap) is not None
    )


def _semantic_withheld_item_tokens(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Return only validated opaque identities and the fixed omission reason."""

    raw_items = source.get("semantic_withheld_items")
    if not isinstance(raw_items, (list, tuple)):
        return ()
    result: list[str] = []
    for raw in raw_items:
        if not isinstance(raw, Mapping) or raw.get("reason") != "never_send_heuristic":
            continue
        item_id = raw.get("item_id")
        try:
            validate_opaque_item_id(item_id)
        except TypeError, ValueError:
            continue
        result.append(f"{cast(str, item_id)} (never_send_heuristic)")
    return tuple(result)


def _semantic_withheld_items_part(source: Mapping[str, JsonValue]) -> Part | None:
    return _list_part(
        "withheld review items: ", _semantic_withheld_item_tokens(source), priority=_P_DETAIL
    )


def _semantic_redacted_value_tokens(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """PL2-1: validated item refs and line numbers only; never a value."""

    raw_items = source.get("semantic_redacted_values")
    if not isinstance(raw_items, (list, tuple)):
        return ()
    result: list[str] = []
    for raw in raw_items:
        try:
            item = SemanticRedactedValue.from_wire(raw)
        except TypeError, ValueError:
            continue
        ref = item.item_id if item.source_ref is None else item.source_ref
        what = "replaced" if item.disposition == "value_replaced" else "item withheld"
        lines = "L" + ",".join(str(line) for line in item.lines) if item.lines else "L?"
        result.append(f"{ref} {what} {lines}")
    return tuple(result)


def _semantic_redacted_values_part(source: Mapping[str, JsonValue]) -> Part | None:
    return _list_part(
        "withheld from external review: ",
        _semantic_redacted_value_tokens(source),
        priority=_P_DISCLOSURE,
    )


def _semantic_redacted_values_line_part(source: Mapping[str, JsonValue]) -> Part | None:
    """The fixed PL2-1 agent line, once, when any item lost a value to external review.

    The full line is used when it fits beside the required text, else the shorter fixed form,
    else nothing (the structured result still has it). It outranks every other optional clause.
    """

    if not _semantic_redacted_value_tokens(source):
        return None
    return Part(
        (SEMANTIC_REDACTED_VALUES_AGENT_LINE, SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT),
        priority=_P_ACTION - 1,
    )


def _review_text(value: object) -> str | None:
    """Return one already privacy-projected review field, or a fixed omission marker."""

    if type(value) is str and value:
        return value
    if isinstance(value, Mapping):
        source = cast(Mapping[str, JsonValue], value)
        if source.get("omitted") is True and source.get("category") == "finding_summary":
            return "[review text omitted by privacy policy]"
    return None


def _review_refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item
        for item in cast(Sequence[JsonValue], value)
        if type(item) is str and _MISSING_REF.fullmatch(item) is not None
    )[:16]


def _clip_review_text(value: str, budget: int) -> str:
    if budget <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= budget:
        return value
    suffix = "…".encode()
    if budget <= len(suffix):
        return suffix[:budget].decode("utf-8", errors="ignore")
    return encoded[: budget - len(suffix)].decode("utf-8", errors="ignore") + "…"


def render_check_reviewer_output(envelope: object) -> str:
    """Render authorized reviewer prose after the structural MCP summary.

    ``render_safe_compact_summary`` stays structural and bounded (4096 bytes since tb4n3 RC-2;
    it was 512). This separate section carries only the privacy-projected Part 2 fields, with fixed
    labels and a larger overall bound so a successful review is visible to text-only hosts.
    """

    source = _mapping(envelope)
    lines: list[str] = []
    summary = _review_text(source.get("review_summary"))
    if summary is not None:
        lines.append("Reviewer summary: " + summary)

    raw_verified = source.get("verified")
    verified = (
        cast(Sequence[JsonValue], raw_verified) if isinstance(raw_verified, (list, tuple)) else ()
    )
    if verified:
        lines.append("Verified judgements:")
        for raw in verified:
            if not isinstance(raw, Mapping):
                continue
            item = cast(Mapping[str, JsonValue], raw)
            verdict = item.get("verdict")
            if verdict not in _REVIEW_VERDICTS:
                continue
            requirement = _review_text(item.get("requirement_or_claim"))
            if requirement is None:
                requirement = "[requirement omitted by privacy policy]"
            refs = _review_refs(item.get("cited_refs"))
            ref_clause = f"; refs: {', '.join(refs)}" if refs else ""
            lines.append(f"- {verdict}: {requirement}{ref_clause}")
            snippet = _review_text(item.get("snippet"))
            if snippet is not None:
                lines.append("  Supporting snippet: " + snippet)

    raw_findings = source.get("findings")
    findings = (
        cast(Sequence[JsonValue], raw_findings) if isinstance(raw_findings, (list, tuple)) else ()
    )
    challenge_rows: list[tuple[str, Mapping[str, JsonValue]]] = []
    for raw in findings:
        if not isinstance(raw, Mapping):
            continue
        finding = cast(Mapping[str, JsonValue], raw)
        challenge = finding.get("challenge")
        if isinstance(challenge, Mapping):
            challenge_rows.append(
                (cast(str, finding.get("kind", "")), cast(Mapping[str, JsonValue], challenge))
            )
    if challenge_rows:
        lines.append("Reviewer challenges:")
        for kind, challenge in challenge_rows:
            if kind not in _REVIEW_KINDS:
                kind = "review finding"
            discrepancy = _review_text(challenge.get("discrepancy"))
            if discrepancy is not None:
                lines.append(f"- {kind}: {discrepancy}")
            snippet = _review_text(challenge.get("snippet"))
            if snippet is not None:
                lines.append("  Supporting snippet: " + snippet)

    if not lines:
        return ""
    lines.insert(0, "AI-powered reviewer output (advisory; model-derived; not independent proof):")
    rendered: list[str] = []
    used = 0
    truncation_notice = "Reviewer output truncated at the local text budget."
    total_bytes = sum(len(line.encode("utf-8")) for line in lines) + max(len(lines) - 1, 0)
    budget = _MAX_REVIEW_OUTPUT_BYTES
    if total_bytes > budget:
        budget -= len(truncation_notice.encode("utf-8")) + 1
    for line in lines:
        separator = 1 if rendered else 0
        remaining = budget - used - separator
        clipped = _clip_review_text(line, remaining)
        if not clipped:
            break
        rendered.append(clipped)
        used += separator + len(clipped.encode("utf-8"))
        if len(clipped) < len(line):
            break
    result = "\n".join(rendered)
    if total_bytes > _MAX_REVIEW_OUTPUT_BYTES and result:
        result += "\n" + truncation_notice
    return result


def _repair_clause(error: Mapping[str, JsonValue]) -> str:
    """Render the bounded field-ownership repair fact, or "" when none travels on the error.

    Hosts are not required to surface structured content, so the one schema-derived repair
    sentence is repeated on the text channel (issue #266). Every token the sentence carries was
    drawn from frozen schema or registry content upstream, and each is re-gated here against the
    closed field-name shape so this projector admits nothing else.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    if typed.get("repair_kind") != "field_ownership":
        return ""
    field = typed.get("repair_field")
    owner = typed.get("repair_owning_family")
    selected = typed.get("repair_selected_family")
    for token in (field, owner, selected):
        if type(token) is not str or _FIELD_NAME.fullmatch(token) is None:
            return ""
    return f" Repair: {field} is admitted only by the {owner} payload, not {selected}."


# Frozen command keys whose values are repository literals gated by ``_TOKEN_DETAIL_VALUES``.
# Rendered in this fixed order so the same continuation always reads the same way.
_CONTINUATION_COMMAND_KEYS: Final = ("prepare_command", "review_command", "authorize_command")


def _continuation_directive(error: Mapping[str, JsonValue]) -> RecoveryDirective | None:
    """Return the registered directive for this error's continuation token, or None."""

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return None
    typed = cast(Mapping[str, JsonValue], details)
    # Re-gate through the protocol normalizer rather than trusting the envelope: the token must
    # still be a member of the closed continuation set before anything is rendered from it.
    gated = normalize_safe_details({"continuation": typed.get("continuation")})
    return directive_for(gated.get("continuation"))


def _continuation_command_clause(error: Mapping[str, JsonValue]) -> str:
    """Render whichever frozen commands this continuation carries.

    Which commands travel is decided upstream (a Cursor bridge carries no authorize command, for
    instance), so the clause reports what is present rather than restating the directive's own
    wording. Every value was admitted by the closed command token sets, so none is caller-derived.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    candidate = {key: typed.get(key) for key in _CONTINUATION_COMMAND_KEYS}
    gated = normalize_safe_details(candidate)
    commands = [
        str(gated[key]) for key in _CONTINUATION_COMMAND_KEYS if type(gated.get(key)) is str
    ]
    if not commands:
        return ""
    return " Commands: " + "; ".join(commands) + "."


def _continuation_parts(error: Mapping[str, JsonValue]) -> list[Part]:
    """Render the frozen recovery directive for a typed continuation (issues #669, #739, #740).

    Nothing here is copied from the public error message. The token is re-gated, the text is
    looked up from the checked-in registry, and each part is optional beside the error identity
    and location. Parts are granted in the ADR-030 order -- directive, commands, guidance
    pointer, nudge -- so a tight budget costs the least load-bearing advice first, and the
    directive itself shrinks to the bare continuation token before it is dropped.
    """

    directive = _continuation_directive(error)
    if directive is None:
        return []
    parts = [
        _opt(
            f"Continuation: {directive.token}. {directive.directive}",
            f"Continuation: {directive.token}.",
            priority=_P_ACTION,
        )
    ]
    commands = _continuation_command_clause(error)
    if commands:
        parts.append(_opt(commands, priority=_P_ACTION + 1))
    if directive.guidance_uri is not None:
        parts.append(_opt(f"Guidance: {directive.guidance_uri}.", priority=_P_ACTION + 2))
    if directive.nudge is not None:
        parts.append(_opt(directive.nudge, priority=_P_ACTION + 3))
    return parts


def _reason_location_clause(error: Mapping[str, JsonValue]) -> str:
    """Render frozen reason_code and field pointer tokens, or "" when none travel on the error.

    Hosts that deliver only the text channel for ``isError`` results otherwise lose the draft
    index and kernel reason (issue #579). Both tokens are already allowlisted structural content
    on ``safe_details``; this projector re-gates them and never copies caller prose. A field with
    no reason code (a ``read_guidance`` rejection names only ``/uri``) is still named, because the
    location is the part of the error the agent can act on (tb4n3 A3).
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    candidate: dict[str, object] = {}
    reason = typed.get("reason_code")
    field = typed.get("field")
    phase = typed.get("phase")
    if type(reason) is str:
        candidate["reason_code"] = reason
    if type(field) is str:
        candidate["field"] = field
    if type(phase) is str:
        candidate["phase"] = phase
    gated = normalize_safe_details(candidate)
    gated_reason = gated.get("reason_code")
    gated_field = gated.get("field")
    gated_phase = gated.get("phase")
    if type(gated_reason) is not str:
        if type(gated_field) is str:
            return f" Field: {gated_field}."
        return ""
    if type(gated_field) is str:
        return f" Reason: {gated_reason} at {gated_field}."
    if gated_phase in SERVICE_STARTUP_PHASES:
        # The stage a spawned service failed at (#1040); its exception class and origin are in
        # the record the correlation_id resolves.
        return f" Reason: {gated_reason} (stage: {gated_phase})."
    return f" Reason: {gated_reason}."


def _reason_remedy_clause(error: Mapping[str, JsonValue]) -> str:
    """Render the fixed remedy sentence for a typed reason that has one (tb4n3 RC-2).

    ``closure_*`` preparation reasons and the typed INTERNAL_ERROR stages used to reach the text
    channel as a bare token (or not at all), with the sentence that says what to do only in the
    structured message. The sentence is repository text selected by the gated reason token; the
    caller's value never appears.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    reason = normalize_safe_details(
        {"reason_code": cast(Mapping[str, JsonValue], details).get("reason_code")}
    ).get("reason_code")
    if type(reason) is not str:
        return ""
    remedy = REASON_REMEDIES.get(reason)
    if remedy is None and reason.startswith("closure_"):
        remedy = PREPARATION_REMEDIATIONS.get(reason)
    return "" if remedy is None else f" Remedy: {remedy}"


def _validation_location_clause(error: Mapping[str, JsonValue]) -> str:
    """Render the frozen location tokens of a schema rejection, or "" when none travel.

    A tool-argument rejection carries ``fields`` and ``reasons`` lists rather than a single
    ``reason_code``/``field`` pair, and those lists are not members of the protocol allowlist, so
    the text channel previously dropped them entirely: an agent that sent a malformed actor id was
    told only ``Error INVALID_REQUEST; retryable: no`` (issue #739). Every rendered token is
    re-gated against the closed reason set and the pointer shape; the two lists must agree in
    length, and at most two locations are named with the remainder counted.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    fields = typed.get("fields")
    reasons = typed.get("reasons")
    if not isinstance(fields, Sequence) or not isinstance(reasons, Sequence):
        return ""
    if isinstance(fields, str) or isinstance(reasons, str) or len(fields) != len(reasons):
        return ""
    named: list[str] = []
    for field, reason in zip(
        cast(Sequence[JsonValue], fields), cast(Sequence[JsonValue], reasons), strict=True
    ):
        if type(reason) is not str or reason not in VALIDATION_REASON_TOKENS:
            return ""
        if type(field) is not str or _VALIDATION_POINTER.fullmatch(field) is None:
            return ""
        named.append(f"{reason} at {field}")
    if not named:
        return ""
    shown = "; ".join(named[:_MAX_NAMED_VALIDATION_LOCATIONS])
    remainder = len(named) - _MAX_NAMED_VALIDATION_LOCATIONS
    if remainder > 0:
        shown += f" (+{remainder} more)"
    return f" Rejected: {shown}."


_RESULT_OUTCOME_POINTER: Final = re.compile(r"\A/event_drafts/[0-9]{1,3}/payload/outcome\Z")
_RESULT_OUTCOME_HINT: Final = (
    " Outcomes: success|failure|partial|unknown (no blocked): record failure or partial, then"
    " repair. A FinishUP limit is never a blocker (respond self_verified), nor a guess or a check"
    " you cannot run (finishup-assumption: or finishup-verification-limit:<obl id>); finishup-blocker:<kind>"
    " is only for an open obligation genuinely blocked outside your control."
)


_RESULT_OUTCOME_HINT_SHORT: Final = " Outcomes: success|failure|partial|unknown (no blocked)."


def _result_outcome_variants(error: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Name the closed outcome set when a result draft's outcome was rejected (#977).

    TB4 agents sent ``outcome: "blocked"`` and learned only that the field was invalid. The clause
    is fixed repository text selected by the frozen rejection pointer; no caller value is echoed.
    The full hint is followed by the short closed-set sentence, so a tight budget keeps the part
    of the hint the agent needs (the valid values) rather than dropping the hint entirely.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ()
    fields = cast(Mapping[str, JsonValue], details).get("fields")
    if not isinstance(fields, Sequence) or isinstance(fields, str):
        return ()
    if any(
        type(field) is str and _RESULT_OUTCOME_POINTER.fullmatch(field) is not None
        for field in cast(Sequence[JsonValue], fields)
    ):
        return (_RESULT_OUTCOME_HINT, _RESULT_OUTCOME_HINT_SHORT)
    return ()


def _claim_revision_clause(error: Mapping[str, JsonValue]) -> str:
    """Render the closed claim-revision invariant and its correction from typed details.

    Until ADR-030 the invariant reached this projector only inside the public error message, so
    this clause matched that whole sentence with a regex and re-derived a token the domain had
    already validated. ``invariant`` is now an allowlisted safe detail: it is re-gated through the
    protocol normalizer here, and the corrective phrase comes from the shared recovery registry
    that the CLI renders from too.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    gated = normalize_safe_details(
        {
            "invariant": typed.get("invariant"),
            "reason_code": typed.get("reason_code"),
        }
    )
    if gated.get("reason_code") != "claim_revision_mismatch":
        return ""
    correction = correction_for_invariant(gated.get("invariant"))
    if correction is None:
        return ""
    return f" Invariant: {gated['invariant']}. Correction: {correction}."


_MAX_SUMMARY_BLOCKING_REASONS: Final = 4


def _blocking_reasons_clause(error: Mapping[str, JsonValue]) -> str:
    """Name what refused a ``self_verified`` answer and its exit (tb4n2 R5, issue #1023).

    The tokens are re-gated through the protocol normalizer (recorded resolution-reason tokens
    only, never prose); the exit sentence is checked-in text.
    """

    details = error.get("safe_details")
    if not isinstance(details, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], details)
    reasons = typed.get("blocking_reasons")
    gated = normalize_safe_details(
        {
            "reason_code": typed.get("reason_code"),
            "blocking_reasons": tuple(reasons) if isinstance(reasons, list | tuple) else None,
        }
    )
    blocking = gated.get("blocking_reasons")
    if gated.get("reason_code") != "finding_not_proof_limited" or type(blocking) is not tuple:
        return ""
    named = ", ".join(blocking[:_MAX_SUMMARY_BLOCKING_REASONS])
    if len(blocking) > _MAX_SUMMARY_BLOCKING_REASONS:
        named += f" (+{len(blocking) - _MAX_SUMMARY_BLOCKING_REASONS})"
    return (
        f" Not a FinishUP limit; still listed: {named}. Repair and check, or disclose a check you"
        " cannot run with finishup-verification-limit:<obligation id>."
    )


def summary_for_public_error(envelope: object) -> str:
    """Render only the stable public error identity, never message or rejected input.

    Bounded exceptions are the field-ownership repair fact (issue #266), the frozen
    ``reason_code``/``field`` location clause (issue #579), and the exact-shape claim-revision
    invariant clause. All projected values come from schema or registry tokens, never caller
    input. A host that drops structured content on ``isError`` would otherwise lose the only
    correction that names which draft and which kernel rule to fix.

    Budget priority (ADR-030): error identity and the rejected location are required; the
    continuation directive, outcome hint, repair and correction clauses, commands, guidance
    pointer and nudge follow in that order and are the first to shrink or drop.
    """

    render = _Render("error")
    source = _mapping(envelope)
    nested = source.get("error")
    error = _mapping(nested) if nested is not None else source
    code = _safe_token(error.get("code"), fallback="INTERNAL_ERROR")
    if code not in {item.value for item in PublicErrorCode}:
        code = "INTERNAL_ERROR"
    retryable = error.get("retryable")
    retry_text = "yes" if retryable is True else "no"
    correlation = error.get("correlation_id")
    correlation_text = (
        correlation
        if type(correlation) is str and _CORRELATION_ID.fullmatch(correlation) is not None
        else "unavailable"
    )
    parts: list[Part | None] = [
        _req(f"Error {code}; retryable: {retry_text}; correlation: {correlation_text}."),
        _opt(render.text("repair", lambda: _repair_clause(error)), priority=_P_IDENTITY),
        _req(render.text("location", lambda: _reason_location_clause(error))),
        _opt(render.text("remedy", lambda: _reason_remedy_clause(error)), priority=_P_ACTION - 1),
        _req(render.text("validation", lambda: _validation_location_clause(error))),
        _opt(
            *render.variants("outcome_hint", lambda: _result_outcome_variants(error)),
            priority=_P_IDENTITY,
        ),
        _opt(
            render.text("claim_revision", lambda: _claim_revision_clause(error)),
            priority=_P_IDENTITY,
        ),
        _opt(
            render.text("blocking_reasons", lambda: _blocking_reasons_clause(error)),
            priority=_P_IDENTITY,
        ),
    ]
    parts.extend(render.guarded_parts("continuation", lambda: _continuation_parts(error)))
    parts.append(render.failure_part())
    return _compose(parts)


def _observations_awaited_clause(source: Mapping[str, JsonValue]) -> str:
    """One short clause for the optional pre-check hook-row wait (issue #1012)."""

    awaited = source.get("observations_awaited")
    if not isinstance(awaited, Mapping):
        return ""
    state = awaited.get("state")
    if state == "complete":
        return "hook observations awaited: complete; "
    if state == "bounded_timeout":
        pending = _safe_count(awaited.get("pending_count"))
        return f"hook observations awaited: bounded_timeout, {pending} still pending; "
    if state == "unavailable":
        return "hook observations awaited: unavailable; "
    return ""


def _check_lead_variants(
    source: Mapping[str, JsonValue], verdict: str, status: str, reason: str
) -> tuple[str, ...]:
    """The check's opening sentence, longest first. The shortest still names the verdict."""

    findings = _item_count(source.get("findings"))
    suppressed = _safe_count(source.get("suppressed_count"))
    counts = f"findings returned: {findings}; suppressed: {suppressed};"
    scoped_local_verdict = (
        verdict == "no_issue_detected"
        and status == "not_requested"
        and reason == "deterministic_mode"
    )
    if status == "not_requested" and (
        "semantic_review_deferred_before_first_edit" in _safe_gap_codes(source)
    ):
        # Issue #1046: a pre-work check ran the local plan checks only; nothing was sent.
        return (
            "AI-powered review deferred until the first material edit (no edit is recorded "
            "yet; the next check after one reviews, and the closing review is never deferred); "
            f"local plan check verdict: {verdict}; {counts}",
            "AI-powered review deferred until the first edit; local plan check verdict: "
            f"{verdict}; {counts}",
            f"AI-powered review deferred; local check verdict: {verdict};",
        )
    if status == "not_requested" and (
        "semantic_review_skipped_insufficient_packet" in _safe_gap_codes(source)
    ):
        # tb4n1 D3: not a local-only request; the round stopped after one insufficient retry.
        return (
            "AI-powered review skipped: the reviewer twice in a row (or four times since the last "
            "assessed review) "
            "could not assess the packet or an answered finding (verify it yourself; a repair "
            "re-arms it until that cap); "
            f"local check verdict: {verdict}; {counts}",
            f"AI-powered review skipped (verify it yourself); local check verdict: {verdict}; "
            f"{counts}",
            f"AI-powered review skipped; local check verdict: {verdict};",
        )
    if scoped_local_verdict:
        return (
            "No issue detected within local coverage; AI-powered review was not "
            f"requested; {counts}",
            f"No issue detected within local coverage; {counts}",
            "No issue detected within local coverage;",
        )
    if status == "not_requested":
        return (
            f"AI-powered review not requested; local-only check verdict: {verdict}; {counts}",
            f"local-only check verdict: {verdict}; {counts}",
            f"local-only check verdict: {verdict};",
        )
    return (f"Check verdict: {verdict}; {counts}", f"Check verdict: {verdict};")


def _route_variants(status: str, source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    if status == "not_requested" and source.get("semantic_route_required") is False:
        # Issue #986 (owner decision E2): the route did not require review, so the missing review
        # is a disclosure; a route that required it omits the field and the gap still blocks.
        return (
            "route did not require AI-powered review (disclosed; does not block receipt);",
            "route: review not required (disclosed);",
        )
    return ()


def _children_clause(source: Mapping[str, JsonValue]) -> str:
    children = source.get("children")
    if (
        isinstance(children, Mapping)
        and type(children.get("label")) is str
        and children.get("label") in {"recorded", "preview"}
    ):
        return f"children ({children['label']}): {_item_count(children.get('items'))};"
    return ""


def _notes_clause(source: Mapping[str, JsonValue]) -> str:
    notes = source.get("advisory_notes")
    if isinstance(notes, (list, tuple)) and notes:
        return f"project advice (non-verdict): {len(notes)};"
    return ""


def _checklist_variants(
    source: Mapping[str, JsonValue], *, input_action_required: bool
) -> tuple[str, ...]:
    checklist = source.get("finding_checklist")
    if not isinstance(checklist, Mapping):
        return ()
    typed = cast(Mapping[str, JsonValue], checklist)
    # An item at its attempt budget needs a decision rather than another repair round (#905); the
    # compact cue is the variant that survives when the whole to-do clause does not fit.
    return (
        _checklist_counts_clause(
            typed.get("counts"),
            typed.get("attempt_budget"),
            typed.get("next"),
            input_action_required=input_action_required,
        ),
        _checklist_budget_cue(typed.get("attempt_budget"), typed.get("next")),
    )


def _continuation_variants(
    status: str, reason: str, source: Mapping[str, JsonValue]
) -> tuple[str, ...]:
    recovery = continuation_for_semantic_outcome(
        status=status,
        reason=reason,
        failure_class=_failure_class_from_mapping(source.get("semantic_provenance")),
    )
    recovered = directive_for(recovery)
    if recovered is None:
        return ()
    return (
        f"Continuation: {recovered.token}. {recovered.directive}",
        f"Continuation: {recovered.token}.",
    )


def _lineage_sentence(raw: object, code: str | None = None) -> str:
    """The first ``Why:`` sentence of a result's ``fact_lineage`` (ADR-045), or ``""``.

    ``raw`` is the wire list; entries that do not parse are skipped. With *code*, only that
    fact's provenance. ASCII by construction (ids, counts and closed tokens only).
    """

    if not isinstance(raw, list | tuple):
        return ""
    items: list[FactLineage] = []
    for entry in cast(Sequence[object], raw):
        try:
            items.append(lineage_from_wire(entry))
        except TypeError, ValueError:
            continue
    texts = lineage_texts(items, code)
    return texts[0] if texts else ""


def _check_time_change_sentence(source: Mapping[str, JsonValue]) -> str:
    # Why the check-time change was unavailable (ADR-031): a fixed sentence per closed code.
    for code in _safe_gap_codes(source):
        sentence = check_time_change_gap_sentence(code)
        if sentence is not None:
            return sentence
    return ""


def _check_fact_why_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Why the first derived fact this check reports fired (ADR-045), from its own provenance.

    The check result carries ``fact_lineage`` beside the known gap codes it explains (an emptied
    declared deliverable, a loosely matched planned command); the sentence is the first one for a
    code the check reports. Optional and at the disclosure priority, so it shrinks away before the
    verdict, the next instruction or the frontier.
    """

    raw = source.get("fact_lineage")
    for code in _safe_gap_codes(source):
        why = _lineage_sentence(raw, code)
        if why:
            return Part((why,), priority=_P_DISCLOSURE)
    return None


def summary_for_check(envelope: object) -> str:
    """Compose the check's text projection: verdict, next instruction and frontier first.

    The required core is the verdict sentence, the task continuation (``overall next``), the
    review status/reason and the frontier with its head digest. Everything else -- route and await
    disclosures, children, advice, the to-do checklist, finding ids, missing-for-assessment items,
    withheld items, the recovery directive -- is granted room by priority and shrinks or drops
    when the bound is tight. The text never raises and never exceeds ``_MAX_SUMMARY_BYTES``
    (tb4n3 RC-2): the closing check of a deterministic run used to overflow 512 bytes, lose its
    verdict to ``INTERNAL_ERROR`` and leave the agent claiming a check it never read.
    """

    render = _Render("check")
    source = _mapping(envelope)
    verdict = _safe_token(source.get("verdict"))
    status = _safe_token(source.get("semantic_status"))
    reason = _safe_token(source.get("semantic_reason"))
    input_action_required = has_agent_suppliable_missing(source.get("missing_for_assessment"))
    overall = render.guarded_parts("overall_next", lambda: _overall_next_parts(source))
    parts: list[Part | None] = [
        # The lead's shortest form already names the verdict and its coverage bound; the longer
        # forms explain, so they are granted room after the instructions and ids.
        Part(
            _check_lead_variants(source, verdict, status, reason),
            required=True,
            priority=_P_DISCLOSURE,
        ),
        _opt(
            *render.variants("route", lambda: _route_variants(status, source)),
            priority=_P_DISCLOSURE,
        ),
        _opt(
            render.text("awaited", lambda: _observations_awaited_clause(source)),
            priority=_P_DISCLOSURE,
        ),
        _opt(render.text("children", lambda: _children_clause(source))),
        _opt(render.text("notes", lambda: _notes_clause(source))),
        *overall,
    ]
    if not overall and input_action_required:
        # Keep the input continuation ahead of the optional checklist and manifest clauses. A
        # large finding list must never consume the bounded summary budget and leave only the
        # finding-only ``request_receipt`` token (#963).
        parts.append(
            _opt(
                "overall next: supply_missing_input before ordinary receipt "
                "(new records only; never change the work to fit the reviewer);",
                priority=_P_ACTION,
            )
        )
    checklist = source.get("finding_checklist")
    at_budget = isinstance(checklist, Mapping) and (
        cast(Mapping[str, JsonValue], checklist).get("next") == "decide_at_budget"
    )
    parts.append(
        _opt(
            *render.variants(
                "checklist",
                lambda: _checklist_variants(
                    source, input_action_required=input_action_required or bool(overall)
                ),
            ),
            # A finding at its attempt budget needs a decision, not another repair round (#905),
            # so that cue is an instruction and outranks the descriptive clauses.
            priority=_P_ACTION if at_budget else _P_STATE,
        )
    )
    parts.append(
        _opt(
            render.text(
                "manifest",
                lambda: _manifest_sentence(source),
            ),
            priority=_P_DETAIL,
        )
    )
    parts.append(
        render.guarded_one("redacted_values", lambda: _semantic_redacted_values_part(source))
    )
    parts.append(render.guarded_one("finding_ids", lambda: _finding_identity_part(source)))
    parts.append(render.guarded_one("missing_items", lambda: _missing_items_part(source)))
    parts.append(
        render.guarded_one("withheld_items", lambda: _semantic_withheld_items_part(source))
    )
    # ADR-049: the mode this check ran in; a task that asked for AI-powered review and still ran
    # local gets the exact continuation as an instruction.
    parts.append(
        _opt(render.text("review_mode", lambda: _review_mode_clause(source)), priority=_P_STATE)
    )
    parts.append(
        _opt(
            render.text("review_mode_next", lambda: _review_mode_next_clause(source)),
            priority=_P_ACTION,
        )
    )
    parts.extend(
        (
            _req(f"AI-powered review status/reason: {status}/{reason};"),
            _req(f"{_frontier_clause(source)}."),
            _opt(
                *render.variants(
                    "continuation", lambda: _continuation_variants(status, reason, source)
                ),
                # The recovery directive is the first optional clause granted (ADR-043).
                priority=_P_ACTION - 2,
            ),
            _opt(
                render.text("gap_sentence", lambda: _check_time_change_sentence(source)),
                priority=_P_DISCLOSURE,
            ),
            render.guarded_one("fact_lineage", lambda: _check_fact_why_part(source)),
            render.guarded_one(
                "redacted_values_line", lambda: _semantic_redacted_values_line_part(source)
            ),
            render.failure_part(),
        )
    )
    return _compose(parts)


def _review_mode_clause(source: Mapping[str, JsonValue]) -> str:
    """ADR-049: the check's review-mode line; closed tokens and an event id only."""

    return check_review_mode_line(source.get("review_mode"))


def _review_mode_next_clause(source: Mapping[str, JsonValue]) -> str:
    review_mode = source.get("review_mode")
    if not isinstance(review_mode, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], review_mode)
    if typed.get("mode") != "local":
        return ""
    continuation = review_mode_continuation(typed.get("local_reason"))
    return "" if not continuation else f"Review mode next: {continuation}"


def _status_review_mode_clause(source: Mapping[str, JsonValue]) -> str:
    """ADR-049: the task's review mode and the owner's setting for status."""

    return status_review_mode_line(source.get("review_mode"))


# ADR-049: the receipt's review-mode sentences, recognised by their fixed openings only; the
# summary points at them with closed wording and never carries their text.
_RECEIPT_REVIEW_MODE_POINTERS: Final = (
    (
        "Review mode switches recorded for this task:",
        "review mode switched in this task (limitations section names each switch);",
    ),
    (
        "The applicable check ran local checks only (FinishUP)",
        "review mode: local (FinishUP); limitations section says how the check ran;",
    ),
    (
        "The applicable check ran with AI-powered review requested.",
        "review mode: AI-powered review; limitations section says how the check ran;",
    ),
)


def _receipt_review_mode_clause(source: Mapping[str, JsonValue]) -> str:
    """ADR-049: a fixed pointer to the receipt's review-mode sentences; never their text."""

    document = source.get("document")
    if not isinstance(document, Mapping):
        return ""
    sections = cast(Mapping[str, JsonValue], document).get("sections")
    if not isinstance(sections, (list, tuple)):
        return ""
    for raw in cast(Sequence[object], sections):
        if not isinstance(raw, Mapping):
            continue
        section = cast(Mapping[str, object], raw)
        body = section.get("body")
        if section.get("key") != "limitations_and_coverage" or type(body) is not str:
            continue
        for opening, pointer in _RECEIPT_REVIEW_MODE_POINTERS:
            if opening in body:
                return pointer
    return ""


def _manifest_sentence(source: Mapping[str, JsonValue]) -> str:
    manifest = render_review_input_manifest_compact(source.get("review_input_manifest"))
    return manifest


def _first_page_item(source: Mapping[str, JsonValue]) -> Mapping[str, JsonValue] | None:
    page = source.get("page")
    if not isinstance(page, Mapping):
        return None
    items = cast(Mapping[str, JsonValue], page).get("items")
    if not isinstance(items, list | tuple) or not items:
        return None
    item = items[0]
    if not isinstance(item, Mapping):
        return None
    return cast(Mapping[str, JsonValue], item)


def _status_freshness(
    source: Mapping[str, JsonValue], view: str, item: Mapping[str, JsonValue] | None
) -> str:
    """Report the compact singleton's own freshness, and the envelope's coverage otherwise.

    The compact item carries the projection's ledger freshness (``partial`` or
    ``stale_after_material_change`` after material change); the result's ``coverage`` carries the
    newest record envelope's, which is routinely ``current`` at exactly that frontier. This summary
    is the documented fallback when a host drops structured content, so it must never read stronger
    than the view it stands in for. Only ``compact`` items carry a ledger freshness — an
    ``evidence`` row's ``freshness`` describes that evidence, not the ledger.
    """

    if view == "compact" and item is not None:
        freshness = _safe_token(item.get("freshness"))
        if freshness != "unavailable":
            return freshness
    coverage = source.get("coverage")
    if isinstance(coverage, Mapping):
        return _safe_token(cast(Mapping[str, JsonValue], coverage).get("ledger_freshness"))
    return "unavailable"


def _acknowledged_obligations_clause(source: Mapping[str, JsonValue]) -> str:
    """#997: obligations acknowledged as not done, never part of the open count."""

    readiness = source.get("closure_readiness")
    if not isinstance(readiness, Mapping):
        return ""
    count = _safe_count(
        cast(Mapping[str, JsonValue], readiness).get("acknowledged_obligation_count")
    )
    if count in {"unavailable", "0"}:
        return ""
    return f"acknowledged not done (not open): {count}; "


def _compact_status_fields(source: Mapping[str, JsonValue], view: str) -> tuple[str, str, str, str]:
    item = _first_page_item(source)
    readiness = source.get("closure_readiness")
    if isinstance(readiness, Mapping):
        typed_readiness = cast(Mapping[str, JsonValue], readiness)
        return (
            _status_freshness(source, view, item),
            _safe_count(typed_readiness.get("open_obligation_count")),
            _safe_count(typed_readiness.get("unanswered_finding_count")),
            _safe_count(typed_readiness.get("receipt_blocking_finding_count")),
        )
    if item is None:
        return "unavailable", "unavailable", "unavailable", "unavailable"
    return (
        _safe_token(item.get("freshness")),
        _safe_count(item.get("open_obligation_count")),
        _safe_count(item.get("unanswered_finding_count")),
        _safe_count(item.get("receipt_blocking_finding_count")),
    )


def _compact_test_edit_clause(source: Mapping[str, JsonValue], view: str) -> str:
    """Render the compact status' bounded latest-check test-edit counters."""

    if view != "compact":
        return ""
    item = _first_page_item(source)
    if item is None or not isinstance(item.get("latest_check_test_edits"), Mapping):
        return ""
    edits = cast(Mapping[str, JsonValue], item["latest_check_test_edits"])
    availability = _safe_token(edits.get("read_availability"))
    return (
        f"test edits {availability}: "
        f"{_safe_count(edits.get('modified'))} modified, "
        f"{_safe_count(edits.get('renamed'))} renamed, "
        f"{_safe_count(edits.get('deleted'))} deleted, "
        f"{_safe_count(edits.get('skipped'))} skipped, "
        f"{_safe_count(edits.get('unjustified'))} unjustified, "
        f"{_safe_count(edits.get('unknown'))} unknown; "
    )


def _credential_heuristic_clause(source: Mapping[str, JsonValue]) -> str:
    """Name the external reviewer's possible-credential filter when it is not plainly on (#982).

    Silent when both the repository and the installation default are on, so ordinary summaries
    are unchanged. Off and unknown are owner/service facts, never agent work.
    """

    state = source.get("credential_heuristic")
    if not isinstance(state, Mapping):
        return ""
    typed = cast(Mapping[str, JsonValue], state)
    words = {"enforced": "on", "disabled": "off", "unknown": "unknown"}
    repository = words.get(str(typed.get("repository")), "unknown")
    machine_default = words.get(str(typed.get("machine_default")), "unknown")
    if repository == "on" and machine_default == "on":
        return ""
    return (
        f"possible-credential filter: {repository} for this repository, "
        f"installation default {machine_default} (owner setting); "
    )


def _status_checklist_clause(source: Mapping[str, JsonValue]) -> str:
    page = source.get("page")
    if not isinstance(page, Mapping):
        return ""
    page_source = cast(Mapping[str, JsonValue], page)
    return _checklist_clause(page_source.get("items"), page_source.get("attempt_budget"), None)


def _status_list_parts(
    render: _Render, source: Mapping[str, JsonValue], view: str
) -> list[Part | None]:
    page = source.get("page")
    typed_page = cast(Mapping[str, JsonValue], page) if isinstance(page, Mapping) else None
    parts: list[Part | None] = [
        render.guarded_one("limitation_refs", lambda: _limitation_refs_required_part(source)),
        render.guarded_one(
            "obligation_ids",
            lambda: _list_part(
                "obligation IDs: ", _obligation_ids_from_status(source, view), priority=_P_IDENTITY
            ),
        ),
    ]
    if view == "findings":
        parts.append(
            render.guarded_one(
                "finding_frontiers",
                lambda: _list_part(
                    "finding frontiers: ",
                    _finding_frontiers_from_status(source),
                    priority=_P_IDENTITY,
                ),
            )
        )
    if typed_page is not None:
        parts.append(
            render.guarded_one(
                "redacted_values", lambda: _semantic_redacted_values_part(typed_page)
            )
        )
        parts.append(
            render.guarded_one("withheld_items", lambda: _semantic_withheld_items_part(typed_page))
        )
    return parts


_ADVICE_PREVIEW_REQUIRED_GAP: Final = "advice_semantic_preview_required"


def _advice_preview_skip_part(source: Mapping[str, JsonValue]) -> Part | None:
    """One fixed sentence when background advice was skipped for a preview policy (#1019 r3)."""

    gaps: list[object] = []
    top = source.get("gaps")
    if isinstance(top, list | tuple):
        gaps.extend(cast(Sequence[object], top))
    coverage = source.get("coverage")
    if isinstance(coverage, Mapping):
        known = cast(Mapping[str, object], coverage).get("known_gaps")
        if isinstance(known, list | tuple):
            gaps.extend(cast(Sequence[object], known))
    if _ADVICE_PREVIEW_REQUIRED_GAP not in gaps:
        return None
    return _req(
        "Background AI-powered advice skipped (advice_semantic_preview_required): the privacy "
        "policy requires previewing each request, so nothing was queued or sent; explicit "
        "checks still offer the preview."
    )


def summary_for_status(envelope: object) -> str:
    """Compose the status text: view, frontier, freshness, counts and the closure state first.

    Required: the view and frontier, the ledger freshness, the open-obligation count, the
    unanswered/receipt-blocking/gap counts and the closure-readiness state. Obligation ids, finding
    frontiers, limitation refs, the test-edit and credential-filter disclosures and the withheld
    lists are granted room by priority (tb4n3 RC-2).
    """

    render = _Render("status")
    source = _mapping(envelope)
    view = _safe_token(source.get("view"))
    if view in {"lineage", "project"}:
        return _summary_for_multi_agent_status(source, view)
    if view == "advice":
        page = source.get("page")
        count = _item_count(page.get("items")) if isinstance(page, Mapping) else "unavailable"
        # Every view carries the closure checklist, so every view names its state (#913).
        return _compose(
            [
                _req(f"Status view: advice; {_frontier_clause(source)}; advice items: {count};"),
                _opt(
                    "Read the structured page for coordination selectors and bounded resource "
                    "details.",
                    priority=_P_ACTION,
                ),
                _advice_preview_skip_part(source),
                *_closure_section(render, source),
                render.failure_part(),
            ]
        )
    freshness, obligations, unanswered, _receipt_blocking = _compact_status_fields(source, view)
    gaps = _item_count(source.get("gaps"))
    parts: list[Part | None] = [
        _req(f"Status view: {view}; {_frontier_clause(source)};"),
        _req(f"freshness: {freshness};"),
        _req(f"open obligations: {obligations};"),
        _opt(
            render.text("acknowledged", lambda: _acknowledged_obligations_clause(source)),
            priority=_P_ACTION,
        ),
        _opt(
            render.text("test_edits", lambda: _compact_test_edit_clause(source, view)),
            priority=_P_STATE,
        ),
        _opt(
            render.text("credential_filter", lambda: _credential_heuristic_clause(source)),
            priority=_P_DISCLOSURE,
        ),
        _opt(
            render.text("review_mode", lambda: _status_review_mode_clause(source)),
            priority=_P_STATE,
        ),
        _opt(
            render.text("review_mode_next", lambda: _review_mode_next_clause(source)),
            priority=_P_ACTION,
        ),
    ]
    if view == "evidence":
        parts.append(
            _opt(
                *render.variants("evidence_channels", lambda: _evidence_channel_variants(source)),
                priority=_P_STATE,
            )
        )
    if view == "operation":
        # The fallback is core; the full progress text is granted behind the closure lineage
        # (_P_CAUSE), which is what makes a listed readiness token true.
        parts.append(
            Part(
                (
                    render.text("operation", lambda: _operation_progress_clause(source)),
                    "semantic progress: see structured page;",
                ),
                required=True,
                priority=_P_BOILERPLATE,
            )
        )
    if view == "findings":
        parts.append(
            _opt(
                render.text("checklist", lambda: _status_checklist_clause(source)),
                priority=_P_STATE,
            )
        )
    parts.extend(_status_list_parts(render, source, view))
    if view == "obligations":
        # tb4n4 (#1049): the view a resolution is authored from names the field it needs.
        recipe = render.variants("resolve_recipe", lambda: _obligation_resolve_recipe(source))
        if recipe:
            parts.append(_opt(*recipe, priority=_P_STATE))
    parts.append(_req(f"unanswered findings: {unanswered}; reported gaps: {gaps}."))
    parts.extend(_closure_section(render, source))
    page = source.get("page")
    if isinstance(page, Mapping):
        typed_page = cast(Mapping[str, JsonValue], page)
        parts.append(
            render.guarded_one(
                "redacted_values_line", lambda: _semantic_redacted_values_line_part(typed_page)
            )
        )
    parts.append(render.failure_part())
    return _compose(parts)


_PUBLICATION_CHANNELS: Final = (
    "codex_jsonl_import",
    "cooperative_mcp",
    "engine_derived",
    "hook_observed",
    "human_import",
    "local_cli",
)


def _evidence_channel_variants(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Count this page's evidence rows per closed publication channel (issue #914).

    The channel is the only structural way to tell the requester's own cooperative evidence from
    host-observed captures when a host drops the structured page; no row prose is rendered. The
    full per-channel breakdown is followed by the bare row count.
    """

    page = source.get("page")
    items = cast(Mapping[str, JsonValue], page).get("items") if isinstance(page, Mapping) else None
    if not isinstance(items, list | tuple):
        return ("evidence rows: unavailable;",)
    rows = cast(Sequence[JsonValue], items)
    counts = {channel: 0 for channel in _PUBLICATION_CHANNELS}
    for row in rows:
        channel = (
            cast(Mapping[str, JsonValue], row).get("publication_channel")
            if isinstance(row, Mapping)
            else None
        )
        if type(channel) is str and channel in counts:
            counts[channel] += 1
    parts = [f"{channel} {count}" for channel, count in counts.items() if count]
    # Rows from earlier 0.3 builds carry no channel; an unknown value is caller text and is never
    # rendered. Both are counted, not named.
    unrecorded = len(rows) - sum(counts.values())
    if unrecorded:
        parts.append(f"unrecorded {unrecorded}")
    return (
        f"evidence rows: {_item_count(rows)} ({', '.join(parts) or 'none'});",
        f"evidence rows: {_item_count(rows)};",
    )


def _readiness_tokens(readiness: Mapping[str, JsonValue], key: str) -> tuple[str, ...]:
    raw = readiness.get(key)
    if not isinstance(raw, list | tuple):
        return ()
    values = cast(Sequence[object], raw)
    return tuple(
        value
        for value in values
        if type(value) is str and _READINESS_ITEM.fullmatch(value) is not None
    )


def _check_cause_variants(source: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """The lineage sentence for ``check_not_applicable`` or a bounding earlier-frontier code.

    Built from the closed ``closure_readiness.check_cause`` fields by the shared frozen text
    (``finishup.protocol.readiness_text.check_cause_sentence``), so the MCP text, the CLI and the
    terminal interface say the same words (tb4n3 RC-6, owner lineage rule). Returns the full
    sentence, then the short form (same record and frontier, no id or rule); an absent or invalid
    cause yields no variant, because a malformed record must not be shown as lineage.
    """

    readiness = source.get("closure_readiness")
    if not isinstance(readiness, Mapping):
        return ()
    cause = cast(Mapping[str, JsonValue], readiness).get("check_cause")
    if not isinstance(cause, Mapping):
        return ()
    fields = cast(Mapping[str, JsonValue], cause)
    texts = {
        key: fields.get(key)
        for key in (
            "effect",
            "event_id",
            "ledger_sequence",
            "check_subject_frontier",
            "family",
            "material_class",
            "rule",
        )
    }
    tool = fields.get("tool")
    if any(type(value) is not str for value in texts.values()) or (
        tool is not None and type(tool) is not str
    ):
        return ()
    variants: list[str] = []
    for compact in (False, True):
        try:
            sentence = check_cause_sentence(
                effect=cast(str, texts["effect"]),
                event_id=cast(str, texts["event_id"]),
                ledger_sequence=texts["ledger_sequence"],
                check_subject_frontier=texts["check_subject_frontier"],
                family=cast(str, texts["family"]),
                material_class=cast(str, texts["material_class"]),
                rule=cast(str, texts["rule"]),
                tool=tool,
                compact=compact,
            )
        except ValueError:
            return ()
        if not sentence.isascii():
            return ()
        variants.append(sentence)
    return tuple(variants)


def _check_cause_part(source: Mapping[str, JsonValue]) -> Part | None:
    """The cause, granted room right after the core and the action clauses.

    The cause is what makes the listed ``check_not_applicable`` or
    ``check_current_as_of_earlier_frontier`` true (tb4n3 RC-6, owner lineage rule), so it ranks
    ahead of every boilerplate sentence: the full directive, the generic closure sentence and the
    operation-progress text yield to it. It is never required, so it cannot displace the closure
    state, the stop instruction or the agent-actionable items, which are reserved first. The full
    sentence is tried before the short form (same record and frontier); a missing or malformed
    cause adds no part.
    """

    variants = _check_cause_variants(source)
    if not variants:
        return None
    return Part(variants, priority=_P_CAUSE)


def _fact_why_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Why the first derived task fact fired (ADR-045), from ``closure_readiness.fact_lineage``.

    The record behind a listed fact token (the emptied deliverable, the loosely matched planned
    command). It ranks right behind the cause of the check's applicability and ahead of every
    boilerplate sentence, and it is optional, so it is dropped before anything required or the
    cause. An absent or unreadable lineage adds no part.
    """

    readiness = source.get("closure_readiness")
    if not isinstance(readiness, Mapping):
        return None
    why = _lineage_sentence(cast(Mapping[str, JsonValue], readiness).get("fact_lineage"))
    return Part((why,), priority=_P_FACT_WHY) if why else None


def _closure_section(render: _Render, source: Mapping[str, JsonValue]) -> list[Part | None]:
    """The closure checklist and the lineage of what it lists; each fails on its own."""

    return [
        *render.guarded_parts("closure", lambda: _closure_parts(source)),
        render.guarded_one("check_cause", lambda: _check_cause_part(source)),
        render.guarded_one("fact_lineage", lambda: _fact_why_part(source)),
    ]


def _closure_parts(source: Mapping[str, JsonValue]) -> list[Part]:
    """Name the closure-readiness state and its frozen directive (issue #913, ADR-032).

    Only the closed state token, service counts and classified gap or condition tokens appear.
    The state is always present. For ``ready_with_limitations`` the owner-approved stop instruction
    is required beside it (the counts sentence of the full directive is granted when room is left)
    and the named limitations are an optional part granted after the action clauses; for
    ``action_required`` the named items are the instruction and are required (their shortest
    rendering is reserved), so they are never displaced by the generic sentence or by the lineage
    of the item. One named list never takes more than the list bound.
    """

    readiness = source.get("closure_readiness")
    if not isinstance(readiness, Mapping):
        return []
    typed = cast(Mapping[str, JsonValue], readiness)
    state = typed.get("state")
    if type(state) is not str or state not in READINESS_STATES:
        return []
    standing = _readiness_tokens(typed, "standing_limitations")
    acknowledged = _safe_count(typed.get("acknowledged_not_done_count"))
    if acknowledged == "unavailable":
        return []
    head = f"Closure: {state}."
    sentence = readiness_directive(state, standing=len(standing), acknowledged=acknowledged)
    # ADR-046: the receipt conclusion this frontier would carry (appended after the owner-approved
    # sentence, never edited into it) and the one set of counters every surface prints.
    verdict_parts = _verdict_parts(typed, state)

    def listed(label: str, values: tuple[str, ...]) -> tuple[str, ...]:
        variants = list_variants(label, values, suffix="")
        within = tuple(variant for variant in variants if len(variant) <= _LIST_MAX_CHARS)
        return tuple(f"{variant}." for variant in within or variants[-1:])

    if state == "action_required":
        parts = [
            Part((head,), required=True),
            Part((sentence,), priority=_P_BOILERPLATE),
        ]
        actionable = _readiness_tokens(typed, "agent_actionable")
        if actionable:
            # Core: at least one named item and the count of the rest are always present.
            parts.append(
                Part(listed("Agent-actionable: ", actionable), required=True, priority=_P_ACTION)
            )
        return [*parts, *verdict_parts]
    if state == "ready_with_limitations":
        # Core: the state and the stop instruction. The counts sentence of the full directive is
        # boilerplate: it is granted after the lineage of the listed limitation (_P_CAUSE) and the
        # provenance of the derived fact (_P_FACT_WHY).
        parts = [
            Part(
                (
                    f"{head} {sentence}",
                    f"{head} Nothing further to do. Request the receipt.",
                ),
                required=True,
                priority=_P_COUNTS_SENTENCE,
            )
        ]
        if standing:
            parts.append(Part(listed("Standing limitations: ", standing), priority=_P_BOILERPLATE))
        return [*parts, *verdict_parts]
    return [Part((f"{head} {sentence}", head), required=True), *verdict_parts]


def _verdict_parts(readiness: Mapping[str, JsonValue], state: str) -> list[Part]:
    """The predicted receipt conclusion and the counters, each an optional, shrinkable part."""

    parts: list[Part] = []
    predicted = _predicted_variants(readiness.get("predicted_receipt"), state)
    if predicted:
        parts.append(Part(predicted, priority=_P_BOILERPLATE))
    # The rejected findings that wait for a reviewer ruling, by id and rejection frontier, and the
    # once-per-frontier re-reads a Stop will ask (tb4n3 RC-8): a "nothing further to do" is never
    # followed by a gate for an item this text did not announce.
    awaiting = awaiting_ruling_variants(readiness)
    if awaiting:
        parts.append(Part(awaiting, priority=_P_FACT_WHY))
    announced = recheck_note(readiness, host=_SUMMARY_HOST.get())
    if announced is not None:
        parts.append(Part((announced, _RECHECK_SHORT), priority=_P_BOILERPLATE))
    counts = closure_counts_variants(
        readiness.get("finding_counts"), readiness.get("obligation_counts")
    )
    if counts:
        parts.append(Part(counts, priority=_P_STATE))
    return parts


def _predicted_variants(prediction: JsonValue | None, state: str) -> tuple[str, ...]:
    if not isinstance(prediction, Mapping):
        return ()
    return predicted_receipt_variants(prediction, state=state)


def _operation_progress_clause(source: Mapping[str, JsonValue]) -> str:
    """Name the operation state and structural review progress with allowlisted values only."""

    page = source.get("page")
    if not isinstance(page, Mapping):
        return "operation: unavailable; "
    typed = cast(Mapping[str, JsonValue], page)
    clause = (
        f"operation state: {_safe_token(typed.get('state'))}; "
        f"kind: {_safe_token(typed.get('operation_kind'), fallback='none')}; "
    )
    admission = typed.get("admission")
    if isinstance(admission, Mapping):
        # Issue #838: an absent page with an admission stage is a refused or in-flight admission,
        # not an unknown request; the exact replay after the named wait is the recovery.
        admitted = cast(Mapping[str, JsonValue], admission)
        return clause + (
            f"admission stage: {_safe_token(admitted.get('stage'))}; "
            f"refusals: {_safe_count(admitted.get('refusal_count'))}; "
            f"elapsed ms: {_safe_count(admitted.get('elapsed_ms'))}; "
            f"retry after ms: {_safe_count(admitted.get('retry_after_ms'))}; "
        )
    progress = typed.get("semantic_progress")
    if not isinstance(progress, Mapping):
        return clause + "semantic progress: none; "
    fields = cast(Mapping[str, JsonValue], progress)
    clause += (
        f"semantic phase: {_safe_token(fields.get('phase'))}; "
        f"attempt: {_safe_count(fields.get('attempt_ordinal'))}; "
        f"condition: {_safe_token(fields.get('condition'))}; "
        f"elapsed ms: {_safe_count(fields.get('elapsed_ms'))}; "
    )
    if fields.get("condition") == "terminal":
        return clause + (
            f"outcome: {_safe_token(fields.get('terminal_outcome'))} "
            f"({_safe_token(fields.get('terminal_reason'))}); "
        )
    return clause + f"remaining ms: {_safe_count(fields.get('remaining_ms'))}; "


def _summary_for_multi_agent_status(source: Mapping[str, JsonValue], view: str) -> str:
    render = _Render("status")
    page = source.get("page")
    head = _req(f"Status view: {view}; {_frontier_clause(source)};")
    if not isinstance(page, Mapping):
        return _compose(
            [
                head,
                _req("page unavailable."),
                *_closure_section(render, source),
                render.failure_part(),
            ]
        )
    typed_page = cast(Mapping[str, JsonValue], page)
    lineage = typed_page if view == "lineage" else typed_page.get("lineage")
    parts: list[Part | None] = [head]
    if view == "project":
        project = typed_page.get("project_id")
        project_id = project if is_valid_id(IdKind.PROJECT, project) else "unavailable"
        grant = typed_page.get("grant_state")
        grant_state = (
            grant
            if type(grant) is str and grant in {"active", "revoked"}
            else "none"
            if grant is None
            else "unavailable"
        )
        parts.append(
            _req(
                f"project: {project_id}; "
                f"generation: {_safe_count(typed_page.get('membership_generation'))}; "
                f"grant: {grant_state or 'none'}; members: {_item_count(typed_page.get('members'))}; "
                f"detections: {_item_count(typed_page.get('detections'))}; "
                f"receipts: {_item_count(typed_page.get('receipts'))};"
            )
        )
    if isinstance(lineage, Mapping):
        typed_lineage = cast(Mapping[str, JsonValue], lineage)
        parent = typed_lineage.get("parent_task_id")
        if view == "lineage":
            parent_id = (
                parent
                if is_valid_id(IdKind.TASK, parent)
                else "none"
                if parent is None
                else "unavailable"
            )
            parts.append(_req(f"parent: {parent_id};"))
        parts.append(
            _req(
                f"children: {_item_count(typed_lineage.get('children'))}; "
                f"host annotations: {_item_count(typed_lineage.get('annotations'))};"
            )
        )
    if view == "project":
        parts.append(_req(f"coverage: {_item_count(typed_page.get('coverage'))};"))
    parts.append(
        render.guarded_one(
            "gap_codes",
            lambda: _list_part("gap codes: ", _safe_status_gap_codes(source), priority=_P_STATE),
        )
    )
    # The parent's own closure checklist travels on these views too (#913).
    if typed_page.get("next_cursor") is not None:
        parts.append(_opt("More pages available.", priority=_P_ACTION))
    parts.append(
        _opt("Read the structured page for child states and row identities.", priority=_P_STATE)
    )
    parts.extend(_closure_section(render, source))
    parts.append(render.failure_part())
    return _compose(parts)


def summary_for_receipt(envelope: object) -> str:
    """Compose the receipt text: conclusion, frontier and limitation count first.

    Open obligation ids, withheld-from-review lists, gap codes and the historical (cleared) gaps
    are granted room by priority; the suppressed-finding count and the fixed redaction line close
    the text (tb4n3 RC-2).
    """

    render = _Render("receipt")
    source = _mapping(envelope)
    conclusion = _safe_token(source.get("conclusion"))
    coverage = source.get("coverage")
    limitations = "unavailable"
    if isinstance(coverage, Mapping):
        typed_coverage = cast(Mapping[str, JsonValue], coverage)
        limitations = _item_count(typed_coverage.get("known_gaps"))
    suppressed = _safe_count(source.get("suppressed_finding_count"))
    document = source.get("document")
    typed_document = (
        cast(Mapping[str, JsonValue], document) if isinstance(document, Mapping) else None
    )
    gap_codes = _safe_gap_codes(source)
    parts: list[Part | None] = [
        _req(f"Receipt conclusion: {conclusion};"),
        _req(f"{_frontier_clause(source)};"),
        _req(f"coverage limitations: {limitations};"),
    ]
    if typed_document is not None:
        document_source = typed_document
        parts.append(
            render.guarded_one(
                "redacted_values", lambda: _semantic_redacted_values_part(document_source)
            )
        )
    parts.append(
        render.guarded_one(
            "open_obligations",
            lambda: _list_part(
                "open obligation IDs: ",
                _open_obligation_ids_from_receipt(source),
                priority=_P_IDENTITY,
            ),
        )
    )
    if typed_document is not None:
        document_source = typed_document
        parts.append(
            render.guarded_one(
                "withheld_items", lambda: _semantic_withheld_items_part(document_source)
            )
        )
    parts.append(_list_part("gap codes: ", gap_codes, priority=_P_DISCLOSURE))
    if typed_document is not None and limitations_name_coordinator_failure(
        typed_document.get("sections")
    ):
        # The gap code stays semantic_relevance_review_not_run. Name the fault (issue #1077).
        parts.append(_opt(COORDINATOR_FAILURE_LIMITATION, priority=_P_DISCLOSURE))
    parts.append(
        _opt(
            render.text("review_mode", lambda: _receipt_review_mode_clause(source)),
            priority=_P_DISCLOSURE,
        )
    )
    # Issue #1017: the result coverage counts live gaps only; gaps a later check cleared are
    # named apart (JSON document; markdown/text carry them in human_text).
    parts.append(
        render.guarded_one(
            "historical_gaps",
            lambda: _list_part(
                "cleared earlier (historical, not limitations): ",
                tuple(
                    f"{code} at {sequence}"
                    for code, sequence in historical_gaps_from_wire(typed_document)
                ),
                priority=_P_DETAIL,
            ),
        )
    )
    parts.append(_req(f"suppressed findings: {suppressed}."))
    if typed_document is not None:
        document_source = typed_document
        parts.append(
            render.guarded_one(
                "redacted_values_line",
                lambda: _semantic_redacted_values_line_part(document_source),
            )
        )
    parts.append(render.failure_part())
    return _compose(parts)


_AWAITING_STATES: Final = MappingProxyType(
    {
        "awaiting_human": "human_approval_required",
        "awaiting_input": "review_input_required",
    }
)
_PENDING_ID: Final = re.compile(
    r"^ppr_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_REPLAY_REQUEST_ID: Final = re.compile(
    r"^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_CONTINUATION_TIMESTAMP: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$", re.ASCII
)


def _awaiting_continuation_command(kind: object, command: object) -> str | None:
    """Return the continuation command only when it is one of the closed schema shapes."""

    if not isinstance(command, Sequence) or isinstance(command, str):
        return None
    parts = tuple(cast(Sequence[object], command))
    # A pre-rename service named the legacy launcher; the text always names the current one
    # (ADR-048).
    if not parts or parts[0] not in LAUNCHER_NAMES:
        return None
    arguments = parts[1:]
    if kind == "review_input_required" and arguments == ("publish-work", "--input", "PATH"):
        return f"{LAUNCHER_NAME} publish-work --input PATH"
    if kind == "repository_privacy_setup" and arguments == ("--privacy",):
        return f"{LAUNCHER_NAME} --privacy"
    if (
        kind == "privacy_disclosure_decision"
        and len(arguments) == 3
        and arguments[:2] == ("privacy", "decide-disclosure")
        and type(arguments[2]) is str
        and _PENDING_ID.fullmatch(arguments[2]) is not None
    ):
        return f"{LAUNCHER_NAME} privacy decide-disclosure {arguments[2]}"
    return None


def summary_for_check_awaiting(envelope: object) -> str:
    """Name the paused check state and its exact continuation on the text channel.

    Hosts that read only ``content`` previously saw "Operation outcome: recorded" for a check that
    had produced no verdict and was waiting on a command, so the one actionable fact was lost.
    Every rendered value is re-gated against its closed schema shape; the free-text instruction is
    never copied.
    """

    source = _mapping(envelope)
    state = source.get("state")
    if type(state) is not str or state not in _AWAITING_STATES:
        return ""
    continuation = source.get("continuation")
    if not isinstance(continuation, Mapping):
        return ""
    typed = cast(Mapping[str, object], continuation)
    command = _awaiting_continuation_command(typed.get("kind"), typed.get("command"))
    replay = typed.get("replay_request_id")
    if command is None or type(replay) is not str or _REPLAY_REQUEST_ID.fullmatch(replay) is None:
        return _compose(
            [
                _req(
                    f"Check state: {state} ({_AWAITING_STATES[state]}); no verdict yet. Read "
                    "structuredContent.continuation for the exact command and replay request_id."
                )
            ]
        )
    if state == "awaiting_input":
        who = "Supply the complete review input with"
    else:
        who = "Show the user this exact trusted local command to run"
    expires_at = typed.get("expires_at")
    expires = (
        f"Expires at {expires_at}."
        if type(expires_at) is str and _CONTINUATION_TIMESTAMP.fullmatch(expires_at) is not None
        else ""
    )
    return _compose(
        [
            _req(
                f"Check state: {state} ({_AWAITING_STATES[state]}); no verdict yet. {who}: {command}."
            ),
            _opt(expires, priority=_P_STATE),
            _req(f"Then replay the same check with request_id {replay}; do not start a new check."),
        ]
    )


def summary_for_check_inspection(envelope: object) -> str:
    """Project a ``mode: inspect`` check (ADR-047) onto the text channel.

    The lead lines (what is left, the gap split, what the hooks saw, the alignment count) are
    required; each obligation, finding, observed action and alignment row is optional detail the
    bound may drop, since the structured result carries every row.
    """

    text = inspection_text(_mapping(envelope))
    return _compose(
        [
            _req(" ".join(text.lead)),
            *(_opt(line, priority=_P_DETAIL) for line in text.details),
        ]
    )


def summary_for_read_guidance(envelope: object) -> str:
    """Name where a guidance result's full text is, without repeating it (issue #918).

    The URI is re-gated against the closed packaged-guidance shape and the byte count against the
    count shape, so the pointer carries only registry facts, never document text.
    """

    source = _mapping(envelope)
    uri = source.get("uri")
    # A registered heading topic (``workflow.md#start-and-resume``) is a closed-catalog constant
    # too; labelling its successful read "unavailable" read as a failure to agents.
    if type(uri) is not str or (
        _GUIDANCE_URI.fullmatch(uri) is None and uri not in _REGISTERED_GUIDANCE_URIS
    ):
        uri = "unavailable"
    if source.get("complete") is not None:
        page = _safe_count(source.get("page"))
        page_count = _safe_count(source.get("page_count"))
        page_bytes = _safe_count(source.get("page_byte_count"))
        total_bytes = _safe_count(source.get("total_byte_count"))
        digest = source.get("digest")
        digest_text = (
            digest
            if type(digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            else "unavailable"
        )
        complete = "yes" if source.get("complete") is True else "no"
        continuation = "yes" if isinstance(source.get("continuation"), Mapping) else "no"
        return _compose(
            [
                _req(
                    f"Guidance page {page}/{page_count} for {uri}: {page_bytes} bytes of "
                    f"{total_bytes}; complete: {complete}; continuation: {continuation}; "
                    f"revision: {digest_text}; full page in structuredContent.text."
                ),
                _guidance_sections_part(source.get("sections")),
            ]
        )
    return _compose(
        [
            _req(
                f"Guidance {uri}: {_safe_count(source.get('byte_count'))} bytes; "
                "full text in structuredContent.text."
            )
        ]
    )


def _guidance_sections_part(raw: object) -> Part | None:
    """Name the sections page zero lists (tb4n5), re-gated against the closed URI catalog."""

    if not isinstance(raw, (list, tuple)):
        return None
    rows: list[str] = []
    for entry in cast("list[object] | tuple[object, ...]", raw):
        uri = _field_of(entry, "uri")
        if type(uri) is not str or uri not in _REGISTERED_GUIDANCE_URIS or "#" not in uri:
            return None
        rows.append(f"#{uri.partition('#')[2]} {_safe_count(_field_of(entry, 'byte_count'))}")
    if not rows:
        return None
    lead = (
        f"{len(rows)} sections in structuredContent.sections; read only the one you need "
        "instead of paging"
    )
    return _opt(f"{lead}: {', '.join(rows)}.", f"{lead}.", priority=_P_ACTION)


def _field_of(entry: object, name: str) -> object:
    if isinstance(entry, Mapping):
        return cast(Mapping[str, object], entry).get(name)
    return None


def summary_for_closure_prepare(envelope: object) -> str:
    """Project the bounded, preparatory-only closure result onto the text channel."""

    source = _mapping(envelope)
    inventory = source.get("inventory")
    counts: list[str] = []
    if isinstance(inventory, Mapping):
        typed_inventory = cast(Mapping[str, JsonValue], inventory)
        for view in ("obligations", "results", "evidence", "findings", "history"):
            counts.append(f"{view} {_item_count(typed_inventory.get(view))}")
    rows = ", ".join(counts) if counts else "unavailable"
    operation = _safe_token(source.get("operation"), fallback="inventory")
    # ADR-046: the same closure state, predicted receipt conclusion and counters every other
    # surface prints (the structured result carries the readiness verbatim).
    verdict: list[Part] = []
    readiness = source.get("closure_readiness")
    if isinstance(readiness, Mapping):
        typed_readiness = cast(Mapping[str, JsonValue], readiness)
        state = typed_readiness.get("state")
        if type(state) is str and state in READINESS_STATES:
            verdict = [
                Part((f"Closure: {state}.",), priority=_P_ACTION + 3),
                *_verdict_parts(typed_readiness, state),
            ]
    return _compose(
        [
            _req(f"Closure preparation only; {_frontier_clause(source)};"),
            _req(f"inventory rows: {rows};"),
            _req(f"next operation: {operation};"),
            *verdict,
            _req("review structuredContent before submitting any request."),
        ]
    )


# tb4n5 (#1048): six first-plan batches sent ``expected_frontier: null`` right after a status read,
# and 85 of 87 later state-sensitive publishes read status first only to copy its frontier. The
# start and accepted-publish texts say which frontier the next write sends; neither is required
# text, so the identity and frontier are never displaced by them.
_START_FRONTIER_NEXT: Final = (
    "Send this frontier as expected_frontier on your first plan publish_work"
    " (next_request_template carries it); no status read is needed for it."
)
_START_FRONTIER_NEXT_SHORT: Final = "Send this frontier as your first plan's expected_frontier."
_WRITE_FRONTIER_NEXT: Final = (
    "Send this frontier as the next write's expected_frontier; no status read is needed for it."
)
_WRITE_FRONTIER_NEXT_SHORT: Final = "Send it as the next expected_frontier."


def _frontier_next_part(source: Mapping[str, JsonValue]) -> Part | None:
    """Which write sends the returned frontier next, for a start or an accepted publish."""

    if _frontier_clause(source) == "frontier: unavailable":
        return None
    if isinstance(source.get("next_request_template"), Mapping):
        return _opt(_START_FRONTIER_NEXT, _START_FRONTIER_NEXT_SHORT, priority=_P_ACTION)
    if source.get("accepted_events") is not None and source.get("outcome") in {
        "accepted",
        "replayed",
    }:
        return _opt(_WRITE_FRONTIER_NEXT, _WRITE_FRONTIER_NEXT_SHORT, priority=_P_ACTION)
    return None


def _summary_for_other_success(source: Mapping[str, JsonValue]) -> str:
    outcome = _safe_token(source.get("outcome"), fallback="recorded")
    identity = _identity_clause(source)
    accepted = source.get("accepted_events")
    parts: list[Part | None] = [_req(f"Operation outcome: {outcome};")]
    if accepted is not None:
        parts.append(_req(f"accepted events: {_item_count(accepted)};"))
    parts.append(_req(f"{identity}{_frontier_clause(source)}."))
    parts.append(_frontier_next_part(source))
    return _compose(parts)


_OBLIGATION_ID: Final = re.compile(
    r"^obl_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_MAX_RENDERED_BLOCKER_NOTICES: Final = 8
_BLOCKER_KINDS: Final = frozenset({"authority", "consent", "credential", "dependency_unavailable"})


def render_publish_blocker_notices(envelope: object) -> str:
    """Render a publish result's finishup-blocker notices as model-visible text (#985).

    Only rows whose closed code, kind and obligation id validate, and whose text is exactly the
    fixed repository text for that code, are rendered; anything else renders nothing. One line
    per notice code, naming the obligations it covers.
    """

    from finishup.protocol.models import PUBLISH_BLOCKER_NOTICE_TEXTS

    source = _mapping(envelope)
    rows = source.get("blocker_notices")
    if not isinstance(rows, Sequence) or isinstance(rows, str):
        return ""
    grouped: dict[str, list[str]] = {}
    for row in cast(Sequence[JsonValue], rows):
        if not isinstance(row, Mapping):
            return ""
        item = cast(Mapping[str, JsonValue], row)
        notice, kind, obligation, text = (
            item.get("notice"),
            item.get("blocker_kind"),
            item.get("obligation_id"),
            item.get("text"),
        )
        if (
            type(notice) is not str
            or notice not in PUBLISH_BLOCKER_NOTICE_TEXTS
            or text != PUBLISH_BLOCKER_NOTICE_TEXTS[notice]
            or kind not in _BLOCKER_KINDS
            or type(obligation) is not str
            or _OBLIGATION_ID.fullmatch(obligation) is None
        ):
            return ""
        grouped.setdefault(notice, []).append(f"{obligation} ({kind})")
    lines: list[str] = []
    for notice in sorted(grouped):
        named = grouped[notice]
        listed = ", ".join(named[:_MAX_RENDERED_BLOCKER_NOTICES])
        hidden = len(named) - _MAX_RENDERED_BLOCKER_NOTICES
        more = f" (+{hidden} more)" if hidden > 0 else ""
        lines.append(f"Blocker notice for {listed}{more}: {PUBLISH_BLOCKER_NOTICE_TEXTS[notice]}")
    return "\n".join(lines)


_ACTION_ID: Final = re.compile(
    r"^act_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_MAX_RENDERED_ACTION_NOTICES: Final = 8


def render_publish_action_notices(envelope: object) -> str:
    """Render a publish result's unlinked-action notices as model-visible text (tb4n5 follow-up).

    Only rows whose closed code and act_ id validate, and whose text is exactly the fixed
    repository text for that code, are rendered; anything else renders nothing. One line per
    notice code, naming the actions it covers.
    """

    from finishup.protocol.models import PUBLISH_ACTION_NOTICE_TEXTS

    source = _mapping(envelope)
    rows = source.get("action_notices")
    if not isinstance(rows, Sequence) or isinstance(rows, str):
        return ""
    grouped: dict[str, list[str]] = {}
    for row in cast(Sequence[JsonValue], rows):
        if not isinstance(row, Mapping):
            return ""
        item = cast(Mapping[str, JsonValue], row)
        notice, action, text = item.get("notice"), item.get("action_id"), item.get("text")
        if (
            type(notice) is not str
            or notice not in PUBLISH_ACTION_NOTICE_TEXTS
            or text != PUBLISH_ACTION_NOTICE_TEXTS[notice]
            or type(action) is not str
            or _ACTION_ID.fullmatch(action) is None
        ):
            return ""
        grouped.setdefault(notice, []).append(action)
    lines: list[str] = []
    for notice in sorted(grouped):
        named = grouped[notice]
        listed = ", ".join(named[:_MAX_RENDERED_ACTION_NOTICES])
        hidden = len(named) - _MAX_RENDERED_ACTION_NOTICES
        more = f" (+{hidden} more)" if hidden > 0 else ""
        lines.append(f"Action notice for {listed}{more}: {PUBLISH_ACTION_NOTICE_TEXTS[notice]}")
    return "\n".join(lines)


def _select_builder(source: Mapping[str, JsonValue]) -> tuple[str, Callable[[object], str]]:
    if source.get("ok") is False or "error" in source:
        return "error", summary_for_public_error
    if source.get("preparatory_only") is True:
        return "closure_prepare", summary_for_closure_prepare
    if source.get("state") == "inspected":
        return "check_inspection", summary_for_check_inspection
    if "verdict" in source:
        return "check", summary_for_check
    if "view" in source:
        return "status", summary_for_status
    if "receipt_id" in source or "conclusion" in source:
        return "receipt", summary_for_receipt
    return "operation", lambda envelope: _summary_for_other_success(_mapping(envelope))


def _minimal_summary(envelope: object, builder: str) -> str:
    """The guaranteed text when a builder's required core failed (tb4n3 RC-2).

    The operation has committed and its structured result is complete, so this names the verdict
    or state token and the frontier when they can still be read, says which builder failed, and
    points at the compact status view. Every step is guarded; the last resort is a fixed sentence.
    """

    source: Mapping[str, JsonValue] = {}
    try:
        source = _mapping(envelope)
    except Exception:  # noqa: BLE001 - the last resort must not raise
        pass

    def guarded(build: Callable[[], str]) -> str:
        try:
            return build()
        except Exception:  # noqa: BLE001 - the last resort must not raise
            return ""

    def identity() -> str:
        if builder == "error":
            nested = source.get("error")
            error = _mapping(nested) if nested is not None else source
            code = _safe_token(error.get("code"), fallback="INTERNAL_ERROR")
            if code not in {item.value for item in PublicErrorCode}:
                code = "INTERNAL_ERROR"
            retry = "yes" if error.get("retryable") is True else "no"
            return f"Error {code}; retryable: {retry};"
        if builder == "check":
            return (
                f"Check verdict: {_safe_token(source.get('verdict'))}; AI-powered review "
                f"status/reason: {_safe_token(source.get('semantic_status'))}/"
                f"{_safe_token(source.get('semantic_reason'))};"
            )
        if builder == "status":
            return f"Status view: {_safe_token(source.get('view'))};"
        if builder == "receipt":
            return f"Receipt conclusion: {_safe_token(source.get('conclusion'))};"
        if builder == "closure_prepare":
            return "Closure preparation only;"
        if builder == "check_inspection":
            return "Check inspection (read only, nothing recorded);"
        return (
            f"Operation outcome: {_safe_token(source.get('outcome'), fallback='recorded')}; "
            f"{_identity_clause(source)}"
        )

    parts = [
        _req(guarded(identity), "Result recorded;"),
        _req(guarded(lambda: f"{_frontier_clause(source)};")),
        _req(
            f"summary_render_failed:{builder}; the operation result is complete in "
            "structuredContent; read status view=compact for the current state."
        ),
    ]
    try:
        return _compose(parts)
    except Exception:  # noqa: BLE001 - the last resort must not raise
        return (
            f"Result recorded; summary_render_failed:{builder}; the operation result is complete "
            "in structuredContent; read status view=compact for the current state."
        )


def render_safe_compact_summary_detailed(
    envelope: object, *, host: str | None = None
) -> SummaryRender:
    """Render the bounded projection and report every clause or builder that degraded.

    Never raises. A failing optional clause is omitted and named in the text; a failing required
    core is replaced by ``_minimal_summary``. Both are returned in ``failures`` so the bridge can
    record which builder and clause broke (tb4n3 RC-2: a committed operation must not become an
    ``INTERNAL_ERROR`` because its text could not be built). ``host`` is the bridge's host
    profile; it only selects the re-check note's acceptance wording (``recheck_note``).
    """

    failures: list[tuple[str, BaseException]] = []
    token = _FAILURE_SINK.set(failures)
    host_token = _SUMMARY_HOST.set(host)
    builder = "summary"
    try:
        try:
            source = _mapping(envelope)
            builder, build = _select_builder(source)
            text = build(envelope)
        except Exception as exc:  # noqa: BLE001 - the core failed; fall back to the minimal text
            failures.append((builder, exc))
            text = _minimal_summary(envelope, builder)
    finally:
        _SUMMARY_HOST.reset(host_token)
        _FAILURE_SINK.reset(token)
    return SummaryRender(text=text, failures=tuple(failures))


def render_safe_compact_summary(envelope: object, *, host: str | None = None) -> str:
    """Render a bounded projection using only allowlisted structural result fields.

    Never raises; see ``render_safe_compact_summary_detailed`` for the failure report.
    """

    return render_safe_compact_summary_detailed(envelope, host=host).text
