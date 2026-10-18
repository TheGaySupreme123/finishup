"""Bounded structural projections for the review-input manifest.

The manifest is metadata only: renderers may expose phase, section status, digests, byte
counts, revisions, and closed omission tokens, but never the selected content.  Keeping this
projection in the domain layer lets check, MCP, TUI, and receipt surfaces use the same wording
without making one adapter depend on another.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Final, cast

from finishup.domain.bounded_text import Part, compose_parts, list_variants
from finishup.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS
from finishup.protocol.readiness_text import predicted_receipt_variants

__all__ = [
    "FINISHUP_LIMIT_MISSING_TEXT",
    "MAX_AGENT_NEXT_BYTES",
    "MISSING_SUPPLY_SENTENCE",
    "OVERALL_NEXT_INSTRUCTIONS",
    "SUPPLY_COUNTS_SENTENCE",
    "SUPPLY_COUNTS_SHORT",
    "has_agent_suppliable_missing",
    "overall_next_instruction",
    "publish_exactly",
    "render_agent_next",
    "has_finishup_limit_missing",
    "render_missing_for_assessment_lines",
    "render_missing_for_assessment_next",
    "render_review_input_manifest_compat_line",
    "render_review_input_manifest_compact",
    "render_review_input_manifest_coverage_note",
    "render_review_input_manifest_lines",
]

_MANIFEST_PHASES: Final = frozenset({"composed", "provider_bound"})
_SECTION_NAMES: Final = (
    "specification",
    "current_diff",
    "caller_evidence",
    "latest_verification",
    "prior_finding_context",
)
_SECTION_STATUSES: Final = frozenset(
    {"complete", "partial", "title_only", "missing", "withheld", "not_selected"}
)
_OMISSION_REASONS: Final = frozenset(
    {
        "capture_unavailable",
        "content_unselected",
        "not_recorded",
        "not_selected",
        "redacted_never_send",
        "task_statement_not_authorized",
        "task_statement_not_supplied",
        "task_statement_unavailable",
        "truncated_payload",
        "withheld_by_policy",
    }
)
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
_MISSING_AVAILABILITIES: Final = frozenset(
    {
        "agent_suppliable",
        "structurally_unavailable_on_this_host",
        "yoetz_limit_packet_room",
        "yoetz_limit_unsupported_data_type",
    }
)
_MISSING_STATUSES: Final = frozenset({"pending", "supplied", "unavailable", "repeated"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)


def _mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    source = cast(Mapping[object, object], value)
    try:
        keys: tuple[object, ...] = tuple(source)
    except Exception:
        return None
    if any(type(key) is not str for key in keys):
        return None
    return cast(Mapping[str, object], value)


def _token(value: object, allowed: frozenset[str]) -> str | None:
    return value if type(value) is str and value in allowed else None


def _count(value: object, maximum: int) -> int | None:
    if type(value) is int and 0 <= value <= maximum:
        return value
    return None


def _refs(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    sequence = cast(Sequence[object], value)
    result: list[str] = []
    for item in sequence:
        if type(item) is str and _OPAQUE_REF.fullmatch(item) is not None:
            result.append(item)
    return tuple(result)


def _section_line(name: str, value: object) -> str | None:
    source = _mapping(value)
    if source is None:
        return None
    status = _token(source.get("status"), _SECTION_STATUSES)
    bytes_count = _count(source.get("content_bytes"), 524_288)
    if status is None or bytes_count is None:
        return None
    parts = [
        f"- {name}: {status}",
        f"items {len(_refs(source.get('item_ids')))}",
        f"bytes {bytes_count}",
        f"sources {len(_refs(source.get('source_refs')))}",
        f"omitted {len(_refs(source.get('omitted_refs')))}",
    ]
    revision = _count(source.get("revision"), 9_007_199_254_740_991)
    if revision is not None:
        parts.append(f"revision {revision}")
    digest = source.get("content_digest")
    if digest is None:
        parts.append("digest none")
    elif type(digest) is str and _DIGEST.fullmatch(digest) is not None:
        parts.append(f"digest {digest}")
    else:
        return None
    reasons = source.get("omission_reasons")
    if isinstance(reasons, Sequence) and not isinstance(reasons, str):
        safe_reasons = tuple(
            item
            for item in cast(Sequence[object], reasons)
            if type(item) is str and item in _OMISSION_REASONS
        )
        if safe_reasons:
            parts.append("omissions " + ",".join(safe_reasons))
    return "; ".join(parts) + "."


def render_review_input_manifest_lines(value: object) -> tuple[str, ...]:
    """Render a validated-looking manifest using only bounded structural fields.

    Invalid or historical absent values produce no lines.  This makes the helper safe for old
    check rows while ensuring a malformed untrusted mapping cannot become public prose.
    """

    source = _mapping(value)
    if source is None or source.get("schema") != "yoetz.review-input-manifest/1":
        return ()
    phase = _token(source.get("phase"), _MANIFEST_PHASES)
    selected = _count(source.get("selected_item_count"), 304)
    excerpt_bytes = _count(source.get("selected_excerpt_bytes"), 262_144)
    omitted = _count(source.get("omitted_item_count"), 64)
    if phase is None or selected is None or excerpt_bytes is None or omitted is None:
        return ()
    # Issue #976 (tb4n1 D11): the true omission total; the listed count saturates at 64. An
    # older manifest without it keeps its listed count.
    total = _count(source.get("omitted_item_total"), 1_048_576)
    omitted_clause = (
        f"omitted items {omitted}"
        if total is None or total <= omitted
        else f"omitted items {total} ({omitted} listed)"
    )
    # Issue #976: the review phase is shown when recorded; "final" is the closing review.
    review_phase = _token(source.get("review_phase"), frozenset({"routine", "final"}))
    phase_clause = "" if review_phase is None else f"review phase {review_phase}; "
    # Issue #1047: this packet is an in-check follow-up FinishUP sent after adding what the reviewer
    # asked for; its missing inputs are that request.
    follow_up = _count(source.get("follow_up_round"), MAX_REVIEW_FOLLOW_UP_ROUNDS)
    follow_up_clause = (
        "" if not follow_up else f"follow-up round {follow_up} of {MAX_REVIEW_FOLLOW_UP_ROUNDS}; "
    )
    lines = [
        f"Review input manifest: {phase}; {phase_clause}{follow_up_clause}"
        f"selected items {selected}; "
        f"selected excerpt bytes {excerpt_bytes}; {omitted_clause}."
    ]
    for name in _SECTION_NAMES:
        line = _section_line(name, source.get(name))
        if line is None:
            return ()
        lines.append(line)
    missing = source.get("missing_inputs")
    if isinstance(missing, Sequence) and not isinstance(missing, str):
        safe_missing: list[str] = []
        for item in cast(Sequence[object], missing):
            row = _mapping(item)
            if row is None:
                continue
            kind = _token(row.get("kind"), _MISSING_KINDS)
            status = _token(row.get("status"), _MISSING_STATUSES)
            if kind is None or status is None:
                continue
            safe_missing.append(
                f"{kind}={status}; targets {len(_refs(row.get('target_refs')))}; "
                f"supplied {len(_refs(row.get('supplied_refs')))}"
            )
        if safe_missing:
            label = (
                "Manifest missing inputs: "
                if not follow_up
                else "Review follow-up (the reviewer's request in this check; supplied = FinishUP "
                "added recorded excerpts for it and asked again): "
            )
            lines.append(label + ", ".join(safe_missing) + ".")
    return tuple(lines)


def render_review_input_manifest_compact(value: object) -> str:
    """Render a short MCP-safe manifest summary, or an empty string when absent/invalid."""

    lines = render_review_input_manifest_lines(value)
    if not lines:
        return ""
    # The first line and specification line are the stable high-value part of the manifest.  The
    # MCP summary is bounded; full section detail remains in structured content and receipts.
    specification = next((line for line in lines if line.startswith("- specification:")), "")
    return (
        lines[0].removesuffix(".") + "; " + specification.removeprefix("- ").removesuffix(".") + "."
    )


def render_review_input_manifest_compat_line(value: object) -> str:
    """Keep the concise provider-bound wording used by older human renderers."""

    source = _mapping(value)
    if source is None or source.get("phase") != "provider_bound":
        return ""
    labels = (
        ("specification", "specification"),
        ("current_diff", "current diff"),
        ("caller_evidence", "caller evidence"),
        ("latest_verification", "latest verification"),
        ("prior_finding_context", "prior finding context"),
    )
    states: list[str] = []
    for key, label in labels:
        section = _mapping(source.get(key))
        if section is None:
            continue
        status = _token(section.get("status"), _SECTION_STATUSES)
        if status is not None:
            states.append(f"{label} {status}")
    return "Provider-bound review input: " + "; ".join(states) + "." if states else ""


def _missing_rows(items: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Return safe ``(kind, availability, target_refs)`` rows for public renderers."""

    if not isinstance(items, Sequence) or isinstance(items, str):
        return ()
    rows: list[tuple[str, str, tuple[str, ...]]] = []
    for item in cast(Sequence[object], items):
        if isinstance(item, Mapping):
            source = _mapping(cast(object, item))
        else:
            raw_item: object = item
            try:
                source = {
                    "kind": getattr(raw_item, "kind"),
                    "target_refs": getattr(raw_item, "target_refs"),
                    "availability": getattr(raw_item, "availability"),
                }
            except Exception:
                source = None
        if source is None:
            continue
        kind = _token(source.get("kind"), _MISSING_KINDS)
        availability = _token(source.get("availability"), _MISSING_AVAILABILITIES)
        if kind is None or availability is None:
            continue
        rows.append((kind, availability, _refs(source.get("target_refs"))))
    return tuple(rows)


def has_agent_suppliable_missing(items: object) -> bool:
    """Whether a check has a named review input the agent can supply or repair."""

    return any(availability == "agent_suppliable" for _, availability, _ in _missing_rows(items))


# What counts as supplying a named item (ADR-006 amendment, W6). Closed wording; the short form is
# the clause every guidance page quotes inside ``MISSING_SUPPLY_SENTENCE``.
SUPPLY_COUNTS_SENTENCE: Final = (
    "Counts as supplied only when new and tied to the target: a result of the target's action or "
    "of the same exact command, evidence whose reference is the target id, its event id or its "
    "path, or a respond when the target is a finding. A re-run FinishUP observed counts only for "
    "a verification_output or other item, and only once its captured output reaches the "
    "reviewer. A respond to anything else, a description, or citing the old record again does "
    "not count."
)
SUPPLY_COUNTS_SHORT: Final = "Only new material tied to the target counts as supplied."
# The same sentence as the operating card, the receipt topic and the coverage page (issue #1079).
MISSING_SUPPLY_SENTENCE: Final = (
    "If `missing_for_assessment` names an `agent_suppliable` item you can supply, publish "
    "exactly that item once, linked to its target, then `check` again. If it is already "
    "supplied, or it is a packet, type or authority limit, go to the receipt and state that "
    "specific limit. " + SUPPLY_COUNTS_SHORT
)
# One closed instruction per kind: what record answers it, naming the field that links it to the
# target. No task content, no invented command. Each entry is its variants, longest first: the
# first is the full instruction every surface prints; a shorter one keeps the record, the linking
# field and any rule an agent would otherwise get wrong, for the bounded ``agent_next`` lead, which
# reserves one variant per requested kind before any target list expands (W6, #1107).
_PUBLISH_EXACTLY: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "command_identity": (
            "Publish one action_recorded whose command is the exact command text of the target "
            "run. A re-run does not count: FinishUP records no command text for a run it observes.",
            "Publish one action_recorded whose command is the exact command text of the target "
            "run; a re-run does not count.",
        ),
        "current_diff_for_path": (
            "Publish evidence whose reference is that path, or one git diff result covering it. "
            "Do not stage an untracked file.",
            "Publish evidence whose reference is that path, or one git diff result covering it.",
        ),
        "other": ("Publish evidence whose reference is the target id.",),
        "plan_or_claim_text": (
            "Publish one plan_revised, or a claim_recorded 1.1.0 whose supersedes_claim_refs "
            "names the target claim.",
        ),
        "prior_finding_context": ("Publish one respond to that finding.",),
        "task_statement": (
            "Publish one plan_revised 1.1.0 whose task_statement is the user's whole request, "
            "linked to the target.",
        ),
        "verification_output": (
            "Publish one result_recorded whose action_id is the target's action and whose "
            "summary is the command output, with its evidence_refs. Publish it even after a "
            "re-run: the output of a run FinishUP observes counts only once it reaches the "
            "reviewer, which the owner's privacy settings may not allow.",
            "Publish one result_recorded whose action_id is the target's action and whose "
            "summary is the command output, with its evidence_refs, even after a re-run: a "
            "re-run counts only once its output reaches the reviewer.",
        ),
    }
)


def publish_exactly(kind: str) -> str:
    """The record to publish for one ``agent_suppliable`` kind, or empty when the kind is closed."""

    if type(kind) is not str:
        return ""
    variants = _PUBLISH_EXACTLY.get(kind, ())
    return variants[0] if variants else ""


def render_missing_for_assessment_next(items: object) -> str:
    """Return the authoritative continuation for actionable review-input gaps, if any."""

    if not has_agent_suppliable_missing(items):
        return ""
    return "Overall next: " + MISSING_SUPPLY_SENTENCE


def has_finishup_limit_missing(items: object) -> bool:
    """Whether the reviewer named content FinishUP's own packet could not show (tb4n1 D1, #983)."""

    return any(
        availability.startswith("yoetz_limit_") for _, availability, _ in _missing_rows(items)
    )


# One fixed sentence for every FinishUP-limit item. It names the limit as FinishUP's, says it is not a
# blocker, and forbids reshaping the deliverable for the reviewer (tb4n1 D1/F2, #983).
FINISHUP_LIMIT_MISSING_TEXT: Final = (
    "FinishUP limit: the review packet cannot show the yoetz_limit_* items (an unsupported data "
    "type such as an image or binary file, or content clipped for packet room). This is not "
    "work for you and never a blocker: verify that content "
    "yourself and record how you verified it; the receipt discloses the limit. Never split, "
    "move, shrink, stash, delete, git-add or git-ignore your work to fit the reviewer."
)


def render_missing_for_assessment_lines(
    items: object, *, include_refs: bool = True
) -> tuple[str, ...]:
    """Render #907 missing-item classifications for any public surface.

    ``items`` may be the typed event rows or their JSON projection.  Only closed kind,
    availability, and already admitted opaque references are copied.
    """

    rows = _missing_rows(items)
    if not rows:
        return ()
    lines = ["Missing for assessment (the reviewer could not assess the packet):"]
    for kind, availability, refs in rows:
        target = (
            ", ".join(refs)
            if include_refs and refs
            else (f"{len(refs)} target refs" if refs else "no packet ref")
        )
        line = f"- {kind} ({target}): {availability}"
        if availability == "agent_suppliable":
            instruction = publish_exactly(kind)
            if instruction:
                line = f"{line}. {instruction}"
        lines.append(line)
    if has_finishup_limit_missing(items):
        lines.append(FINISHUP_LIMIT_MISSING_TEXT)
    next_step = render_missing_for_assessment_next(items)
    if next_step:
        lines.append(next_step)
    return tuple(lines) if len(lines) > 1 else ()


def render_review_input_manifest_coverage_note(
    manifest: object,
    missing_items: object = (),
) -> str | None:
    """Combine manifest and missing-item metadata for an existing receipt coverage note."""

    manifest_lines = render_review_input_manifest_lines(manifest)
    missing_lines = render_missing_for_assessment_lines(missing_items, include_refs=False)
    lines = list(manifest_lines)
    if missing_lines:
        lines.extend(missing_lines)
    if not lines:
        return None
    text = "Review input coverage (metadata only):\n" + "\n".join(lines)
    encoded = text.encode("utf-8")
    if len(encoded) <= 4096:
        return text
    # Structural fields are already bounded; this defensive fallback keeps the existing receipt
    # section contract closed if a future admitted vocabulary grows.
    return text[:4090].encode("utf-8", errors="ignore").decode("utf-8", errors="ignore") + " […]"


# The one per-action instruction table every surface reads (W6, ADR-043 amendment): the CLI's
# ``Overall next`` line and the ``agent_next`` lead of every check result. Closed sentences only.
OVERALL_NEXT_INSTRUCTIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "supply_missing_input": (
            "If `missing_for_assessment` names an `agent_suppliable` item you can supply, "
            "publish exactly that item once, linked to its target, then `check` again. If it "
            "is already supplied, or it is a packet, type or authority limit, go to the receipt "
            "and state that specific limit. Never change your work to fit the reviewer"
        ),
        "disclose_limitations": (
            "Disclose the named limitation requests (respond acknowledged with the reason if the "
            "requirement may be met but cannot be verified here; acknowledged_not_done only when "
            "you know it is not met; no repair is needed)"
        ),
        "work_open_findings": "Repair or answer the named open findings",
        "request_ruling": (
            "Run check with final_review: true so the reviewer rules on the rejected findings"
        ),
        "review_recorded_work": (
            "Review the recorded work for open obligations or undisclosed failures"
        ),
        "request_receipt": "Request the receipt",
    }
)
# ``work_open_findings`` when a limitation request rides among the open findings (tb4n3 RC-1).
_OPEN_FINDINGS_WITH_REQUESTS: Final = (
    "Repair or answer the named open findings (a limitation request among them needs only a "
    "response: acknowledged with the reason if it may be met but cannot be verified here, "
    "acknowledged_not_done only when you know it is not met; an agent_criterion_unmet is your "
    "own criterion: fix it, or narrow it with acknowledged and a reason)"
)
# ``request_receipt`` at ``ready_with_limitations``.
_RECEIPT_WITH_LIMITATIONS: Final = "Disclose the limitation at the receipt endpoint"
_OVERALL_NEXT_STATUSES: Final = frozenset({"action_required", "ready_with_limitations", "ready"})
_SUBJECT_REF: Final = re.compile(
    r"^(?:act|clm|evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}"
    r"-[0-9a-f]{12}$",
    re.ASCII,
)
# Codex keeps only the head and tail of a structured tool result (ADR-043 amendment); this bound
# keeps the lead inside the smallest head window with room to spare.
MAX_AGENT_NEXT_BYTES: Final = 2_048
_AGENT_NEXT_SUPPLY_LEAD: Final = (
    "Supply each agent_suppliable item below once, then check again; if one is already supplied "
    "or is a packet, type or authority limit, state that limit in the receipt instead. Never "
    "change your work to fit the reviewer."
)
_AGENT_NEXT_SUPPLY_LEAD_SHORT: Final = "Supply each item below once, then check again."
_AGENT_NEXT_LIMIT: Final = (
    "FinishUP limit (not your work, never a blocker): {n} item(s) the packet cannot show; "
    "verify them yourself, record how, and never reshape the work to fit the reviewer."
)
_AGENT_NEXT_LIMIT_SHORT: Final = "FinishUP limit: {n} item(s); verify yourself, never reshape."
_AGENT_NEXT_UNAVAILABLE: Final = (
    "{n} item(s) this host cannot carry: state that limit in the receipt."
)
# A missing item names at most this many targets (check-result ``missing_item.target_refs``).
_MAX_ITEM_REFS: Final = 4


def overall_next_instruction(action: str, status: str, *, limitation_requests: bool = False) -> str:
    """The instruction for one ``overall_next`` action, or empty for an unknown action."""

    if type(action) is not str or action not in OVERALL_NEXT_INSTRUCTIONS:
        return ""
    if action == "work_open_findings" and limitation_requests:
        return _OPEN_FINDINGS_WITH_REQUESTS
    if action == "request_receipt" and status == "ready_with_limitations":
        return _RECEIPT_WITH_LIMITATIONS
    return OVERALL_NEXT_INSTRUCTIONS[action]


def _field(value: object, name: str) -> object:
    source = _mapping(value)
    if source is not None:
        return source.get(name)
    try:
        return cast(object, getattr(value, name, None))
    except Exception:
        return None


def _subject_refs(value: object) -> tuple[str, ...]:
    return tuple(ref for ref in _refs(value) if _SUBJECT_REF.fullmatch(ref) is not None)


def _agent_next_item(label: str, refs: tuple[str, ...], shown: int) -> tuple[str, ...]:
    """One supply item naming at most ``shown`` of its targets, then its bare target count."""

    if not refs:
        return (f"{label}(no packet ref).",)
    count = f"{label}{len(refs)} target(s)."
    shown = min(shown, len(refs))
    if shown <= 0:
        return (count,)
    more = f" (+{len(refs) - shown} more)" if shown < len(refs) else ""
    return (f"{label}{','.join(refs[:shown])}{more}.", count)


def _compose_agent_next(parts: list[Part], items: list[tuple[int, str, tuple[str, ...]]]) -> str:
    """Compose under the bound, naming the same number of targets for every supply item.

    The largest per-item bound at which every item's list fits wins; an item that could not
    take it would read only its count while an earlier one named all of its targets.
    """

    shown = min(max((len(refs) for _index, _label, refs in items), default=0), _MAX_ITEM_REFS)
    while True:
        for index, label, refs in items:
            parts[index] = Part(_agent_next_item(label, refs, shown), required=True, priority=1)
        composition = compose_parts(parts, MAX_AGENT_NEXT_BYTES)
        if shown <= 0 or not {index for index, _label, _refs in items} & set(composition.shortened):
            return composition.text
        shown -= 1


def render_agent_next(
    overall_next: object, missing: object = (), *, limitation_requests: bool = False
) -> str:
    """The bounded first instruction of a check result for every host (W6, ADR-043 amendment).

    Closed tokens, fixed sentences and admitted subject ids only: never reviewer prose, task text,
    paths or command text. One ASCII line of at most ``MAX_AGENT_NEXT_BYTES``. ``overall_next``
    and ``missing`` may be JSON mappings or typed rows. Returns ``""`` when there is no
    continuation (``overall_next`` absent or malformed) and never raises.
    """

    try:
        return _render_agent_next(overall_next, missing, limitation_requests=limitation_requests)
    except Exception:
        return ""


def _render_agent_next(overall_next: object, missing: object, *, limitation_requests: bool) -> str:
    action = _field(overall_next, "action")
    status = _field(overall_next, "status")
    if (
        type(action) is not str
        or action not in OVERALL_NEXT_INSTRUCTIONS
        or type(status) is not str
        or status not in _OVERALL_NEXT_STATUSES
    ):
        return ""
    targets = _subject_refs(_field(overall_next, "target_refs"))
    # Supply items as (part index, label, refs): ``_compose_agent_next`` bounds their target lists.
    items: list[tuple[int, str, tuple[str, ...]]] = []
    parts: list[Part] = [Part((f"Next: {action} ({status}).",), required=True, priority=0)]
    if action == "supply_missing_input":
        rows = tuple(
            (kind, availability, tuple(ref for ref in refs if _SUBJECT_REF.fullmatch(ref)))
            for kind, availability, refs in _missing_rows(missing)
        )
        own = tuple(row for row in rows if row[1] == "agent_suppliable")
        limits = sum(row[1].startswith("yoetz_limit_") for row in rows)
        unavailable = sum(row[1] == "structurally_unavailable_on_this_host" for row in rows)
        parts.append(
            Part(
                (_AGENT_NEXT_SUPPLY_LEAD, _AGENT_NEXT_SUPPLY_LEAD_SHORT), required=True, priority=4
            )
        )
        # Room is reserved before anything expands (W6, #1107): every item's kind and target
        # count, one direction per requested kind (its shortest variant from the shared table) and
        # every disclosed limit count are required. Target lists then expand, every item to the
        # same bound with an explicit "+N more", and only after them the longer directions. A
        # direction is never dropped to make room for a target id: the ids also ride in
        # ``missing_for_assessment``, the direction only here.
        instructed: set[str] = set()
        for index, (kind, _availability, refs) in enumerate(own, start=1):
            label = f"({index}) {kind} for "
            items.append((len(parts), label, refs))
            parts.append(Part(_agent_next_item(label, refs, 0), required=True, priority=1))
            directions = _PUBLISH_EXACTLY.get(kind, ())
            if directions and kind not in instructed:
                instructed.add(kind)
                parts.append(
                    Part(
                        tuple(f"How: {direction}" for direction in directions),
                        required=True,
                        priority=2,
                    )
                )
        if not own and targets:
            parts.append(
                Part(list_variants("Targets: ", targets, joiner=",", suffix="."), priority=1)
            )
        parts.append(Part((SUPPLY_COUNTS_SENTENCE, SUPPLY_COUNTS_SHORT), required=True, priority=2))
        if limits:
            parts.append(
                Part(
                    (_AGENT_NEXT_LIMIT.format(n=limits), _AGENT_NEXT_LIMIT_SHORT.format(n=limits)),
                    required=True,
                    priority=2,
                )
            )
        if unavailable:
            parts.append(
                Part((_AGENT_NEXT_UNAVAILABLE.format(n=unavailable),), required=True, priority=2)
            )
    else:
        instruction = overall_next_instruction(
            action, status, limitation_requests=limitation_requests
        )
        parts.append(Part((instruction + ".",), required=True, priority=0))
        if targets:
            parts.append(
                Part(
                    list_variants(
                        "Targets: ", targets, joiner=",", more=" (+{n} more)", suffix="."
                    ),
                    priority=1,
                )
            )
    predicted = _field(overall_next, "predicted_conclusion")
    if type(predicted) is str:
        parts.append(
            Part(
                predicted_receipt_variants(
                    {"conclusion": predicted, "reasons": ()},
                    state="action_required" if status == "action_required" else "ready",
                ),
                priority=5,
            )
        )
    text = _compose_agent_next(parts, items)
    if "\n" in text or not text.isascii() or not text.isprintable():
        return ""
    return text
