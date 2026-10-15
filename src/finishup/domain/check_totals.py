"""Closed, prose-free check counters shared by durable and public projections."""

from collections.abc import Mapping
from typing import Final, cast

from finishup.domain.values import JsonObject, JsonValue, freeze_json
from finishup.protocol.coverage import EvidenceImmutability

CHECK_TOTAL_KEYS: Final = {
    "obligations": frozenset(
        {"declared", "resolved", "open", "unreadable", "with_evidence", "scope_known"}
    ),
    "requested_items": frozenset({"attempted", "unattempted"}),
    "commands": frozenset(
        {
            "observed",
            "failed",
            "unknown",
            "live_failed",
            "retired_by_rerun",
            "disclosed_not_rerun_green",
        }
    ),
    "evidence": frozenset(item.value for item in EvidenceImmutability),
    "findings": frozenset(
        {"returned", "actionable_returned", "coverage_only_returned", "suppressed"}
    ),
    # Structural visibility of edits to tests that predated the task baseline. ``examined=0``
    # means no admitted capture was available; ``baseline_known=0`` keeps a first-check/head
    # fallback distinguishable from a clean task-start capture.
    "test_edits": frozenset(
        {
            "examined",
            "baseline_known",
            "modified",
            "renamed",
            "deleted",
            "skipped",
            "unjustified",
            "unknown",
        }
    ),
}

# These counters are availability flags rather than quantities.  Keep their closed
# domain in one place so runtime validation and the generated wire schemas cannot
# drift into accepting values such as ``2``.
CHECK_TOTAL_FLAG_KEYS: Final = frozenset(
    {
        ("obligations", "scope_known"),
        ("test_edits", "examined"),
        ("test_edits", "baseline_known"),
    }
)


def validate_check_totals(value: object) -> JsonObject:
    """Validate canonical unsigned counters and reject unrecognized structural keys."""

    if not isinstance(value, Mapping):
        raise ValueError("check_totals_invalid")
    source = cast(Mapping[object, object], value)
    if frozenset(source) != frozenset(CHECK_TOTAL_KEYS):
        raise ValueError("check_totals_invalid")
    for group, keys in CHECK_TOTAL_KEYS.items():
        counters = source[group]
        if not isinstance(counters, Mapping):
            raise ValueError("check_totals_invalid")
        counts = cast(Mapping[object, object], counters)
        if frozenset(counts) != keys:
            raise ValueError("check_totals_invalid")
        for key, count in counts.items():
            if (
                type(count) is not str
                or not count.isascii()
                or not count.isdecimal()
                or (len(count) > 1 and count.startswith("0"))
                or len(count) > 20
                or int(count) > 2**64 - 1
            ):
                raise ValueError("check_totals_invalid")
            if (group, key) in CHECK_TOTAL_FLAG_KEYS and count not in {"0", "1"}:
                raise ValueError("check_totals_invalid")
    return cast(JsonObject, freeze_json(cast(JsonValue, value)))


def render_check_totals(value: object) -> str:
    """Render only a validated closed set of counters, safe for structural summaries."""

    try:
        totals = validate_check_totals(value)
    except ValueError:
        return ""
    groups = cast(Mapping[str, Mapping[str, str]], totals)
    obligations, items = groups["obligations"], groups["requested_items"]
    commands, evidence, findings = groups["commands"], groups["evidence"], groups["findings"]
    test_edits = groups["test_edits"]
    if obligations.get("scope_known") != "1":
        obligation_text = "obligations unavailable (current plan scope is unreadable); "
        requested_items_text = "requested items unavailable (current plan scope is unreadable); "
    else:
        # #997: obligations acknowledged as not done are the remainder of ``declared``.
        acknowledged = int(obligations["declared"]) - sum(
            int(obligations[key]) for key in ("resolved", "open", "unreadable")
        )
        acknowledged_text = f"{acknowledged} acknowledged not done, " if acknowledged > 0 else ""
        obligation_text = (
            f"obligations {obligations['declared']} declared, {obligations['resolved']} resolved, "
            f"{obligations['open']} open, {acknowledged_text}{obligations['unreadable']} "
            f"unreadable, {obligations['with_evidence']} with evidence; "
        )
        requested_items_text = (
            f"requested items {items['attempted']} attempted, {items['unattempted']} unattempted; "
        )
    test_edit_text = (
        "test edits unavailable (no admitted capture; "
        f"baseline known {test_edits['baseline_known']});"
        if test_edits.get("examined") != "1"
        else (
            f"test edits {test_edits['modified']} modified, "
            f"{test_edits['renamed']} renamed, {test_edits['deleted']} deleted, "
            f"{test_edits['skipped']} skipped, {test_edits['unjustified']} unjustified, "
            f"{test_edits['unknown']} unknown "
            f"(baseline known {test_edits['baseline_known']});"
        )
    )
    return (
        f"Totals: {obligation_text}"
        f"{requested_items_text}"
        f"commands {commands['observed']} observed, {commands['failed']} failed, "
        f"{commands['unknown']} unknown, {commands['live_failed']} live failures, "
        f"{commands['retired_by_rerun']} retired by rerun, "
        f"{commands['disclosed_not_rerun_green']} test failures disclosed without green rerun; "
        "evidence " + ", ".join(f"{evidence[key]} {key}" for key in sorted(evidence)) + "; "
        f"findings {findings['returned']} returned, {findings['actionable_returned']} actionable, "
        f"{findings['coverage_only_returned']} coverage-only, {findings['suppressed']} suppressed; "
        f"{test_edit_text}."
    )
