"""Bounded structural projections for the review-input manifest.

The manifest is metadata only: renderers may expose phase, section status, digests, byte
counts, revisions, and closed omission tokens, but never the selected content.  Keeping this
projection in the domain layer lets check, MCP, TUI, and receipt surfaces use the same wording
without making one adapter depend on another.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final, cast

from yoetz.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS

__all__ = [
    "YOETZ_LIMIT_MISSING_TEXT",
    "has_agent_suppliable_missing",
    "has_yoetz_limit_missing",
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
    # Issue #1047: this packet is an in-check follow-up Yoetz sent after adding what the reviewer
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
                else "Review follow-up (the reviewer's request in this check; supplied = Yoetz "
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


def render_missing_for_assessment_next(items: object) -> str:
    """Return the authoritative continuation for actionable review-input gaps, if any."""

    if not has_agent_suppliable_missing(items):
        return ""
    return (
        "Overall next: supply the named agent-suppliable review input as new records tied to "
        "the named ref before requesting an ordinary receipt. Never change your work to fit "
        "the reviewer."
    )


def has_yoetz_limit_missing(items: object) -> bool:
    """Whether the reviewer named content Yoetz's own packet could not show (tb4n1 D1, #983)."""

    return any(
        availability.startswith("yoetz_limit_") for _, availability, _ in _missing_rows(items)
    )


# One fixed sentence for every Yoetz-limit item. It names the limit as Yoetz's, says it is not a
# blocker, and forbids reshaping the deliverable for the reviewer (tb4n1 D1/F2, #983).
YOETZ_LIMIT_MISSING_TEXT: Final = (
    "Yoetz limit: the review packet cannot show the yoetz_limit_* items (an unsupported data "
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
        lines.append(f"- {kind} ({target}): {availability}")
    if has_yoetz_limit_missing(items):
        lines.append(YOETZ_LIMIT_MISSING_TEXT)
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
