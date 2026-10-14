"""Frozen agent-facing text for a ``mode: inspect`` check result (issue #1048, ADR-047).

The CLI and the MCP text channel print the same lines, rebuilt locally from the structural
inspection branch: every rendered value is re-gated against its closed shape (ids, tokens,
counts, item indexes, keyed commitments), so a value that does not fit is dropped rather than
copied. No command text, path or prose exists in the branch to print.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from finishup.protocol.canonical import JsonValue
from finishup.protocol.readiness_text import readiness_directive

__all__ = ["INSPECTION_BOUNDS", "InspectionText", "inspection_text"]

_TOKEN: Final = re.compile(r"^(?:unclassified_gap:)?[a-z][a-z0-9_]{0,127}$", re.ASCII)
_ID: Final = re.compile(
    r"^(?:evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_COUNT: Final = re.compile(r"^(?:0|[1-9][0-9]{0,18})$", re.ASCII)
_TOOL: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", re.ASCII)
_COMMITMENT: Final = re.compile(r"^hmac-sha256:[0-9a-f]{64}$", re.ASCII)
_MAX_ROWS: Final = 8

# The one coverage bound every rendering states beside the alignment rows.
INSPECTION_BOUNDS: Final = (
    "Compared through recorded links only (the attempted_items of the action behind each cited "
    "result or evidence item, and the keyed identity of an observed run against a requested "
    "command); FinishUP records no command text, edit path, working directory, environment or "
    "service configuration."
)

_MISSING_TEXT: Final = {
    "blocker_unconfirmed": "blocker claimed, not confirmed",
    "command_attempt_mismatch": "asserted command differs from the observed run",
    "command_run_not_observed": "asserted command run has no linked hook observation",
    "requested_item_not_attempted": "requested items not attempted",
    "resolution_evidence_not_cited": "no resolution evidence cited",
}


@dataclass(frozen=True, slots=True)
class InspectionText:
    """``lead`` is always printed; ``details`` are the per-row lines a bounded channel may drop."""

    lead: tuple[str, ...]
    details: tuple[str, ...]


def _map(value: object) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], value) if isinstance(value, Mapping) else {}


def _rows(value: object) -> tuple[Mapping[str, JsonValue], ...]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(_map(item) for item in cast(Sequence[object], value))
    return ()


def _tok(value: object, fallback: str = "unknown") -> str:
    return value if type(value) is str and _TOKEN.fullmatch(value) else fallback


def _ident(value: object) -> str | None:
    return value if type(value) is str and _ID.fullmatch(value) else None


def _num(value: object) -> str:
    if type(value) is int:
        return str(value)
    return value if type(value) is str and _COUNT.fullmatch(value) else "?"


def _tokens(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return []
    return [
        item
        for item in cast(Sequence[object], value)
        if type(item) is str and _TOKEN.fullmatch(item) is not None
    ]


def _indexes(value: object) -> str:
    items = [
        f"#{item}"
        for item in (
            cast(Sequence[object], value)
            if isinstance(value, Sequence) and not isinstance(value, str)
            else ()
        )
        if type(item) is str and item.isascii() and item.isdigit()
    ]
    return ", ".join(items)


def _short(commitment: object) -> str | None:
    if type(commitment) is str and _COMMITMENT.fullmatch(commitment):
        return commitment[: len("hmac-sha256:") + 12]
    return None


def _remaining_lines(remaining: Mapping[str, JsonValue]) -> tuple[list[str], list[str]]:
    state = _tok(remaining.get("readiness"))
    agent = _tokens(remaining.get("agent_actionable"))
    standing = _tokens(remaining.get("standing_limitations"))
    predicted = remaining.get("predicted_conclusion")
    head = f"What is left: readiness {state}"
    if type(predicted) is str and _TOKEN.fullmatch(predicted):
        head += f"; a receipt now would conclude {predicted}"
    lead = [
        head + ".",
        "Your gaps: " + (", ".join(agent) if agent else "none") + ".",
        "FinishUP's standing limitations (disclosed, not your work): "
        + (", ".join(standing) if standing else "none")
        + ".",
    ]
    obligations = _rows(remaining.get("obligations"))
    findings = _rows(remaining.get("findings"))
    acknowledged = sum(
        1 for row in (*obligations, *findings) if row.get("closure_class") == "settled_unmet"
    )
    if state in {"action_required", "ready", "ready_with_limitations", "unknown"}:
        lead.append(readiness_directive(state, standing=len(standing), acknowledged=acknowledged))
    details: list[str] = []
    lead.append(
        f"Unresolved obligations: {_num(remaining.get('obligation_count'))}; "
        f"unresolved findings: {_num(remaining.get('finding_count'))}."
    )
    for row in obligations[:_MAX_ROWS]:
        ident = _ident(row.get("obligation_id"))
        if ident is None:
            continue
        parts: list[str] = []
        for missing in _rows(row.get("missing")):
            kind = _tok(missing.get("kind"))
            owner = "FinishUP" if missing.get("owner") == "yoetz" else "you"
            text = _MISSING_TEXT.get(kind, kind)
            where = _indexes(missing.get("item_indexes"))
            parts.append(f"{text}{f' ({where})' if where else ''} [{owner}]")
        why = f"{_tok(row.get('closure_class'))}/{_tok(row.get('closure_basis'))}"
        details.append(f"  {ident} {why}" + (f": {'; '.join(parts)}" if parts else ""))
    for row in findings[:_MAX_ROWS]:
        ident = _ident(row.get("finding_id"))
        if ident is not None:
            details.append(
                f"  {ident} {_tok(row.get('closure_class'))}/{_tok(row.get('closure_basis'))}"
            )
    return lead, details


def _observed_lines(observed: Mapping[str, JsonValue]) -> tuple[list[str], list[str]]:
    since = observed.get("last_check_frontier")
    actions = _rows(observed.get("actions"))
    where = (
        f"since the last check (frontier {_num(since)})"
        if since is not None
        else "(no check recorded yet)"
    )
    lead = [
        f"Observed by hooks {where}: {_num(observed.get('action_count'))} action(s), "
        f"{len(actions)} listed; FinishUP's own calls and host bookkeeping are not listed."
    ]
    details: list[str] = []
    for row in actions[-_MAX_ROWS:]:
        parts = [f"  #{_num(row.get('ledger_sequence'))}", _tok(row.get("action_kind"))]
        tool = row.get("tool_name")
        if type(tool) is str and _TOOL.fullmatch(tool):
            parts.append(tool)
        parts.append(_tok(row.get("material_class")))
        scope = row.get("write_scope")
        if scope is not None:
            parts.append(f"write {_tok(scope)}")
        outcome = row.get("outcome")
        if outcome is not None:
            parts.append(_tok(outcome))
        exit_status = row.get("exit_status")
        if type(exit_status) is int:
            parts.append(f"exit {exit_status}")
        short = _short(row.get("command_commitment"))
        if short is not None:
            parts.append(f"command {short}...")
        details.append(" ".join(parts))
    return lead, details


def _alignment_lines(alignment: Mapping[str, JsonValue]) -> tuple[list[str], list[str]]:
    rows = _rows(alignment.get("obligations"))
    lead = [
        f"Evidence against declared items: {_num(alignment.get('obligation_count'))} "
        f"obligation(s) cite resolution evidence, {len(rows)} listed; "
        f"{_num(alignment.get('off_declared_count'))} cite evidence with no recorded link to any "
        "declared deliverable or requested command."
    ]
    details: list[str] = []
    for row in rows[:_MAX_ROWS]:
        ident = _ident(row.get("obligation_id"))
        if ident is None:
            continue
        declared = ", ".join(
            f"#{_num(item.get('index'))} {_tok(item.get('item_kind'))}"
            for item in _rows(row.get("declared_items"))
        )
        sources: list[str] = []
        for source in _rows(row.get("sources")):
            ref = _ident(source.get("ref"))
            if ref is None:
                continue
            bits = [ref, _tok(source.get("origin"))]
            short = _short(source.get("command_commitment"))
            if short is not None:
                bits.append(f"command {short}...")
            if source.get("outcome") is not None:
                bits.append(_tok(source.get("outcome")))
            named = _indexes(source.get("named_item_indexes"))
            bits.append(f"names {named}" if named else "names no declared item")
            sources.append(" ".join(bits))
        details.append(
            f"  {ident} {_tok(row.get('alignment'))}: declared "
            f"{declared or 'nothing'}; evidence {'; '.join(sources) or 'none'}"
        )
    if rows:
        details.append(INSPECTION_BOUNDS)
    return lead, details


def inspection_text(wire: Mapping[str, JsonValue]) -> InspectionText:
    """The lines every surface prints for one inspection branch."""

    frontier = _map(wire.get("subject_frontier"))
    lead = [
        f"Inspection at frontier {_num(frontier.get('sequence'))}: read only; nothing was "
        "recorded, no finding was minted and no AI-powered review ran."
    ]
    details: list[str] = []
    for builder, key in (
        (_remaining_lines, "remaining"),
        (_observed_lines, "observed_since_check"),
        (_alignment_lines, "evidence_alignment"),
    ):
        section_lead, section_details = builder(_map(wire.get(key)))
        lead.extend(section_lead)
        details.extend(section_details)
    awaited = _map(wire.get("observations_awaited"))
    if awaited:
        lead.append(
            f"Observation wait: {_tok(awaited.get('state'))} "
            f"({_num(awaited.get('pending_count'))} still pending)."
        )
    return InspectionText(tuple(lead), tuple(details))
