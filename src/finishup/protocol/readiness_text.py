"""Frozen agent-facing text for the closure-readiness checklist states (issue #913, ADR-032).

Like ``finishup.protocol.recovery``, the *state token* travels and the text does not: every surface
(the MCP text summary, the CLI, the terminal interface and the shipped guidance) reconstructs the
same repository-authored sentence locally from ``closure_readiness.state`` and two service counts.
Nothing here is derived from a caller, a payload or model output.

The ``ready_with_limitations`` sentence is the owner-approved wording. It is an instruction to
stop and request the receipt, never a claim about the work: a standing limitation or an
acknowledged item is disclosed on the receipt exactly as recorded, and the receipt's verdict and
coverage stay bounded by them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, Literal, cast

__all__ = [
    "CODEX_CHECK_CELL_PRAGMA",
    "CODEX_CHECK_YIELD_TIME_MS",
    "OBLIGATION_RESOLVE_RECIPE_VARIANTS",
    "READINESS_STATES",
    "awaiting_ruling_variants",
    "COORDINATOR_FAILURE_SENTENCE",
    "COORDINATOR_FAILURE_TOKEN",
    "check_cause_sentence",
    "closure_counts_variants",
    "admissible_verification_sentence",
    "coordinator_failure_note",
    "obligation_resolve_recipe_variants",
    "predicted_receipt_variants",
    "readiness_directive",
    "reason_phrases",
    "recheck_note",
]

type ReadinessState = Literal["action_required", "ready", "ready_with_limitations", "unknown"]

READINESS_STATES: Final[tuple[ReadinessState, ...]] = (
    "action_required",
    "ready",
    "ready_with_limitations",
    "unknown",
)

_ACTION_REQUIRED: Final = (
    "Work remains. Clear each agent-actionable item; standing limitations need no action."
)
_READY: Final = "Nothing further to do. Request the receipt."
# tb4n5 (P6): a code-mode `check` cell without this deadline yields, and the yielded `exec`
# cell lands after the check and makes it stale. `startup.md` states the pragma for a JavaScript
# `exec` cell. The status sentence repeats it only when the cause's tool is that cell (`exec`),
# and the Stop gate repeats it only when code mode was positively observed (#1079). The value is
# the bridge's `check` call deadline (a test pins the two together).
CODEX_CHECK_YIELD_TIME_MS: Final = 300_000
CODEX_CHECK_CELL_PRAGMA: Final = '// @exec: {"yield_time_ms": 300000}'
# The tool name a code-mode cell records. Direct ``exec_command`` is a shell tool, not this.
_CODEX_CELL_TOOL: Final = "exec"
_UNKNOWN: Final = (
    "Readiness is unknown at this frontier. Read status again once the projection is readable."
)


def _count(value: object) -> int:
    if type(value) is int and value >= 0:
        return value
    if type(value) is str and value.isascii() and value.isdigit():
        return int(value)
    raise ValueError("readiness_count_invalid")


# Issue #1079 item 3: an unchanged coordinator failure is a FinishUP limit, not another identical
# closing-review request. The token is a readiness standing code, not a coverage gap.
COORDINATOR_FAILURE_TOKEN: Final = "semantic_coordinator_failure"
COORDINATOR_FAILURE_SENTENCE: Final = (
    "The closing review stopped on an unchanged coordinator failure. That is a FinishUP limit;"
    " do not send the same check again."
)


_OBLIGATION_ID: Final = re.compile(
    r"obl_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_VERIFICATION_ID: Final = re.compile(
    r"(?:evd_|res_)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def admissible_verification_sentence(readiness: object) -> str:
    """One sentence naming admissible observed ids, or empty when none are listed.

    Only obligation ids and ``evd_`` / ``res_`` ids are copied. A missing list, or a row that
    is not those ids, adds nothing.
    """

    raw = _field(readiness, "admissible_verification")
    if not isinstance(raw, (tuple, list)):
        return ""
    pieces: list[str] = []
    for item in tuple(cast("tuple[object, ...] | list[object]", raw))[:8]:
        obligation = _field(item, "obligation_id")
        refs = _field(item, "refs")
        if type(obligation) is not str or _OBLIGATION_ID.fullmatch(obligation) is None:
            continue
        if not isinstance(refs, (tuple, list)):
            continue
        shown = [
            ref
            for ref in tuple(cast("tuple[object, ...] | list[object]", refs))[:8]
            if type(ref) is str and _VERIFICATION_ID.fullmatch(ref) is not None
        ]
        if shown:
            pieces.append(f"{obligation} linked {','.join(shown)}")
    unresolved: list[str] = []
    rechecks = _field(readiness, "rechecks")
    linked = {piece.split(" ", 1)[0] for piece in pieces}
    if isinstance(rechecks, (tuple, list)):
        for entry in rechecks:
            if (
                _field(entry, "kind") != "acceptance"
                or _field(entry, "rule") != _ACCEPTANCE_RISK_RULE
            ):
                continue
            subjects = _field(entry, "subjects")
            if isinstance(subjects, (tuple, list)):
                unresolved.extend(
                    ref
                    for ref in subjects
                    if type(ref) is str and _OBLIGATION_ID.fullmatch(ref) and ref not in linked
                )
    sentences = ["Admissible verification: " + "; ".join(pieces) + "."] if pieces else []
    if unresolved:
        sentences.append(
            "Unresolved verification limitation for "
            + ", ".join(sorted(set(unresolved)))
            + ": no admissible observed verification link or recorded verification limit; "
            "an unanswered acceptance invitation does not establish coverage."
        )
    return " ".join(sentences)


def coordinator_failure_note(readiness: object) -> str | None:
    """The standing sentence when readiness names an unchanged coordinator failure.

    ``None`` when the token is absent, so a checklist without it keeps its exact text.
    """

    raw = _field(readiness, "standing_limitations")
    if isinstance(raw, (tuple, list)) and COORDINATOR_FAILURE_TOKEN in raw:
        return COORDINATOR_FAILURE_SENTENCE
    return None


def readiness_directive(state: str, *, standing: object = 0, acknowledged: object = 0) -> str:
    """Return the frozen sentence for one readiness state, filled only with service counts."""

    if state == "ready_with_limitations":
        return (
            f"Nothing further to do. {_count(standing)} standing limitation(s) and "
            f"{_count(acknowledged)} acknowledged item(s) will be disclosed on the receipt. "
            "Request the receipt."
        )
    if state == "ready":
        return _READY
    if state == "action_required":
        return _ACTION_REQUIRED
    if state == "unknown":
        return _UNKNOWN
    raise ValueError("readiness_state_invalid")


def check_cause_sentence(
    *,
    effect: str,
    event_id: str,
    ledger_sequence: object,
    check_subject_frontier: object,
    family: str,
    material_class: str,
    rule: str,
    tool: str | None = None,
    compact: bool = False,
) -> str:
    """The owner-lineage sentence for ``check_not_applicable`` or a bounding earlier-frontier code.

    Built only from the closed fields ``closure_readiness.check_cause`` carries (service-minted
    ids, counters, a family and rule token, the recorded tool name), so every surface (status text,
    CLI, terminal interface) reconstructs the same words locally. The hook records the tool and
    whether a write left the workspace, never the path, so this names the record and the check
    frontier, not a file.
    """

    via = "" if tool is None else f" via {tool}"
    # An observed code-mode cell (`exec`), not the host brand. Usually the yielded check cell.
    cell = tool == _CODEX_CELL_TOOL
    if compact:
        # The short form for a byte-bounded text: no id, no rule, the same record and frontier.
        record = f"ledger record {_count(ledger_sequence)}"
        tested = f"frontier {_count(check_subject_frontier)}"
        pragma = f" Start the next check cell with `{CODEX_CHECK_CELL_PRAGMA}`." if cell else ""
        if effect == "superseded":
            what = "observed edit" if material_class == "edit_or_write" else f"{family} record"
            return (
                f"Why check_not_applicable: {what}{via} ({record}) after the check at {tested}."
                f"{pragma}"
            )
        if effect == "bounds_conclusion":
            return (
                f"Why check_current_as_of_earlier_frontier: {family} record{via} ({record}) "
                f"after the check at {tested} is unclassified.{pragma}"
            )
        raise ValueError("check_cause_effect_invalid")
    pragma = (
        " If it was a Codex `check` cell that yielded, start the next check cell with "
        f"`{CODEX_CHECK_CELL_PRAGMA}` so the check finishes in its own cell."
        if cell
        else ""
    )
    where = f"ledger record {_count(ledger_sequence)}, {event_id}"
    tested = f"subject frontier {_count(check_subject_frontier)}"
    if effect == "superseded":
        what = (
            f"an observed edit{via}"
            if material_class == "edit_or_write"
            else f"a {family} record{via}"
        )
        return (
            f"Why check_not_applicable: {what} ({where}) was recorded after the check at "
            f"{tested} (rule {rule}). Re-run check after your last change.{pragma}"
        )
    if effect == "bounds_conclusion":
        return (
            "Why check_current_as_of_earlier_frontier: after the check at "
            f"{tested}, a {family} record{via} ({where}) could not be classified as FinishUP's own "
            f"call, a read-only read or host bookkeeping (rule {rule}). FinishUP cannot tell whether "
            f"it changed the work; the receipt discloses it.{pragma}"
        )
    raise ValueError("check_cause_effect_invalid")


# ---------------------------------------------------------------------------------------------
# The one closure verdict (tb4n3 RC-3, ADR-046): the predicted receipt conclusion and the counters
# ---------------------------------------------------------------------------------------------

# One phrase per prediction reason code; ``{n}`` is the reason's count and ``{refs}`` its cited
# ids or gap codes. ASCII only; built from closed tokens and service counts, never from prose.
_REASON_PHRASES: Final[Mapping[str, str]] = {
    "completion_scope_gap": "the completion scope is not declared",
    "findings_to_do": "{n} finding(s) to do",
    "findings_awaiting_ruling": "{n} rejected finding(s) awaiting a reviewer ruling",
    "findings_unmet": "{n} acknowledged requirement(s) not met",
    "child_findings_actionable": "{n} child finding(s) to do",
    "limitations_to_disclose": "{n} limitation(s) to disclose",
    "findings_disclosed": "{n} disclosed finding(s)",
    # Not "open": a resolved obligation whose declared deliverable was emptied is agent work too,
    # while readiness counts only status-open obligations as "open" (ADR-046).
    "obligations_open": "{n} unfinished obligation(s)",
    "obligations_acknowledged": "{n} acknowledged obligation(s)",
    "obligations_disclosed": "{n} disclosed obligation(s)",
    "lineage_blocks": "a child task blocks completion",
    "no_applicable_check": "no check covers the current state",
    "check_suppressed_findings": "the latest check suppressed {n} finding(s)",
    "check_verdict_insufficient": "the latest check read {refs}",
    "policy_execution_incomplete": "a policy did not run to completion",
    "live_gap_bounds": "{n} limitation(s) bound it ({refs})",
}
_CONCLUSIONS: Final = frozenset(
    {
        "unresolved_findings_remain",
        "insufficient_coverage",
        "no_unresolved_deterministic_findings",
    }
)


def _field(source: object, name: str) -> object:
    if isinstance(source, Mapping):
        return source.get(name)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return getattr(source, name, None)


def _reason_phrase(reason: object) -> str | None:
    code = _field(reason, "code")
    template = _REASON_PHRASES.get(code) if type(code) is str else None
    if template is None:
        return None
    count = _field(reason, "count")
    refs = _field(reason, "refs")
    ref_items: tuple[object, ...] = (
        tuple(cast("tuple[object, ...] | list[object]", refs))
        if isinstance(refs, (tuple, list))
        else ()
    )
    named = ", ".join(item for item in ref_items if type(item) is str and item.isascii())
    return template.format(n=_count(count) if count is not None else 1, refs=named or "below clean")


def predicted_receipt_variants(prediction: object, *, state: str = "ready") -> tuple[str, ...]:
    """The predicted-conclusion sentence, longest variant first (owner decision Q1).

    Appended after the owner-approved stop sentence, never edited into it. A ready state reads
    "The receipt will read ..."; while work remains it reads "A receipt requested now would read
    ..." so the sentence is true at every state. Returns ``()`` when the prediction is absent or
    malformed (a surface then prints nothing rather than guess).
    """

    conclusion = _field(prediction, "conclusion")
    if type(conclusion) is not str or conclusion not in _CONCLUSIONS:
        return ()
    raw_reasons = _field(prediction, "reasons")
    reasons: tuple[object, ...] = (
        tuple(cast("tuple[object, ...] | list[object]", raw_reasons))
        if isinstance(raw_reasons, (tuple, list))
        else ()
    )
    phrases = [phrase for reason in reasons if (phrase := _reason_phrase(reason)) is not None]
    lead = (
        f"A receipt requested now would read {conclusion}"
        if state == "action_required"
        else f"The receipt will read {conclusion}"
    )
    tail = (
        " (provisional: a check is running or a dependency is not yet recorded)"
        if (_field(prediction, "provisional") is True)
        else ""
    )
    variants: list[str] = []
    if phrases:
        variants.append(f"{lead}: {', '.join(phrases)}{tail}.")
        if len(phrases) > 1:
            variants.append(f"{lead}: {phrases[0]}{tail}.")
    variants.append(f"{lead}{tail}.")
    if tail:
        variants.append(f"{lead}.")
    return tuple(dict.fromkeys(variants))


def closure_counts_variants(finding_counts: object, obligation_counts: object) -> tuple[str, ...]:
    """The counters sentence ("findings to do: N ..."), longest variant first.

    ``to do`` includes ``awaiting ruling``; ``unmet`` are acknowledged requirements; ``disclosed``
    are settled findings the receipt discloses; ``to disclose`` are a reviewer's limitation
    requests the agent has not yet disclosed. Zero groups are left out; no phrase says
    "receipt-blocking".
    """

    if finding_counts is None and obligation_counts is None:
        return ()

    def number(source: object, name: str) -> int | None:
        value = _field(source, name)
        try:
            return _count(value)
        except ValueError:
            return None

    findings: list[str] = []
    if finding_counts is not None:
        to_do = number(finding_counts, "to_do")
        awaiting = number(finding_counts, "awaiting_ruling")
        unmet = number(finding_counts, "unmet")
        disclosed = number(finding_counts, "disclosed")
        to_disclose = number(finding_counts, "to_disclose")
        if None in (to_do, awaiting, unmet, disclosed, to_disclose):
            return ()
        assert to_do is not None and awaiting is not None and unmet is not None
        assert disclosed is not None and to_disclose is not None
        head = f"to do: {to_do}" + (f" (awaiting ruling: {awaiting})" if awaiting else "")
        findings = [head]
        if unmet:
            findings.append(f"unmet (acknowledged requirements): {unmet}")
        if disclosed:
            findings.append(f"disclosed: {disclosed}")
        if to_disclose:
            findings.append(f"to disclose: {to_disclose}")
    obligations: list[str] = []
    if obligation_counts is not None:
        acknowledged = number(obligation_counts, "acknowledged")
        disclosed_obligations = number(obligation_counts, "disclosed")
        if acknowledged is None or disclosed_obligations is None:
            return ()
        if acknowledged:
            obligations.append(f"acknowledged not done: {acknowledged}")
        if disclosed_obligations:
            obligations.append(f"disclosed: {disclosed_obligations}")
    sentence = ""
    if findings:
        sentence = "Findings " + "; ".join(findings) + "."
    if obligations:
        sentence += (" " if sentence else "") + "Obligations " + "; ".join(obligations) + "."
    short = f"Findings {findings[0]}." if findings else ""
    return tuple(dict.fromkeys(item for item in (sentence, short) if item))


def reason_phrases(reasons: object) -> tuple[str, ...]:
    """One phrase per prediction reason, in order; unknown or malformed reasons are skipped."""

    if not isinstance(reasons, (tuple, list)):
        return ()
    items = tuple(cast("tuple[object, ...] | list[object]", reasons))
    return tuple(phrase for item in items if (phrase := _reason_phrase(item)) is not None)


# ---------------------------------------------------------------------------------------------
# Announced re-reads and awaiting-ruling findings (tb4n3 RC-8, ADR-046)
# ---------------------------------------------------------------------------------------------

_RECHECK_PHRASES: Final[Mapping[str, str]] = {
    "acceptance": "the acceptance criteria of your resolved obligations",
    "acknowledgement": "obligations you recorded as not done",
    "blocker": "a blocker you recorded",
    "premise": "findings you acknowledged that the review says the task requires",
}
# tb4n5 (#1050): an acceptance re-read limited to the resolved obligations the ledger flags, and
# the per-obligation line that answers it before the Stop.
_ACCEPTANCE_RISK_RULE: Final = "resolved_obligations_acceptance_risk"
_ACCEPTANCE_RISK_PHRASE: Final = (
    "the acceptance criteria of the resolved obligations FinishUP flags (rechecks lists them; a line"
    " `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` or"
    " `finishup-verification-limit:<obligation id>` in your final answer answers it; saying every"
    " criterion is met does not)"
)
# Cursor's Stop hook receives no final message, so it never names the acceptance line. The note
# tells the agent to record the limit or the observed id. Saying the criteria are met does not
# answer the re-read. The re-read returns only after the work, its verification, or the review
# mode changes.
_ACCEPTANCE_RISK_PHRASE_CURSOR: Final = (
    "the acceptance criteria of the resolved obligations FinishUP flags (rechecks lists them; Cursor"
    " passes FinishUP no final answer, so publish a decision"
    " `finishup-verification-limit:<obligation id>` or link the observed evd_ or res_ id in a"
    " record; this re-read is asked again only after the work, its verification, or the review mode"
    " changes, and saying every criterion is met does not"
    " answer it)"
)
# A surface that does not know its host (the CLI, the TUI, a generic MCP profile) names which
# hosts read the line, so an agent on Cursor is never told a final-answer line answers the re-read.
_ACCEPTANCE_RISK_PHRASE_ANY_HOST: Final = (
    "the acceptance criteria of the resolved obligations FinishUP flags (rechecks lists them; on"
    " Codex and Claude Code a line `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` or"
    " `finishup-verification-limit:<obligation id>` in your final answer answers it; Cursor passes"
    " no final answer, so there publish a decision `finishup-verification-limit:<obligation id>`"
    " or link the observed evd_ or res_ id in a record; saying every criterion is met does not"
    " answer it)"
)
_MAX_NAMED_RULING_FINDINGS: Final = 3


def recheck_note(readiness: object, *, host: str | None = None) -> str | None:
    """One sentence naming the re-checks the Stop gate will ask once (tb4n3 RC-8).

    ``closure_readiness.rechecks`` is the list status, ``closure_prepare`` and the Stop gate all
    read, so a surface that says "nothing further" never precedes a gate for an item it did not
    name. ``readiness`` is the wire mapping or the typed model. ``None`` when the readiness
    announces none (or an older service sent no list).

    ``host`` decides how a flagged acceptance re-read is answered: ``None``, ``codex`` or
    ``claude`` (the hosts whose Stop passes the final message) name the linked
    ``finishup-acceptance:<obligation id>:met:<evd_ or res_ id>`` line or a verification-limit
    line; ``cursor`` (no final message at Stop) never names ``finishup-acceptance`` and instead
    names a recorded limit or an evidence link; ``generic`` (a surface that does not know its
    host) names both. Saying every criterion is met does not answer the flagged re-read.
    """

    raw = _field(readiness, "rechecks")
    if not isinstance(raw, (tuple, list)):
        return None
    kinds: list[str] = []
    flagged = False
    for entry in tuple(cast("tuple[object, ...] | list[object]", raw)):
        kind = _field(entry, "kind")
        if type(kind) is str and kind in _RECHECK_PHRASES and kind not in kinds:
            kinds.append(kind)
            flagged = flagged or (
                kind == "acceptance" and _field(entry, "rule") == _ACCEPTANCE_RISK_RULE
            )
    if not kinds:
        return None
    risk_phrase = (
        _ACCEPTANCE_RISK_PHRASE_CURSOR
        if host == "cursor"
        else _ACCEPTANCE_RISK_PHRASE_ANY_HOST
        if host == "generic"
        else _ACCEPTANCE_RISK_PHRASE
    )
    named = "; ".join(
        risk_phrase if kind == "acceptance" and flagged else _RECHECK_PHRASES[kind]
        for kind in kinds
    )
    return (
        "At Stop you will be asked once to re-read: "
        f"{named}. closure_readiness.rechecks lists each with its key."
    )


def awaiting_ruling_variants(readiness: object) -> tuple[str, ...]:
    """Name the rejected findings that await a reviewer ruling, longest variant first.

    Built from ``closure_readiness.awaiting_ruling_findings`` (service-minted ids and the frontier
    of the agent's rejection) and ``finding_counts.awaiting_ruling``. ``()`` when nothing awaits a
    ruling or an older service sent no list.
    """

    counts = _field(readiness, "finding_counts")
    try:
        total = _count(_field(counts, "awaiting_ruling"))
    except ValueError:
        return ()
    if not total:
        return ()
    raw = _field(readiness, "awaiting_ruling_findings")
    entries: list[str] = []
    if isinstance(raw, (tuple, list)):
        for entry in tuple(cast("tuple[object, ...] | list[object]", raw)):
            finding = _field(entry, "finding_id")
            frontier = _field(entry, "since_frontier")
            try:
                since = _count(frontier)
            except ValueError:
                continue
            if type(finding) is str and finding.isascii():
                entries.append(f"{finding} (rejected at frontier {since})")
    lead = f"{total} finding(s) you rejected await a reviewer ruling"
    variants: list[str] = []
    if entries:
        shown = entries[:_MAX_NAMED_RULING_FINDINGS]
        more = total - len(shown)
        variants.append(
            f"{lead}: {', '.join(shown)}" + (f" and {more} more" if more > 0 else "") + "."
        )
        variants.append(
            f"{lead}: {shown[0]}" + (f" and {total - 1} more" if total > 1 else "") + "."
        )
    variants.append(f"{lead}; request a check for it, or status view=findings lists them.")
    variants.append(f"{lead}.")
    return tuple(dict.fromkeys(variants))


# tb4n4 (#1049): eight resolutions left ``resolution_evidence_refs`` out and were refused. The
# obligations view is where an agent reads the fields a resolution repeats, so every surface that
# renders it states the one resolution recipe, that field included (longest variant first).
OBLIGATION_RESOLVE_RECIPE_VARIANTS: Final[tuple[str, ...]] = (
    "To resolve an obligation, publish obligation_published again with its obligation_id and every"
    " other field exactly as recorded, status resolved, and resolution_evidence_refs naming the"
    " evidence (evd_) or result (res_) ids that show it done.",
    "Resolve: republish it with status resolved and resolution_evidence_refs (evd_/res_ ids).",
)
_RESOLVABLE_OBLIGATION_STATUSES: Final = frozenset({"open", "acknowledged_not_done"})


def obligation_resolve_recipe_variants(items: object) -> tuple[str, ...]:
    """The resolution recipe when an obligations page holds one not yet resolved, else ``()``.

    *items* is the page's rows (wire mappings or models); only the closed ``status`` token is read.
    """

    if not isinstance(items, (tuple, list)):
        return ()
    for item in tuple(cast("tuple[object, ...] | list[object]", items)):
        status = _field(item, "status")
        if type(status) is str and status in _RESOLVABLE_OBLIGATION_STATUSES:
            return OBLIGATION_RESOLVE_RECIPE_VARIANTS
    return ()
