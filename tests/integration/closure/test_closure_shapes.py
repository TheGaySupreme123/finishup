"""One closure verdict, every surface (tb4n3 RC-3, issue #1026, ADR-046).

tb4n3 ended 16 of 16 successful runs on a status that said "Nothing further to do" and then
received a receipt below clean, and the same ks S finding read four different ways on four
surfaces. The cause was fourteen private answers to "does this item still bound closure?".

Each scenario below is a run shape the real attempts reached, driven through the real
``Application`` facade (status in every view, check, closure preparation, receipt) and reduced to
the two things a reader trusts: the receipt conclusion the state predicts and the finding and
obligation counters. ``assert_surfaces_agree`` is the merge gate: the same conclusion and the same
counters must appear on status JSON (every view), the MCP text, the CLI and terminal lines,
closure_prepare, the check's next step and the receipt in JSON, markdown and text.

Shapes: (a) a deterministic run clean except for FinishUP's own calls (music D, html D, payments D);
(b) ks S, a rejection that awaits a reviewer ruling; (c) cargo D, acknowledged obligations and
bookkeeping findings; (d) vpp S and ks S, a reviewer's limitation request (owner decisions Q4 and 2026-10-12): the agent's
answer decides what it means, so the shape is driven with both answers (``acknowledged`` is a
disclosed verification limit at ``insufficient_coverage``, ``acknowledged_not_done`` is an unmet
requirement at ``unresolved_findings_remain``). Controls that must not change: lake S (a genuine
unmet requirement, whether the reviewer said ``act`` or asked for a stated limit and the agent
answered "not done"), cad D (digest-only evidence bounds a deterministic run) and interleaved D (a
host observation that arrives after the check).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast

import pytest

import integration.application.test_respond_status_receipt as h
from builders.observed_runs import INSTALLATION_KEY
from builders.start_application import protocol_id, start_request
from finishup.application import check_change
from finishup.application.check import CheckCommitResult, FinalSemanticEvaluation
from finishup.application.status import StatusInternalResult
from finishup.cli.closure import Selection, prepare_closure
from finishup.cli.render import render_closure_readiness_lines, render_human_status
from finishup.domain.findings import FindingKind
from finishup.domain.receipts import SchemaVersionEntry
from finishup.kernel.task_facts import RequestedOutputState, register_command_identity_key
from finishup.mcp.summaries import summary_for_closure_prepare, summary_for_status
from finishup.ports.semantic import ReviewerChallenge, SemanticJudgment
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    CheckRequest,
    ReceiptRequest,
    RespondRequest,
    StatusRequest,
    StatusResultModel,
    StatusSuccessModel,
)
from integration.application import test_tb4n3_own_calls_cross_surface as own_calls
from integration.application.test_closure_readiness_checklist import _Session, public_status

pytestmark = pytest.mark.anyio

_CLEAN = "no_unresolved_deterministic_findings"
_INSUFFICIENT = "insufficient_coverage"
_UNRESOLVED = "unresolved_findings_remain"

# (to do, awaiting a ruling, unmet, disclosed, to disclose): the five finding counters.
type Counts = tuple[int, int, int, int, int]
_NO_FINDINGS: Counts = (0, 0, 0, 0, 0)

_STATUS_VIEWS = (
    "compact",
    "obligations",
    "findings",
    "evidence",
    "results",
    "history",
    "advice",
    "versions",
    "candidate_findings",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def receipt_artifact_1_3_0(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped receipt artifact (the harness default is the 1.0.0 reader, with no basis)."""

    original = h._versions

    def versions() -> Any:
        return replace(
            original(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        )

    monkeypatch.setattr(h, "_versions", versions)


# -- The run: a task driven through the public operations --------------------------------------


class _Run(_Session):
    """``_Session`` plus the semantic check mode and ``respond``."""

    async def check_in(self, mode: str) -> CheckCommitResult:
        result = await self.app.check(
            CheckRequest.model_validate(
                {
                    **h._request_base(self.next("req_")),
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": h._frontier(self.frontier),
                    "mode": mode,
                    "max_findings": "10",
                }
            )
        )
        assert type(result) is CheckCommitResult
        self.frontier = result.result_frontier
        return result

    async def respond(
        self,
        finding_id: str,
        finding_frontier: Any,
        disposition: str,
        reason: str | None = None,
        evidence_refs: list[str] | None = None,
    ) -> None:
        result = await self.app.respond(
            RespondRequest.model_validate(
                {
                    **h._request_base(self.next("req_")),
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": h._frontier(self.frontier),
                    "finding_id": finding_id,
                    "finding_frontier": h._frontier(finding_frontier),
                    "disposition": disposition,
                    **({} if reason is None else {"reason": reason}),
                    **({} if evidence_refs is None else {"evidence_refs": evidence_refs}),
                }
            )
        )
        self.frontier = result.result_frontier


def _obligation(run: _Run, number: int, **fields: JsonValue) -> dict[str, JsonValue]:
    draft = run.draft(
        "obligation_published",
        {
            "obligation_id": protocol_id("obl_", 7000 + number),
            "description": f"Requirement {number}",
            "acceptance_criteria": f"Requirement {number} holds.",
            "evidence_expectation": "A recorded result.",
            "status": "open",
            **fields,
        },
    )
    if "requested_items" in fields:
        cast(dict[str, JsonValue], draft["schema"])["version"] = "1.1.0"
    return draft


def _action(run: _Run, number: int) -> dict[str, JsonValue]:
    return run.draft(
        "action_recorded",
        {
            "action_id": protocol_id("act_", 7100 + number),
            "action_kind": "other",
            "description": f"Attempt {number}",
            "obligation_refs": [protocol_id("obl_", 7000 + number)],
        },
    )


def _plan(run: _Run, *numbers: int) -> dict[str, JsonValue]:
    return run.draft(
        "plan_published",
        {
            "plan_version": 1,
            "summary": "The plan",
            "obligation_refs": [protocol_id("obl_", 7000 + n) for n in numbers],
        },
    )


async def _begin(
    *,
    seed: int,
    semantic: Literal["disabled", "optional"] = "disabled",
    evaluator: Callable[..., Awaitable[object]] | None = None,
    backend: Literal["memory", "sqlite"] = "memory",
) -> _Run:
    app, runtime, _ = h._build_app(
        seed_offset=seed, semantic=semantic, semantic_evaluator=evaluator, ledger_backend=backend
    )
    started = await app.start(start_request(seed, title=f"closure shape {seed}"))
    return _Run(app, runtime, started)


def _challenge(
    claim_ref: str,
    obligation_ref: str,
    *,
    kind: FindingKind,
    next_step: str,
    script: list[str],
) -> Callable[..., Awaitable[object]]:
    """A reviewer that raises one challenge on the first review and none afterwards."""

    cited = tuple(sorted({claim_ref, obligation_ref}, key=str.encode))

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await h._semantic_succeeds(frozen, findings))
        if (script.pop(0) if script else "none") != "challenge":
            return succeeded
        item = ReviewerChallenge(
            kind,
            "The accuracy requirement is not shown.",
            cited,
            "No recorded result reaches the stated accuracy.",
            "A hidden evaluator may measure it.",
            "Reach it, or say plainly that it cannot be verified here.",
            next_step,  # type: ignore[arg-type]
            "The packet carries no measurement.",
        )
        return replace(succeeded, judgment=SemanticJudgment("challenges_returned", (item,)))

    return evaluate


async def _ai_finding(
    run: _Run, *, kind: FindingKind, next_step: str, script: list[str], number: int = 1
) -> CheckCommitResult:
    """Resolve a requirement on recorded evidence, claim it complete, then run the semantic check.

    The reviewer (``_challenge``) then disputes the claim, so the only finding is the AI-powered
    one and no deterministic finding rides beside it.
    """

    obligation = protocol_id("obl_", 7000 + number)
    claim = protocol_id("clm_", 7200 + number)
    evidence = protocol_id("evd_", 7300 + number)
    await run.publish(_obligation(run, number), _plan(run, number))
    await run.publish(
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The focused test run passed.",
            },
        ),
        _obligation(run, number, status="resolved", resolution_evidence_refs=[evidence]),
        run.draft(
            "claim_recorded",
            {
                "claim_id": claim,
                "claim_kind": "completion",
                "statement": "The work is complete.",
                "supporting_refs": [evidence],
                "obligation_refs": [obligation],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    checked = await run.check_in("semantic_if_configured")
    assert any(item.origin.value == "semantic_model_derived" for item in checked.findings)
    return checked


def _reviewer_finding(checked: CheckCommitResult) -> Any:
    """The AI-powered finding of a check (the only one the recipe above produces)."""

    return next(item for item in checked.findings if item.origin.value == "semantic_model_derived")


# -- One reading of every surface -------------------------------------------------------------


@dataclass
class _Surfaces:
    status: dict[str, StatusInternalResult] = field(default_factory=dict[str, StatusInternalResult])
    prepared: dict[str, Any] = field(default_factory=dict[str, Any])
    receipts: dict[str, Any] = field(default_factory=dict[str, Any])


def _public(status: StatusInternalResult) -> StatusSuccessModel:
    parsed = public_status(status).root
    assert type(parsed) is StatusSuccessModel
    return parsed


def _actionable(status: StatusInternalResult) -> tuple[str, ...]:
    return tuple(status.closure_readiness.agent_actionable or ())


async def _surfaces(run: _Run, *, receipts: bool = True) -> _Surfaces:
    """Read every surface at the run's current frontier; receipts last (they append)."""

    gathered = _Surfaces()
    for view in _STATUS_VIEWS:
        gathered.status[view] = await run.status(view)

    async def status_fn(request: StatusRequest) -> StatusResultModel:
        return public_status(await run.app.status(request))

    gathered.prepared = cast(
        dict[str, Any],
        await prepare_closure(
            status_fn, run.started.session_id, run.started.writer_id, Selection()
        ),
    )
    if receipts:
        frontier = run.frontier
        for offset, fmt in enumerate(("json", "markdown", "text")):
            gathered.receipts[fmt] = await run.app.receipt(
                ReceiptRequest.model_validate(
                    {
                        **h._receipt_wire(
                            run.serial + 900 + offset,
                            task_id=run.started.task_id,
                            session=run.started.session_id,
                            writer=run.started.writer_id,
                            frontier=frontier,
                        ),
                        "format": fmt,
                    }
                )
            )
    return gathered


_TEXT_CONCLUSION = re.compile(r"(?:will read|would read) (\w+)")
_FINDING_SENTENCE = re.compile(r"Findings to do: [^.]*\.")
_RECEIPT_FINDINGS = re.compile(
    r"Findings: (\d+) to do(?: \((\d+) awaiting a reviewer ruling\))?, (\d+) unmet "
    r"\(acknowledged requirement\), (\d+) disclosed(?: \([^)]*\))?(?:, (\d+) to disclose)?\."
)


def _text_counts(text: str) -> Counts:
    """The finding counters a status text (MCP, CLI, TUI) prints."""

    sentence = _FINDING_SENTENCE.search(text)
    assert sentence is not None, text

    def number(pattern: str) -> int:
        match = re.search(pattern, sentence.group(0))
        return 0 if match is None else int(match.group(1))

    return (
        number(r"to do: (\d+)"),
        number(r"awaiting ruling: (\d+)"),
        number(r"unmet \(acknowledged requirements\): (\d+)"),
        number(r"; disclosed: (\d+)"),
        number(r"to disclose: (\d+)"),
    )


def _wire_counts(readiness: Any) -> Counts:
    counts = readiness.finding_counts
    assert counts is not None
    return (
        int(counts.to_do),
        int(counts.awaiting_ruling),
        int(counts.unmet),
        int(counts.disclosed),
        int(counts.to_disclose),
    )


def _receipt_counts(text: str) -> Counts:
    match = _RECEIPT_FINDINGS.search(text)
    assert match is not None, text
    to_do, awaiting, unmet, disclosed, to_disclose = match.groups()
    return (int(to_do), int(awaiting or 0), int(unmet), int(disclosed), int(to_disclose or 0))


def assert_surfaces_agree(
    gathered: _Surfaces,
    *,
    conclusion: str,
    counts: Counts,
    check: CheckCommitResult | None = None,
) -> None:
    """The merge gate (DESIGN section 4): one conclusion and one set of counters everywhere."""

    for view, status in gathered.status.items():
        readiness = status.closure_readiness
        assert readiness.predicted_receipt is not None, view
        assert readiness.predicted_receipt.conclusion == conclusion, view
        assert _wire_counts(readiness) == counts, view
        # The counters are the verdict: to do + unmet is the unchanged wire count.
        assert int(readiness.receipt_blocking_finding_count or "0") == counts[0] + counts[2], view
        # State and actionable list agree on every view.
        assert (readiness.state == "action_required") == bool(readiness.agent_actionable), view
        mcp = summary_for_status(status.as_json())
        assert _TEXT_CONCLUSION.search(mcp) is not None and (
            _TEXT_CONCLUSION.search(mcp).group(1) == conclusion  # type: ignore[union-attr]
        ), (view, mcp)
        assert _text_counts(mcp) == counts, (view, mcp)
        assert "receipt-blocking" not in mcp.lower(), view
        cli = render_human_status(_public(status))
        assert _TEXT_CONCLUSION.search(cli).group(1) == conclusion, (view, cli)  # type: ignore[union-attr]
        assert _text_counts(cli) == counts, (view, cli)
        assert "receipt-blocking" not in cli.lower(), view
        tui = "\n".join(render_closure_readiness_lines(_public(status).closure_readiness))
        assert _TEXT_CONCLUSION.search(tui).group(1) == conclusion, (view, tui)  # type: ignore[union-attr]
        assert _text_counts(tui) == counts, (view, tui)

    prepared = gathered.prepared["closure_readiness"]
    assert prepared["predicted_receipt"]["conclusion"] == conclusion
    assert (
        int(prepared["finding_counts"]["to_do"]),
        int(prepared["finding_counts"]["awaiting_ruling"]),
        int(prepared["finding_counts"]["unmet"]),
        int(prepared["finding_counts"]["disclosed"]),
        int(prepared["finding_counts"]["to_disclose"]),
    ) == counts
    prepared_text = summary_for_closure_prepare(gathered.prepared)
    assert _TEXT_CONCLUSION.search(prepared_text).group(1) == conclusion, prepared_text  # type: ignore[union-attr]
    assert _text_counts(prepared_text) == counts, prepared_text

    if check is not None:
        assert check.overall_next is not None
        assert check.overall_next.predicted_conclusion == conclusion
        assert check.finding_checklist is not None
        wire = check.finding_checklist.closure_counts
        assert wire is not None
        assert (
            wire.to_do,
            wire.awaiting_ruling,
            wire.unmet,
            wire.disclosed,
            wire.to_disclose,
        ) == counts

    for fmt, receipt in gathered.receipts.items():
        assert receipt.conclusion == conclusion, fmt
        if receipt.document is not None:
            document = receipt.document
            assert document["conclusion"] == conclusion
            basis = document["conclusion_basis"]
            predicted = gathered.status["compact"].closure_readiness.predicted_receipt
            assert predicted is not None
            assert [item["code"] for item in basis["reasons"]] == [
                item.code for item in predicted.reasons
            ]
            assert str(basis["reason_total"]) == predicted.reason_total
        else:
            text = cast(str, receipt.human_text)
            assert _receipt_counts(text) == counts, (fmt, text)
            if conclusion != _CLEAN:
                assert f"Why {conclusion}" in text, (fmt, text)


# -- Shape (a): a deterministic run clean except for FinishUP's own calls --------------------------


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_clean_deterministic_run_with_only_its_own_calls_predicts_and_reads_clean(
    backend: Literal["memory", "sqlite"],
) -> None:
    """music D / html D / payments D: status said "ready" and the receipt said below clean.

    Both now read the same function over the same context, and the agent's own status polls and
    host bookkeeping after the check are not a bound.
    """

    app, runtime, _ = h._build_app(seed_offset=70, ledger_backend=backend)
    started, checked = await own_calls._checked(app, runtime, backend)
    appended = await own_calls._append_observed(
        app,
        runtime,
        started,
        own_calls._own_calls_and_bookkeeping(7300),
        seed=7300,
        expected_frontier=checked.result_frontier.sequence,
    )
    run = _Run(app, runtime, started)
    run.frontier = appended.result_frontier
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_CLEAN, counts=_NO_FINDINGS)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.predicted_receipt is not None and not readiness.predicted_receipt.reasons
    # The agent's own calls after the check do not supersede it: no check item is listed as work.
    assert not {"check_not_recorded", "check_not_applicable"} & set(
        readiness.agent_actionable or ()
    )


# -- Shape (c): cargo D, acknowledged obligations and bookkeeping findings ----------------------


async def test_acknowledged_obligations_and_bookkeeping_findings_agree_on_every_surface() -> None:
    """cargo D: check said "review_recorded_work", status "nothing to do", receipt "unresolved".

    Two ``action_without_result`` findings answered ``acknowledged_not_done`` are bookkeeping
    (disclosed, not unmet), the acknowledged obligations are not work, and the one check next step,
    the status and the receipt all say so: nothing left to do, the receipt reads
    ``insufficient_coverage``.
    """

    run = await _begin(seed=71)
    reason = "The task owner decides this later; I recorded it in my answer."
    await run.publish(
        _obligation(run, 1),
        _obligation(run, 2),
        _obligation(run, 3),
        _plan(run, 1, 2, 3),
        _action(run, 1),
    )
    # Each action in its own batch: a same-batch sibling is never the later work that raises
    # ``action_without_result`` (tb4n5 follow-up), so later batches raise the first two.
    await run.publish(_action(run, 2))
    await run.publish(_action(run, 3))
    first = await run.check_in("deterministic_only")
    bookkeeping = [
        item for item in first.findings if item.kind is FindingKind.ACTION_WITHOUT_RESULT
    ]
    assert len(bookkeeping) == 2
    # Answer each finding, acknowledging it as not done.
    for item in bookkeeping:
        await run.respond(item.finding_id, first.result_frontier, "acknowledged_not_done", reason)
    # The agent also records its obligations as not done (obligation_published 1.1.0).
    drafts: list[dict[str, JsonValue]] = []
    for number in (1, 2, 3):
        draft = _obligation(
            run,
            number,
            status="acknowledged_not_done",
            acknowledged_not_done_reason=reason,
        )
        cast(dict[str, JsonValue], draft["schema"])["version"] = "1.1.0"
        drafts.append(draft)
    await run.publish(*drafts)
    checked = await run.check_in("deterministic_only")

    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.agent_actionable == (), readiness.agent_actionable
    assert readiness.obligation_counts is not None
    assert readiness.obligation_counts.acknowledged == "3"
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 2, 0), check=checked)
    # The check no longer calls acknowledged obligations open work.
    assert checked.overall_next is not None
    assert checked.overall_next.action == "request_receipt"
    assert checked.overall_next.status in {"ready_with_limitations", "ready"}


# -- Shape (b): ks S, a rejection that awaits a reviewer ruling ---------------------------------


async def test_a_rejected_finding_awaits_a_ruling_and_is_never_offered_acknowledgement() -> None:
    """ks S: the gate offered repair / acknowledge and never "run check so the reviewer rules"."""

    obligation = protocol_id("obl_", 7001)
    claim = protocol_id("clm_", 7201)
    script = ["challenge", "none"]
    run = await _begin(
        seed=72,
        semantic="optional",
        evaluator=_challenge(
            claim,
            obligation,
            kind=FindingKind.TASK_REQUIREMENT_UNMET,
            next_step="act",
            script=script,
        ),
    )
    checked = await _ai_finding(
        run, kind=FindingKind.TASK_REQUIREMENT_UNMET, next_step="act", script=script
    )
    assert _reviewer_finding(checked).kind is FindingKind.TASK_REQUIREMENT_UNMET
    await run.respond(
        _reviewer_finding(checked).finding_id,
        checked.result_frontier,
        "rejected",
        "The accuracy is measured by a hidden evaluator; nothing to repair.",
    )
    after = await run.check_in("semantic_if_configured")

    gathered = await _surfaces(run)
    assert "finding_rejection_awaiting_ruling" in _actionable(gathered.status["compact"])
    assert "receipt_findings_unresolved" not in _actionable(gathered.status["compact"])
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(1, 1, 0, 0, 0), check=after)
    assert after.overall_next is not None
    assert after.overall_next.action == "request_ruling"
    assert after.finding_checklist is not None and after.finding_checklist.next == "request_ruling"
    row = next(
        item
        for item in cast(Any, gathered.status["findings"].page).items
        if item.finding_id == _reviewer_finding(checked).finding_id
    )
    assert (row.closure_class, row.closure_basis) == ("awaiting_ruling", "rejected_awaiting_ruling")
    assert "acknowledge" not in (row.next_actions or ())


# -- Shape (d): vpp S, a reviewer's limitation request (owner decision Q4) -----------------------


@pytest.mark.parametrize(
    ("kind", "disposition", "conclusion", "counts", "basis"),
    [
        # vpp S answered "may be met, cannot be verified here": a disclosed verification limit.
        (
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            "acknowledged",
            _INSUFFICIENT,
            (0, 0, 0, 1, 0),
            "limitation_disclosed",
        ),
        # ks S / lake S answered "not done": the requirement is not met, so it stays unresolved.
        (
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            "acknowledged_not_done",
            _UNRESOLVED,
            (0, 0, 1, 0, 0),
            "limitation_acknowledged_not_done",
        ),
        (
            FindingKind.TASK_REQUIREMENT_UNMET,
            "acknowledged",
            _INSUFFICIENT,
            (0, 0, 0, 1, 0),
            "limitation_disclosed",
        ),
        (
            FindingKind.TASK_REQUIREMENT_UNMET,
            "acknowledged_not_done",
            _UNRESOLVED,
            (0, 0, 1, 0, 0),
            "limitation_acknowledged_not_done",
        ),
    ],
)
async def test_a_limitation_request_needs_one_answer_and_the_answer_decides_what_it_means(
    kind: FindingKind,
    disposition: str,
    conclusion: str,
    counts: Counts,
    basis: str,
) -> None:
    """vpp S / ks S / lake S: a request to state a limit is agent work to answer once.

    Before the answer it is never blocking work. The answer decides: ``acknowledged`` discloses a
    verification limit (``insufficient_coverage``, listed under "Verification limits");
    ``acknowledged_not_done`` says the requirement is not met (``unresolved_findings_remain``,
    like any requirement acknowledged as not done, and never under "Verification limits").
    """

    claim = protocol_id("clm_", 7201)
    obligation = protocol_id("obl_", 7001)
    script = ["challenge", "challenge", "challenge"]
    run = await _begin(
        seed=73 + [*FindingKind].index(kind),
        semantic="optional",
        evaluator=_challenge(
            claim,
            obligation,
            kind=kind,
            next_step="state_unresolved_limitation",
            script=script,
        ),
    )
    checked = await _ai_finding(
        run,
        kind=kind,
        next_step="state_unresolved_limitation",
        script=script,
    )
    assert checked.verdict.value == "insufficient_coverage"

    before = await _surfaces(run)
    readiness = before.status["compact"].closure_readiness
    assert "findings_unanswered" in _actionable(before.status["compact"])
    assert "receipt_findings_unresolved" not in _actionable(before.status["compact"])
    assert_surfaces_agree(before, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 0, 1), check=checked)
    row = next(iter(cast(Any, before.status["findings"].page).items))
    assert (row.closure_class, row.closure_basis, tuple(row.next_actions)) == (
        "agent_work",
        "limitation_requested",
        ("acknowledge",),
    )
    # The only remaining agent work is the disclosure, so the check says so (owner decision
    # 2026-10-12): its own continuation value, never "work_open_findings" (repair).
    assert checked.finding_checklist is not None and checked.overall_next is not None
    assert checked.finding_checklist.next == "disclose_limitations"
    assert checked.overall_next.action == "disclose_limitations"

    # Acknowledging a reviewer finding needs one recorded attempt after it (issue #885).
    attempt = protocol_id("evd_", 7390)
    await run.publish(
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": attempt,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:05:00.000Z",
                "description": "I tried to measure the accuracy; no evaluator is reachable here.",
            },
        )
    )
    # The attempt supersedes the review, so the reviewer reviews again (and, still unable to see a
    # measurement, repeats the same request) before the agent answers it.
    rechecked = await run.check_in("semantic_if_configured")
    assert not rechecked.findings  # the same open request is carried, not raised twice
    await run.respond(
        _reviewer_finding(checked).finding_id,
        checked.result_frontier,
        disposition,
        "The evaluator is hidden; I cannot measure it here.",
        evidence_refs=[attempt],
    )
    # The answer is a response to a finding the last check did not return, so it supersedes that
    # check; the reviewer reads the answer and repeats the same request.
    answered = await run.check_in("semantic_if_configured")
    after = await _surfaces(run)
    readiness = after.status["compact"].closure_readiness
    assert readiness.agent_actionable == ()
    assert readiness.state == "ready_with_limitations"
    assert_surfaces_agree(after, conclusion=conclusion, counts=counts, check=answered)
    answered_row = next(iter(cast(Any, after.status["findings"].page).items))
    assert answered_row.closure_basis == basis
    # Nothing is left to disclose or repair on any answer: the check says to request the receipt.
    assert answered.finding_checklist is not None
    assert answered.finding_checklist.next == "request_receipt"
    document = after.receipts["json"].document
    if basis == "limitation_disclosed":
        assert document["limitation_disclosed_finding_ids"] == [
            _reviewer_finding(checked).finding_id
        ]
        for fmt in ("markdown", "text"):
            assert "Verification limits" in after.receipts[fmt].human_text
    else:
        assert "limitation_disclosed_finding_ids" not in document
        for fmt in ("markdown", "text"):
            assert "Verification limits" not in after.receipts[fmt].human_text


# -- Shape (e): formal-crypto S, a resolved obligation whose deliverable was emptied ------------


@dataclass
class _Deliverable:
    """The declared file as the check reads it (patched in for the workspace read)."""

    state: RequestedOutputState


async def _emptied_run(monkeypatch: pytest.MonkeyPatch, seed: int) -> tuple[_Run, _Deliverable]:
    """A solver obligation resolved on a delivered ``/app/solve.sage`` that is then emptied.

    Returns after the first check read the delivered file; the caller empties it
    (``deliverable.state``) and checks again. The reviewer always succeeds with no challenge, so
    nothing but the path-keyed fact (ADR-045) can stop the receipt reading clean.
    """

    delivered = _Deliverable(
        RequestedOutputState(
            "inside", exists=True, changed=True, size_bytes=15_975, lines=310, relative="solve.sage"
        )
    )
    obligation = protocol_id("obl_", 7001)

    async def states(**_kwargs: object) -> dict[tuple[object, int], RequestedOutputState]:
        return {(obligation, 0): delivered.state}

    async def approves(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        return await h._semantic_succeeds(frozen, findings)

    monkeypatch.setattr(check_change, "requested_output_states", states)
    register_command_identity_key(INSTALLATION_KEY)
    run = await _begin(seed=seed, semantic="optional", evaluator=approves)
    evidence = protocol_id("evd_", 7301)
    item = {"item_kind": "file", "value": "/app/solve.sage", "role": "output"}
    await run.publish(
        _obligation(run, 1, requested_items=[item]),
        _plan(run, 1),
        run.draft(
            "action_recorded",
            {
                "action_id": protocol_id("act_", 7101),
                "action_kind": "other",
                "description": "Wrote the solver",
                "obligation_refs": [obligation],
                "attempted_items": ["/app/solve.sage"],
            },
        ),
        run.draft(
            "result_recorded",
            {
                "result_id": protocol_id("res_", 7400),
                "action_id": protocol_id("act_", 7101),
                "outcome": "success",
                "summary": "Wrote the solver.",
            },
        ),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The solver passed the timed runs.",
            },
        ),
        _obligation(
            run,
            1,
            status="resolved",
            resolution_evidence_refs=[evidence],
            requested_items=[item],
        ),
        run.draft(
            "claim_recorded",
            {
                "claim_id": protocol_id("clm_", 7201),
                "claim_kind": "completion",
                "statement": "The solver is delivered.",
                "supporting_refs": [evidence],
                "obligation_refs": [obligation],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    first = await run.check_in("semantic_if_configured")
    assert "declared_output_emptied" not in first.coverage.known_gaps
    return run, delivered


async def _obligation_row(run: _Run) -> tuple[str, str]:
    status = await run.status("obligations")
    row = next(iter(cast(Any, status.page).items))
    return row.closure_class, row.closure_basis


async def test_a_resolved_obligation_whose_deliverable_is_emptied_is_agent_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """formal-crypto S: ``resolved`` stops counting once its file is emptied, on every surface.

    The reviewer succeeds and raises nothing, yet the check is not clean and the receipt cannot
    be (the reviewer never approves an emptied deliverable: the fact is actionable on both
    routes). The obligation reads ``resolved_deliverable_emptied`` (agent work, below clean) in
    status, in ``obligation_counts`` and in the receipt reasons, and the prediction is the
    receipt's conclusion.
    """

    try:
        run, deliverable = await _emptied_run(monkeypatch, 78)
        deliverable.state = RequestedOutputState(
            "inside", exists=True, changed=True, size_bytes=0, lines=0, relative="solve.sage"
        )
        checked = await run.check_in("semantic_if_configured")
        assert "declared_output_emptied" in checked.coverage.known_gaps
        assert checked.verdict.value != "no_issue_detected"
        assert await _obligation_row(run) == ("agent_work", "resolved_deliverable_emptied")

        gathered = await _surfaces(run)
        readiness = gathered.status["compact"].closure_readiness
        assert "declared_output_emptied" in (readiness.agent_actionable or ())
        assert readiness.obligation_counts is not None
        assert (readiness.obligation_counts.open, readiness.obligation_counts.acknowledged) == (
            "1",
            "0",
        )
        assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=_NO_FINDINGS)
        predicted = readiness.predicted_receipt
        assert predicted is not None
        assert "obligations_open" in {item.code for item in predicted.reasons}
    finally:
        register_command_identity_key(None)


async def test_a_finishup_assumption_naming_the_path_returns_the_obligation_to_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner default: an assumption that names the emptied path clears the fact.

    The decision is material, so it supersedes the check that carried the fact (the stale fact is
    not read); the next check records the path as accepted and the obligation stays ``resolved``.
    """

    try:
        run, deliverable = await _emptied_run(monkeypatch, 79)
        deliverable.state = RequestedOutputState(
            "inside", exists=True, changed=True, size_bytes=0, lines=0, relative="solve.sage"
        )
        await run.check_in("semantic_if_configured")
        assert await _obligation_row(run) == ("agent_work", "resolved_deliverable_emptied")

        await run.publish(
            run.draft(
                "decision_recorded",
                {
                    "statement": f"The solver is deliberately empty.\nfinishup-assumption:{protocol_id('obl_', 7001)}",
                    "rationale": "The task statement says /app/solve.sage must be empty.",
                    "authority": "harness:codex",
                    "affected_obligation_ids": [protocol_id("obl_", 7001)],
                },
            )
        )
        assert await _obligation_row(run) == ("resolved", "resolved")
        checked = await run.check_in("semantic_if_configured")
        assert "declared_output_emptied" not in checked.coverage.known_gaps
        assert await _obligation_row(run) == ("resolved", "resolved")
    finally:
        register_command_identity_key(None)


# -- Controls: what must not change -------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        FindingKind.TASK_REQUIREMENT_UNMET,
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
    ],
)
async def test_control_lake_s_a_genuine_unmet_requirement_stays_unresolved(
    kind: FindingKind,
) -> None:
    """lake S: the reviewer said ``act`` and the agent gave up; the label stays unresolved.

    Every requirement kind a reviewer may raise as a limitation request is covered: an ``act``
    challenge never qualifies as a limitation request (only ``state_unresolved_limitation`` does),
    so acknowledging it as not done is an unmet requirement, never a verification limit.
    """

    claim = protocol_id("clm_", 7201)
    obligation = protocol_id("obl_", 7001)
    script = ["challenge"]
    run = await _begin(
        seed=100 + [*FindingKind].index(kind),
        semantic="optional",
        evaluator=_challenge(
            claim,
            obligation,
            kind=kind,
            next_step="act",
            script=script,
        ),
    )
    checked = await _ai_finding(run, kind=kind, next_step="act", script=script)
    await run.respond(
        _reviewer_finding(checked).finding_id,
        checked.result_frontier,
        "acknowledged_not_done",
        "I could not reach that accuracy.",
    )
    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.agent_actionable == ()
    assert readiness.state == "ready_with_limitations"
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(0, 0, 1, 0, 0))
    row = next(iter(cast(Any, gathered.status["findings"].page).items))
    assert row.closure_basis == "acknowledged_not_done_requirement"


async def test_control_lake_s_a_recheck_that_raises_nothing_new_keeps_the_label() -> None:
    """lake S after a re-check: a review that merely raises nothing is not an absence proof.

    The ``act`` finding is acknowledged as not done and the agent re-checks; the reviewer returns
    no new challenge. The acknowledged requirement stays ``settled_unmet`` (only a recorded
    absence proof releases it), so the receipt still reads ``unresolved_findings_remain`` and the
    status prediction before the receipt is that conclusion.
    """

    claim = protocol_id("clm_", 7201)
    obligation = protocol_id("obl_", 7001)
    script = ["challenge", "none"]
    run = await _begin(
        seed=77,
        semantic="optional",
        evaluator=_challenge(
            claim,
            obligation,
            kind=FindingKind.TASK_REQUIREMENT_UNMET,
            next_step="act",
            script=script,
        ),
    )
    checked = await _ai_finding(
        run, kind=FindingKind.TASK_REQUIREMENT_UNMET, next_step="act", script=script
    )
    await run.respond(
        _reviewer_finding(checked).finding_id,
        checked.result_frontier,
        "acknowledged_not_done",
        "I could not reach that accuracy.",
    )
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    assert gathered.status["compact"].closure_readiness.agent_actionable == ()
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(0, 0, 1, 0, 0))
    row = next(iter(cast(Any, gathered.status["findings"].page).items))
    assert (row.closure_class, row.closure_basis) == (
        "settled_unmet",
        "acknowledged_not_done_requirement",
    )


async def test_control_cad_d_digest_only_evidence_keeps_a_deterministic_run_insufficient() -> None:
    """cad D: evidence seen only by digest is not a FinishUP budget, so it bounds on every surface."""

    run = await _begin(seed=75)
    evidence = protocol_id("evd_", 7301)
    await run.publish(
        _obligation(run, 1),
        _plan(run, 1),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "content_digest",
                "content_digest": "sha256:" + "1" * 64,
                "observed_at": "2026-08-04T12:00:02.000Z",
                "description": "The focused test passed.",
                "digest_binding": {
                    "subject": "test_stdout",
                    "content_availability": "digest_only",
                    "byte_count": 2048,
                    "provenance": "caller_asserted",
                },
            },
        ),
        _obligation(run, 1, status="resolved", resolution_evidence_refs=[evidence]),
    )
    checked = await run.check_in("deterministic_only")
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=_NO_FINDINGS, check=checked)
    predicted = gathered.status["compact"].closure_readiness.predicted_receipt
    assert predicted is not None
    bound = next(item for item in predicted.reasons if item.code == "live_gap_bounds")
    assert "evidence_content_digest_only" in bound.refs
    assert "evidence_content_digest_only" in (
        gathered.status["compact"].closure_readiness.standing_limitations or ()
    )


async def test_control_interleaved_d_a_host_observation_after_the_check_stays_a_bound() -> None:
    """interleaved D: a host gap the check never carried bounds the receipt, and status says so."""

    run = await _begin(seed=76)
    checked = await run.check_in("deterministic_only")
    await run.codex_post_tool_use(paired=False)
    gathered = await _surfaces(run)
    predicted = gathered.status["compact"].closure_readiness.predicted_receipt
    assert predicted is not None
    assert predicted.conclusion == _INSUFFICIENT
    assert any(item.code == "live_gap_bounds" for item in predicted.reasons)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=_NO_FINDINGS)
    del checked
