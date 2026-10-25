"""Fix or decline before the receipt (issue #1209, ADR-032 amendment).

A TB4 Bun attempt's final status listed ``requested_output_unchanged`` under "Nothing further to
do ... Request the receipt." and the agent closed with a requested output it had never changed.
Here a requested output the record says was written is unchanged at check time: the check, every
status view, the MCP text, the CLI and terminal lines and the check's ``agent_next`` name it with
its obligation as "fix, or decline with a reason" instead of the frozen sentence, the Stop gate
does not continue the agent for it, and the receipt prediction still equals the receipt. After the
agent declines it (a ``finishup-assumption`` decision with its reason as the rationale) the
frozen sentence returns, and the receipt discloses both the code and the decision.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

import integration.application.test_respond_status_receipt as h
from builders.start_application import protocol_id
from finishup.application import check_change
from finishup.application.check import check_internal_json
from finishup.application.status import brief_status_body
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_closure_readiness_lines, render_human_status
from finishup.kernel.task_facts import RequestedOutputState
from finishup.mcp.summaries import summary_for_check, summary_for_status
from integration.closure.test_closure_shapes import (
    _NO_FINDINGS,
    _begin,
    _obligation,
    _plan,
    _public,
    _Run,
    _surfaces,
    assert_surfaces_agree,
)

pytestmark = pytest.mark.anyio

_OBLIGATION = protocol_id("obl_", 7001)
_FROZEN = "Nothing further to do."
_DIRECTIVE = (
    f"Before the receipt: fix, or decline with a reason: requested_output_unchanged ({_OBLIGATION})"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def receipt_artifact_1_3_0(monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    from finishup.domain.receipts import SchemaVersionEntry

    original = h._versions

    def versions() -> Any:
        return replace(
            original(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        )

    monkeypatch.setattr(h, "_versions", versions)


async def _unchanged_run(monkeypatch: pytest.MonkeyPatch, seed: int) -> _Run:
    """A resolved obligation whose declared output exists but is unchanged from the task base."""

    unchanged = RequestedOutputState(
        "inside", exists=True, changed=False, size_bytes=120, lines=4, relative="out.txt"
    )

    async def states(**_kwargs: object) -> dict[tuple[object, int], RequestedOutputState]:
        return {(_OBLIGATION, 0): unchanged}

    async def approves(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        return await h._semantic_succeeds(frozen, findings)

    monkeypatch.setattr(check_change, "requested_output_states", states)
    run = await _begin(seed=seed, semantic="optional", evaluator=approves)
    evidence = protocol_id("evd_", 7301)
    item = {"item_kind": "file", "value": "/app/out.txt", "role": "output"}
    await run.publish(_obligation(run, 1, requested_items=[item]), _plan(run, 1))
    await run.publish(
        run.draft(
            "action_recorded",
            {
                "action_id": protocol_id("act_", 7101),
                "action_kind": "other",
                "description": "Wrote the output",
                "obligation_refs": [_OBLIGATION],
                "attempted_items": ["/app/out.txt"],
            },
        ),
        run.draft(
            "result_recorded",
            {
                "result_id": protocol_id("res_", 7400),
                "action_id": protocol_id("act_", 7101),
                "outcome": "success",
                "summary": "Wrote the output.",
            },
        ),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The output was produced.",
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
                "statement": "The output is delivered.",
                "supporting_refs": [evidence],
                "obligation_refs": [_OBLIGATION],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    return run


def _fix_or_decline(readiness: Any) -> tuple[tuple[str, str], ...]:
    return tuple((item.code, str(item.obligation_id)) for item in readiness.fix_or_decline or ())


async def test_an_unchanged_output_is_fix_or_decline_on_every_surface_and_never_a_stop_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = await _unchanged_run(monkeypatch, 120_901)
    checked = await run.check_in("semantic_if_configured")
    assert "requested_output_unchanged" in checked.coverage.known_gaps, checked.coverage
    assert not checked.findings, [(f.kind, f.subject_refs) for f in checked.findings]

    gathered = await _surfaces(run)
    for view, status in gathered.status.items():
        readiness = status.closure_readiness
        assert readiness.state == "ready_with_limitations", (view, readiness.agent_actionable)
        assert readiness.gap_classification_version == "9"
        assert _fix_or_decline(readiness) == (("requested_output_unchanged", _OBLIGATION),), view
        assert "requested_output_unchanged" in (readiness.standing_limitations or ())
        assert "requested_output_unchanged" not in (readiness.agent_actionable or ())
        for text in (
            summary_for_status(status.as_json()),
            render_human_status(_public(status)),
            "\n".join(render_closure_readiness_lines(_public(status).closure_readiness)),
        ):
            assert _DIRECTIVE in text, (view, text)
            assert _FROZEN not in text, (view, text)
        # A brief body carries the items too, so it never reads "nothing further" either.
        brief = summary_for_status(brief_status_body(status.as_json()))
        assert _DIRECTIVE in brief and _FROZEN not in brief, (view, brief)
        # ADR-033 D1: never a Stop item.
        assert (
            closure_gate_from_readiness(
                _public(status).closure_readiness,
                frontier_sequence="7",
                frontier_digest="sha256:" + "d" * 64,
                observation_pending=False,
            )
            is None
        ), view
    # ADR-046: the prediction is the receipt (the conclusion is unchanged by the new group).
    predicted = gathered.status["compact"].closure_readiness.predicted_receipt
    assert predicted is not None
    assert_surfaces_agree(gathered, conclusion=predicted.conclusion, counts=_NO_FINDINGS)

    # The check that recorded the fact names it in its readiness and its agent_next lead.
    assert checked.closure_readiness is not None
    rows = cast(list[dict[str, str]], checked.closure_readiness["fix_or_decline"])
    assert [dict(row) for row in rows] == [
        {"code": "requested_output_unchanged", "obligation_id": _OBLIGATION}
    ]
    wire = check_internal_json(checked)
    assert _DIRECTIVE in cast(str, wire["agent_next"])
    assert _DIRECTIVE in summary_for_check(wire)
    assert _FROZEN not in summary_for_check(wire)


async def test_a_declined_item_returns_the_frozen_sentence_and_is_disclosed_with_its_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = await _unchanged_run(monkeypatch, 120_902)
    await run.check_in("semantic_if_configured")
    published = await run.publish(
        run.draft(
            "decision_recorded",
            {
                "statement": f"The output was already correct.\nfinishup-assumption:{_OBLIGATION}",
                "rationale": "The task base already held the requested output byte for byte.",
                "authority": "harness:codex",
                "affected_obligation_ids": [_OBLIGATION],
            },
        )
    )
    decision = published.accepted_events[0].event_id
    # A decision is material: the check that recorded the fact no longer applies, so the item is
    # not listed while the next check is owed, and that check finds the decline already recorded.
    owed = (await run.status()).closure_readiness
    assert owed.state == "action_required" and owed.fix_or_decline is None, owed.agent_actionable
    await run.check_in("semantic_if_configured")

    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.state == "ready_with_limitations"
    assert readiness.fix_or_decline is None
    standing = readiness.standing_limitations or ()
    assert {"requested_output_unchanged", "assumption_disclosed"} <= set(standing)
    text = summary_for_status(gathered.status["compact"].as_json())
    assert _FROZEN in text and "Before the receipt" not in text
    predicted = readiness.predicted_receipt
    assert predicted is not None
    assert_surfaces_agree(gathered, conclusion=predicted.conclusion, counts=_NO_FINDINGS)
    document = gathered.receipts["json"].document
    assert document is not None
    assert "requested_output_unchanged" in document["coverage"]["known_gaps"]
    assert {
        "decision_event_id": str(decision),
        "kind": "assumption",
        "obligation_id": _OBLIGATION,
    } in document["disclosed_assumptions"]
    for fmt in ("markdown", "text"):
        assert str(decision) in cast(str, gathered.receipts[fmt].human_text)
