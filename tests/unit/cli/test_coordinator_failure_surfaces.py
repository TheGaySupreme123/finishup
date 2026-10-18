"""The closing-review limits are plain sentences on the CLI check and on every host's Stop text.

An unchanged coordinator failure (#1079) and a closing review that ended without a judgment
(n7 RC1, #1105) each stop the closing review from being asked again.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from builders.gate_readiness import acceptance_recheck, readiness
from finishup.cli import closure_gate, render
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_closure_readiness_lines, render_human_check
from finishup.domain import closure
from finishup.domain.receipts import COORDINATOR_FAILURE_LIMITATION
from finishup.kernel.closure_readiness import GAP_CLASSIFICATION_VERSION
from finishup.mcp import summaries
from finishup.mcp.summaries import summary_for_closure_prepare, summary_for_status
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckSuccessModel,
    ClosureSelectionModel,
    FrontierModel,
    StatusClosureReadinessModel,
    StatusSuccessModel,
)
from finishup.protocol.readiness_text import (
    COORDINATOR_FAILURE_SENTENCE,
    NO_JUDGMENT_SENTENCE,
    NO_JUDGMENT_TOKEN,
    closing_review_limit_note,
    coordinator_failure_note,
)

_DIGEST = "sha256:" + "d" * 64


def test_cli_check_text_uses_the_coordinator_failure_sentence() -> None:
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="failed",
        semantic_reason="coordinator_failure",
        semantic_route_required=True,
        findings=(),
        review_mode=None,
        totals=None,
        observations_awaited=None,
        review_input_manifest=None,
        semantic_provenance=None,
        suppressed_count=0,
        coverage=SimpleNamespace(known_gaps=()),
    )
    text = render_human_check(result)
    assert COORDINATOR_FAILURE_LIMITATION in text
    assert "AI-powered review: failed (coordinator_failure)" not in text


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_stop_text_names_an_unchanged_coordinator_failure_on_every_host(host: str) -> None:
    announced = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(),),
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
        standing_limitations=("semantic_coordinator_failure",),
    )
    gate = closure_gate_from_readiness(
        announced,
        frontier_sequence="442",
        frontier_digest=_DIGEST,
        observation_pending=False,
        host=host,
    )
    assert gate is not None
    assert COORDINATOR_FAILURE_SENTENCE in gate.text
    required = readiness(
        "action_required",
        ("obligations_open",),
        standing_limitations=("semantic_coordinator_failure",),
    )
    fired = closure_gate_from_readiness(
        required,
        frontier_sequence="442",
        frontier_digest=_DIGEST,
        observation_pending=False,
        host=host,
    )
    assert fired is not None
    assert COORDINATOR_FAILURE_SENTENCE in fired.text
    quiet = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(),),
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
    )
    without = closure_gate_from_readiness(
        quiet,
        frontier_sequence="442",
        frontier_digest=_DIGEST,
        observation_pending=False,
        host=host,
    )
    assert without is not None
    assert COORDINATOR_FAILURE_SENTENCE not in without.text


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_stop_text_says_a_closing_review_without_a_judgment_is_not_asked_again(host: str) -> None:
    """n7 RC1 (#1105): the Stop text agrees with the check's ``semantic_no_judgment`` continuation.

    It never asks for "the closing review" again; it allows one new check or a disclosed finish.
    """

    announced = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(),),
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
        standing_limitations=(NO_JUDGMENT_TOKEN,),
    )
    gate = closure_gate_from_readiness(
        announced,
        frontier_sequence="442",
        frontier_digest=_DIGEST,
        observation_pending=False,
        host=host,
    )
    assert gate is not None
    assert NO_JUDGMENT_SENTENCE in gate.text
    assert COORDINATOR_FAILURE_SENTENCE not in gate.text
    assert "closing review has not run" not in gate.text


def test_every_surface_reads_one_closing_review_limit_sentence() -> None:
    """CLI status, closure-prepare, the MCP summaries and the Stop gate share one function."""

    assert coordinator_failure_note is closing_review_limit_note
    for surface in (closure_gate, render, closure, summaries):
        assert surface.coordinator_failure_note is closing_review_limit_note
    no_judgment = SimpleNamespace(standing_limitations=(NO_JUDGMENT_TOKEN,))
    assert closing_review_limit_note(no_judgment) == NO_JUDGMENT_SENTENCE
    assert closing_review_limit_note({"standing_limitations": [NO_JUDGMENT_TOKEN]}) == (
        NO_JUDGMENT_SENTENCE
    )
    both = SimpleNamespace(standing_limitations=(NO_JUDGMENT_TOKEN, "semantic_coordinator_failure"))
    assert closing_review_limit_note(both) == COORDINATOR_FAILURE_SENTENCE
    assert closing_review_limit_note(SimpleNamespace(standing_limitations=())) is None


def _no_judgment_wire(token: str = NO_JUDGMENT_TOKEN) -> dict[str, Any]:
    return {
        "state": "ready_with_limitations",
        "agent_actionable": [],
        "standing_limitations": [token],
        "acknowledged_not_done": [],
        "acknowledged_not_done_count": "0",
        "receipt_blocking_finding_count": "0",
        "open_obligation_count": "0",
        "declared_obligation_count": "1",
        "no_obligations_reason": None,
        "gap_classification_version": GAP_CLASSIFICATION_VERSION,
        "unanswered_finding_count": "0",
        "blocking_conditions": [],
    }


def _cli_text(wire: dict[str, Any]) -> str:
    return "\n".join(
        render_closure_readiness_lines(StatusClosureReadinessModel.model_validate(wire))
    )


def _mcp_status_text(wire: dict[str, Any]) -> str:
    return summary_for_status(
        {
            "view": "compact",
            "head_frontier": {"sequence": "442", "head_digest": _DIGEST},
            "gaps": [],
            "closure_readiness": wire,
        }
    )


def _mcp_prepare_text(wire: dict[str, Any]) -> str:
    return summary_for_closure_prepare(
        {
            "preparatory_only": True,
            "frontier": {"sequence": "442", "head_digest": _DIGEST},
            "closure_readiness": wire,
            "inventory": {},
        }
    )


def _prepare_notes(wire: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> str:
    """The closure-prepare ``notes`` (``domain.closure.prepare_closure``) over a stub status."""

    frontier = FrontierModel.model_validate({"sequence": "442", "head_digest": _DIGEST})
    compact = StatusSuccessModel.model_construct(
        subject_frontier=frontier,
        closure_readiness=StatusClosureReadinessModel.model_validate(wire),
    )

    async def status(_request: object) -> Any:
        return SimpleNamespace(root=compact)

    def empty_page(_wrapped: object) -> dict[str, Any]:
        return {"page": {"items": [], "next_cursor": None}}

    monkeypatch.setattr(closure, "public_model_to_wire", empty_page)
    output = asyncio.run(
        closure.prepare_closure(
            status,
            str(new_id(IdKind.SESSION)),
            str(new_id(IdKind.WRITER)),
            ClosureSelectionModel(),
        )
    )
    notes = output["notes"]
    assert isinstance(notes, list)
    return "\n".join(str(note) for note in notes)


_SURFACES = ("cli_check", "mcp_status", "mcp_closure_prepare", "closure_prepare_notes")


@pytest.mark.parametrize("surface", _SURFACES)
def test_every_surface_renders_the_no_judgment_sentence(
    surface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Design test 8: each renderer, driven with the standing token, prints the sentence."""

    def text(wire: dict[str, Any]) -> str:
        if surface == "cli_check":
            return _cli_text(wire)
        if surface == "mcp_status":
            return _mcp_status_text(wire)
        if surface == "mcp_closure_prepare":
            return _mcp_prepare_text(wire)
        return _prepare_notes(wire, monkeypatch)

    rendered = text(_no_judgment_wire())
    assert NO_JUDGMENT_SENTENCE in rendered
    assert "closing review has not run" not in rendered
    assert COORDINATOR_FAILURE_SENTENCE not in rendered
    failure = text(_no_judgment_wire("semantic_coordinator_failure"))
    assert COORDINATOR_FAILURE_SENTENCE in failure
    assert NO_JUDGMENT_SENTENCE not in failure
    plain = text(_no_judgment_wire("semantic_relevance_review_not_run"))
    assert NO_JUDGMENT_SENTENCE not in plain
