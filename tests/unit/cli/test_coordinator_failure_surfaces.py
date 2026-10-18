"""The closing-review limits are plain sentences on the CLI check and on every host's Stop text.

An unchanged coordinator failure (#1079) and a closing review that ended without a judgment
(n7 RC1, #1105) each stop the closing review from being asked again.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from builders.gate_readiness import acceptance_recheck, readiness
from finishup.cli import closure_gate, render
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_human_check
from finishup.domain import closure
from finishup.domain.receipts import COORDINATOR_FAILURE_LIMITATION
from finishup.mcp import summaries
from finishup.protocol.models import CheckSuccessModel
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
