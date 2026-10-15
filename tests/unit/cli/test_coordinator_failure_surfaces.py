"""The coordinator failure is a plain sentence on the CLI check and on every host's Stop text."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from builders.gate_readiness import acceptance_recheck, readiness
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_human_check
from finishup.domain.receipts import COORDINATOR_FAILURE_LIMITATION
from finishup.protocol.models import CheckSuccessModel
from finishup.protocol.readiness_text import COORDINATOR_FAILURE_SENTENCE

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
