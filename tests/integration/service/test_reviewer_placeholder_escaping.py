"""#1138/#1230: a real service job reviews a packet whose values were replaced."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import finishup.application.egress as egress
import finishup.service.ready_composition as composition
from finishup.domain.privacy import ReviewContextProfile
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.semantic import SemanticCase
from finishup.protocol.models import SemanticReason, SemanticStatus
from integration.service.test_reviewer_conversation_composition import (
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _run,  # pyright: ignore[reportPrivateUsage]
    frozen_request,
)
from integration.service.test_reviewer_oversize_first_exchange import (
    _composed,  # pyright: ignore[reportPrivateUsage]
    _expanded_policy,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.anyio
async def test_withheld_value_survives_packet_and_exchange_encoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _composed(
        monkeypatch,
        diff=b"diff --git a/config.py b/config.py\n+password=hunter2\n",
    )
    result, gateway, runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    assert result.status is SemanticStatus.SUCCEEDED
    ((_, history),) = gateway.exchanges
    assert EGRESS_CREDENTIAL_PLACEHOLDER.decode() in history[1][1]
    assert "hunter2" not in history[1][1]
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.SEMANTIC_COMPLETED


@pytest.mark.anyio
async def test_replacement_growth_is_cut_to_the_bound_and_the_job_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1230: the #1142 boundary no longer fails the review as ``case_capacity_exceeded``.

    The case is handed to the job exactly as composed (it fits the excerpt total as written);
    replacing ``hunter2`` with the longer placeholder takes it over. Disclosure cuts the excerpt
    back within the approved total, says so in the provider-bound manifest, and sends it.
    """

    case = _semantic_case(
        b"diff --git a/config.py b/config.py\n+password=hunter2\n", with_aws_key=False
    )

    # A frozen selection that exactly fits before minimization: the reproduced #1142 boundary.
    def selected_case(**_kwargs: object) -> SemanticCase:
        return case

    monkeypatch.setattr(composition, "build_semantic_case", selected_case)
    policy = _expanded_policy()
    selected = sum(item.content_bytes for item in case.items if item.section == "excerpt")
    policy = replace(
        policy,
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=replace(policy.review_selection, max_total_excerpt_bytes=selected),
    )
    events: list[dict[str, object]] = []

    def record(**kwargs: object) -> str:
        events.append(kwargs)
        return ""

    monkeypatch.setattr(composition, "record_bounded_counts_without_raising", record)
    monkeypatch.setattr(egress, "record_bounded_counts_without_raising", record)
    result, gateway, runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=policy)
    assert (result.status, result.reason) == (
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    ((_, history),) = gateway.exchanges
    packet = json.loads(history[1][1])
    rows = [row for row in packet["items"] if row["section"] == "excerpt"]
    assert sum(row["content_bytes"] for row in rows) <= selected
    assert "hunter2" not in history[1][1]
    current_diff = packet["review_packet"]["provider_input_manifest"]["current_diff"]
    assert current_diff["status"] == "partial"
    assert "truncated_payload" in current_diff["omission_reasons"]
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.SEMANTIC_COMPLETED
    assert not [e for e in events if e["operation"] == "semantic_disclosure_capacity_exceeded"]
    (fitted,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]
    assert fitted["counts"] == {
        "semantic_excerpts_cut_at_disclosure": 1,
        "semantic_excerpts_unselected_at_disclosure": 0,
    }
