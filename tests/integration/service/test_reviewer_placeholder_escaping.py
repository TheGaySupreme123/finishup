"""#1138: a real service job can review a packet containing FinishUP's withheld value."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

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
async def test_replacement_growth_finishes_the_job_as_capacity_not_network_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1230: composition now sizes the change as disclosed; this case is handed to the job as
    # composed before that, and its only excerpt is the change, which disclosure never leaves
    # out or cuts, so it still ends as capacity, never as a network denial.
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
    result, gateway, runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=policy)
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert gateway.exchanges == []
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.CASE_CAPACITY_EXCEEDED
    (capacity,) = [
        event for event in events if event["operation"] == "semantic_disclosure_capacity_exceeded"
    ]
    assert capacity["counts"] == {
        "semantic_excerpt_total_attempted_bytes": selected
        + len(EGRESS_CREDENTIAL_PLACEHOLDER)
        - len(b"hunter2"),
        "semantic_excerpt_total_limit_bytes": selected,
    }


# #1248 P1: the TB4 line shapes after a value FinishUP replaced, in the change under review. The
# real service composes, minimizes and frames the case, so the marker reaches the reviewer
# conversation as FinishUP wrote it, at depth 2, and must never refuse the review.
_SHAPES = {
    "indented_line": b"+db:\n+  password: hunter2\n+    role: admin\n",
    "column_0_line": b"+DB_PASSWORD=hunter2\n+DB_USER=app\n",
    "blank_line": b"+password=hunter2\n+\n+retries=3\n",
    "crlf": b"+password=hunter2\r\n+DB_USER=app\r\n",
    "diff_context_line": b"+password=hunter2\n unchanged_line = 1\n",
    "diff_plus_line": b"+password=hunter2\n+retries = 3\n",
}


@pytest.mark.anyio
@pytest.mark.parametrize("shape", _SHAPES.values(), ids=_SHAPES.keys())
async def test_a_withheld_value_never_refuses_the_review_whatever_line_follows_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: bytes
) -> None:
    _composed(monkeypatch, diff=b"diff --git a/config.yml b/config.yml\n" + shape)
    result, gateway, runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    assert result.status is SemanticStatus.SUCCEEDED
    ((_, history),) = gateway.exchanges
    assert EGRESS_CREDENTIAL_PLACEHOLDER.decode() in history[1][1]
    assert "hunter2" not in history[1][1]
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.SEMANTIC_COMPLETED
