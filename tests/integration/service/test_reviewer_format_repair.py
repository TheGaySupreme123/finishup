"""#1118 R4: the reviewer conversation's one format repair, through the real composition.

A completed answer that is not one JSON object gets the same single durable repair as a decoded
reply that is not valid; a second malformed answer ends the review honestly, and a failed
generation is never repaired. Only the provider behind the gateway is scripted.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from finishup.domain.findings import SemanticFailureClass
from finishup.ports.semantic import SemanticResultInvalid, SemanticResultTimeout
from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as c

pytestmark = pytest.mark.anyio


def _not_json(_case: object, provenance: Any) -> SemanticResultInvalid:
    """A completed answer that is not one JSON object (the API routes' typed classification)."""

    return SemanticResultInvalid(
        replace(
            provenance,
            status=SemanticStatus.INVALID,
            failure_class=SemanticFailureClass.RESPONSE_SCHEMA,
        ),
        8,
    )


def _timed_out(_case: object, provenance: Any) -> SemanticResultTimeout:
    return SemanticResultTimeout(replace(provenance, status=SemanticStatus.TIMEOUT))


async def test_a_completed_answer_that_is_not_json_gets_the_one_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, runtime = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        _not_json,
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    assert len(gateway.exchanges) == 2
    # The repair names the code, never echoes the malformed text, and is one durable step.
    note = gateway.exchanges[1][1][-1]
    assert note[0] == "user" and note[1].startswith("format_error: output_not_json.")
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", c.frozen_request())
    assert job is not None
    steps = await runtime.ledger.review_step_usage(job.job_id)  # type: ignore[attr-defined]
    assert steps == (3, 0)  # two turns and the repair, all captured


async def test_a_second_malformed_answer_ends_the_review_without_a_judgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, _not_json, {}
    )
    assert result.status is SemanticStatus.INVALID and result.judgment is None
    assert len(gateway.exchanges) == 2
    assert result.reviewer is not None and result.reviewer.ended == "format_invalid"


async def test_a_failed_generation_is_never_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        _timed_out,
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.TIMEOUT and len(gateway.exchanges) == 1
    assert result.reviewer is not None and result.reviewer.ended == "reviewer_exchange_timeout"
