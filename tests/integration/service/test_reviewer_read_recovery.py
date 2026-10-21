"""#1173: read recovery, encrypted telemetry and owner metrics through the real service."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.application import reviewer_run
from finishup.application.reviewer_telemetry import (
    export_reviewer_read_metrics,
    read_usage_from_wire,
)
from finishup.protocol.models import SemanticStatus
from finishup.service.ready_composition import (
    _recover_response_evaluation,  # pyright: ignore[reportPrivateUsage]
)
from integration.service import test_reviewer_conversation_composition as c

pytestmark = pytest.mark.anyio
_read_file = c._read_file  # pyright: ignore[reportPrivateUsage]
_FINAL = c._FINAL  # pyright: ignore[reportPrivateUsage]


async def test_two_corrections_preserve_three_reads_and_export_only_selector_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diagnostics: list[dict[str, Any]] = []

    def diagnostic(**fields: Any) -> None:
        diagnostics.append(fields)

    monkeypatch.setattr(
        reviewer_run,
        "record_bounded_counts_without_raising",
        diagnostic,
    )
    replies = [
        {},
        _read_file("/absolute/calc.py"),
        _read_file("absent.py"),
        *([_read_file("calc.py")] * 3),
        _FINAL,
    ]
    result, gateway, runtime = await c._run(tmp_path, monkeypatch, *replies)  # pyright: ignore[reportPrivateUsage]
    assert result.status is SemanticStatus.SUCCEEDED
    assert len(gateway.exchanges) == 7
    record = result.reviewer
    assert record is not None and record.exchanges == 7 and len(record.reads) == 5
    assert record.as_wire()["reads_used"] == "3"
    assert [r.reason for r in record.reads] == ["forbidden_path", "not_recorded", None, None, None]
    assert all(r.disclosure is not None for r in record.reads)
    assert "final_judgment now" in gateway.exchanges[-1][1][-1][1]
    # A stable provider schema/digest, including the final phase, on the real dispatch path.
    from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
    from finishup.ports.semantic import reviewer_exchange

    exchanges = [
        reviewer_exchange(
            media,
            json.dumps([{"role": role, "content": text} for role, text in history]).encode(),
            REVIEWER_REPLY_SCHEMAS,
        )
        for media, history in gateway.exchanges
    ]
    assert len({e.schema_digest for e in exchanges if e is not None}) == 1
    assert len(diagnostics) == 5
    assert [d["counts"] for d in diagnostics] == [{"operation_count": n} for n in range(1, 6)]
    assert [d["outcome"] for d in diagnostics] == [
        "forbidden_path",
        "not_recorded",
        "ok",
        "ok",
        "ok",
    ]
    assert "calc.py" not in json.dumps(diagnostics) and "return a + b" not in json.dumps(
        diagnostics
    )
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", c.frozen_request())
    assert job is not None
    attempts = await runtime.ledger.list_semantic_attempts(job.job_id)
    assert len(attempts) == 1
    metrics = await export_reviewer_read_metrics(attempts, runtime.objects)
    usage = cast(
        list[dict[str, Any]],
        cast(list[dict[str, Any]], metrics["attempt_usages"])[0]["reviewer_reads"],
    )
    assert [r["args"]["path"] for r in usage] == [
        "/absolute/calc.py",
        "absent.py",
        *(["calc.py"] * 3),
    ]
    assert [r["reason"] for r in usage] == ["forbidden_path", "not_recorded", None, None, None]
    assert "return a + b" not in json.dumps(metrics) and "final_judgment" not in json.dumps(metrics)
    assert "calc.py" not in json.dumps(record.as_wire())
    response = attempts[0].result_object_ref
    assert response is not None
    recovered = await _recover_response_evaluation(runtime, response)
    assert recovered is not None and list(recovered.reviewer_read_usage or ()) == usage
    assert await runtime.ledger.review_step_usage(job.job_id) == (13, 0)  # type: ignore[attr-defined]  # pyright: ignore


async def test_incomplete_review_keeps_five_failed_attempts_for_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, runtime = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        *([_read_file("/wrong")] * 6),
    )
    assert result.status is SemanticStatus.INVALID and len(gateway.exchanges) == 6
    assert result.reviewer is not None and result.reviewer.as_wire()["reads_used"] == "0"
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", c.frozen_request())
    assert job is not None
    metrics = await export_reviewer_read_metrics(
        await runtime.ledger.list_semantic_attempts(job.job_id), runtime.objects
    )
    usage = cast(
        list[dict[str, Any]],
        cast(list[dict[str, Any]], metrics["attempt_usages"])[0]["reviewer_reads"],
    )
    assert len(usage) == 5 and all(r["reason"] == "forbidden_path" for r in usage)


def test_private_usage_rejects_result_text_and_extra_arguments() -> None:
    base: dict[str, Any] = {
        "call": 1,
        "action": "read_file",
        "args": {
            "root_id": "w1",
            "path": "calc.py",
            "mode": "text",
            "start_line": 1,
            "line_count": 20,
        },
        "status": "ok",
        "reason": None,
    }
    assert read_usage_from_wire([base]) is not None
    assert read_usage_from_wire([{**base, "content": "returned evidence"}]) is None
    assert read_usage_from_wire([{**base, "args": {**base["args"], "text": "evidence"}}]) is None
    assert read_usage_from_wire([{**base, "call": 6}]) is None
    assert read_usage_from_wire(None) is None
