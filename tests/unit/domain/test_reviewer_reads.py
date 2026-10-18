"""#1118 unit 4: the reviewer-read summary keeps counts, closed tokens and aliases, never paths."""

from __future__ import annotations

import json

from finishup.domain.reviewer_reads import render_reviewer_reads_lines, summarize_reviewer_reads


def _envelope(ordinal: int, status: str, size: int, data: object, reason: str | None = None) -> str:
    return json.dumps(
        {
            "tool_ref": f"job:read:{ordinal}",
            "call_index": ordinal,
            "status": status,
            "reason": reason,
            "truncated": ordinal == 1,
            "data": data,
            "result_utf8_bytes": size,
        }
    )


def _history() -> list[tuple[str, str]]:
    secret_path = "o1:specs/customer-plan.md"
    file_read = {
        "text": "THE SPEC TEXT",
        "provenance": {
            "source_ref": secret_path,
            "root_id": "o1",
            "standing": "outside_input_snapshot",
            "baseline": "task_start",
        },
    }
    ledger_read = {
        "records": [
            {
                "ref": "res_1",
                "text": "3 passed",
                "provenance": {
                    "source_ref": "res_1",
                    "root_id": None,
                    "standing": "finishup_record",
                    "baseline": "check_time",
                },
            }
        ]
    }
    return [
        ("system", "instruction"),
        ("user", "packet"),
        ("assistant", json.dumps({"action": "read_file", "args": {"root_id": "o1"}})),
        ("user", _envelope(1, "ok", 4000, file_read)),
        ("user", "format_error: not_json"),
        ("assistant", json.dumps({"action": "read_ledger", "args": {"view": "command_output"}})),
        ("user", _envelope(2, "ok", 900, ledger_read)),
        ("assistant", json.dumps({"action": "read_file", "args": {"root_id": "/etc"}})),
        ("user", _envelope(3, "denied", 300, None, reason="forbidden_path")),
        ("assistant", json.dumps({"final_judgment": {"conclusion": "insufficient_packet"}})),
    ]


def test_reads_are_counted_and_named_by_alias_and_standing_only() -> None:
    summary = summarize_reviewer_reads(_history())
    assert summary is not None
    assert summary["reads_used"] == 3
    assert summary["result_bytes"] == 5200
    lines = render_reviewer_reads_lines(summary)
    assert lines[0].startswith("Reviewer reads: 3 of 3, 5200 result bytes")
    assert (
        lines[1]
        == "- 1. read_file: ok, 4000 bytes, clipped; o1 (outside_input_snapshot, task_start)"
    )
    assert lines[2] == "- 2. read_ledger: ok, 900 bytes; record (finishup_record, check_time)"
    assert lines[3] == "- 3. read_file: denied forbidden_path, 300 bytes"
    rendered = json.dumps(summary) + "\n".join(lines)
    for leaked in ("customer-plan", "specs/", "THE SPEC TEXT", "3 passed", "/etc"):
        assert leaked not in rendered


def test_a_review_without_reads_or_with_malformed_turns_renders_nothing() -> None:
    assert summarize_reviewer_reads([("system", "x"), ("user", "packet")]) is None
    forged = [
        ("assistant", json.dumps({"action": "read_file"})),
        ("user", _envelope(9, "ok", 10, None)),
        ("assistant", json.dumps({"action": "shell"})),
        ("user", _envelope(1, "ok", 10, None)),
    ]
    assert summarize_reviewer_reads(forged) is None
    assert render_reviewer_reads_lines(None) == ()
    assert render_reviewer_reads_lines({"reads": "x"}) == ()
