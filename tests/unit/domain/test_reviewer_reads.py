"""#1118: the reviewer conversation record every surface renders alike."""

from __future__ import annotations

import pytest

from finishup.domain.reviewer_reads import (
    ReviewerRead,
    ReviewerRecord,
    render_reviewer_lines,
    reviewer_record_from_wire,
)

_DIGEST = "sha256:" + "a" * 64


def _read(call: int, **changes: object) -> ReviewerRead:
    fields: dict[str, object] = {
        "call": call,
        "action": "read_file",
        "status": "ok",
        "reason": None,
        "source": "src_" + "0" * 23 + str(call),
        "root": "w1",
        "standing": "workspace_content",
        "baseline": "read_time",
        "lines": (1, 2),
        "result_bytes": 300,
        "result_digest": _DIGEST,
        "disclosure": f"egr_{call}",
    }
    fields.update(changes)
    return ReviewerRead(**fields)  # pyright: ignore[reportArgumentType]


def test_the_wire_form_round_trips_and_renders_without_paths() -> None:
    record = ReviewerRecord(
        3, (_read(1), _read(2, status="denied", reason="forbidden_path", lines=None)), None, None
    )
    wire = record.as_wire()
    assert wire["reads_used"] == "2" and wire["read_bytes"] == "600"
    assert reviewer_record_from_wire(wire) == record
    lines = render_reviewer_lines(record)
    assert lines[0] == "Reviewer reads: 2 of 3, 600 bytes, 3 model exchanges"
    assert lines[1].startswith("- 1. read_file: ok [w1 src_") and "lines 1-2" in lines[1]
    assert "sent under receipt egr_1" in lines[1]
    assert lines[2].startswith("- 2. read_file: denied forbidden_path")


def test_an_early_end_and_an_unsent_read_are_named() -> None:
    record = ReviewerRecord(4, (_read(1, disclosure=None),), "read_limit", "terminated")
    lines = render_reviewer_lines(record)
    assert lines[0].endswith("; ended early: read_limit")
    assert lines[1].endswith(", not sent")


@pytest.mark.parametrize(
    "change",
    [
        {"root": "/home/user/project"},
        {"source": "src/private_name.py"},
        {"status": "bogus"},
        {"result_bytes": 9000},
        {"lines": (3, 1)},
        {"action": "run_shell"},
    ],
)
def test_anything_but_closed_tokens_and_opaque_ids_is_refused(change: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="reviewer_read_invalid"):
        _read(1, **change)


def test_an_older_or_malformed_response_has_no_record() -> None:
    assert reviewer_record_from_wire(None) is None
    assert reviewer_record_from_wire({"exchanges": 1}) is None
    assert render_reviewer_lines(None) == ()
