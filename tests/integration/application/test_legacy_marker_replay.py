"""A ledger that carries the legacy possible-credential marker replays byte for byte (#1248 P4).

Since #1248 step P4 (owner decision P-D5, ADR-048 2026-10-31 amendment) FinishUP writes
``[withheld-by-finishup:possible-credential]``. Content stored by an earlier release keeps the
frozen legacy spelling ``[withheld-by-yoetz:possible-credential]``, and every reader accepts both
forever; nothing is rewritten.

``test_a_ledger_carrying_the_legacy_marker_replays_byte_identically`` runs the real application
over a ledger whose agent-published text carries the legacy marker (in assignment position, where
the agent-context filter re-judges it, and in prose), then projects every public result (start,
publish, check, respond, every status view and the JSON, markdown and text receipts) exactly as the
MCP bridge receives it. ``test_a_stored_check_time_change_keeps_its_counts_and_views`` does the same
for a stored check-time change: its redaction counts, clean prefix and keyed view inputs.

Both pin every byte to ``tests/fixtures/legacy-marker-replay/golden.json``, which was generated from
the code *before* P4 (at #1271's head, ce1f283bd). Regenerate it only for an intended output change
that is unrelated to the marker spelling, with::

    FINISHUP_LEGACY_MARKER_GOLDEN=write uv run pytest \
        tests/integration/application/test_legacy_marker_replay.py
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Final, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    frontier_json,
    project_case,
    request_base,
    run_projection_workflow,
)
from builders.start_application import protocol_id
from finishup.application.receipt import ReceiptInternalResult
from finishup.application.semantic_case import check_time_change_shown_files
from finishup.ports.change_capture import CheckChangeCapture
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReceiptRequest

_GOLDEN: Final = (
    Path(__file__).resolve().parents[2] / "fixtures" / "legacy-marker-replay" / "golden.json"
)
_WRITE: Final = os.environ.get("FINISHUP_LEGACY_MARKER_GOLDEN") == "write"
# Frozen legacy identifier (ADR-048): the spelling stored content written before #1248 P4 carries.
_LEGACY: Final = "[withheld-by-yoetz:possible-credential]"
_NEW: Final = "[withheld-by-finishup:possible-credential]"
_SEED: Final = 7100


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _with_legacy_markers(drafts: list[JsonValue]) -> list[JsonValue]:
    """The sweep batch with the legacy marker in agent text, as an earlier release stored it."""

    text = json.dumps(drafts)
    for before, after in (
        # Assignment position: the agent-context filter re-judges this value on every read.
        (
            "Edited the projection sweep fixture.",
            f"Edited the fixture; config.env keeps DB_PASSWORD={_LEGACY}",
        ),
        (
            "The projection sweep fixture was edited.",
            f'The fixture now reads api_key = "{_LEGACY}" and password: {_LEGACY}',
        ),
        # Prose position: a marker quoted in a sentence.
        (
            "The projection sweep work is complete.",
            f"The work is complete; the value shown as {_LEGACY} was never needed.",
        ),
        ("the projection sweep fixture", f"fixture line token={_LEGACY}"),
    ):
        assert before in text, before
        text = text.replace(before, json.dumps(after)[1:-1])
    return cast(list[JsonValue], json.loads(text))


def _digest(value: JsonValue) -> str:
    return "sha256:" + hashlib.sha256(canonical_encode(value)).hexdigest()


def _golden() -> dict[str, JsonValue]:
    if not _GOLDEN.exists():
        return {}
    return cast(dict[str, JsonValue], json.loads(_GOLDEN.read_text(encoding="utf-8")))


def _store(section: str, observed: dict[str, JsonValue]) -> None:
    golden = _golden()
    golden[section] = cast(JsonValue, observed)
    _GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    _GOLDEN.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _compare(section: str, observed: dict[str, JsonValue]) -> None:
    if _WRITE:
        _store(section, observed)
        return
    expected = cast(dict[str, JsonValue], _golden()[section])
    assert sorted(observed) == sorted(expected)
    for key in sorted(expected):
        assert observed[key] == expected[key], key


@pytest.mark.anyio
async def test_a_ledger_carrying_the_legacy_marker_replays_byte_identically() -> None:
    workflow = await run_projection_workflow(seed=_SEED, event_drafts=_with_legacy_markers)
    cases = list(workflow.cases)
    receipt_case = workflow.case("receipt")
    receipt = cast(ReceiptInternalResult, receipt_case.internal)
    for offset, fmt in enumerate(("markdown", "text")):
        body: dict[str, JsonValue] = {
            **request_base(protocol_id("req_", _SEED + 60 + offset)),
            "task_id": receipt.task_id,
            "session_id": receipt.session_id,
            "writer_id": cast(str, receipt_case.request_body["writer_id"]),
            "expected_frontier": frontier_json(receipt.result_frontier),
            "format": fmt,
            "include": "standard",
            "redaction_profile": "full_local",
        }
        rendered = await workflow.app.receipt(ReceiptRequest.model_validate(body))
        receipt = rendered
        cases.append(ProjectionCase(f"receipt/{fmt}", ControlMethod.RECEIPT, body, rendered))

    observed: dict[str, JsonValue] = {}
    carried = 0
    for offset, case in enumerate(cases):
        wire = await project_case(workflow.app, case, _SEED + 100 + offset)
        encoded = canonical_encode(cast(JsonValue, wire)).decode("utf-8")
        # Stored legacy bytes are never rewritten into the new spelling on any surface.
        assert _NEW not in encoded, case.label
        carried += encoded.count(_LEGACY)
        observed[case.label] = _digest(cast(JsonValue, wire))
    # The legacy marker reaches the agent's projections, so the replay exercises its bytes.
    assert carried > 0
    _compare("ledger", observed)


def _section(marker: bytes) -> bytes:
    return (
        b"diff --git a/app/db.py b/app/db.py\n"
        b"--- a/app/db.py\n"
        b"+++ b/app/db.py\n"
        b"@@ -1,3 +1,4 @@\n"
        b" import os\n"
        b"+password = " + marker + b"\n"
        b"+token=[REDACTED]\n"
        b" PORT = 5432\n"
    )


def _shown(text: bytes, budget: int) -> JsonValue:
    capture = CheckChangeCapture(
        base="task_start",
        text=text,
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        redacted=True,
        base_commit="a" * 40,
    )
    return [
        {
            "whole": item.whole,
            "shown_bytes": item.shown_bytes,
            "redactions": item.redactions,
            "section_admitted": item.section_admitted,
            "clean_bytes": item.clean_bytes,
            "view": "sha256:" + hashlib.sha256(item.view).hexdigest(),
            "identity": "sha256:" + hashlib.sha256(item.identity).hexdigest(),
        }
        for item in check_time_change_shown_files(capture, budget)
    ]


def test_a_stored_check_time_change_keeps_its_counts_and_views() -> None:
    stored = _section(_LEGACY.encode("ascii"))
    edge = stored.index(_LEGACY.encode("ascii")) + 5
    observed: dict[str, JsonValue] = {
        "whole": _shown(stored, len(stored)),
        "cut_inside_marker": _shown(stored, edge),
        "cut_after_marker": _shown(stored, stored.index(b"+token")),
    }
    for shown in observed.values():
        for item in cast(list[dict[str, JsonValue]], shown):
            assert cast(int, item["redactions"]) >= 1 and item["whole"] is False
    _compare("check_time_change", observed)
    # The new spelling is counted exactly like the legacy one.
    renamed = _section(_NEW.encode("ascii"))
    legacy_counts = [
        (item["redactions"], item["whole"])
        for item in cast(list[dict[str, JsonValue]], observed["whole"])
    ]
    new_counts = [
        (item["redactions"], item["whole"])
        for item in cast(list[dict[str, JsonValue]], _shown(renamed, len(renamed)))
    ]
    assert new_counts == legacy_counts


@pytest.mark.parametrize(
    "stored",
    (
        b"password=" + _LEGACY.encode("ascii") + b"\n    role: admin\n",
        b'API_KEY="' + _LEGACY.encode("ascii") + b'"\n',
        b"db:\n  token: " + _LEGACY.encode("ascii") + b"\n\nport: 5432\n",
    ),
    ids=("unquoted_next_line", "quoted", "nested_blank_line"),
)
def test_stored_legacy_markers_leave_in_the_packet_exactly_as_before(stored: bytes) -> None:
    # A marker stored before P4 has no recorded span, so egress re-judges it as a value and
    # replaces it in the spelling it was stored with: the packet and its recorded spans are the
    # pre-P4 bytes, and the new spelling appears nowhere.
    from unit.privacy.test_local_enforcer import (
        _minimize_all,  # pyright: ignore[reportPrivateUsage]
        _two_excerpt_semantic_candidate,  # pyright: ignore[reportPrivateUsage]
    )

    minimized = _minimize_all(_two_excerpt_semantic_candidate(b"clean evidence", stored))
    assert minimized.forbidden_findings == () and minimized.heuristic_findings == ()
    assert _NEW.encode("ascii") not in minimized.prepared_bytes
    assert _LEGACY.encode("ascii") in minimized.prepared_bytes
    observed: dict[str, JsonValue] = {
        "prepared": "sha256:" + hashlib.sha256(minimized.prepared_bytes).hexdigest(),
        "marker_spans": [list(span) for span in minimized.marker_spans],
        "included": list(minimized.included_item_ids),
        "withheld": list(minimized.withheld_item_ids),
        "redacted_span_count": minimized.redacted_span_count,
    }
    key = hashlib.sha256(stored).hexdigest()[:16]
    if _WRITE:
        golden = cast(dict[str, JsonValue], _golden().get("egress", {}))
        golden[key] = cast(JsonValue, observed)
        _store("egress", golden)
        return
    assert observed == cast(dict[str, JsonValue], _golden()["egress"])[key]
