"""What a Codex model actually reads of a large check result (issue #1107, W6; ADR-043 amendment).

Codex 0.159 shows a model ``serde_json::to_string(structuredContent)`` behind a ``Wall time``
header, never the text channel, and cuts the middle of a long body: for a model slug without a
bundled ``models.json`` entry it keeps the first and last 6,000 bytes. Its ``serde_json`` keeps
insertion order, so the model sees FinishUP's own field order. These tests emulate that view on
the real bridge projection and pin that the bounded ``agent_next`` lead always survives it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final, cast

from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.mcp.server import result_from_public_model
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import CheckResult

# codex-rs/models-manager model_info.rs fallback ``bytes(10_000)`` x1.2 serialization allowance.
_CODEX_WINDOW_BYTES: Final = 12_000
_CODEX_HEADER: Final = "Wall time: 0.0000 seconds\nOutput:\n"
_FIXTURE: Final = (
    Path(__file__).resolve().parents[3] / "fixtures/canonical/check-agent-next-1.5.0.case.json"
)


def _vector(vector_id: str) -> dict[str, Any]:
    vectors = cast(list[dict[str, Any]], json.loads(_FIXTURE.read_bytes())["input"]["vectors"])
    return next(item["payload"] for item in vectors if item["vector_id"] == vector_id)


def _uuid(number: int) -> str:
    return f"10000000-0000-4000-8000-{number:012x}"


def _n7_shaped_wire() -> dict[str, Any]:
    """A worst-case insufficient-packet result: many findings, gaps and omitted pointers."""

    wire = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    vector = _vector("supply_worst_case_shrinks_to_the_bound")
    wire["agent_next"] = vector["agent_next"]
    wire["overall_next"] = vector["overall_next"]
    wire["missing_for_assessment"] = vector["missing_for_assessment"]
    finding = wire["findings"][0]
    wire["findings"] = [
        {
            **finding,
            "finding_id": f"fnd_{_uuid(500 + index)}",
            "summary": "An action has no result. " * 20,
            "detail": "Record the terminal result for the run the reviewer named. " * 30,
        }
        for index in range(6)
    ]
    wire["coverage"]["known_gaps"] = sorted(f"gap_code_number_{index:02d}" for index in range(64))
    wire["privacy_projection"]["omitted_pointers"] = sorted(
        (f"/findings/{index}/detail" for index in range(6)), key=str.encode
    )
    return wire


def _codex_view(structured: dict[str, object]) -> tuple[str, str, int]:
    body = (
        _CODEX_HEADER + json.dumps(structured, separators=(",", ":"), ensure_ascii=False)
    ).encode("utf-8")
    half = _CODEX_WINDOW_BYTES // 2
    return (
        body[:half].decode("utf-8", errors="ignore"),
        body[-half:].decode("utf-8", errors="ignore"),
        len(body),
    )


def test_agent_next_survives_a_codex_head_and_tail_cut() -> None:
    wire = _n7_shaped_wire()
    result = result_from_public_model(CheckResult.model_validate(wire), host_profile="codex")
    structured = result.structuredContent
    assert structured is not None
    head, _tail, size = _codex_view(structured)
    # The result really is cut: the middle (findings, coverage) is gone.
    assert size > 2 * _CODEX_WINDOW_BYTES
    agent_next = cast(str, structured["agent_next"])
    assert json.dumps(agent_next) in head
    assert '"action":"supply_missing_input"' in head
    for item in cast(list[dict[str, Any]], structured["missing_for_assessment"]):
        assert f"{item['kind']} for" in agent_next


def test_check_wire_order_puts_the_continuation_before_bulk() -> None:
    result = result_from_public_model(
        CheckResult.model_validate(_n7_shaped_wire()), host_profile="codex"
    )
    structured = result.structuredContent
    assert structured is not None
    keys = list(structured)
    assert keys.index("verdict") < keys.index("agent_next") < keys.index("overall_next")
    assert keys.index("overall_next") < keys.index("missing_for_assessment")
    assert keys.index("missing_for_assessment") < keys.index("findings")
    compact = json.dumps(structured, separators=(",", ":"), ensure_ascii=False)
    lead = compact.index('"agent_next":')
    assert lead + len(json.dumps(structured["agent_next"])) < 3_000


def test_cursor_canonical_copy_lists_agent_next_first_or_second() -> None:
    result = result_from_public_model(
        CheckResult.model_validate(_n7_shaped_wire()), host_profile="cursor"
    )
    # The text Cursor's model reads is the bridge's canonical JSON copy in ``content[0]``.
    (content,) = result.content
    assert content.type == "text"
    copy = json.loads(content.text)
    keys = list(copy)
    assert keys.index("agent_next") <= 1
    assert copy["agent_next"] == cast(dict[str, Any], result.structuredContent)["agent_next"]
    assert content.text.encode() == canonical_encode(cast(Any, result.structuredContent))
