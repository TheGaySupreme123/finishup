"""The code-mode `check` cell deadline is repeated only when that capability was observed.

In tb4n5, 5 of 9 S attempts ran FinishUP-only `check` cells that yielded (no `yield_time_ms`, or
1,000 ms); the yielded `exec` cell landed after the check and made it stale in 6 of 9, bounding the
receipt in 3. The pragma lived only in `startup.md`. Issue #1079: the Stop gate repeats it when a
code-mode cell was positively observed (`code_mode=True`, or `check_cause.tool == "exec"`), not
because the host is Codex. The status sentence still repeats it for an `exec` cause only.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final

import pytest

from finishup.cli import closure_gate as gate
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.mcp import server as bridge
from finishup.protocol.readiness_text import (
    CODEX_CHECK_CELL_PRAGMA,
    CODEX_CHECK_YIELD_TIME_MS,
    check_cause_sentence,
)

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_DIGEST: Final = "sha256:" + "e" * 64
_TOKENS: Final = gate._GATE_TOKENS  # pyright: ignore[reportPrivateUsage]


def test_the_pragma_waits_past_the_bridge_check_deadline_and_is_the_startup_example() -> None:
    deadlines = bridge._DEFAULT_RPC_DEADLINES_MS  # pyright: ignore[reportPrivateUsage]
    host_limit = bridge._HOST_TOOL_CALL_LIMIT_MS  # pyright: ignore[reportPrivateUsage]
    # #1226: the cell outwaits the bridge's typed check timeout, and never the host's own limit.
    assert deadlines["check"] < CODEX_CHECK_YIELD_TIME_MS == host_limit
    assert CODEX_CHECK_CELL_PRAGMA == f'// @exec: {{"yield_time_ms": {CODEX_CHECK_YIELD_TIME_MS}}}'
    startup = (_REPO_ROOT / "guidance" / "startup.md").read_text(encoding="utf-8")
    assert re.search(rf"^{re.escape(CODEX_CHECK_CELL_PRAGMA)}$", startup, re.MULTILINE)


def _readiness(tokens: tuple[str, ...]) -> Any:
    return SimpleNamespace(
        state="action_required",
        agent_actionable=tokens,
        open_obligation_count="3",
        receipt_blocking_finding_count="2",
        limitation_refs_required=tuple(
            f"res_97700000-0000-4000-8000-{index:012d}" for index in range(5)
        ),
        limitation_refs_required_count="40",
    )


def test_the_observed_code_mode_close_instruction_survives_the_host_bound() -> None:
    """The longer cell sentence still fits; the host brand alone does not select it."""

    checked = 0
    for size in (1, 2, 3, len(_TOKENS) - 1, len(_TOKENS)):
        for tokens in itertools.combinations(_TOKENS, size):
            decision = closure_gate_from_readiness(
                _readiness(tokens),
                frontier_sequence="999999",
                frontier_digest=_DIGEST,
                observation_pending=False,
                code_mode=True,
            )
            assert decision is not None
            assert len(decision.text) <= 2000, tokens
            assert CODEX_CHECK_CELL_PRAGMA in decision.text, tokens
            assert gate._CLOSE_TEXT not in decision.text  # pyright: ignore[reportPrivateUsage]
            checked += 1
    assert checked > 100
    plain = closure_gate_from_readiness(
        _readiness(("closing_review_required",)),
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert plain is not None
    assert gate._CLOSE_TEXT in plain.text  # pyright: ignore[reportPrivateUsage]
    assert "yield_time_ms" not in plain.text


def test_without_a_recorded_cell_the_close_instruction_is_unchanged() -> None:
    # The gate takes no host since ADR-033 D1: the decision is the same on Codex, Claude Code and
    # Cursor, so no host brand can select the cell sentence.
    decision = closure_gate_from_readiness(
        _readiness(("closing_review_required",)),
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert decision is not None
    assert gate._CLOSE_TEXT in decision.text  # pyright: ignore[reportPrivateUsage]
    assert "yield_time_ms" not in decision.text


def test_an_exec_check_cause_selects_the_cell_instruction_on_any_host() -> None:
    readiness = _readiness(("closing_review_required",))
    readiness.check_cause = SimpleNamespace(tool="exec")
    decision = closure_gate_from_readiness(
        readiness,
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert decision is not None
    assert CODEX_CHECK_CELL_PRAGMA in decision.text
    shell = _readiness(("closing_review_required",))
    shell.check_cause = SimpleNamespace(tool="exec_command")
    decision = closure_gate_from_readiness(
        shell,
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert decision is not None
    assert "yield_time_ms" not in decision.text


@pytest.mark.parametrize("effect", ("superseded", "bounds_conclusion"))
@pytest.mark.parametrize("compact", (False, True))
def test_an_exec_check_cause_repeats_the_pragma_and_other_tools_do_not(
    effect: str, compact: bool
) -> None:
    def sentence(tool: str | None) -> str:
        return check_cause_sentence(
            effect=effect,
            event_id="evt_97700000-0000-4000-8000-000000000001",
            ledger_sequence=295,
            check_subject_frontier=290,
            family="observed_action",
            material_class="other",
            rule="unclassified_observed_action",
            tool=tool,
            compact=compact,
        )

    cell = sentence("exec")
    assert CODEX_CHECK_CELL_PRAGMA in cell
    assert cell.isascii()
    for tool in (None, "Bash", "Shell"):
        assert "yield_time_ms" not in sentence(tool)
