"""#1118: a large but legal case plans its reviewer conversation under the disclosure cap.

A benchmark smoke ended four reviews ``coordinator_failure`` at ``finishup.ports.privacy:529``: the
packet fit the planner's estimate (the ceiling less 8 KiB, less a fifth for escaping), but the first
exchange (the loop instruction, the packet as a JSON string, the read catalog) came to more than the
262,144 bytes one ``MinimizedDisclosure`` may carry, whether the excerpts were diff parts or
captured output alone under the excerpt budget. Building that disclosure raised inside the privacy
coordinator.

These tests drive the real service evaluator, composition, ceiling planning, privacy coordinator
and reviewer conversation over a durable job, with the real setup ceilings. Only the provider is
scripted; no model, network or credential is used.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.service.ready_composition as ready_composition_module
from builders.privacy_policies import minimal_external_policy
from finishup.adapters.privacy.local_enforcer import estimated_token_count
from finishup.application.reviewer_run import reviewer_first_exchange
from finishup.domain.events import EvidenceKind
from finishup.domain.privacy import (
    EgressChannel,
    PrivacyPolicy,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import MAX_MINIMIZED_DISCLOSURE_BYTES
from finishup.ports.semantic import ReviewerMessage, encode_reviewer_exchange
from finishup.protocol.models import SemanticStatus
from integration.service.test_reviewer_conversation_composition import (
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _run,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case_packet_completeness import (
    _change,  # pyright: ignore[reportPrivateUsage]
    _react_case,  # pyright: ignore[reportPrivateUsage]
    _with_evidence,  # pyright: ignore[reportPrivateUsage]
)

# The setup's LLM channel ceilings (``cli/privacy_setup._CASE_MAX_BYTES``/``_CASE_MAX_TOKENS``).
_CEILING = 256 * 1024


def _code_diff(files: int, lines: int) -> bytes:
    """Ordinary Python edits whose quotes and backslashes JSON escapes twice in the conversation."""

    out: list[bytes] = []
    for index in range(files):
        out.append(f"diff --git a/pkg/mod{index}.py b/pkg/mod{index}.py\n".encode())
        for line in range(lines):
            out.append(
                (
                    f'+    row = {{"id": "{index}-{line}", "path": "C:\\\\data\\\\{line}", '
                    f'"label": "say \\"ok\\""}}\n'
                ).encode()
            )
    return b"".join(out)


def _tool_output(outputs: int) -> tuple[tuple[EvidenceKind, str], ...]:
    """Agent-published command output, JSON log lines: excerpts with no diff part at all."""

    line = '{"level": "info", "msg": "row \\"%d\\" ok", "path": "C:\\\\run\\\\%d"}\n'
    return tuple(
        (EvidenceKind.COMMAND_OUTPUT, "".join(line % (i, n) for n in range(110))[:8000])
        for i in range(outputs)
    )


def _expanded_policy() -> PrivacyPolicy:
    base = minimal_external_policy()
    channels = tuple(
        replace(channel, max_bytes=_CEILING, max_tokens=estimated_token_count(_CEILING))
        if channel.channel is EgressChannel.LLM_INFERENCE
        else channel
        for channel in base.channel_policies
    )
    return replace(
        base,
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        channel_policies=channels,
    )


def _composed(
    monkeypatch: pytest.MonkeyPatch, *, diff: bytes | None, outputs: int = 0
) -> list[Any]:
    """Compose the real case over a linked work record with a check-time change of ``diff`` (none
    when ``None``) and ``outputs`` captured command outputs; return each case built."""

    real = ready_composition_module.build_semantic_case
    frozen = _with_evidence(_react_case(), *_tool_output(outputs)) if outputs else _react_case()
    built: list[Any] = []

    def build(**kwargs: Any) -> Any:  # noqa: ANN401
        change = None if diff is None else _change(diff)
        options: dict[str, Any] = {**kwargs, "frozen_case": frozen, "check_time_change": change}
        case = real(**options)
        built.append(case)
        return case

    monkeypatch.setattr(ready_composition_module, "build_semantic_case", build)
    return built


def _encoded(history: tuple[tuple[str, str], ...]) -> bytes:
    return encode_reviewer_exchange(cast(tuple[ReviewerMessage, ...], history))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("diff", "outputs"),
    (
        # Eight diff parts of quoted code fill the 131,072-byte excerpt budget.
        (_code_diff(files=8, lines=400), 0),
        # No diff part: captured JSON tool output alone, under the excerpt budget.
        (None, 16),
    ),
    ids=("diff_parts", "captured_output_only"),
)
async def test_a_case_filling_the_excerpt_budget_is_reviewed_within_the_disclosure_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diff: bytes | None, outputs: int
) -> None:
    built = _composed(monkeypatch, diff=diff, outputs=outputs)
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    # Not a coordinator failure: the review ran and concluded.
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    # The exact first exchange the provider received fits the cap one disclosure carries.
    assert len(_encoded(history)) <= MAX_MINIMIZED_DISCLOSURE_BYTES
    # Planning measured these same bytes: the renderer it uses is the one the exchange was sent in.
    assert reviewer_first_exchange(history[1][1].encode(), history[2][1]) == _encoded(history)
    # The full selection did not fit, so planning narrowed it and the packet says so.
    approved, planned = built[0], built[-1]
    assert sum(i.content_bytes for i in planned.items if i.section == "excerpt") < sum(
        i.content_bytes for i in approved.items if i.section == "excerpt"
    )
    packet = json.loads(history[1][1])
    assert "content_unselected" in packet["review_packet"]["coverage"]["known_gaps"]


@pytest.mark.anyio
async def test_an_exchange_over_the_disclosure_cap_is_refused_typed_and_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the rendered conversation still outgrows the cap, nothing is sent and the review ends
    blocked by policy, never as a coordinator failure."""

    import finishup.application.reviewer_run as reviewer_run_module

    _composed(monkeypatch, diff=_code_diff(files=1, lines=20))
    real_catalog = reviewer_run_module.reviewer_catalog

    def oversize_catalog(roots: Any, reads: int) -> str:  # noqa: ANN401
        body = json.loads(real_catalog(roots, reads))
        body["reviewer_catalog"]["padding"] = "x" * MAX_MINIMIZED_DISCLOSURE_BYTES
        return json.dumps(body)

    monkeypatch.setattr(reviewer_run_module, "reviewer_catalog", oversize_catalog)
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    assert gateway.exchanges == []
    assert result.status is SemanticStatus.BLOCKED_BY_POLICY, (result.status, result.reason)
