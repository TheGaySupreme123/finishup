"""#966 (items 1 and 4): a privacy block names what stays unmet and the one safe continuation.

TB4 full-sol: the guidance told agents to publish a safe replacement and check once more, but the
refused bytes sat in items FinishUP composed itself (``task-input-NN``), which no agent can
replace. A block now says whether any agent action can help: only text the agent published can be
revised; for everything FinishUP composed or captured the required review honestly stays unmet,
with no retry and no local-only downgrade presented as review.
"""

from __future__ import annotations

from typing import cast

import pytest

from finishup.cli.render import render_semantic_outcome_recovery_lines
from finishup.domain.receipts import privacy_block_sentence
from finishup.kernel.closure_class import UNDELIVERABLE_SEMANTIC_STATUSES
from finishup.mcp.summaries import (
    _continuation_variants,  # pyright: ignore[reportPrivateUsage]
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.recovery import continuation_for_semantic_outcome, directive_for
from finishup.protocol.redacted_values import (
    SemanticRedactedValue,
    review_block_agent_revisable,
)


def _blocked(item_id: str) -> SemanticRedactedValue:
    return SemanticRedactedValue(
        item_id, "review_blocked", (), None, "reviewer_exchange", "heuristic"
    )


@pytest.mark.parametrize(
    ("item_ids", "revisable"),
    (
        (("claim-clm_10000000-0000-4000-8000-000000000001",), True),
        (("obligation-obl_10000000-0000-4000-8000-000000000001", "decision-1"), True),
        (("task-input-03",), False),
        (("change-check-time-001",), False),
        (("excerpt-evd_10000000-0000-4000-8000-000000000001",), False),
        (("review-packet",), False),
        (("claim-clm_10000000-0000-4000-8000-000000000001", "task-input-03"), False),
    ),
)
def test_only_text_the_agent_published_can_be_revised(
    item_ids: tuple[str, ...], revisable: bool
) -> None:
    values = tuple(_blocked(item_id) for item_id in sorted(item_ids, key=str.encode))
    assert review_block_agent_revisable(values) is revisable
    token = continuation_for_semantic_outcome(
        status=SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        reason=SemanticReason.NEVER_SEND_DETECTED,
        agent_revisable=revisable,
    )
    expected = "semantic_privacy_blocked" if revisable else "semantic_privacy_blocked_unrecoverable"
    assert token == expected
    directive = directive_for(token)
    assert directive is not None
    # Each says what stays unmet; only the revisable one offers a new check.
    assert "unmet" in directive.directive
    assert ("NEW request_id" in directive.directive) is revisable
    sentence = privacy_block_sentence(values)
    if revisable:
        assert "Only a revision of that published text without the value" in sentence
    else:
        assert "No agent action clears it: a required AI-powered review stays unmet." in sentence


def test_a_block_with_no_recorded_item_keeps_the_general_directive() -> None:
    assert review_block_agent_revisable(()) is None
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.BLOCKED_FORBIDDEN_DATA,
            reason=SemanticReason.NEVER_SEND_DETECTED,
        )
        == "semantic_privacy_blocked"
    )
    # Classification uncertainty is unchanged.
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.CLASSIFICATION_UNCERTAIN,
            reason=SemanticReason.CLASSIFICATION_UNCERTAIN,
            agent_revisable=False,
        )
        == "semantic_privacy_blocked"
    )


def test_the_check_renderings_name_the_unrecoverable_continuation() -> None:
    source: dict[str, JsonValue] = {
        "semantic_redacted_values": [cast(JsonValue, _blocked("task-input-03").as_wire())],
    }
    (long, short) = _continuation_variants("blocked_forbidden_data", "never_send_detected", source)
    assert short == "Continuation: semantic_privacy_blocked_unrecoverable."
    assert "Report the required review as unmet" in long
    lines = render_semantic_outcome_recovery_lines(
        status="blocked_forbidden_data", reason="never_send_detected", agent_revisable=False
    )
    assert any("semantic_privacy_blocked_unrecoverable" in line for line in lines)


def test_the_blocked_state_stays_undeliverable_never_a_local_only_success() -> None:
    """Item 4: with no safe recovery the review stays blocked; it never reads as run or skipped."""

    assert SemanticStatus.BLOCKED_FORBIDDEN_DATA in UNDELIVERABLE_SEMANTIC_STATUSES
    assert SemanticStatus.NOT_REQUESTED not in UNDELIVERABLE_SEMANTIC_STATUSES
