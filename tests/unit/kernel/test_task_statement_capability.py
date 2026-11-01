"""Which ledger events count as able to have given a reviewer the task statement (issue #908).

The pre-statement resolution fallback lets an AI-powered finding raised before any review could
have held the user's request clear on a later review that also lacked it. A ``session_opened``
1.2.0 event may carry a statement, but a lineage-only child opens on that version without one, so
the envelope alone overstates what the ledger held. A readable payload decides; a payload the
ledger can no longer read (redacted, key unavailable) still counts, so a later redaction never
makes a review that held the statement look as though it predates it.
"""

from __future__ import annotations

import pytest

from builders.replay import genesis_session_opened, genesis_session_opened_variant
from finishup.domain.events import RedactionState
from finishup.domain.task_statement import may_carry_task_statement
from finishup.kernel.finding_resolution import first_task_statement_sequence_of
from finishup.kernel.reducers import empty_replay_index, extend_replay_index

_STATEMENT = "Under Ascii, Style.Truncate returns plain text without tail."


def test_a_released_open_cannot_carry_a_statement() -> None:
    assert may_carry_task_statement(genesis_session_opened()) is False


@pytest.mark.parametrize(
    ("statement", "redaction", "capable"),
    [
        # A readable payload proves the event carried no statement.
        (None, RedactionState.PRESENT, False),
        (_STATEMENT, RedactionState.PRESENT, True),
        # A payload the ledger cannot read may have carried one.
        (_STATEMENT, RedactionState.LOGICALLY_REDACTED, True),
        (None, RedactionState.KEY_UNAVAILABLE, True),
    ],
)
def test_only_a_readable_payload_without_a_statement_is_excluded(
    statement: str | None, redaction: RedactionState, capable: bool
) -> None:
    record = genesis_session_opened_variant(
        version="1.2.0", statement=statement, redaction=redaction
    )
    assert may_carry_task_statement(record) is capable


def test_a_lineage_only_open_does_not_start_the_statement_frontier() -> None:
    """942-G2: a statement-less 1.2.0 open leaves pre-statement findings recognizable."""

    without = genesis_session_opened_variant(version="1.2.0", statement=None)
    with_statement = genesis_session_opened_variant(version="1.2.0", statement=_STATEMENT)

    assert extend_replay_index(empty_replay_index(), without).first_task_statement_sequence is None
    assert first_task_statement_sequence_of((without,)) is None
    assert (
        extend_replay_index(empty_replay_index(), with_statement).first_task_statement_sequence == 1
    )
    assert first_task_statement_sequence_of((with_statement,)) == 1
