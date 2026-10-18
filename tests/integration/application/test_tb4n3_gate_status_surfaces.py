"""The Stop gate, status and closure_prepare answer the same question (tb4n3 RC-8, ADR-033 D1).

Producer to consumers through the real application: a task whose obligation is resolved and
claimed on self-asserted evidence (the bandit B shape of ``test_closure_readiness_checklist``)
reads ``ready_with_limitations`` ("Nothing further to do"). Before D1 it announced the acceptance
re-read and the Stop gate asked it. Since D1 status announces no re-check here: it names the
acceptance-provenance risk once, as a receipt coverage limit (``closure_readiness.acceptance_risk``
and the standing ``unresolved_verification_limitation``), closure_prepare's notes say the same
sentence, and the Stop gate lets the agent stop. An honest downgrade of that resolved obligation
to ``acknowledged_not_done`` is not re-checked (replay-derived), while an acknowledgement of work
never claimed still is, once.
"""

from __future__ import annotations

from typing import Literal

import pytest

from finishup.cli.closure_gate import (
    ACKNOWLEDGEMENT_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from finishup.domain.closure import recheck_note
from finishup.protocol.readiness_text import acceptance_risk_note, readiness_directive
from integration.application.test_closure_readiness_checklist import (
    _bandit_b,  # pyright: ignore[reportPrivateUsage]
    _wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "d" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _gate(readiness: object, sequence: str, memory: frozenset[str], *, active: bool = False):  # noqa: ANN202
    return closure_gate_from_readiness(
        readiness,
        frontier_sequence=sequence,
        frontier_digest=_DIGEST,
        observation_pending=False,
        reasked_blockers=memory,
        active_stop=active,
    )


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_status_names_acceptance_provenance_once_and_the_gate_lets_the_agent_stop(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, _checked = await _bandit_b(ledger_backend)
    status = _wire(await session.status())
    readiness = status.closure_readiness
    assert readiness.state == "ready_with_limitations"
    # The status directive is the owner-approved sentence: nothing further to do.
    assert readiness.standing_limitations is not None
    assert readiness.acknowledged_not_done_count is not None
    directive = readiness_directive(
        readiness.state,
        standing=len(readiness.standing_limitations),
        acknowledged=int(readiness.acknowledged_not_done_count),
    )
    assert directive.startswith("Nothing further to do.")

    # No re-check is announced: acceptance provenance is a coverage limit, not a Stop item.
    assert readiness.rechecks is not None
    assert [item.kind for item in readiness.rechecks] == []
    assert recheck_note(readiness) is None
    assert readiness.admissible_verification is None
    assert readiness.acceptance_risk is not None
    (row,) = readiness.acceptance_risk
    assert row.reasons == ("evidence_self_asserted_only",)
    assert "unresolved_verification_limitation" in readiness.standing_limitations
    note = acceptance_risk_note(readiness)
    assert note.startswith("Acceptance provenance (a receipt coverage limit, not a Stop item):")
    assert str(row.obligation_id) in note

    sequence = status.head_frontier.sequence
    for active in (False, True):
        assert _gate(readiness, sequence, frozenset(), active=active) is None


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_an_honest_downgrade_is_not_rechecked_and_a_never_claimed_acknowledgement_is(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, _checked = await _bandit_b(ledger_backend)
    first = _wire(await session.status()).closure_readiness
    assert first.acceptance_risk is not None
    (row,) = first.acceptance_risk
    resolved = str(row.obligation_id)

    # The agent's output does not meet the resolved obligation's criteria: it republishes that
    # obligation acknowledged_not_done (the downgrade the status note offers), and acknowledges
    # an optional obligation it never claimed.
    downgrade = session.draft(
        "obligation_published",
        {
            "obligation_id": resolved,
            "description": "Add interprocedural taint checks.",
            "evidence_expectation": "The focused test run passes.",
            "status": "acknowledged_not_done",
            "acknowledged_not_done_reason": "The checks miss cross-module flows.",
        },
    )
    downgrade["schema"] = {"name": "obligation_published", "version": "1.1.0"}
    other = session.next("obl_")
    acknowledged = session.draft(
        "obligation_published",
        {
            "obligation_id": other,
            "description": "Optional polish.",
            "evidence_expectation": "Nothing further.",
            "status": "acknowledged_not_done",
            "acknowledged_not_done_reason": "Out of scope for this task.",
        },
    )
    acknowledged["schema"] = {"name": "obligation_published", "version": "1.1.0"}
    # The new obligation joins the plan (an unplanned obligation is not effective work).
    plan = session.draft(
        "plan_published",
        {
            "plan_version": 2,
            "summary": "Taint checks and polish",
            "obligation_refs": [resolved, other],
        },
    )
    await session.publish(downgrade, acknowledged, plan)
    after = _wire(await session.status())
    readiness = after.closure_readiness
    assert readiness.rechecks is not None
    # The downgrade is not challenged; the never-claimed acknowledgement is announced once.
    assert [item.key for item in readiness.rechecks] == [f"ack:{other}"]
    # Nothing resolved is flagged any more, so the coverage limit is gone too.
    assert readiness.acceptance_risk is None
    gate = _gate(readiness, after.head_frontier.sequence, frozenset())
    assert gate is not None
    assert gate.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)
    assert other in gate.text
    assert resolved not in gate.text
    assert _gate(readiness, after.head_frontier.sequence, frozenset(gate.blocker_keys)) is None
