"""The Stop gate, status and closure_prepare answer the same question (tb4n3 RC-8, #1031).

Producer to consumers through the real application: a task whose obligation is resolved and
claimed (the bandit B shape of ``test_closure_readiness_checklist``) reads
``ready_with_limitations`` ("Nothing further to do") and announces exactly one re-check, the
acceptance re-read of the resolved obligation, in ``closure_readiness.rechecks``. The Stop gate
asks that and nothing else, closure_prepare's notes name it, and an obligation the agent then
acknowledges after the invite was delivered is announced by status but, being the answer to the
invite, is not challenged. Before this change the gate asked nothing here (the re-read rode on
other tokens) and the status line promised nothing.
"""

from __future__ import annotations

from typing import Literal

import pytest

from integration.application.test_closure_readiness_checklist import (
    _bandit_b,  # pyright: ignore[reportPrivateUsage]
    _wire,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.cli.closure_gate import (
    ACCEPTANCE_RECHECK_ITEM,
    ACKNOWLEDGEMENT_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from yoetz.domain.closure import recheck_note
from yoetz.protocol.models import StatusClosureReadinessModel
from yoetz.protocol.readiness_text import readiness_directive

pytestmark = [
    pytest.mark.anyio,
    # The status wire that carries ``rechecks`` is W2-A's lane and merges before this one; this
    # lane's branch alone has no producer to ask, so the test runs from the merge onward.
    pytest.mark.skipif(
        "rechecks" not in StatusClosureReadinessModel.model_fields,
        reason="closure_readiness.rechecks is produced by the W2-A status wire",
    ),
]

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
async def test_status_closure_prepare_and_the_gate_name_the_same_rechecks(
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

    # ... and it announces the one re-check the Stop will ask.
    assert readiness.rechecks is not None
    assert [item.kind for item in readiness.rechecks] == ["acceptance"]
    announced = readiness.rechecks[0]
    assert announced.key.startswith("accept:")

    # closure_prepare names it; the Stop gate asks exactly it, once.
    note = recheck_note(readiness)
    assert note is not None and "acceptance criteria" in note
    sequence = status.head_frontier.sequence
    gate = _gate(readiness, sequence, frozenset())
    assert gate is not None
    assert gate.items == (ACCEPTANCE_RECHECK_ITEM,)
    assert gate.blocker_keys == (f"{announced.key}@{sequence}",)
    assert "acceptance_criteria" in gate.text
    assert _gate(readiness, sequence, frozenset(gate.blocker_keys)) is None
    assert _gate(readiness, sequence, frozenset(gate.blocker_keys), active=True) is None


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_an_acknowledgement_published_after_the_invite_is_announced_but_not_challenged(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, _checked = await _bandit_b(ledger_backend)
    first = _wire(await session.status()).closure_readiness
    sequence = _wire(await session.status()).head_frontier.sequence
    invite = _gate(first, sequence, frozenset())
    assert invite is not None
    memory = frozenset(invite.blocker_keys)

    # The agent answers the invite by acknowledging an obligation it did not do.
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
    assert first.rechecks is not None
    # The new obligation joins the plan (an unplanned obligation is not effective work).
    plan = session.draft(
        "plan_published",
        {
            "plan_version": 2,
            "summary": "Taint checks and polish",
            "obligation_refs": [*first.rechecks[0].subjects, other],
        },
    )
    await session.publish(acknowledged, plan)
    after = _wire(await session.status())
    readiness = after.closure_readiness
    assert readiness.rechecks is not None
    kinds = {item.kind for item in readiness.rechecks}
    assert kinds == {"acceptance", "acknowledgement"}
    ack = next(item for item in readiness.rechecks if item.kind == "acknowledgement")
    assert ack.key == f"ack:{other}"
    # Status announces it (honestly: it is an acknowledged obligation) ...
    assert int(ack.since_frontier) > int(sequence)
    # ... but it answers the invite the gate already delivered, so the Stop does not challenge it.
    assert _gate(readiness, after.head_frontier.sequence, memory) is None
    assert _gate(readiness, after.head_frontier.sequence, memory, active=True) is None
    # Without the invite in memory, the same acknowledgement is asked once (the pretrain S rescue).
    challenged = _gate(readiness, after.head_frontier.sequence, frozenset())
    assert challenged is not None
    assert ACKNOWLEDGEMENT_RECHECK_ITEM in challenged.items
    assert other in challenged.text
