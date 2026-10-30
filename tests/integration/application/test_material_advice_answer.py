"""#1240 D1/D3: unanswered material advice caps the receipt; one answer lifts the cap.

The reviewer's strongest remaining check is material advice. While it has no recorded answer,
status predicts the cap (R11), announces one ``advice`` re-check, and the receipt Summary counts
it; ``kept_choice`` answers it. Driven through the real application on memory and SQLite.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from dataclasses import replace
from typing import Any, Literal, cast

import pytest

import integration.application.test_respond_status_receipt as h
from builders.start_application import protocol_id
from finishup.application.check import FinalSemanticEvaluation
from finishup.domain.receipts import ReceiptVersionSlice, SchemaVersionEntry
from finishup.kernel.correctness_advisories import correctness_advisories
from finishup.ports.semantic import RemainingCheck
from finishup.protocol.models import ReceiptRequest, RespondRequest, StatusRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_the_strongest_remaining_check_is_answered_once(
    backend: Literal["memory", "sqlite"],
) -> None:
    seed = 218400
    cited = protocol_id("res_", seed + 5)

    async def reviewer(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        del runtime, lineage_evaluation
        succeeded = cast(FinalSemanticEvaluation, await h._semantic_succeeds(frozen, findings))
        assert succeeded.judgment is not None
        judgment = replace(
            succeeded.judgment,
            strongest_remaining_check=RemainingCheck(
                "Run the rotated-receptacle placement case.", (cited,)
            ),
        )
        # The stub sends no packet text; the recorded disclosure names the cited result as sent,
        # so the production fence keeps the citation.
        sent = frozenset({cited})
        return replace(
            succeeded, judgment=judgment, case_included_refs=sent, case_citable_refs=sent
        )

    app, runtime, _ = h._build_app(
        semantic="required", ledger_backend=backend, semantic_evaluator=reviewer
    )

    def versions(_runtime: object) -> ReceiptVersionSlice:
        return replace(
            h._versions(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        )

    app = replace(app, receipt_version_resolver=versions)
    started, checked, _refs = await h._routine_advisory_task(app, seed=seed)
    ledger, _objects = runtime.resources[started.task_id]
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    notes = correctness_advisories(records)
    assert [note.concern.get("origin") for note in notes] == ["strongest_remaining_check"]
    note = notes[0].advisory_id

    async def readiness(serial: int) -> Any:
        status = await app.status(
            StatusRequest.model_validate(
                {
                    **h._request_base(protocol_id("req_", seed + serial)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            )
        )
        return status.closure_readiness

    async def receipt(serial: int, frontier: Any) -> dict[str, Any]:
        built = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **h._receipt_wire(
                        request_seed=seed + serial,
                        task_id=started.task_id,
                        session=started.session_id,
                        writer=started.writer_id,
                        frontier=frontier,
                    ),
                    "format": "markdown",
                    "include": "summary",
                }
            )
        )
        return dict(built.as_json())

    before = await readiness(20)
    reasons = {reason.code: reason for reason in before.predicted_receipt.reasons}
    assert reasons["advice_unanswered"].count == "1"
    assert before.predicted_receipt.conclusion != "no_unresolved_deterministic_findings"
    (advice,) = (item for item in before.rechecks if item.kind == "advice")
    assert advice.rule == "material_advice_unanswered"
    assert advice.subjects == (note.split(":")[0],)
    built = await receipt(21, checked.result_frontier)
    text = str(built)
    assert "Reviewer notes: 1; not answered: 1 (1 material)." in text
    # #1240 D5: the reply asks the agent to tell the user the conclusion and the open note.
    assert built["agent_closing_prompt"] == (
        f"Tell the user in your final message: receipt conclusion {built['conclusion']}; "
        "reviewer notes: 1, not answered: 1, declined: 0; "
        "name each note not answered or declined."
    )

    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", seed + 22)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(checked.result_frontier),
                "finding_id": note,
                "finding_frontier": h._frontier(checked.result_frontier),
                "disposition": "kept_choice",
                "reason": "The upright case covers the requirement; rotation is out of scope.",
            }
        )
    )
    assert answered.response.disposition == "kept_choice"
    after = await readiness(23)
    assert "advice_unanswered" not in {reason.code for reason in after.predicted_receipt.reasons}
    assert not any(item.kind == "advice" for item in after.rechecks or ())
    built = await receipt(24, answered.result_frontier)
    text = str(built)
    assert "Reviewer notes: 1; not answered: 0; answered: 1 kept my choice." in text
    assert built["agent_closing_prompt"] == (
        f"Tell the user in your final message: receipt conclusion {built['conclusion']}; "
        "reviewer notes: 1, not answered: 0, declined: 0."
    )
    assert "checked, kept my choice (agent-reported, with reason)" in text

    # A later answer replaces the shown one: a declined note is named by count, too.
    declined = await app.respond(
        RespondRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", seed + 25)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(answered.result_frontier),
                "finding_id": note,
                "finding_frontier": h._frontier(answered.result_frontier),
                "disposition": "declined",
                "reason": "Rotation is out of scope for this task.",
            }
        )
    )
    built = await receipt(26, declined.result_frontier)
    assert "answered: 1 declined." in str(built)
    assert built["agent_closing_prompt"] == (
        f"Tell the user in your final message: receipt conclusion {built['conclusion']}; "
        "reviewer notes: 1, not answered: 0, declined: 1; "
        "name each note not answered or declined."
    )
