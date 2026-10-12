"""tb4n4 interleaved-vigenere S: a delivered file that loads an undeclared file blocks closure (#1044).

The agent delivered ``artifacts/cracker.py``, which loaded ``english_ngrams.npz`` and
``english_words.npz`` from beside itself, and declared only the cracker and its
``requirements.txt``. Yoetz's advice said "embed it, rebuild it at runtime, or disclose the
dependency"; the agent disclosed it and verified the cracker itself. The grader received only the
two declared files, the program printed nothing, and the reward was 0.

``deliverable_references_undeclared_file`` is now agent work on every surface: the check is not
clean, status lists it as agent-actionable and names the files, the Stop gate continues the agent
and names them, and the receipt (JSON, markdown, text) names them and reads below clean. A
disclosure decision does not clear it; declaring the files as delivered outputs, or a cracker that
no longer loads them, does. The workspace read itself is the adapter's (covered with a real
repository in ``tests/unit/adapters/test_deliverable_references_undeclared_file.py``); here it is
replaced by one that applies the same declaration rule, so the run drives the real check, status,
receipt and gate.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from builders.observed_runs import INSTALLATION_KEY
from builders.start_application import protocol_id
from integration.application import test_respond_status_receipt as h
from integration.closure.test_closure_shapes import (
    _INSUFFICIENT,
    _NO_FINDINGS,
    _begin,
    _obligation,
    _plan,
    _public,
    _Run,
    _surfaces,
    assert_surfaces_agree,
    receipt_artifact_1_3_0,  # noqa: F401  # pyright: ignore[reportUnusedImport] - autouse fixture
)
from yoetz.application import check_change
from yoetz.cli.closure_gate import closure_gate_from_readiness
from yoetz.domain.task_fact_tokens import DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
from yoetz.kernel.delivered_set import undeclared_reference_inputs
from yoetz.kernel.task_facts import RequestedOutputState, register_command_identity_key
from yoetz.mcp.summaries import summary_for_status

pytestmark = pytest.mark.anyio

_CODE = DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP
_CRACKER = "/app/artifacts/cracker.py"
_REQUIREMENTS = "/app/artifacts/requirements.txt"
_MODELS = ("artifacts/english_ngrams.npz", "artifacts/english_words.npz")
_OBLIGATION = protocol_id("obl_", 7001)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Workspace:
    """What the cracker on disk does; ``False`` once it embeds or rebuilds its tables."""

    loads_models: bool = True


def _items(*models: str) -> list[Any]:
    return [
        {"item_kind": "file", "value": value, "role": "output"}
        for value in (_CRACKER, _REQUIREMENTS, *(f"/app/{model}" for model in models))
    ]


async def _vigenere_run(monkeypatch: pytest.MonkeyPatch, seed: int) -> tuple[_Run, _Workspace]:
    """The cracker obligation resolved and claimed with only the cracker and requirements declared.

    The reviewer approves (``semantic_if_configured`` with a review that raises nothing), so the
    undeclared dependency is the only thing between the run and a clean receipt.
    """

    workspace = _Workspace()

    async def states(**kwargs: Any) -> dict[tuple[object, int], RequestedOutputState]:
        projection = kwargs["projection"]
        found: dict[tuple[object, int], RequestedOutputState] = {}
        for obligation, record in projection.obligations.items():
            if record.payload is None:
                continue
            for index, item in enumerate(record.payload.requested_items):
                found[(obligation, index)] = RequestedOutputState(
                    "inside",
                    exists=True,
                    changed=True,
                    size_bytes=4_096,
                    lines=120,
                    relative=item.value.removeprefix("/app/"),
                )
        return found

    async def references(**kwargs: Any) -> tuple[tuple[str, str], ...]:
        # The adapter's rule: a created file counts unless any requested file item declares it.
        if not workspace.loads_models:
            return ()
        deliverables, declared = undeclared_reference_inputs(
            kwargs["projection"], kwargs["states"], blocked=kwargs["blocked"]
        )
        if _CRACKER not in deliverables:
            return ()
        named = {value.removeprefix("/app/") for value in declared}
        return tuple(("artifacts/cracker.py", model) for model in _MODELS if model not in named)

    async def approves(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        return await h._semantic_succeeds(frozen, findings)

    monkeypatch.setattr(check_change, "requested_output_states", states)
    monkeypatch.setattr(check_change, "undeclared_references", references)
    register_command_identity_key(INSTALLATION_KEY)
    run = await _begin(seed=seed, semantic="optional", evaluator=approves)
    evidence = protocol_id("evd_", 7301)
    await run.publish(
        _obligation(run, 1, requested_items=_items()),
        _plan(run, 1),
        run.draft(
            "action_recorded",
            {
                "action_id": protocol_id("act_", 7101),
                "action_kind": "other",
                "description": "Wrote the cracker and its frequency models",
                "obligation_refs": [_OBLIGATION],
                "attempted_items": [_CRACKER, _REQUIREMENTS],
            },
        ),
        run.draft(
            "result_recorded",
            {
                "result_id": protocol_id("res_", 7400),
                "action_id": protocol_id("act_", 7101),
                "outcome": "success",
                "summary": "The cracker recovers the sample plaintexts.",
            },
        ),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The cracker recovered every sample plaintext.",
            },
        ),
        _obligation(
            run, 1, status="resolved", resolution_evidence_refs=[evidence], requested_items=_items()
        ),
        run.draft(
            "claim_recorded",
            {
                "claim_id": protocol_id("clm_", 7201),
                "claim_kind": "completion",
                "statement": "The cracker is delivered.",
                "supporting_refs": [evidence],
                "obligation_refs": [_OBLIGATION],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    return run, workspace


async def _declare_models(run: _Run, *models: str) -> None:
    """Declare model files as delivered outputs: a new obligation the restated plan names.

    A resolved obligation's requested items cannot change in place (its meaning fields repeat), so
    the honest way to add delivered files is an obligation of their own in the next plan version.
    """

    await run.publish(
        run.draft(
            "obligation_published",
            {
                "obligation_id": protocol_id("obl_", 7002),
                "description": "Deliver the cracker's frequency models beside it",
                "acceptance_criteria": "The models ship with the cracker.",
                "evidence_expectation": "The files are in the delivery.",
                "status": "open",
                "requested_items": [
                    {"item_kind": "file", "value": f"/app/{model}", "role": "output"}
                    for model in models
                ],
            },
        )
        | {"schema": {"name": "obligation_published", "version": "1.1.0"}},
        run.draft(
            "plan_published",
            {
                "plan_version": 2,
                "summary": "The cracker and its models",
                "obligation_refs": [_OBLIGATION, protocol_id("obl_", 7002)],
            },
        ),
    )


def _gate(readiness: Any) -> Any:
    return closure_gate_from_readiness(
        readiness, frontier_sequence="9", frontier_digest="d", observation_pending=False
    )


async def test_vigenere_undeclared_models_block_closure_and_are_named_everywhere(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        run, _workspace = await _vigenere_run(monkeypatch, 82)
        checked = await run.check_in("semantic_if_configured")
        assert _CODE in checked.coverage.known_gaps
        assert checked.verdict.value != "no_issue_detected"

        gathered = await _surfaces(run)
        status = gathered.status["compact"]
        readiness = status.closure_readiness
        assert readiness.state == "action_required"
        assert _CODE in (readiness.agent_actionable or ())
        assert _CODE not in (readiness.standing_limitations or ())
        assert readiness.undeclared_references is not None
        (named,) = readiness.undeclared_references
        assert (named.obligation_id, named.item_index, named.paths, named.total) == (
            _OBLIGATION,
            "0",
            _MODELS,
            "2",
        )
        # The one verdict: every surface reads below clean for the same reason set.
        assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=_NO_FINDINGS)
        # The MCP text summary names no path (honesty rule: no user-controlled text there).
        assert "english_ngrams" not in summary_for_status(status.as_json())

        # The receipt names both files, in every format.
        for fmt, receipt in gathered.receipts.items():
            text = (
                str(receipt.document) if receipt.document is not None else str(receipt.human_text)
            )
            assert '"artifacts/english_ngrams.npz"' in text.replace("\\", ""), fmt
            assert '"artifacts/english_words.npz"' in text.replace("\\", ""), fmt
            assert "disclose the dependency." not in text, fmt
        document = gathered.receipts["json"].document
        (row,) = [gap for gap in document["gaps"] if gap["code"] == _CODE]
        assert row["effect"] == "bounds"
        assert f'{_OBLIGATION} item 0 names "artifacts/english_ngrams.npz"' in row["detail"]

        # The Stop gate continues the agent and names the files.
        gate = _gate(_public(status).closure_readiness)
        assert gate is not None
        assert _CODE in gate.items
        assert '"artifacts/english_ngrams.npz" and "artifacts/english_words.npz"' in gate.text
        assert "disclosing the dependency does not clear this" in gate.text
    finally:
        register_command_identity_key(None)


async def test_a_disclosure_does_not_clear_it_and_declaring_or_embedding_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        run, workspace = await _vigenere_run(monkeypatch, 83)
        await run.check_in("semantic_if_configured")

        # "Disclose the dependency": the agent's choice in the recorded run. It changes nothing.
        await run.publish(
            run.draft(
                "decision_recorded",
                {
                    "statement": (
                        "The cracker loads english_ngrams.npz and english_words.npz from its own"
                        f" directory.\nyoetz-assumption:{_OBLIGATION}\n"
                        f"yoetz-verification-limit:{_OBLIGATION}"
                    ),
                    "rationale": "Disclosing the model dependency of the cracker.",
                    "authority": "harness:codex",
                    "affected_obligation_ids": [_OBLIGATION],
                },
            )
        )
        disclosed = await run.check_in("semantic_if_configured")
        assert _CODE in disclosed.coverage.known_gaps
        status = await run.status("compact")
        assert _CODE in (status.closure_readiness.agent_actionable or ())
        assert _gate(_public(status).closure_readiness) is not None

        # Declaring one model as a delivered output leaves the other one named.
        await _declare_models(run, _MODELS[0])
        partly = await run.check_in("semantic_if_configured")
        assert _CODE in partly.coverage.known_gaps
        status = await run.status("compact")
        assert status.closure_readiness.undeclared_references is not None
        (named,) = status.closure_readiness.undeclared_references
        assert named.paths == (_MODELS[1],)

        # A cracker that rebuilds its tables at run time names no undeclared file: cleared.
        workspace.loads_models = False
        cleared = await run.check_in("semantic_if_configured")
        assert _CODE not in cleared.coverage.known_gaps
        status = await run.status("compact")
        assert _CODE not in (status.closure_readiness.agent_actionable or ())
        assert status.closure_readiness.undeclared_references is None
    finally:
        register_command_identity_key(None)


async def test_declaring_every_model_as_a_delivered_output_clears_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        run, _workspace = await _vigenere_run(monkeypatch, 84)
        await run.check_in("semantic_if_configured")
        await _declare_models(run, *_MODELS)
        checked = await run.check_in("semantic_if_configured")
        assert _CODE not in checked.coverage.known_gaps
        status = await run.status("compact")
        assert _CODE not in (status.closure_readiness.agent_actionable or ())
        assert status.closure_readiness.undeclared_references is None
    finally:
        register_command_identity_key(None)
