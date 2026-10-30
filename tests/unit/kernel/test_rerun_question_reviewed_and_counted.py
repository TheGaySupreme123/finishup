"""#1241 D9: the reviewer judges rerun answers, and the question's cost is counted from the ledger."""

# pyright: reportPrivateUsage=false

import json
from collections.abc import Iterator
from typing import Any, cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.adapters.providers.openai_responses import normalize_judgment
from finishup.application.semantic_case import _local_answer_items
from finishup.domain.events import EventSchema, ResultOutcome
from finishup.domain.findings import Finding, ResponseDisposition
from finishup.domain.values import finding_id
from finishup.domain.workspace_effect import workspace_path_identity
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.policies.work_integrity import _verification_questions
from finishup.kernel.reducers import replay
from finishup.kernel.rerun_accounting import rerun_question_accounting
from finishup.kernel.task_facts import register_command_identity_key
from finishup.protocol.canonical import JsonValue

_QUESTION = finding_id("fnd_00000000-0000-4000-8000-000000001241")


@pytest.fixture(autouse=True)
def key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _answered(ledger: ObservedLedger) -> Finding:
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    ledger.run(
        "python update.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
        workspace_changed_entries=(workspace_path_identity(INSTALLATION_KEY, "build/out.txt"),),
    )
    case = build_deterministic_case(replay(ledger.prefix), ledger.prefix, CaseAvailabilityFacts())
    candidate = _verification_questions(case)[0].candidate
    finding = Finding(
        _QUESTION,
        candidate.kind,
        candidate.origin,
        candidate.priority,
        candidate.summary,
        candidate.detail,
        candidate.subject_refs,
        candidate.policy_id,
        candidate.policy_version,
        candidate.subject_frontier,
        candidate.coverage,
        candidate.provenance,
    )
    ledger.append(EventSchema("finding_recorded", "1.0.0"), finding, observed=False)
    ledger.respond(
        _QUESTION, ResponseDisposition.ACKNOWLEDGED, reason="Only the build output changed."
    )
    return finding


def test_a_freshness_answer_is_its_own_packet_row_type() -> None:
    ledger = ObservedLedger()
    _answered(ledger)
    projection = replay(ledger.prefix)
    rows = _local_answer_items(
        str(_QUESTION), projection.findings[_QUESTION], projection, include_prose=False
    )
    body = json.loads(rows[0].content)
    assert body["schema"] == "yoetz.freshness-answer/1"
    assert body["question"] == "verification_rerun"


def test_the_reviewer_says_whether_it_agrees_and_malformed_rows_cost_only_themselves() -> None:
    judgment: dict[str, Any] = {
        "conclusion": "no_material_discrepancy",
        "review_summary": "Weighed the rerun answers.",
        "prior_finding_verdicts": [],
        "reviewer_challenges": [],
        "verified": [],
        "strongest_remaining_check": None,
        "declared_test_verdicts": None,
        "freshness_verdicts": [
            {"finding_id": str(_QUESTION), "agrees": False},
            {"finding_id": str(_QUESTION), "agrees": True},
            {"finding_id": "not-a-finding", "agrees": True},
        ],
    }
    decoded = normalize_judgment(cast(JsonValue, {"judgment": judgment}), require_part2=True)
    assert [(row.finding_id, row.agrees) for row in decoded.freshness_verdicts] == [
        (str(_QUESTION), False)
    ]
    judgment["freshness_verdicts"] = None
    assert not normalize_judgment(
        cast(JsonValue, {"judgment": judgment}), require_part2=True
    ).freshness_verdicts


def test_reruns_after_an_answer_and_changed_results_are_derived_from_the_ledger() -> None:
    ledger = ObservedLedger()
    _answered(ledger)
    before = rerun_question_accounting(replay(ledger.prefix))
    assert (before.answered, before.reruns_after_answer, before.reruns_after_answer_changed) == (
        1,
        0,
        0,
    )
    ledger.run("pytest -q", ResultOutcome.FAILURE, exit_status=1, runner="test")
    after = rerun_question_accounting(replay(ledger.prefix))
    assert (after.answered, after.reruns_after_answer, after.reruns_after_answer_changed) == (
        1,
        1,
        1,
    )
