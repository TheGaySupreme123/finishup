"""DET-2: trusted indirect writes must invalidate earlier verification."""

# pyright: reportPrivateUsage=false

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import ClaimKind, ClaimRecordedPayload, EventSchema, ResultOutcome
from finishup.domain.values import claim_id
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key, task_fact_signals

VERIFICATION_RERUN_QUESTION_GAP = "verification_rerun_question"


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def test_indirect_changed_workspace_cannot_keep_prior_test_fresh() -> None:
    ledger = ObservedLedger()
    ledger.plan("python -m unittest -q")
    ledger.edit(write_scope="workspace")
    tested = ledger.passes("python -m unittest -q")
    ledger.run(
        "python modify.py", ResultOutcome.SUCCESS, runner="other", workspace_effect="changed"
    )
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000000992"),
            ClaimKind.COMPLETION,
            "The final code passed the test",
            (tested,),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    facts = task_fact_signals(state, ledger.prefix)
    case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
    assert "verification_rerun_question" in facts.codes
    assert "verification_rerun_question" in facts.codes
    assert not _uncorroborated_completion_findings(case)


@pytest.mark.parametrize(
    ("effect", "scopes", "stale"),
    [
        ("changed", ("workspace",), True),
        ("changed", ("docs",), False),
        ("changed", ("notes",), False),
        ("changed", ("scratch",), False),
        ("changed", ("yoetz_owned",), False),
        ("changed", ("docs", "notes"), False),
        ("changed", ("docs", "workspace"), True),
        ("changed", (), False),
        ("changed", None, True),
        ("unavailable", None, True),
        ("unavailable", ("docs",), True),
        ("unchanged", None, False),
    ],
)
@pytest.mark.parametrize("annotation", [False, True])
def test_actual_workspace_classes_control_both_freshness_consumers(
    effect: str, scopes: tuple[str, ...] | None, stale: bool, annotation: bool
) -> None:
    from finishup.kernel.deterministic_checks import (
        deterministic_case_from_json,
        deterministic_case_to_json,
    )

    ledger = ObservedLedger()
    ledger.plan("python -m unittest -q")
    tested = ledger.passes("python -m unittest -q")
    result = ledger.run(
        "python modify.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect=None if annotation else effect,
        workspace_write_scopes=None if annotation else scopes,
    )
    if annotation:
        ledger.annotate_workspace_effect(result, effect, scopes=scopes)
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000000992"),
            ClaimKind.COMPLETION,
            "The final code passed the test",
            (tested,),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    facts = task_fact_signals(state, ledger.prefix)
    assert ("verification_rerun_question" in facts.codes) is stale
    assert ("verification_rerun_question" in facts.codes) is stale
    case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
    assert not _uncorroborated_completion_findings(case)
    restored = deterministic_case_from_json(deterministic_case_to_json(case))
    assert restored == case
    assert not _uncorroborated_completion_findings(restored)
    ledger.passes("python -m unittest -q")
    assert (
        "verification_rerun_question"
        not in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


@pytest.mark.parametrize("observed", [False, True])
def test_only_service_observation_can_stale_verification(observed: bool) -> None:
    ledger = ObservedLedger()
    ledger.plan("python -m unittest -q")
    ledger.passes("python -m unittest -q")
    ledger.run(
        "python modify.py",
        ResultOutcome.SUCCESS,
        runner="other",
        observed=observed,
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
    )
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert ("verification_rerun_question" in facts.codes) is observed


def test_code_change_wins_over_later_exempt_duplicate() -> None:
    ledger = ObservedLedger()
    ledger.plan("python -m unittest -q")
    ledger.passes("python -m unittest -q")
    result = ledger.run(
        "python modify.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
    )
    ledger.annotate_workspace_effect(result, "changed", scopes=("docs",))
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


@pytest.mark.parametrize(
    "scope,path",
    [
        ("docs", "README.md"),
        ("notes", "run.log"),
        ("notes", "build/generated.py"),
        ("yoetz_owned", "finishup_receipt.md"),
        ("scratch", "/tmp/delivered.py"),
    ],
)
@pytest.mark.parametrize("output", [True, False])
def test_declared_output_precedence_applies_to_actual_changed_classes(
    scope: str, path: str, output: bool
) -> None:
    from finishup.domain.events import (
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )
    from finishup.domain.values import obligation_id

    ledger = ObservedLedger()
    obligation = obligation_id("obl_00000000-0000-4000-8000-000000000001")
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Deliver",
            evidence_expectation="Tests",
            status=ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.COMMAND, "python -m unittest -q"),
                RequestedItem(
                    RequestedItemKind.FILE,
                    path,
                    role=RequestedItemRole.OUTPUT if output else RequestedItemRole.INPUT,
                ),
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Deliver", (obligation,)),
        observed=False,
    )
    ledger.passes("python -m unittest -q")
    ledger.run(
        "python modify.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_write_scopes=(scope,),
    )
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    ) is True
