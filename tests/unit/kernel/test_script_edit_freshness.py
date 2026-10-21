"""DET-2: trusted indirect writes must invalidate earlier verification."""

# pyright: reportPrivateUsage=false

import json
from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
)
from finishup.domain.values import ResultId, claim_id, evidence_id, timestamp_from_string
from finishup.domain.workspace_effect import workspace_path_identity
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key, task_fact_signals
from finishup.protocol.coverage import EvidenceImmutability


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _declare_inputs(ledger: ObservedLedger, run: ResultId, *inputs: str) -> None:
    """Record the per-run input declaration ADR-042 defines for *run*."""

    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000000992"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-21T12:00:00.000Z"),
            reference=f"finishup-verification-inputs/v1:{run}",
            description=json.dumps({"inputs": list(inputs), "outputs": [], "complete": True}),
        ),
        observed=False,
    )


@pytest.mark.parametrize("declared", [False, True])
def test_indirect_changed_workspace_cannot_keep_prior_test_fresh(declared: bool) -> None:
    """An indirect change keeps an earlier test fresh only when it provably misses its inputs.

    With the run's inputs declared and the changed path known, both freshness consumers agree the
    test is stale. With unknown inputs, both ask instead: a question, never a staleness assertion.
    """

    ledger = ObservedLedger()
    ledger.plan("python -m unittest -q")
    ledger.edit(write_scope="workspace")
    tested = ledger.passes("python -m unittest -q")
    if declared:
        _declare_inputs(ledger, tested, "app.py")
    ledger.run(
        "python modify.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_changed_entries=(
            (workspace_path_identity(INSTALLATION_KEY, "app.py"),) if declared else None
        ),
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
    assert ("verification_rerun_question" in facts.codes) is not declared
    assert ("edited_after_last_verification" in facts.codes) is declared
    assert ("planned_verification_stale" in facts.codes) is declared
    assert len(_uncorroborated_completion_findings(case)) == (1 if declared else 0)


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
    # No recorded input: the class decides whether to ask, never whether the test is stale.
    assert not {"edited_after_last_verification", "planned_verification_stale"} & set(facts.codes)
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
@pytest.mark.parametrize("named", [True, False])
def test_declared_output_precedence_applies_to_actual_changed_classes(
    scope: str, path: str, output: bool, named: bool
) -> None:
    """A declared output overrides its class exemption; a declared input changed is stale.

    The change writes exactly *path*. As a declared output it still counts (no exempt class hides
    a delivery) but is not a verification input, so it asks. As a requested input whose change is
    named, it makes the verification stale. An input FinishUP cannot compare, or a change whose
    paths are unknown, asks: an exempt class never hides a possible input change.
    """

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
        workspace_changed_entries=(
            (workspace_path_identity(INSTALLATION_KEY, path),) if named else None
        ),
    )
    codes = set(task_fact_signals(replay(ledger.prefix), ledger.prefix).codes)
    stale = not output and named and not path.startswith("/")
    assert ("planned_verification_stale" in codes) is stale
    assert ("edited_after_last_verification" in codes) is stale
    assert ("verification_rerun_question" in codes) is not stale
