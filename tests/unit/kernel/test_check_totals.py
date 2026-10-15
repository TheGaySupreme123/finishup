"""Focused accounting vectors for the frozen check totals projection (#971)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from builders.observed_runs import ObservedLedger
from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    act,
    evd,
    evidence_record,
    evt,
    fnd,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.domain.check_totals import (
    CHECK_TOTAL_KEYS,
    render_check_totals,
    validate_check_totals,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.findings import FINDING_KIND_TRAITS, Finding, FindingKind, FindingOrigin
from finishup.domain.values import EvidenceId, ResultId, object_id, timestamp_from_string
from finishup.kernel.check_totals import build_check_totals
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
    case_coverage,
)
from finishup.kernel.deterministic_scope import deterministic_scope_is_clean
from finishup.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from finishup.kernel.reducers import replay
from finishup.kernel.test_edit_visibility import PreExistingTestEdits
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    EvidenceImmutability,
    PublicationChannel,
    coverage_for_channel,
)

type TotalsCase = tuple[DeterministicCase, tuple[Finding, ...], int]


def _empty_totals() -> dict[str, dict[str, str]]:
    return {group: {key: "0" for key in keys} for group, keys in CHECK_TOTAL_KEYS.items()}


def _obligation(
    number: int,
    status: ObligationStatus = ObligationStatus.OPEN,
    *,
    requested: tuple[str, ...] = (),
    resolution_evidence_refs: tuple[EvidenceId | ResultId, ...] = (),
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obl(number),
        description=f"Obligation {number}",
        evidence_expectation="Recorded evidence",
        status=status,
        requested_items=tuple(RequestedItem(RequestedItemKind.COMMAND, item) for item in requested),
        resolution_evidence_refs=resolution_evidence_refs,
    )


def _snapshot_evidence(number: int) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evidence_id=evd(number),
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-09-29T17:58:11.363Z"),
        captured_object_id=object_id(f"obj_10000000-0000-4000-8000-{number:012x}"),
        content_digest="sha256:" + "a" * 64,
    )


def _totals_group(value: Mapping[str, object], group: str) -> dict[str, str]:
    counters = value[group]
    if not isinstance(counters, Mapping):
        raise AssertionError(f"invalid totals group: {group}")
    return dict(cast(Mapping[str, str], counters))


def _observed_case(ledger: ObservedLedger) -> DeterministicCase:
    records = ledger.prefix
    return build_deterministic_case(replay(records), records, CaseAvailabilityFacts())


def _clean_scoped_case() -> DeterministicCase:
    plan = PlanPublishedPayload(1, "Current clean plan", (obl(101), obl(102)))
    obligations = {
        obl(101): obligation_record(
            _obligation(
                101,
                ObligationStatus.RESOLVED,
                requested=("first check",),
                resolution_evidence_refs=(evd(111),),
            ),
            11,
        ),
        obl(102): obligation_record(
            _obligation(
                102,
                ObligationStatus.RESOLVED,
                requested=("second check",),
                resolution_evidence_refs=(evd(112),),
            ),
            12,
        ),
    }
    actions = {
        act(103): record(
            ActionRecordedPayload(
                act(103),
                ActionKind.COMMAND,
                "Observed first check",
                command="omitted:structural",
                obligation_refs=(obl(101),),
                attempted_items=("first check",),
            ),
            13,
        ),
        act(105): record(
            ActionRecordedPayload(
                act(105),
                ActionKind.COMMAND,
                "Observed second check",
                command="omitted:structural",
                obligation_refs=(obl(102),),
                attempted_items=("second check",),
            ),
            15,
        ),
    }
    results = {
        res(14): record(
            ResultRecordedPayload(
                res(14),
                act(103),
                ResultOutcome.SUCCESS,
            ),
            14,
        ),
        res(16): record(
            ResultRecordedPayload(
                res(16),
                act(105),
                ResultOutcome.SUCCESS,
            ),
            16,
        ),
    }
    hook = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    return make_case(
        plans={1: plan_record(plan, 10)},
        obligations=obligations,
        actions=actions,
        results=results,
        evidence={
            evd(111): evidence_record(_snapshot_evidence(111), 17),
            evd(112): evidence_record(_snapshot_evidence(112), 18),
        },
        coverage_overrides={
            evt(13): hook,
            evt(14): hook,
            evt(15): hook,
            evt(16): hook,
        },
    )


def _insufficient_case() -> DeterministicCase:
    plan = PlanPublishedPayload(1, "Incomplete plan", (obl(201), obl(202)))
    action = ActionRecordedPayload(
        act(203),
        ActionKind.COMMAND,
        "Observed unknown check",
        command="omitted:structural",
    )
    result = ResultRecordedPayload(res(24), act(203), ResultOutcome.UNKNOWN)
    hook = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    hook = replace(hook, known_gaps=("host_outcome_unavailable",))
    return make_case(
        plans={1: plan_record(plan, 20)},
        obligations={
            obl(201): obligation_record(_obligation(201, requested=("missing check",)), 21)
        },
        actions={act(203): record(action, 23)},
        results={result.result_id: record(result, 24)},
        coverage_overrides={evt(23): hook, evt(24): hook},
    )


def _findings_case() -> DeterministicCase:
    plan = PlanPublishedPayload(1, "Finding scope", (obl(303),))
    obligation = _obligation(
        303,
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(evd(305),),
    )
    return make_case(
        plans={1: plan_record(plan, 30)},
        obligations={obl(303): obligation_record(obligation, 31)},
        evidence={evd(305): evidence_record(_snapshot_evidence(305), 32)},
    )


def _finding(number: int, kind: FindingKind) -> Finding:
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A bounded finding",
        detail="The finding remains structural.",
        subject_refs=(evt(number),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
    )


def test_current_plan_scope_counts_only_current_obligations() -> None:
    evidence = _snapshot_evidence(11)
    current = PlanPublishedPayload(1, "Current plan", (obl(1), obl(2), obl(3)))
    case = make_case(
        plans={1: plan_record(current, 1)},
        obligations={
            obl(1): obligation_record(
                _obligation(
                    1,
                    ObligationStatus.RESOLVED,
                    resolution_evidence_refs=(evd(11),),
                ),
                2,
            ),
            obl(2): obligation_record(_obligation(2), 3),
        },
        evidence={evd(11): evidence_record(evidence, 4)},
    )

    totals = build_check_totals(case)

    assert _totals_group(totals, "obligations") == {
        "declared": "3",
        "resolved": "1",
        "open": "1",
        "unreadable": "1",
        "with_evidence": "1",
        "scope_known": "1",
    }
    assert _totals_group(totals, "requested_items") == {"attempted": "0", "unattempted": "0"}


def test_unreadable_plan_scope_is_unavailable_and_cannot_earn_scoped_clean() -> None:
    unreadable_plan = replace(
        plan_record(PlanPublishedPayload(1, "Unreadable plan", (obl(1),)), 1),
        payload=None,
        redacted=True,
    )
    case = make_case(plans={1: unreadable_plan})

    totals = build_check_totals(case)

    obligations = _totals_group(totals, "obligations")
    assert obligations["scope_known"] == "0"
    assert obligations["declared"] == "0"
    rendered = render_check_totals(totals)
    assert "obligations unavailable (current plan scope is unreadable)" in rendered
    assert "requested items unavailable (current plan scope is unreadable)" in rendered
    assert not deterministic_scope_is_clean(
        coverage=case_coverage(case), totals=totals, findings=()
    )


def test_attempted_items_are_attributed_per_obligation() -> None:
    plan = PlanPublishedPayload(1, "Current plan", (obl(1), obl(2)))
    obligations = {
        obl(1): obligation_record(_obligation(1, requested=("shared", "one", "two")), 1),
        obl(2): obligation_record(_obligation(2, requested=("shared", "one", "two")), 2),
    }
    actions = {
        act(3): record(
            ActionRecordedPayload(
                act(3),
                ActionKind.OTHER,
                "Global assertion",
                attempted_items=("shared",),
            ),
            3,
        ),
        act(4): record(
            ActionRecordedPayload(
                act(4),
                ActionKind.OTHER,
                "First obligation assertion",
                obligation_refs=(obl(1),),
                attempted_items=("one",),
            ),
            4,
        ),
        act(5): record(
            ActionRecordedPayload(
                act(5),
                ActionKind.OTHER,
                "Second obligation assertion",
                obligation_refs=(obl(2),),
                attempted_items=("two",),
            ),
            5,
        ),
    }

    totals = build_check_totals(
        make_case(
            plans={1: plan_record(plan, 6)},
            obligations=obligations,
            actions=actions,
        )
    )

    assert _totals_group(totals, "requested_items") == {"attempted": "4", "unattempted": "2"}


def test_only_hook_observed_results_enter_command_totals() -> None:
    observed_action = ActionRecordedPayload(
        act(1), ActionKind.COMMAND, "Observed command", command="omitted:structural"
    )
    observed_result = ResultRecordedPayload(
        res(2),
        act(1),
        ResultOutcome.FAILURE,
    )
    cooperative_action = ActionRecordedPayload(
        act(3), ActionKind.COMMAND, "Cooperative command", command="omitted:structural"
    )
    cooperative_result = ResultRecordedPayload(
        res(4),
        act(3),
        ResultOutcome.FAILURE,
    )
    hook = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    case = make_case(
        actions={act(1): record(observed_action, 1), act(3): record(cooperative_action, 3)},
        results={
            observed_result.result_id: record(observed_result, 2),
            cooperative_result.result_id: record(cooperative_result, 4),
        },
        coverage_overrides={evt(1): hook, evt(2): hook},
    )

    totals = build_check_totals(case)

    commands = _totals_group(totals, "commands")
    assert commands["observed"] == "1"
    assert commands["failed"] == "1"
    assert commands["live_failed"] == "1"
    assert commands["retired_by_rerun"] == "0"


def test_failed_rerun_is_history_while_latest_failure_stays_live() -> None:
    ledger = ObservedLedger()
    ledger.fail("pytest -q tests/checks.py")
    ledger.fail("pytest -q tests/checks.py")

    commands = _totals_group(build_check_totals(_observed_case(ledger)), "commands")

    assert commands["observed"] == "2"
    assert commands["failed"] == "2"
    assert commands["retired_by_rerun"] == "1"
    assert commands["live_failed"] == "1"
    assert commands["disclosed_not_rerun_green"] == "0"


def test_disclosed_test_failure_is_still_live_and_not_green() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/checks.py")
    ledger.claim(limitations=(failed,))

    commands = _totals_group(build_check_totals(_observed_case(ledger)), "commands")

    assert commands["observed"] == "1"
    assert commands["failed"] == "1"
    assert commands["live_failed"] == "1"
    assert commands["retired_by_rerun"] == "0"
    assert commands["disclosed_not_rerun_green"] == "1"


def test_findings_are_counted_by_closed_actionability_trait() -> None:
    totals = build_check_totals(
        make_case(),
        findings=(
            _finding(1, FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED),
            _finding(2, FindingKind.LEDGER_STALE_OR_INCOMPLETE),
        ),
        suppressed_count=3,
    )

    assert _totals_group(totals, "findings") == {
        "returned": "2",
        "actionable_returned": "1",
        "coverage_only_returned": "1",
        "suppressed": "3",
    }


def test_preexisting_test_edit_counts_are_structural_and_bounded() -> None:
    totals = build_check_totals(
        make_case(),
        test_edits=PreExistingTestEdits(
            modified=2,
            renamed=1,
            deleted=1,
            skipped=1,
            baseline_known=False,
            unjustified=2,
            unknown=1,
        ),
    )

    assert _totals_group(totals, "test_edits") == {
        "examined": "1",
        "baseline_known": "0",
        "modified": "2",
        "renamed": "1",
        "deleted": "1",
        "skipped": "1",
        "unjustified": "2",
        "unknown": "1",
    }


@pytest.mark.parametrize("bad_count", [1, True, -1, "01", "١", "9" * 21, str(2**64)])
def test_validate_check_totals_rejects_noncanonical_counter_values(bad_count: object) -> None:
    totals = _empty_totals()
    totals["commands"]["observed"] = bad_count  # type: ignore[assignment]

    with pytest.raises(ValueError, match="check_totals_invalid"):
        validate_check_totals(totals)


@pytest.mark.parametrize(
    ("group", "key"),
    [
        ("obligations", "scope_known"),
        ("test_edits", "examined"),
        ("test_edits", "baseline_known"),
    ],
)
def test_validate_check_totals_rejects_non_binary_availability_flags(group: str, key: str) -> None:
    totals = _empty_totals()
    totals[group][key] = "2"

    with pytest.raises(ValueError, match="check_totals_invalid"):
        validate_check_totals(totals)


@pytest.mark.parametrize(
    "shape", ["missing_group", "extra_group", "missing_counter", "extra_counter"]
)
def test_validate_check_totals_rejects_open_structural_shapes(shape: str) -> None:
    totals = _empty_totals()
    if shape == "missing_group":
        del totals["commands"]
    elif shape == "extra_group":
        totals["raw_command"] = {}
    elif shape == "missing_counter":
        del totals["commands"]["observed"]
    else:
        totals["commands"]["raw_command"] = "0"

    with pytest.raises(ValueError, match="check_totals_invalid"):
        validate_check_totals(totals)


def test_totals_are_closed_structural_data_without_raw_command_strings() -> None:
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run a command containing a secret",
        command="token=super-secret.value",
    )
    totals = build_check_totals(make_case(actions={act(1): record(action, 1)}))
    encoded = canonical_encode(totals)

    assert b"super-secret" not in encoded
    assert b"token" not in encoded
    assert b'"command":' not in encoded
    assert set(totals) == set(CHECK_TOTAL_KEYS)


def test_canonical_fixture_vectors_match_independent_accounting_cases() -> None:
    path = Path(__file__).resolve().parents[3] / "fixtures/canonical/check-totals-1.4.0.case.json"
    fixture = cast(dict[str, Any], json.loads(path.read_bytes()))
    vectors = cast(list[dict[str, Any]], cast(dict[str, Any], fixture["input"])["vectors"])
    cases: dict[str, TotalsCase] = {
        "clean_scoped": (_clean_scoped_case(), (), 0),
        "insufficient": (_insufficient_case(), (), 0),
        "findings": (
            _findings_case(),
            (
                _finding(301, FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED),
                _finding(302, FindingKind.LEDGER_STALE_OR_INCOMPLETE),
            ),
            3,
        ),
    }
    livefailure = ObservedLedger()
    livefailure.fail("pytest -q tests/checks.py")
    livefailure.claim()
    cases["livefailure"] = (
        _observed_case(livefailure),
        (_finding(401, FindingKind.FAILED_WORK_OMITTED),),
        0,
    )

    for vector in vectors:
        vector_id = cast(str, vector["vector_id"])
        payload = cast(dict[str, Any], vector["payload"])
        assert canonical_encode(payload).hex() == vector["canonical_hex"]
        assert canonical_digest(payload) == vector["digest"]
        case, findings, suppressed = cases[vector_id]
        actual_totals = build_check_totals(case, findings, suppressed)
        assert actual_totals == payload["totals"]
        coverage = case_coverage(case)
        clean = deterministic_scope_is_clean(
            coverage=coverage,
            totals=actual_totals,
            findings=findings,
        )
        if clean:
            completeness = CheckCompleteness.SCOPED_COMPLETE
        elif coverage.known_gaps:
            completeness = CheckCompleteness.COVERAGE_INCOMPLETE
        else:
            completeness = CheckCompleteness.COMPLETE
        rankable_findings = tuple(replace(finding, coverage=coverage) for finding in findings)
        ranked = rank_findings(
            rankable_findings,
            (),
            RankingContext(coverage, completeness),
            3,
        )
        assert ranked.verdict.value == payload["verdict"]


def test_codex_unknown_hook_result_enriched_by_the_stream_counts_once() -> None:
    """#1001 (tb4n1 B6): retro-console-soc D recorded 43 Codex calls as unknown + corrected.

    Codex reports a shell outcome only on its session stream, so the PostToolUse hook result is
    unknown and the stream appends a corrected result for the same action. One host call is one
    command, and the recorded outcome supersedes the unknown and its host-outcome gap.
    """

    ledger = ObservedLedger()
    unknown = ledger.run("pytest -q tests/test_soc.py", ResultOutcome.UNKNOWN)
    ledger.correct_outcome(unknown, ResultOutcome.SUCCESS, exit_status=0)
    failed = ledger.run("make lint", ResultOutcome.UNKNOWN)
    ledger.correct_outcome(failed, ResultOutcome.FAILURE, exit_status=2)

    case = _observed_case(ledger)
    commands = _totals_group(build_check_totals(case), "commands")
    assert commands["observed"] == "2"
    assert commands["unknown"] == "0"
    assert commands["failed"] == "1"
    assert "host_outcome_unavailable" not in case_coverage(case).known_gaps


def test_an_unknown_hook_result_without_a_correction_stays_unknown() -> None:
    ledger = ObservedLedger()
    ledger.run("pytest -q tests/test_soc.py", ResultOutcome.UNKNOWN)
    corrected = ledger.run("make lint", ResultOutcome.UNKNOWN)
    ledger.correct_outcome(corrected, ResultOutcome.SUCCESS, exit_status=0)

    case = _observed_case(ledger)
    commands = _totals_group(build_check_totals(case), "commands")
    assert commands["observed"] == "2"
    assert commands["unknown"] == "1"
    assert "host_outcome_unavailable" in case_coverage(case).known_gaps
