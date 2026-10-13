"""tb4n5 react-lead-form: a conditional output absent on an accepted clean lead (ADR-033 amendment).

The task asked for ``incomplete_leads.json`` only when a contactable lead is incomplete and for
``rejected_ledgers.json`` only when an existing ledger is malformed. The agent declared both as
unconditional ``file`` outputs; the final input was a complete, accepted lead, so neither file
existed and ``requested_output_absent`` blocked the receipt. In 5 of 5 Yoetz attempts the agent
invented its own exit: a false ``acknowledged_not_done``, an undocumented plan reclassification,
or deliverable code that wrote empty placeholder ledgers on every accepted submit.

The documented exit is a plan correction: supersede the obligation with one that models the
behavior as a ``change`` item naming the condition, plus the source files that implement it, and
never write a placeholder to satisfy the declaration. These tests drive that correction through
the real check, status and receipt with a workspace in which the two conditional ledgers never
appear, and keep an unconditional missing output blocking.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from builders.start_application import protocol_id
from integration.closure.test_closure_shapes import (
    _begin,
    _Run,
    receipt_artifact_1_3_0,  # noqa: F401  # pyright: ignore[reportUnusedImport] - autouse fixture
)
from yoetz.application import check_change
from yoetz.domain.findings import FindingKind
from yoetz.kernel.deterministic_checks import REQUESTED_OUTPUT_ABSENT_SUMMARY
from yoetz.kernel.task_facts import RequestedOutputState
from yoetz.protocol.canonical import JsonValue

pytestmark = pytest.mark.anyio

_OUT = "/app/output/"
_LEDGER_SOURCE = "/app/src/lib/leadLedger.ts"
_INCOMPLETE = _OUT + "incomplete_leads.json"
_REJECTED = _OUT + "rejected_ledgers.json"
_RECONCILE = protocol_id("obl_", 8101)
_COMMIT = protocol_id("obl_", 8102)
_RECONCILE_FIXED = protocol_id("obl_", 8103)
_COMMIT_FIXED = protocol_id("obl_", 8104)
_INCOMPLETE_CHANGE = (
    "Write /app/output/incomplete_leads.json when a contactable lead is incomplete;"
    " an accepted complete lead writes none"
)
_REJECTED_CHANGE = (
    "Write /app/output/rejected_ledgers.json when an existing ledger is malformed;"
    " a well-formed ledger is repaired silently and writes none"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Workspace:
    """The files on disk, read by every check. The two conditional ledgers are never on it."""

    present: set[str] = field(
        default_factory=lambda: {
            _OUT + "crm_leads.json",
            _OUT + "lead_sources.json",
            _OUT + "reconciliation.json",
            _OUT + "submission.json",
            _LEDGER_SOURCE,
        }
    )


def _file(value: str) -> dict[str, JsonValue]:
    return {"item_kind": "file", "value": value, "role": "output"}


def _change(value: str) -> dict[str, JsonValue]:
    return {"item_kind": "change", "value": value}


def _obligation(
    run: _Run,
    obligation: str,
    items: list[dict[str, JsonValue]],
    *,
    resolved_by: str | None = None,
) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "obligation_id": obligation,
        "description": f"Lead ledger behavior {obligation[-4:]}",
        "acceptance_criteria": "The submit pipeline meets the lead ledger contract.",
        "evidence_expectation": "The passing regression suite.",
        "status": "open" if resolved_by is None else "resolved",
        "requested_items": list(items),
    }
    if resolved_by is not None:
        payload["resolution_evidence_refs"] = [resolved_by]
    draft = run.draft("obligation_published", payload)
    draft["schema"] = {"name": "obligation_published", "version": "1.1.0"}
    return draft


def _values(items: list[dict[str, JsonValue]]) -> list[str]:
    return sorted((str(item["value"]) for item in items), key=str.encode)


async def _work(
    run: _Run,
    seed: int,
    plan: dict[str, list[dict[str, JsonValue]]],
    *,
    supersedes_claim: str | None = None,
    action_kind: str = "other",
) -> str:
    """Record the work on every obligation in *plan*, resolve them and claim completion."""

    action = protocol_id("act_", seed)
    evidence = protocol_id("evd_", seed)
    claim = protocol_id("clm_", seed)
    obligations: list[JsonValue] = list(sorted(plan, key=str.encode))
    attempted: list[JsonValue] = list(
        sorted({value for items in plan.values() for value in _values(items)}, key=str.encode)
    )
    await run.publish(
        run.draft(
            "action_recorded",
            {
                "action_id": action,
                "action_kind": action_kind,
                "description": "Implemented the shared submit pipeline and its ledgers",
                "obligation_refs": obligations,
                "attempted_items": attempted,
            },
        ),
        run.draft(
            "result_recorded",
            {
                "result_id": protocol_id("res_", seed),
                "action_id": action,
                "outcome": "success",
                "summary": "96 tests pass, including the incomplete and quarantine flows.",
            },
        ),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-10-13T12:00:00.000Z",
                "description": "npm test: 96 passed, including incomplete and malformed cases.",
            },
        ),
        *(
            _obligation(run, str(obligation), plan[str(obligation)], resolved_by=evidence)
            for obligation in obligations
        ),
        run.draft(
            "claim_recorded",
            {
                "claim_id": claim,
                "claim_kind": "completion",
                "statement": "The lead submit pipeline is implemented and tested.",
                "supporting_refs": [evidence],
                "obligation_refs": obligations,
                "limitation_refs": [],
                "supersedes_claim_refs": [] if supersedes_claim is None else [supersedes_claim],
            },
        ),
    )
    return claim


def _original_plan() -> dict[str, list[dict[str, JsonValue]]]:
    return {
        _RECONCILE: [
            _file(_OUT + "crm_leads.json"),
            _file(_INCOMPLETE),
            _file(_OUT + "lead_sources.json"),
            _file(_OUT + "reconciliation.json"),
        ],
        _COMMIT: [_file(_OUT + "submission.json"), _file(_REJECTED)],
    }


def _corrected_plan(*, keep_crm: bool = True) -> dict[str, list[dict[str, JsonValue]]]:
    reconcile = [
        _file(_OUT + "lead_sources.json"),
        _file(_OUT + "reconciliation.json"),
        _change(_INCOMPLETE_CHANGE),
        _file(_LEDGER_SOURCE),
    ]
    if keep_crm:
        reconcile.insert(0, _file(_OUT + "crm_leads.json"))
    return {
        _RECONCILE_FIXED: reconcile,
        _COMMIT_FIXED: [
            _file(_OUT + "submission.json"),
            _change(_REJECTED_CHANGE),
            _file(_LEDGER_SOURCE),
        ],
    }


async def _react_run(monkeypatch: pytest.MonkeyPatch, seed: int) -> tuple[_Run, _Workspace, str]:
    workspace = _Workspace()

    async def states(**kwargs: Any) -> dict[tuple[object, int], RequestedOutputState]:
        found: dict[tuple[object, int], RequestedOutputState] = {}
        for obligation, record in kwargs["projection"].obligations.items():
            if record.payload is None:
                continue
            for index, item in enumerate(record.payload.requested_items):
                if item.item_kind.value != "file":
                    continue
                exists = item.value in workspace.present
                found[(obligation, index)] = RequestedOutputState(
                    "inside",
                    exists=exists,
                    changed=exists,
                    size_bytes=256 if exists else None,
                    lines=12 if exists else None,
                    relative=item.value.removeprefix("/app/"),
                )
        return found

    monkeypatch.setattr(check_change, "requested_output_states", states)
    run = await _begin(seed=seed)
    plan = _original_plan()
    await run.publish(
        *(_obligation(run, obligation, items) for obligation, items in plan.items()),
        run.draft(
            "plan_published",
            {
                "plan_version": 1,
                "summary": "Lead submit pipeline",
                "obligation_refs": list[JsonValue](sorted(plan, key=str.encode)),
            },
        ),
    )
    claim = await _work(run, seed * 10 + 1, plan)
    return run, workspace, claim


async def _correct(
    run: _Run, seed: int, claim: str, *, keep_crm: bool = True, action_kind: str = "edit"
) -> None:
    """The documented exit: a plan revision with change items, then the work recorded on them."""

    corrected = _corrected_plan(keep_crm=keep_crm)
    await run.publish(
        *(
            _obligation(run, obligation, items)
            for obligation, items in sorted(corrected.items(), key=lambda row: row[0].encode())
        ),
        run.draft(
            "plan_revised",
            {
                "plan_version": 2,
                "supersedes_plan_version": 1,
                "reason": (
                    "The task writes incomplete_leads.json and rejected_ledgers.json only under a"
                    " condition the accepted sample does not meet; they are runtime behavior, not"
                    " files delivered now."
                ),
                "summary": "Model the conditional ledgers as change items",
                "obligation_changes": [
                    {
                        "obligation_id": _RECONCILE,
                        "change": "superseded",
                        "reason": "incomplete_leads.json is conditional runtime output",
                        "replacement_obligation_ids": [_RECONCILE_FIXED],
                    },
                    {
                        "obligation_id": _COMMIT,
                        "change": "superseded",
                        "reason": "rejected_ledgers.json is conditional runtime output",
                        "replacement_obligation_ids": [_COMMIT_FIXED],
                    },
                ],
            },
        ),
    )
    await _work(run, seed, corrected, supersedes_claim=claim, action_kind=action_kind)


def _absent_findings(checked: Any) -> list[Any]:
    return [
        finding
        for finding in checked.findings
        if finding.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
        and finding.summary == REQUESTED_OUTPUT_ABSENT_SUMMARY
    ]


async def test_conditional_ledgers_absent_on_an_accepted_lead_close_after_a_plan_correction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, workspace, claim = await _react_run(monkeypatch, 8100)
    checked = await run.check()
    absent = _absent_findings(checked)
    assert {finding.subject_refs for finding in absent} == {(_RECONCILE,), (_COMMIT,)}
    for finding in absent:
        # The continuation names the honest exit and forbids the placeholder.
        assert "only under a condition your final state does not meet" in finding.detail
        assert "`change` item names the condition" in finding.detail
        assert "Never write an empty or placeholder file" in finding.detail

    await _correct(run, 8200, claim)
    rechecked = await run.check()
    assert not _absent_findings(rechecked)
    assert not [
        f for f in rechecked.findings if f.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
    ]

    # The historical absence findings are resolved by that qualifying check, not answered away.
    findings = await run.status("findings")
    rows = {row.finding_id: row for row in cast(Any, findings.page).items}
    for finding in absent:
        assert rows[finding.finding_id].resolved is True, rows[finding.finding_id]
    compact = await run.status("compact")
    readiness = compact.closure_readiness
    assert readiness.receipt_blocking_finding_count in (None, "0"), readiness
    assert readiness.predicted_receipt is not None
    assert readiness.predicted_receipt.conclusion != "unresolved_findings_remain"
    # Closed with the conditional ledgers still absent: no placeholder satisfied the declaration.
    assert _INCOMPLETE not in workspace.present
    assert _REJECTED not in workspace.present


async def test_an_unconditional_missing_output_still_blocks_after_the_correction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, workspace, claim = await _react_run(monkeypatch, 8300)
    workspace.present.discard(_OUT + "crm_leads.json")
    await run.check()

    # The correction cannot launder an unconditional output: crm_leads.json is still declared and
    # still absent, so the replacement obligation raises the same finding.
    await _correct(run, 8400, claim, action_kind="other")
    rechecked = await run.check()
    absent = _absent_findings(rechecked)
    assert [finding.subject_refs for finding in absent] == [(_RECONCILE_FIXED,)]
    compact = await run.status("compact")
    readiness = compact.closure_readiness
    assert readiness.state == "action_required"
    assert int(readiness.receipt_blocking_finding_count or "0") >= 1
