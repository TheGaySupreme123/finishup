"""The reviewer's declared-test verdicts become tracked, non-blocking advice (issue #1145).

The closing packet lists the agent's declared test (#1220) with its own ``expected_from`` tag; a
reviewer verdict that the expected value is shared with the implementation, or that the test
cannot fail, with a runnable counter-example, becomes one advisory row keyed on the test's pinned
digest. The real ready composition runs with the scripted fake provider's judgment; the case,
the fence, the commit and every host rendering are production's.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.review_manifests import provider_bound_manifest
from builders.start_application import protocol_id, start_request
from finishup.adapters.providers.fake import scripted_success
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.semantic_case import build_semantic_case, semantic_case_packet_view
from finishup.application.service import Application
from finishup.cli.render import render_human_check
from finishup.domain.findings import Finding
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.reviewer_reads import ReviewerRecord
from finishup.kernel.declared_tests import DeclaredTest, declared_test_candidates
from finishup.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import CheckCommitResult, FrozenCase
from finishup.ports.semantic import DeclaredTestVerdict, SemanticCase, SemanticJudgment
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    CheckRequest,
    CheckResult,
    CheckSuccessModel,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StatusRequest,
    public_model_to_wire,
)
from integration.application.test_review_dialogue_workflow import (
    _provenance,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_CRITERION = "Stop at EOS once min_new_tokens is reached."
_TEST_FILE = "/tmp/test_stop_rule.py"
_PROBE = "generate(min_new_tokens=4) on a prompt whose 2nd token is EOS vs single-sequence"


@dataclass
class _Run:
    app: Application
    wires: list[Mapping[str, Any]]
    ids: dict[str, JsonValue]
    task_id: str
    frontier: Any
    bodies: list[dict[str, JsonValue]] = field(default_factory=lambda: [])


@dataclass
class _ScriptedReviewer:
    """Builds the real closing case with the declared tests pinned at ``digests[n]``, then
    answers with the scripted fake provider's judgment carrying ``verdicts[n]``."""

    digests: list[str]
    verdicts: list[tuple[DeclaredTestVerdict, ...]]
    seed: int
    # The prepared byte ceiling the case is built under; 16 KiB is the small-channel gate.
    ceiling: int | None = None
    # A reviewer conversation record to report with the judgment (a real one, from the broker).
    reviewer: ReviewerRecord | None = None
    cases: list[SemanticCase] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        round_ = len(self.cases)
        statement = frozen.case.task_statement
        pinned = tuple(
            DeclaredTest(
                f"dt{n}",
                candidate.path,
                self.digests[round_],
                candidate.criterion_ref,
                candidate.expected_from,
            )
            for n, candidate in enumerate(
                declared_test_candidates(
                    frozen.case.projection, None if statement is None else statement.text
                ),
                1,
            )
        )
        case = build_semantic_case(
            case_id=protocol_id("cas_", self.seed + round_),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.GOAL_AWARE,
            review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
            policy_id=protocol_id("pvy_", self.seed),
            policy_version="1",
            final_review=True,
            declared_tests=pinned,
            prepared_byte_ceiling=self.ceiling,
        )
        self.cases.append(case)
        step = scripted_success(
            SemanticJudgment(
                "no_material_discrepancy",
                (),
                review_summary="Traced the stopping rule.",
                declared_test_verdicts=self.verdicts[round_],
            )
        )
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=cast(Any, step.result).judgment,
            provenance=_provenance(self.seed + 10 + round_),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            provider_input_manifest=provider_bound_manifest(),
            case_declared_tests=case.packet.declared_tests,
            reviewer=self.reviewer,
        )


def _draft(
    event_id: str, name: str, payload: Mapping[str, JsonValue], version: str = "1.0.0"
) -> dict[str, JsonValue]:
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": version},
        "occurred_at": "2026-10-26T12:00:00.000Z",
        "causal_parents": [],
        "payload": dict(payload),
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _checks(seed: int, reviewer: _ScriptedReviewer, rounds: int) -> _Run:
    obligation = protocol_id("obl_", seed + 1)
    command = protocol_id("act_", seed + 3)
    result = protocol_id("res_", seed + 5)
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(
        start_request(seed, title="Batched evaluation parity").model_copy(
            update={"task_statement": f"Make batched generation match: {_CRITERION}"}
        )
    )
    ids: dict[str, JsonValue] = {"session_id": started.session_id, "writer_id": started.writer_id}
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 10)),
                **ids,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    _draft(
                        protocol_id("evt_", seed + 2),
                        "obligation_published",
                        {
                            "obligation_id": obligation,
                            "description": "Batched generation matches single-sequence output.",
                            "acceptance_criteria": _CRITERION,
                            "evidence_expectation": "The parity test passes.",
                            "status": "open",
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 4),
                        "action_recorded",
                        {
                            "action_id": command,
                            "action_kind": "command",
                            "description": "Run the parity test.",
                            "command": f"pytest {_TEST_FILE}",
                            "obligation_refs": [obligation],
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 8),
                        "result_recorded",
                        {
                            "result_id": result,
                            "action_id": command,
                            "outcome": "success",
                            "summary": "4 passed.",
                            "verification": {
                                "criterion_quote": _CRITERION,
                                "data_source": "own_generated",
                                "cases": 4,
                                "failing": 0,
                                "test_file": _TEST_FILE,
                                "results_file": "/tmp/results.json",
                                "report_digest": "sha256:" + "c" * 64,
                                "expected_from": "task_text",
                            },
                        },
                        version="1.1.0",
                    ),
                ],
            }
        )
    )
    frontier = published.result_frontier
    wires: list[Mapping[str, Any]] = []
    bodies: list[dict[str, JsonValue]] = []
    for round_ in range(rounds):
        body: dict[str, JsonValue] = {
            **request_base(protocol_id("req_", seed + 20 + round_)),
            **ids,
            "expected_frontier": frontier_json(frontier),
            "mode": "semantic_required",
            "max_findings": "5",
            "final_review": True,
        }
        bodies.append(body)
        checked = await app.check(CheckRequest.model_validate(body))
        assert type(checked) is CheckCommitResult, type(checked)
        frontier = checked.result_frontier
        wires.append(
            await project_case(
                app, ProjectionCase("check", ControlMethod.CHECK, body, checked), seed + 40 + round_
            )
        )
    return _Run(app, wires, ids, started.task_id, frontier, bodies)


def _advice(projected: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    wire = public_model_to_wire(CheckResult.model_validate(projected))
    return [
        row
        for row in cast(list[Mapping[str, Any]], wire.get("correctness_advisories", []))
        if row["origin"] == "declared_test_verdict"
    ]


def _digest(byte: str) -> str:
    return "sha256:" + byte * 64


_SHARED = DeclaredTestVerdict("dt1", "shared_with_implementation", _PROBE)


async def test_a_shared_expected_value_becomes_tracked_advice_on_every_host() -> None:
    reviewer = _ScriptedReviewer([_digest("a")], [(_SHARED,)], seed=9100)
    run = await _checks(9100, reviewer, 1)
    (projected,) = run.wires
    (case,) = reviewer.cases
    # The packet lists the test with the agent's own tag beside it.
    (listed,) = case.packet.declared_tests
    assert (listed.path, listed.expected_from) == (_TEST_FILE, "task_text")

    (row,) = _advice(projected)
    advisory_id = cast(str, row["advisory_id"])
    summary = cast(str, row["summary"])
    assert summary == (
        f"Your test {_TEST_FILE} for '{_CRITERION}' takes its expected value from the "
        "implementation (you tagged expected_from=task_text; the reviewer observed "
        f"shared_with_implementation). Run: {_PROBE}, or show it fails on a deliberately broken "
        "scratch copy, or decline with a reason."
    )
    assert row["subject_refs"] == [protocol_id("obl_", 9101)]
    wire = public_model_to_wire(CheckResult.model_validate(projected))
    counts = cast(Mapping[str, Any], wire["closure_readiness"])["correctness_advisory_counts"]
    assert counts["no_recorded_response"] == "1"
    # Codex reads structuredContent, Claude the text channel, Cursor its canonical JSON copy.
    for host in ("codex", "claude", "cursor"):
        text = _result_text(wire, host_profile=host)
        assert advisory_id in text, host
        assert _PROBE in text, host
    model = CheckResult.model_validate(projected).root
    assert type(model) is CheckSuccessModel
    cli = render_human_check(model)
    assert f"{advisory_id} (reviewer's declared-test verdict" in cli
    assert "expected_from=task_text" in cli
    readiness = cast(Mapping[str, Any], wire["closure_readiness"])
    assert "advice unanswered" in cast(str, readiness["evidence_basis_summary"])

    async def receipt_text(seed: int) -> str:
        receipt = await run.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **request_base(protocol_id("req_", seed)),
                    "task_id": run.task_id,
                    **run.ids,
                    "expected_frontier": frontier_json(run.frontier),
                    "format": "text",
                    "include": "summary",
                    "redaction_profile": "full_local",
                }
            )
        )
        run.frontier = receipt.result_frontier
        # The repr escapes the label's apostrophe.
        return str(receipt.as_json()).replace("\\'", "'")

    unanswered = await receipt_text(9160)
    assert f"Correctness advisory {advisory_id} (reviewer's declared-test verdict): no" in (
        unanswered
    )
    # One answer closes it (respond pairing, #1162), and the receipt says how.
    answered = await run.app.respond(
        RespondRequest.model_validate(
            {
                **request_base(protocol_id("req_", 9170)),
                **run.ids,
                "expected_frontier": frontier_json(run.frontier),
                "finding_id": advisory_id,
                "finding_frontier": frontier_json(run.frontier),
                "disposition": "declined",
                "reason": "The stop rule is quoted from the task text, not the loop.",
                "evidence_refs": [],
            }
        )
    )
    run.frontier = answered.result_frontier
    closed = await receipt_text(9180)
    assert "no recorded response: 0" in closed
    assert "The stop rule is quoted from the task text, not the loop." in closed


async def test_the_same_test_bytes_are_never_advised_twice_and_new_bytes_are() -> None:
    reviewer = _ScriptedReviewer(
        [_digest("a"), _digest("a"), _digest("b"), _digest("c")],
        [(_SHARED,), (_SHARED,), (_SHARED,), (_SHARED,)],
        seed=9200,
    )
    wires = (await _checks(9200, reviewer, 4)).wires
    first, unchanged, changed, capped = (_advice(wire) for wire in wires)
    assert len(first) == 1
    # Same digest: folded onto the first identity and disclosed in fixed words.
    assert unchanged == []
    summary = cast(str, wires[1]["review_summary"])
    assert "concern test bytes already advised" in summary
    assert cast(str, first[0]["advisory_id"]) in summary
    # A changed test is advised again, once more: at most two per task.
    assert len(changed) == 1
    assert changed[0]["advisory_id"] != first[0]["advisory_id"]
    assert capped == []
    assert "at most 2 per task" in cast(str, wires[3]["review_summary"])


async def test_only_shared_or_cannot_fail_with_a_probe_on_a_listed_test_is_advised() -> None:
    verdicts = (
        DeclaredTestVerdict("dt1", "task_text", "f(0)"),
        DeclaredTestVerdict("dt2", "cannot_fail", "f(0)"),  # not listed: one declared test
    )
    empty_probe = (DeclaredTestVerdict("dt1", "cannot_fail", "  "),)
    reviewer = _ScriptedReviewer([_digest("a"), _digest("a")], [verdicts, empty_probe], seed=9300)
    wires = (await _checks(9300, reviewer, 2)).wires
    assert [_advice(wire) for wire in wires] == [[], []]
    assert not re.search(r"declared-test verdict", json.dumps(wires))


async def test_a_minimal_channel_review_lists_no_test_and_mints_no_verdict_advice() -> None:
    """The small-channel gate (PR #1221 review): nothing is listed, so a verdict the reviewer
    returns anyway fences to no listed test and records nothing."""

    reviewer = _ScriptedReviewer([_digest("a")], [(_SHARED,)], seed=9400, ceiling=16_384)
    (projected,) = (await _checks(9400, reviewer, 1)).wires
    (case,) = reviewer.cases
    assert case.packet.declared_tests == ()
    assert not any("declared_test_verdicts" in question for question in case.question_set)
    assert _advice(projected) == []


def _strings(value: object) -> str:
    """Every string in a JSON-like value, so rendered text keeps its own line breaks."""

    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(_strings(item) for item in cast(Mapping[str, object], value).values())
    if isinstance(value, (list, tuple)):
        return "\n".join(_strings(item) for item in cast(list[object], value))
    return ""


def _shown(probe: str, text: str) -> bool:
    """The probe verbatim in a text channel, or as the JSON string a JSON channel carries."""

    return probe in text or json.dumps(probe)[1:-1] in text


async def test_a_probe_keeps_its_exact_spacing_and_lines_on_every_surface() -> None:
    """PR #1224 review: the counter-example is runnable, so spacing and line breaks are kept
    verbatim (a multi-line probe in a fenced block), only blankness is tested on its strip."""

    spaced = "assert split('a  b') == ['a', '', 'b']"
    multi = "rows = load('fixture.csv')\nassert rows[0]['eos']  == 1\n    # indented note"
    reviewer = _ScriptedReviewer(
        [_digest("a"), _digest("b")],
        [
            (DeclaredTestVerdict("dt1", "shared_with_implementation", spaced),),
            (DeclaredTestVerdict("dt1", "cannot_fail", multi + "\x1b"),),
        ],
        seed=9500,
    )
    run = await _checks(9500, reviewer, 2)
    (one_line,) = _advice(run.wires[0])
    assert f"Run: {spaced}, or show it fails" in cast(str, one_line["summary"])
    (block,) = _advice(run.wires[1])
    summary = cast(str, block["summary"])
    # The control character is dropped; every space and line break of the probe stays.
    assert f"\n```\n{multi}\n```" in summary
    advisory_id = cast(str, block["advisory_id"])
    wire = public_model_to_wire(CheckResult.model_validate(run.wires[1]))
    for host in ("codex", "claude", "cursor"):
        text = _result_text(wire, host_profile=host)
        assert advisory_id in text and _shown(multi, text), host
    model = CheckResult.model_validate(run.wires[1]).root
    assert type(model) is CheckSuccessModel
    assert multi in render_human_check(model)
    for form, seed in (("text", 9560), ("markdown", 9570)):
        receipt = await run.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **request_base(protocol_id("req_", seed)),
                    "task_id": run.task_id,
                    **run.ids,
                    "expected_frontier": frontier_json(run.frontier),
                    "format": form,
                    "include": "summary",
                    "redaction_profile": "full_local",
                }
            )
        )
        run.frontier = receipt.result_frontier
        rendered = _strings(receipt.as_json())
        assert spaced in rendered and multi in rendered, form


async def test_a_check_whose_reviewer_read_a_declared_test_validates_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #1224 review (a #1221 regression): a reviewer read through ``t1`` is recorded with
    ``standing: declared_test``, which the check result model refused. The record comes from the
    real broker reading a declared test; the check, its hosts, history and receipt all carry it."""

    from integration.service import test_declared_test_reads as reads
    from integration.service import test_reviewer_conversation_composition as composition

    test = reads._outside(tmp_path)  # pyright: ignore[reportPrivateUsage]
    reads._declare(monkeypatch, str(test))  # pyright: ignore[reportPrivateUsage]
    evaluated, _gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        reads._declared(),  # pyright: ignore[reportPrivateUsage]
        reads._FINAL,  # pyright: ignore[reportPrivateUsage]
        policy=reads._ROOMY,  # pyright: ignore[reportPrivateUsage]
    )
    record = evaluated.reviewer
    assert record is not None
    assert [(read.root, read.standing) for read in record.reads] == [("t1", "declared_test")]

    reviewer = _ScriptedReviewer([_digest("a")], [(_SHARED,)], seed=9600, reviewer=record)
    run = await _checks(9600, reviewer, 1)
    (projected,) = run.wires
    model = CheckResult.model_validate(projected).root
    assert type(model) is CheckSuccessModel
    wire = public_model_to_wire(CheckResult.model_validate(projected))
    reads_wire = cast(list[Mapping[str, Any]], cast(Mapping[str, Any], wire["reviewer"])["reads"])
    assert [(read["root"], read["standing"]) for read in reads_wire] == [("t1", "declared_test")]
    for host in ("codex", "claude", "cursor"):
        assert "declared_test" in _result_text(wire, host_profile=host), host
    assert render_human_check(model)

    history = await run.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", 9650)),
                **run.ids,
                "view": "history",
                "detail": "full",
            }
        )
    )
    # History rows carry the advisory (not the reviewer record); readiness names its origin.
    assert "reviewer's declared-test verdict" in json.dumps(history.as_json(), default=str)
    assert any(
        row.get("correctness_advisories")
        for row in cast(Mapping[str, Any], history.as_json()["page"])["items"]
    )
    # A same-id replay re-reads the recorded check, reviewer record included.
    replayed = await run.app.check(CheckRequest.model_validate(run.bodies[0]))
    assert type(replayed) is CheckCommitResult and replayed.outcome == "replayed"
    again = await project_case(
        run.app,
        ProjectionCase("check", ControlMethod.CHECK, run.bodies[0], replayed),
        9670,
    )
    assert type(CheckResult.model_validate(again).root) is CheckSuccessModel
    receipt = await run.app.receipt(
        ReceiptRequest.model_validate(
            {
                **request_base(protocol_id("req_", 9660)),
                "task_id": run.task_id,
                **run.ids,
                "expected_frontier": frontier_json(run.frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "reviewer's declared-test verdict" in _strings(receipt.as_json())
