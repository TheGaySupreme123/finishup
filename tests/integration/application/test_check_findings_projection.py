"""A ``check`` that produced a finding must project to a complete ``CheckSuccessModel``.

2026-07-28 run 4 dogfood: every ``check`` that produced at least one finding committed durably
(``check_recorded`` and ``finding_recorded`` landed, the frontier advanced) and then failed to
project, so the caller received ``INTERNAL_ERROR`` / ``response_projection_failed`` and never
learned the verdict, the finding, or the AI-powered review outcome. ``findings[]`` is the delivery channel
for a check's entire answer, and it had never worked in any mode; the only reason this stayed
hidden through three dogfoods is that no check had ever produced a finding.

Two defects of one class stacked here. The internal check body carries each finding as a
``JsonObject`` — a real ``Mapping``, but not a built-in ``dict`` — and the public result models are
configured ``strict=True``, where only a ``dict`` (or an instance of the target model) is admitted
for a nested model field; the scalar top-level fields sailed through while every nested entry was
rejected. Behind that, the check result's ``projected_finding`` requires ``provenance`` to be
present and nullable, while the ``findings/finding-1.0.0`` encoding events and receipts share
leaves it absent on a local finding — a second rejection the first one had masked.

These cases run the real ready composition — real vault objects, the real privacy coordinator and
shipped default policy, the real closed-model validation the daemon runs for an MCP bridge client —
and pin a complete response carrying the finding, in all three check modes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Literal, cast

import pytest

import yoetz.application.service as service_module
from builders.observed_runs import ObservedLedger
from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from yoetz.application.check import FinalSemanticEvaluation, build_overall_next
from yoetz.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectedControlBody,
    ProjectionRenderMode,
)
from yoetz.domain.findings import Finding, FindingKind, SemanticDispatchKind, SemanticProvenance
from yoetz.domain.privacy import PrivacyPolicy
from yoetz.domain.values import JsonObject
from yoetz.kernel.check_totals import build_check_totals
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    case_coverage,
)
from yoetz.kernel.finding_todo import FindingTodoCounts
from yoetz.kernel.reducers import replay
from yoetz.ports.control import ControlClientKind, ControlMethod
from yoetz.ports.ledger import CheckCommitResult, CheckFindingChecklist, FrozenCase
from yoetz.ports.semantic import ReviewerChallenge, SamplingParams, SemanticJudgment
from yoetz.protocol.canonical import MAX_JSON_DEPTH, JsonValue, canonical_encode
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.models import (
    MAX_FINDINGS_LIMIT,
    CheckProjectedFindingModel,
    CheckRequest,
    DataCategory,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
    public_model_to_wire,
)

pytestmark = pytest.mark.anyio

# The projection boundary itself, exercised directly where a test needs a body the workflow cannot
# produce — a deliberately malformed or pathologically nested one.
_public_model = cast(
    "Callable[[ControlMethod, Mapping[str, JsonValue]], ProjectedControlBody]",
    getattr(service_module, "_public_model"),
)
_plain_nested_mappings = cast(
    "Callable[[JsonValue], JsonValue]",
    getattr(service_module, "_plain_nested_mappings"),
)

_MODES: tuple[tuple[Literal["disabled", "optional"], str], ...] = (
    ("disabled", "deterministic_only"),
    ("optional", "semantic_if_configured"),
    ("optional", "semantic_required"),
)
_DIGEST = "sha256:" + "7" * 64


async def _semantic_challenge(
    frozen: FrozenCase,
    findings: tuple[Finding, ...],
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> FinalSemanticEvaluation:
    """Hermetic second reviewer that challenges one real local finding."""

    del frozen, runtime, lineage_evaluation
    assert findings
    provenance = SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id=protocol_id("att_", 1510),
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=protocol_id("egr_", 1511),
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-semantic-request-1",
        egress_authorization_id=protocol_id("aut_", 1512),
        request_commitment="hmac-sha256:" + "b" * 64,
    )
    challenge = ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "The completion claim overstates its evidence",
        (str(findings[0].finding_id),),
        "The cited material records an obligation but no admissible completion evidence.",
        "The work may be complete, but the frozen case does not establish that conclusion.",
        "Cite admissible evidence or narrow the completion claim.",
        "provide_evidence",
        "Additional evidence may exist outside the frozen case.",
    )
    return FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=SemanticJudgment("challenges_returned", (challenge,)),
        provenance=provenance,
    )


async def _semantic_unavailable(
    frozen: FrozenCase,
    findings: tuple[Finding, ...],
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> FinalSemanticEvaluation:
    del frozen, findings, runtime, lineage_evaluation
    return FinalSemanticEvaluation(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.CREDENTIAL_UNAVAILABLE,
    )


async def _binding(
    app: Application,
    request_body: Mapping[str, JsonValue],
    internal: CheckCommitResult,
    seed: int,
) -> ControlProjectionBinding:
    """Build the daemon-equivalent projection binding for a check."""

    facts = await app.projection_binding_facts(ControlMethod.CHECK, request_body, internal)
    rpc_id = protocol_id("rpc_", seed)
    service_instance_id = protocol_id("svc_", seed + 1)
    return ControlProjectionBinding(
        rpc_id,
        ControlMethod.CHECK,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "check",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )


async def _project(
    app: Application,
    request_body: Mapping[str, JsonValue],
    internal: CheckCommitResult,
    seed: int,
) -> Mapping[str, JsonValue]:
    """Run the daemon's exact post-commit projection sequence for an MCP bridge client."""

    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
        ),
        await _binding(app, request_body, internal, seed),
        internal,
    )
    return public_model_to_wire(projected)


def _unsupported_claim(seed: int, obligation_id: str, parent: str, index: int) -> JsonValue:
    """One completion claim resting on an obligation alone — no admissible evidence."""

    return {
        "event_id": protocol_id("evt_", seed + 100 + index),
        "schema": {"name": "claim_recorded", "version": "1.0.0"},
        "occurred_at": f"2026-07-28T12:00:{index + 1:02d}.000Z",
        "causal_parents": [parent],
        "payload": {
            "claim_id": protocol_id("clm_", seed + 200 + index),
            "claim_kind": "completion",
            "statement": f"Unsupported completion claim {index}.",
            "supporting_refs": [obligation_id],
            "obligation_refs": [obligation_id],
        },
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _work_with_unsupported_claims(
    app: Application, seed: int, count: int
) -> tuple[str, str, JsonValue]:
    """Publish *count* claims whose only support is an obligation, so findings fire."""

    started = await app.start(start_request(seed, title="Check findings projection"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    publish_wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 3)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": [
            {
                "event_id": obligation_event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-28T12:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Publish a result for the check-findings exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "requested_items": [{"item_kind": "change", "value": "workflow-result"}],
                    "status": "open",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
            *(
                _unsupported_claim(seed, obligation_id, obligation_event_id, index)
                for index in range(count)
            ),
        ],
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    return started.session_id, started.writer_id, frontier_json(published.result_frontier)


async def _checked(
    semantic: Literal["disabled", "optional"],
    mode: str,
    seed: int,
    *,
    claims: int = 1,
    max_findings: int = 3,
) -> tuple[Application, Mapping[str, JsonValue], CheckCommitResult, PrivacyPolicy]:
    """Run one real check that produces findings, and hand back everything needed to project it."""

    app, policy = await build_projection_application(semantic, seed=seed, max_findings=max_findings)
    session, writer, frontier = await _work_with_unsupported_claims(app, seed, claims)
    check_wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 6)),
        "session_id": session,
        "writer_id": writer,
        "expected_frontier": frontier,
        "mode": mode,
        "max_findings": str(max_findings),
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    return app, check_wire, checked, policy


async def _semantic_projected(seed: int) -> Mapping[str, JsonValue]:
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=3)
    app = replace(app, semantic_evaluator=_semantic_challenge)
    session, writer, frontier = await _work_with_unsupported_claims(app, seed, 1)
    check_wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 6)),
        "session_id": session,
        "writer_id": writer,
        "expected_frontier": frontier,
        "mode": "semantic_required",
        "max_findings": "3",
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return await _project(app, check_wire, checked, seed + 7)


def _empty_finding_checklist() -> CheckFindingChecklist:
    return CheckFindingChecklist(
        5,
        (),
        "request_receipt",
        FindingTodoCounts(),
    )


async def test_overall_next_uses_current_live_failures_and_allows_disclosed_limits() -> None:
    """Retired or disclosed observed failures must not create another work continuation."""

    _app, _check_wire, checked, _policy = await _checked(
        "disabled", "deterministic_only", 1660, claims=1
    )
    checklist = _empty_finding_checklist()

    ledger = ObservedLedger()
    retired = ledger.fail("pytest -q tests/checks.py")
    live = ledger.fail("pytest -q tests/checks.py")
    case = build_deterministic_case(replay(ledger.prefix), ledger.prefix, CaseAvailabilityFacts())
    continuation = build_overall_next(
        replace(checked, totals=build_check_totals(case), coverage=case_coverage(case)),
        checklist,
        case.projection,
        case.coverage_by_ref,
    )
    assert continuation is not None
    assert continuation.action == "review_recorded_work"
    assert str(live) in continuation.target_refs
    assert str(retired) not in continuation.target_refs
    live_payload = case.projection.results[live].payload
    assert live_payload is not None
    assert str(live_payload.action_id) in continuation.target_refs

    disclosed_ledger = ObservedLedger()
    disclosed = disclosed_ledger.fail("pytest -q tests/checks.py")
    disclosed_ledger.claim(limitations=(disclosed,))
    disclosed_case = build_deterministic_case(
        replay(disclosed_ledger.prefix), disclosed_ledger.prefix, CaseAvailabilityFacts()
    )
    limited = build_overall_next(
        replace(
            checked,
            totals=build_check_totals(disclosed_case),
            coverage=case_coverage(disclosed_case),
        ),
        checklist,
        disclosed_case.projection,
        disclosed_case.coverage_by_ref,
    )
    assert limited is not None
    assert limited.status == "ready_with_limitations"
    assert limited.action == "request_receipt"
    assert limited.acknowledged_incomplete_endpoint == "receipt"


@pytest.mark.parametrize(("semantic", "mode"), _MODES)
async def test_check_with_a_finding_projects_a_complete_success(
    semantic: Literal["disabled", "optional"], mode: str
) -> None:
    """The finding reaches the caller intact — and the mode it was produced under is irrelevant."""

    seed = 1310 + 20 * _MODES.index((semantic, mode))
    app, check_wire, checked, policy = await _checked(semantic, mode, seed)
    # The disclosure boundary must not be what silences the answer: the shipped default really does
    # include the finding summary for the agent context, so the text below is text, not a marker.
    assert DataCategory.FINDING_SUMMARY in policy.agent_context_categories

    projected = await _project(app, check_wire, checked, seed + 7)

    assert projected["ok"] is True
    assert projected["verdict"] == "action_required"
    # Frozen work counters must survive the same privacy/public-model projection as findings,
    # in every configured review mode; no follow-up status call is needed (#971).
    assert checked.totals is not None
    totals = cast(Mapping[str, Mapping[str, str]], projected["totals"])
    assert totals["commands"]["observed"] == "0"
    assert int(totals["findings"]["returned"]) == len(checked.findings)
    assert int(totals["findings"]["actionable_returned"]) > 0
    overall_next = cast(Mapping[str, JsonValue], projected["overall_next"])
    assert overall_next["status"] == "action_required"
    assert overall_next["action"] == "work_open_findings"
    assert checked.finding_checklist is not None
    assert set(cast(tuple[str, ...], overall_next["target_refs"])) == {
        str(item.finding_id) for item in checked.finding_checklist.items
    }
    assert projected["semantic_status"] == (
        "not_requested" if semantic == "disabled" else "succeeded"
    )
    findings = cast(list[Mapping[str, JsonValue]], projected["findings"])
    assert len(findings) == len(checked.findings)
    expected = checked.findings[0]
    finding = findings[0]
    assert finding["finding_id"] == expected.finding_id
    assert finding["kind"] == expected.kind.value
    assert finding["origin"] == expected.origin.value
    assert finding["priority"] == expected.priority
    # The shipped default includes the finding summary for the agent context, so the text the check
    # exists to deliver arrives as text — not as an omission marker.
    assert finding["summary"] == expected.summary
    assert finding["detail"] == expected.detail
    assert finding["subject_refs"] == list(expected.subject_refs)
    assert finding["policy_id"] == expected.policy_id
    assert finding["policy_version"] == expected.policy_version
    assert isinstance(finding["subject_frontier"], Mapping)
    assert isinstance(finding["coverage"], Mapping)
    # A local finding has no AI-powered review provenance; the check result's projected finding
    # requires the key all the same, as an explicit null.
    assert "provenance" in finding
    executions = cast(list[Mapping[str, JsonValue]], projected["policy_executions"])
    assert [item["policy_id"] for item in executions] == [
        "coordination",
        "research-evidence",
        "work-integrity",
    ]


async def test_semantic_finding_projects_with_provenance_and_advice_text() -> None:
    """A second reviewer's challenge reaches the agent with its explanation and provenance."""

    projected = await _semantic_projected(1515)

    assert projected["semantic_status"] == "succeeded"
    assert projected["semantic_reason"] == "semantic_completed"
    findings = cast(list[Mapping[str, JsonValue]], projected["findings"])
    semantic = next(item for item in findings if item["origin"] == "semantic_model_derived")
    assert semantic["summary"] == "The completion claim overstates its evidence"
    assert semantic["detail"] == "Cite admissible evidence or narrow the completion claim."
    provenance = cast(Mapping[str, JsonValue], semantic["provenance"])
    assert provenance["provider_request_id"] == "fake-semantic-request-1"
    assert provenance["status"] == "succeeded"
    assert provenance["reason"] == "semantic_completed"


async def test_projected_finding_origin_and_provenance_pairing_is_strict() -> None:
    projected = await _semantic_projected(1545)
    findings = cast(list[Mapping[str, JsonValue]], projected["findings"])
    semantic = next(item for item in findings if item["origin"] == "semantic_model_derived")
    deterministic = next(item for item in findings if item["origin"] == "deterministic")

    with pytest.raises(ValueError, match="semantic_finding_provenance_missing"):
        CheckProjectedFindingModel.model_validate({**semantic, "provenance": None})
    with pytest.raises(ValueError, match="deterministic_finding_provenance_invalid"):
        CheckProjectedFindingModel.model_validate(
            {**deterministic, "provenance": semantic["provenance"]}
        )


async def test_semantic_required_non_dispatch_projects_the_exact_reason() -> None:
    seed = 1575
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=3)
    app = replace(app, semantic_evaluator=_semantic_unavailable)
    session, writer, frontier = await _work_with_unsupported_claims(app, seed, 1)
    check_wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 6)),
        "session_id": session,
        "writer_id": writer,
        "expected_frontier": frontier,
        "mode": "semantic_required",
        "max_findings": "3",
    }

    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    projected = await _project(app, check_wire, checked, seed + 7)

    assert projected["ok"] is True
    assert projected["verdict"] == "incomplete_check"
    assert projected["semantic_status"] == "unavailable"
    assert projected["semantic_reason"] == "credential_unavailable"
    coverage = cast(Mapping[str, JsonValue], projected["coverage"])
    assert "semantic_relevance_review_not_run" in cast(list[str], coverage["known_gaps"])


async def test_the_maximum_permitted_finding_count_projects() -> None:
    """The ceiling case projects too — the defect was per-element, so the count must be pinned."""

    seed = 1420
    app, check_wire, checked, _policy = await _checked(
        "disabled",
        "deterministic_only",
        seed,
        claims=MAX_FINDINGS_LIMIT + 2,
        max_findings=MAX_FINDINGS_LIMIT,
    )
    assert len(checked.findings) == MAX_FINDINGS_LIMIT

    projected = await _project(app, check_wire, checked, seed + 7)

    assert projected["ok"] is True
    findings = cast(list[Mapping[str, JsonValue]], projected["findings"])
    assert len(findings) == MAX_FINDINGS_LIMIT
    assert len({cast(str, item["finding_id"]) for item in findings}) == MAX_FINDINGS_LIMIT
    # More findings existed than the request admitted, and the caller is told so rather than the
    # remainder vanishing silently.
    assert projected["suppressed_count"] != "0"


async def test_a_malformed_nested_finding_is_still_rejected() -> None:
    """Normalization is structural. It must not become a shape-laundering step.

    The same body, in the same internal container type, with one nested leaf made genuinely
    invalid: projection must still fail, and fail *at that leaf* — not be quietly repaired into
    something the closed model accepts.
    """

    seed = 1450
    app, check_wire, checked, _policy = await _checked("disabled", "deterministic_only", seed)
    projected = await _project(app, check_wire, checked, seed + 7)

    findings = cast(list[Mapping[str, JsonValue]], projected["findings"])
    corrupted = {**findings[0], "priority": "1"}
    body = {
        **projected,
        # Re-freeze into the container the internal result actually uses, so the malformed entry
        # travels the normalization path rather than side-stepping it.
        "findings": tuple(
            JsonObject(corrupted if index == 0 else item) for index, item in enumerate(findings)
        ),
    }

    with pytest.raises(Exception) as raised:  # noqa: PT011 - the pointer is the assertion
        _public_model(ControlMethod.CHECK, body)
    message = str(raised.value)
    assert "findings.0.priority" in message, message
    assert "findings.0\n" not in message, message


async def test_a_well_formed_body_in_the_internal_container_projects() -> None:
    """The control for the case above: same route, nothing corrupted, and it validates."""

    seed = 1480
    app, check_wire, checked, _policy = await _checked("disabled", "deterministic_only", seed)
    projected = await _project(app, check_wire, checked, seed + 7)

    body = {
        **projected,
        "findings": tuple(
            JsonObject(item) for item in cast(list[Mapping[str, JsonValue]], projected["findings"])
        ),
    }
    assert public_model_to_wire(_public_model(ControlMethod.CHECK, body))["ok"] is True


def _nested(containers: int, *, terminal: str = "empty") -> JsonValue:
    """A chain of exactly *containers* nested objects, outermost at depth zero.

    ``terminal="empty"`` ends the chain with an empty object, so the deepest *container* sits at
    ``containers - 1`` and nothing lives below it. That is the shape that separates the two
    depth-counting conventions: a guard that only rejects a node *below* the limit never sees one
    here, while a guard that rejects the container itself does. A scalar terminal hides the
    difference — the leaf beneath the deepest container trips the looser guard by accident — so the
    boundary case deliberately does not use one.
    """

    value: JsonValue = "leaf" if terminal == "scalar" else {}
    for _ in range(containers - 1):
        value = {"next": value}
    return value


def test_the_depth_bound_is_exactly_the_canonical_one() -> None:
    """Normalization must not admit a structure canonicalization would reject.

    The bound is not decorative: everything reaching this boundary was already built under
    ``MAX_JSON_DEPTH``, so a looser guard here would let the projection window accept a shape the
    rest of the protocol treats as too deep. Pinned against ``canonical_encode`` rather than a
    hand-copied constant, so the two cannot drift apart again.
    """

    deepest = _nested(MAX_JSON_DEPTH)
    too_deep = _nested(MAX_JSON_DEPTH + 1)

    # The reference: what the protocol itself admits at each of the two depths.
    canonical_encode(deepest)
    with pytest.raises(ProtocolValueError, match="nesting_too_deep"):
        canonical_encode(too_deep)

    # The boundary agrees, in both directions.
    assert _plain_nested_mappings(deepest) == deepest
    with pytest.raises(ValueError, match="projection_value_too_deep"):
        _plain_nested_mappings(too_deep)


@pytest.mark.parametrize("container", [list, tuple])
def test_the_depth_bound_counts_sequences_too(
    container: Callable[[list[JsonValue]], JsonValue],
) -> None:
    """Arrays nest as readily as objects, and the canonical limit counts them the same way."""

    def chain(depth: int) -> JsonValue:
        value: JsonValue = container([])
        for _ in range(depth - 1):
            value = container([value])
        return value

    assert _plain_nested_mappings(chain(MAX_JSON_DEPTH)) == chain(MAX_JSON_DEPTH)
    with pytest.raises(ValueError, match="projection_value_too_deep"):
        _plain_nested_mappings(chain(MAX_JSON_DEPTH + 1))
