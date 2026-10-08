"""A recorded blocker is disclosed, named in status, and verified once by the closing review.

Issues #976 and #977 (TB4 validation, pretrain-shard-corruption): an agent recorded
``yoetz-blocker:dependency_unavailable`` for "no original snapshot found" although the task said
the data was recoverable. Yoetz honoured it silently. These cases run the real ready composition
with a hermetic reviewer:

* status names the blocked obligation, its claimed kind and the decision (ids and the closed kind
  only) and discloses it as a standing limitation instead of failing validation;
* the closing review's case lists the blocker in its question set, keeps the blocker decision
  first in the decision section, and its rationale (agent text) passes through privacy redaction;
* a reviewer challenge that cites the contradicted blocker becomes an AI-powered finding the
  agent answers with ``respond``, and the next review carries that answer.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
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
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.semantic_case import (
    build_semantic_case,
    semantic_case_packet_view,
    semantic_case_to_candidate_context,
)
from yoetz.application.service import Application
from yoetz.cli.closure_gate import BLOCKER_RECHECK_ITEM, closure_gate_from_readiness
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.kernel.task_facts import OBLIGATION_BLOCKED_GAP
from yoetz.ports.control import ControlMethod
from yoetz.ports.ledger import CheckCommitResult, FrozenCase
from yoetz.ports.privacy import EffectivePrivacyPolicy
from yoetz.ports.semantic import (
    ReviewerChallenge,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.models import (
    CheckRequest,
    DataCategory,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "8" * 64
_SECRET = "bounded-but-suspicious-value"
_RATIONALE = f"No original snapshot was found under /data. auth_token: '{_SECRET}'"


def _provenance(seed: int) -> SemanticProvenance:
    return SemanticProvenance(
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
        semantic_attempt_id=protocol_id("att_", seed),
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=protocol_id("egr_", seed + 1),
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id=f"fake-blocker-{seed}",
        egress_authorization_id=protocol_id("aut_", seed + 2),
        request_commitment="hmac-sha256:" + "c" * 64,
    )


@dataclass
class _Reviewer:
    """A hermetic reviewer that records each case it was shown and answers from a script."""

    answers: list[Callable[[SemanticCase], SemanticJudgment]]
    cases: list[SemanticCase] = field(default_factory=lambda: [])
    seed: int = 9700
    profile: ReviewContextProfile = ReviewContextProfile.GOAL_AWARE

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation, require_complete_specification
        case = build_semantic_case(
            case_id=protocol_id("cas_", self.seed + len(self.cases)),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=self.profile,
            review_selection=ReviewSelectionPolicy.for_profile(self.profile),
            policy_id=protocol_id("pvy_", self.seed),
            policy_version="1",
            final_review=final_review,
        )
        self.cases.append(case)
        judgment = self.answers[len(self.cases) - 1](case)
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=judgment,
            provenance=_provenance(self.seed + 10 * len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            provider_input_manifest=provider_bound_manifest(),
        )


@dataclass(frozen=True, slots=True)
class _Session:
    app: Application
    session_id: str
    writer_id: str
    obligation_id: str
    decision_event_id: str


def _draft(event_id: str, name: str, payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-10-06T12:00:00.000Z",
        "causal_parents": [],
        "payload": dict(payload),
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _session(reviewer: _Reviewer, seed: int) -> tuple[_Session, JsonValue]:
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(
        start_request(seed, title="Recover the corrupted pretraining shards (data is recoverable)")
    )
    obligation = protocol_id("obl_", seed + 1)
    decision = protocol_id("evt_", seed + 4)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 5)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    _draft(
                        protocol_id("evt_", seed + 2),
                        "obligation_published",
                        {
                            "obligation_id": obligation,
                            "description": "Restore the corrupted shards and rerun pretraining.",
                            "evidence_expectation": "A recorded successful pretraining run.",
                            "status": "open",
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 3),
                        "plan_published",
                        {
                            "plan_version": 1,
                            "summary": "Restore the shards, then rerun pretraining.",
                            "obligation_refs": [obligation],
                        },
                    ),
                    _draft(
                        decision,
                        "decision_recorded",
                        {
                            "statement": "Stop: the original data is gone.\n"
                            "yoetz-blocker:dependency_unavailable",
                            "rationale": _RATIONALE,
                            "authority": "harness:codex",
                            "affected_obligation_ids": [obligation],
                        },
                    ),
                ],
            }
        )
    )
    session = _Session(app, started.session_id, started.writer_id, obligation, decision)
    return session, frontier_json(published.result_frontier)


async def _check(session: _Session, frontier: JsonValue, seed: int) -> CheckCommitResult:
    checked = await session.app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "mode": "semantic_required",
                "max_findings": "5",
                "final_review": True,
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


def _challenge_blocker(session: _Session) -> Callable[[SemanticCase], SemanticJudgment]:
    def answer(case: SemanticCase) -> SemanticJudgment:
        assert session.decision_event_id in case.frontier_refs
        challenge = ReviewerChallenge(
            FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
            "The recorded dependency_unavailable blocker contradicts the task",
            tuple(sorted((session.decision_event_id, session.obligation_id), key=str.encode)),
            "The task statement says the corrupted data is recoverable, yet the agent recorded "
            "the missing snapshot as a blocker outside its control.",
            "The task may have meant only the snapshot copy, not the shards themselves.",
            "Recover the shards from the redundant copies the task describes and rerun.",
            "act",
            "The recovery path may need a tool the environment lacks.",
        )
        return SemanticJudgment("challenges_returned", (challenge,))

    return answer


def _no_challenges(_case: SemanticCase) -> SemanticJudgment:
    return SemanticJudgment("no_material_discrepancy", ())


async def test_status_names_the_blocker_and_discloses_it_without_failing() -> None:
    seed = 9100
    session, _frontier = await _session(_Reviewer([]), seed)
    status = await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 20)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "compact",
                "limit": "1",
            }
        )
    )
    readiness = status.closure_readiness
    assert readiness.blocking_conditions[0] == "obligations_open"
    assert readiness.agent_actionable is not None
    assert "obligations_open" not in readiness.agent_actionable
    assert readiness.standing_limitations is not None
    assert OBLIGATION_BLOCKED_GAP in readiness.standing_limitations
    assert readiness.blocked_obligations is not None
    [blocked] = readiness.blocked_obligations
    assert blocked.obligation_id == session.obligation_id
    assert blocked.blocker_kind == "dependency_unavailable"
    assert blocked.decision_event_id == session.decision_event_id
    # The wire form carries ids and the closed kind only, never the rationale.
    wire = status.as_json()
    assert _SECRET not in str(wire)
    assert "snapshot" not in str(cast(Mapping[str, Any], wire)["closure_readiness"])

    # The MCP bridge projection keeps the structural rows (ids and the closed kind only).
    request_wire = {
        **request_base(protocol_id("req_", seed + 20)),
        "session_id": session.session_id,
        "writer_id": session.writer_id,
        "view": "compact",
        "limit": "1",
    }
    projected = await project_case(
        session.app,
        ProjectionCase("status", ControlMethod.STATUS, request_wire, status),
        seed + 21,
    )
    projected_rows = cast(
        Mapping[str, Any], cast(Mapping[str, Any], projected)["closure_readiness"]
    )["blocked_obligations"]
    assert projected_rows == [
        {
            "obligation_id": session.obligation_id,
            "blocker_kind": "dependency_unavailable",
            "decision_event_id": session.decision_event_id,
        }
    ]

    # The receipt still discloses the blocked obligation as a standing limitation.
    receipt = await session.app.receipt(
        ReceiptRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 22)),
                "task_id": status.task_id,
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier_json(status.head_frontier),
                "format": "markdown",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert OBLIGATION_BLOCKED_GAP in str(receipt)

    # The Stop gate re-asks this blocker once, naming the obligation and the claimed kind.
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence=str(status.head_frontier.sequence),
        frontier_digest=status.head_frontier.head_digest,
        observation_pending=False,
    )
    assert gate is not None
    assert BLOCKER_RECHECK_ITEM in gate.items
    assert f"{session.obligation_id} (dependency_unavailable)" in gate.text
    again = closure_gate_from_readiness(
        readiness,
        frontier_sequence=str(status.head_frontier.sequence),
        frontier_digest=status.head_frontier.head_digest,
        observation_pending=False,
        reasked_blockers=frozenset(gate.blocker_keys),
    )
    # A closing review is still owed here, so the gate may continue for that, never the blocker.
    assert again is None or BLOCKER_RECHECK_ITEM not in again.items


async def test_closing_review_challenges_a_contradicted_blocker_and_the_agent_answers() -> None:
    seed = 9200
    reviewer = _Reviewer([])
    session, frontier = await _session(reviewer, seed)
    reviewer.answers.extend([_challenge_blocker(session), _no_challenges])

    first = await _check(session, frontier, seed + 30)
    [case] = reviewer.cases
    # The final phase lists the blocker by ids and kind in its own question.
    blocker_question = case.question_set[-1]
    assert blocker_question.startswith("Recorded blockers: ")
    assert (
        f"decision {session.decision_event_id} declares yoetz-blocker:dependency_unavailable"
        f" for {session.obligation_id}"
    ) in blocker_question
    assert "recoverable" in blocker_question
    # The blocker decision leads the decision section, so the cap never drops it.
    assert case.packet.decision_item_ids[0] == f"decision-{session.decision_event_id}"

    # The rationale is agent text: it reaches the reviewer only through privacy enforcement,
    # which withholds the offending span and keeps the rest of the blocker.
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        "ins_97000000-0000-4000-8000-000000000001",
        "hmac-sha256:" + "1" * 64,
        "tsk_97000000-0000-4000-8000-000000000002",
    )
    candidate = semantic_case_to_candidate_context(
        case,
        request_id=protocol_id("req_", seed + 31),
        scope=scope,
        provider_binding=ProviderBinding(
            "fake", "fake-model", "fake-provider", "1.0.0", "external"
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective_policy(scope))
    minimized = enforcer.minimize_and_scan(
        classified,
        PrivacyDecision(
            tuple(sorted((item.item_id for item in candidate.items), key=str.encode)),
            (),
            PrivacyOutcome.COMPLETED,
            None,
        ),
    )
    prepared = minimized.prepared_bytes
    assert _SECRET.encode() not in prepared
    document = cast(Mapping[str, JsonValue], strict_json_parse(prepared))
    decision_rows = [
        row
        for row in cast(list[Mapping[str, JsonValue]], document["items"])
        if row.get("item_id") == f"decision-{session.decision_event_id}"
    ]
    assert len(decision_rows) == 1
    content = str(decision_rows[0].get("content"))
    assert "yoetz-blocker:dependency_unavailable" in content
    assert "No original snapshot was found" in content
    # Egress replaces only the credential-like value, in place (issue #982).
    from yoetz.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER

    assert EGRESS_CREDENTIAL_PLACEHOLDER.decode() in content
    assert any(
        "Recorded blockers: " in str(question)
        for question in cast(list[JsonValue], document["question_set"])
    )

    # The challenge is an ordinary AI-powered finding that names the blocker decision.
    raised = next(
        item for item in first.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert session.decision_event_id in raised.subject_refs
    assert session.obligation_id in raised.subject_refs

    responded = await session.app.respond(
        RespondRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 40)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier_json(first.result_frontier),
                "finding_id": raised.finding_id,
                "finding_frontier": frontier_json(first.result_frontier),
                "disposition": "rejected",
                "reason": "The redundant copies are also corrupted; the task's backup is absent.",
            }
        )
    )
    assert responded.response.disposition == "rejected"

    await _check(session, frontier_json(responded.result_frontier), seed + 50)
    second = reviewer.cases[1]
    texts = {item.item_id: item.content.decode("utf-8") for item in second.items}
    assert (
        "redundant copies are also corrupted"
        in texts[f"prior-finding-response-{raised.finding_id}"]
    )
    # The blocker is still recorded, so the closing review is asked about it again.
    assert second.question_set[-1].startswith("Recorded blockers: ")


def _effective_policy(scope: AuthorizationScope) -> EffectivePrivacyPolicy:
    """A local policy for exercising the enforcer's classification and span redaction."""

    disabled = tuple(
        ChannelPolicy(
            channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
        )
        for channel in sorted(EgressChannel, key=lambda item: item.value)
    )
    policy = PrivacyPolicy(
        policy_id="pvy_97000000-0000-4000-8000-000000000004",
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=False,
        effective_scope=scope,
        channel_policies=disabled,
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(DataCategory.FINDING_SUMMARY,),
        agent_context_data_classes=(DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
        ),
        created_at=datetime(2026, 10, 6, tzinfo=UTC),
    )
    return EffectivePrivacyPolicy(policy, 1, _DIGEST)


async def test_a_withheld_decision_still_names_the_blocker_by_id_only() -> None:
    """With a profile that sends no decision text, the question still lists the blocker by ids,
    and the reviewer is told to cite only refs the packet makes citable."""

    seed = 9300
    reviewer = _Reviewer([_no_challenges], profile=ReviewContextProfile.STRUCTURAL)
    session, frontier = await _session(reviewer, seed)
    checked = await _check(session, frontier, seed + 30)
    assert checked.findings is not None
    [case] = reviewer.cases
    assert case.packet.decision_item_ids == ()
    question = case.question_set[-1]
    assert f"decision {session.decision_event_id}" in question
    assert "citable_refs" in question
    assert all(_SECRET.encode() not in item.content for item in case.items)
