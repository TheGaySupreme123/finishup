"""A recorded blocker is disclosed, named in status, and verified once by the closing review.

Issues #976 and #977 (TB4 validation, pretrain-shard-corruption): an agent recorded
``finishup-blocker:dependency_unavailable`` for "no original snapshot found" although the task said
the data was recoverable. FinishUP honoured it silently. These cases run the real ready composition
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
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.semantic_case import (
    build_semantic_case,
    semantic_case_packet_view,
    semantic_case_to_candidate_context,
)
from finishup.application.service import Application
from finishup.cli.closure_gate import BLOCKER_RECHECK_ITEM, closure_gate_from_readiness
from finishup.domain.findings import (
    Finding,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.privacy import (
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
from finishup.kernel.task_facts import OBLIGATION_BLOCKED_GAP
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import CheckCommitResult, FrozenCase
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.ports.semantic import (
    ReviewerChallenge,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.models import (
    CheckRequest,
    DataCategory,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StartRequest,
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
                            "finishup-blocker:dependency_unavailable",
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


async def _confirm(
    session: _Session, frontier: JsonValue, seed: int, *, dry_run: bool = False
) -> Any:
    """Publish the same finishup-blocker line again in a later decision (#985)."""

    return await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                **({"dry_run": True} if dry_run else {}),
                "event_drafts": [
                    _draft(
                        protocol_id("evt_", seed + 1),
                        "decision_recorded",
                        {
                            "statement": "Still blocked after the challenge.\n"
                            "finishup-blocker:dependency_unavailable",
                            "rationale": "Reconsidered: the source is outside the workspace.",
                            "authority": "harness:codex",
                            "affected_obligation_ids": [session.obligation_id],
                        },
                    )
                ],
            }
        )
    )


def _body(result: object) -> Mapping[str, Any]:
    """The JSON body of an internal publish result or a public (dry-run) result model."""

    if hasattr(result, "as_json"):
        return cast(Mapping[str, Any], cast(Any, result).as_json())
    return cast(Mapping[str, Any], cast(Any, result).model_dump(mode="json", exclude_none=True))


def _notices(result: object) -> list[tuple[str, str, str]]:
    body = _body(result)
    return [
        (row["obligation_id"], row["blocker_kind"], row["notice"])
        for row in body.get("blocker_notices", ())
    ]


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


async def _compact_status(session: _Session, seed: int) -> Any:
    return await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "compact",
                "limit": "1",
            }
        )
    )


async def test_a_first_blocker_is_claimed_and_challenged_until_confirmed() -> None:
    """#985 (C2b, C4): the publish result challenges a first blocker, dry runs included, and
    readiness keeps the obligation as agent work until a later decision confirms it."""

    seed = 9050
    session, frontier = await _session(_Reviewer([]), seed)
    claimed = await _compact_status(session, seed + 20)
    readiness = claimed.closure_readiness
    assert readiness.state == "action_required"
    assert "obligation_blocker_unconfirmed" in readiness.agent_actionable
    assert "obligations_open" not in readiness.agent_actionable
    assert OBLIGATION_BLOCKED_GAP not in readiness.standing_limitations
    [row] = readiness.blocked_obligations
    assert (row.confirmation, row.confirmation_event_id) == ("claimed", None)

    preview = await _confirm(session, frontier, seed + 30, dry_run=True)
    assert _notices(preview) == [
        (session.obligation_id, "dependency_unavailable", "blocker_confirmed")
    ]
    # The dry run changed nothing.
    again = await _compact_status(session, seed + 40)
    assert "obligation_blocker_unconfirmed" in again.closure_readiness.agent_actionable

    confirmed = await _confirm(session, frontier, seed + 50)
    assert _notices(confirmed) == [
        (session.obligation_id, "dependency_unavailable", "blocker_confirmed")
    ]
    status = await _compact_status(session, seed + 60)
    readiness = status.closure_readiness
    assert "obligation_blocker_unconfirmed" not in readiness.agent_actionable
    assert OBLIGATION_BLOCKED_GAP in readiness.standing_limitations
    [row] = readiness.blocked_obligations
    assert row.confirmation == "confirmed"
    assert row.confirmation_event_id == protocol_id("evt_", seed + 51)


async def test_publish_challenges_a_first_blocker_and_flags_one_on_finished_work() -> None:
    from finishup.protocol.models import PUBLISH_BLOCKER_NOTICE_TEXTS

    seed = 9070
    reviewer = _Reviewer([])
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title="Recover the corrupted shards"))
    open_obligation = protocol_id("obl_", seed + 1)
    blocker = _draft(
        protocol_id("evt_", seed + 4),
        "decision_recorded",
        {
            "statement": "finishup-blocker:dependency_unavailable",
            "rationale": "dependency_unavailable: authoritative historical source",
            "authority": "harness:codex",
            "affected_obligation_ids": [open_obligation],
        },
    )
    drafts = [
        _draft(
            protocol_id("evt_", seed + 2),
            "obligation_published",
            {
                "obligation_id": open_obligation,
                "description": "Recover exact intended training examples",
                "evidence_expectation": "The recovered shards pass the verifier.",
                "status": "open",
            },
        ),
        _draft(
            protocol_id("evt_", seed + 3),
            "plan_published",
            {
                "plan_version": 1,
                "summary": "Recover the shards.",
                "obligation_refs": [open_obligation],
            },
        ),
        blocker,
    ]
    base = {
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": drafts,
    }
    preview = await app.publish_work(
        PublishWorkRequest.model_validate(
            {**request_base(protocol_id("req_", seed + 5)), **base, "dry_run": True}
        )
    )
    expected = [(open_obligation, "dependency_unavailable", "blocker_claimed")]
    assert _notices(preview) == expected
    # The same line twice in one batch skips the challenge, so it is still only claimed.
    doubled = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 8)),
                **base,
                "dry_run": True,
                "event_drafts": [*drafts, {**blocker, "event_id": protocol_id("evt_", seed + 9)}],
            }
        )
    )
    assert _notices(doubled) == expected
    published = await app.publish_work(
        PublishWorkRequest.model_validate({**request_base(protocol_id("req_", seed + 6)), **base})
    )
    assert _notices(published) == expected
    text = _body(published)["blocker_notices"][0]["text"]
    assert text == PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"]
    assert "Repair the obligation first" in text
    assert "A FinishUP limit" in text and "never a" in text and "respond self_verified" in text
    assert "recoverable" in text
    assert "publish the same finishup-blocker line for it again in a later" in text
    # The MCP bridge projection keeps the notices: closed codes, ids and fixed text only.
    request_wire = {**request_base(protocol_id("req_", seed + 6)), **base}
    projected = await project_case(
        app,
        ProjectionCase(
            "publish_work",
            ControlMethod.PUBLISH_WORK,
            cast(Mapping[str, JsonValue], request_wire),
            cast(Any, published),
        ),
        seed + 7,
    )
    assert cast(Mapping[str, Any], projected)["blocker_notices"] == [
        {
            "obligation_id": open_obligation,
            "blocker_kind": "dependency_unavailable",
            "notice": "blocker_claimed",
            "text": PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"],
        }
    ]
    # A replay of the same request returns the same notices.
    replayed = await app.publish_work(
        PublishWorkRequest.model_validate({**request_base(protocol_id("req_", seed + 6)), **base})
    )
    assert _notices(replayed) == expected


async def test_status_names_the_blocker_and_discloses_it_without_failing() -> None:
    seed = 9100
    session, frontier = await _session(_Reviewer([]), seed)
    await _confirm(session, frontier, seed + 10)
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
            "confirmation": "confirmed",
            "confirmation_event_id": protocol_id("evt_", seed + 11),
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

    # The Stop gate may re-ask a blocker once (its wording is the gate's), never in a loop.
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence=str(status.head_frontier.sequence),
        frontier_digest=status.head_frontier.head_digest,
        observation_pending=False,
    )
    if gate is not None and BLOCKER_RECHECK_ITEM in gate.items:
        assert f"{session.obligation_id} (dependency_unavailable)" in gate.text
    again = closure_gate_from_readiness(
        readiness,
        frontier_sequence=str(status.head_frontier.sequence),
        frontier_digest=status.head_frontier.head_digest,
        observation_pending=False,
        reasked_blockers=frozenset(() if gate is None else gate.blocker_keys),
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
        f"decision {session.decision_event_id} declares finishup-blocker:dependency_unavailable"
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
    assert "finishup-blocker:dependency_unavailable" in content
    assert "No original snapshot was found" in content
    # Egress replaces only the credential-like value, in place (issue #982).
    from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER

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


# tb4v2/tb4n1 pretrain-shard-corruption (#978): the reviewer accepted
# "dependency_unavailable: authoritative historical source" on the task's main deliverable,
# although the statement said the final state should recover the intended training examples.
_PRETRAIN_STATEMENT = (
    "Some pretraining shards were corrupted. The final state should recover the intended "
    "training examples and rerun pretraining."
)
_PRETRAIN_GOLDEN = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "tb4_replay"
    / "pretrain_blocker_review_question.json"
)


async def test_pretrain_blocker_question_requires_a_challenge_on_the_main_deliverable() -> None:
    from finishup.application.semantic_case import BLOCKER_REVIEW_INSTRUCTION

    seed = 9300
    reviewer = _Reviewer([_no_challenges])
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(
        StartRequest.model_validate(
            {
                **start_request(seed, title="Pretrain shard corruption").model_dump(
                    mode="json", exclude_none=True
                ),
                "task_statement": _PRETRAIN_STATEMENT,
            }
        )
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
                            "description": "Recover exact intended training examples",
                            "evidence_expectation": "The recovered shards match the intended "
                            "examples and pretraining reruns.",
                            "status": "open",
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 3),
                        "plan_published",
                        {
                            "plan_version": 1,
                            "summary": "Recover the shards, then rerun pretraining.",
                            "obligation_refs": [obligation],
                        },
                    ),
                    _draft(
                        decision,
                        "decision_recorded",
                        {
                            "statement": "finishup-blocker:dependency_unavailable",
                            "rationale": "dependency_unavailable: authoritative historical source",
                            "authority": "harness:codex",
                            "affected_obligation_ids": [obligation],
                        },
                    ),
                ],
            }
        )
    )
    session = _Session(app, started.session_id, started.writer_id, obligation, decision)
    await _check(session, frontier_json(published.result_frontier), seed + 30)
    [case] = reviewer.cases

    question = case.question_set[-1]
    golden = cast(Mapping[str, Any], strict_json_parse(_PRETRAIN_GOLDEN.read_bytes()))
    # The golden is recorded tb4 evidence from before the rename (ADR-048) and stays byte-identical;
    # the question differs from it only in the product name and the marker spelling.
    assert question == (
        cast(str, golden["question_template"])
        .replace("<decision>", decision)
        .replace("<obligation>", obligation)
        .replace("yoetz-blocker:", "finishup-blocker:")
        .replace("Yoetz or this review", "FinishUP or this review")
    )
    assert question.endswith(BLOCKER_REVIEW_INSTRUCTION)
    assert "You must challenge it" in question
    # The statement says the data is recoverable: that, not "main deliverable", forces it.
    assert "the task statement says the outcome is achievable or the data recoverable" in question
    assert "the data recoverable" in question
    # The obligation's own text and the statement reach the reviewer as their packet items, the
    # question names the obligation item it must quote, and the blocker is listed even though the
    # agent has not confirmed it yet.
    assert f"obligation-{obligation}" in case.packet.obligation_item_ids
    assert "obligation-<obligation id>" in question
    texts = {item.item_id: item.content.decode("utf-8") for item in case.items}
    assert "Recover exact intended training examples" in texts[f"obligation-{obligation}"]
    assert any("recover the intended training examples" in text for text in texts.values()), (
        "the task statement must be in the packet"
    )
