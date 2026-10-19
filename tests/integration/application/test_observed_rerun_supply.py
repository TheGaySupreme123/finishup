"""A re-run FinishUP observed is named as supplied on the next check (issue #1107, W6; ADR-006).

The real application, ledger and check commit with a hermetic reviewer that builds the real review
case. The agent publishes a failing ``uv run pytest -q`` run; the first check's reviewer asks for
its output (``verification_output``). The agent then re-runs the same command in a Codex shell:
the production materialization commits an already-normalized ``PostToolUse`` envelope whose
structural keys are the ones the Codex hook mapping produces (keyed command commitment, the
mapped exit status, one captured tool-output part) into hook-observed rows. The next check's
packet names the observed rows as supplied since the request, a repeat is not dropped as already
supplied while the packet never carried the captured output, and the result's lead says to publish
the output. Host-shaped input from the recorded Codex fixture, both host copies (the hook and the
session stream) and the positive path where the packet carries the captured output are covered
by ``test_observed_rerun_host_copies.py``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.application.check import FinalSemanticEvaluation, check_internal_json
from finishup.application.missing_for_assessment import ReviewFollowUp
from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    observation_author,
)
from finishup.application.semantic_case import build_semantic_case, semantic_case_packet_view
from finishup.domain.events import EvidenceRecordedPayload, media_type_for
from finishup.domain.findings import Finding, SemanticDispatchKind, SemanticProvenance
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import JsonObject, Timestamp
from finishup.kernel.task_facts import register_command_identity_key, requested_command_identity
from finishup.ports.ledger import (
    AppendCommand,
    AppendEntry,
    CheckCommitResult,
    FrozenCase,
    OperationKind,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.ports.semantic import (
    MissingForAssessment,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
    StatusOperationPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_SEED = 5600
_KEY = b"w6-observed-rerun-installation-k"
_COMMAND = "uv run pytest -q"
_ACTION = protocol_id("act_", _SEED + 3)
_TARGET = protocol_id("res_", _SEED + 5)


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    """The service registers the installation key at startup; the hook commits with the same."""

    register_command_identity_key(_KEY)
    try:
        yield
    finally:
        register_command_identity_key(None)


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
        provider_request_id=f"fake-observed-rerun-{seed}",
        egress_authorization_id=protocol_id("aut_", seed + 2),
        request_commitment="hmac-sha256:" + "b" * 64,
    )


@dataclass
class _Reviewer:
    """Builds the real case and keeps asking for the target run's output."""

    cases: list[SemanticCase] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        follow_up: ReviewFollowUp | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        case = build_semantic_case(
            case_id=protocol_id("cas_", _SEED + len(self.cases)),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.EXPANDED,
            review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
            policy_id=protocol_id("pvy_", _SEED),
            policy_version="1",
            follow_up=follow_up,
        )
        self.cases.append(case)
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment("verification_output", (_TARGET,), "The test output."),
                ),
                review_summary="The failing run's output is not in the packet.",
            ),
            provenance=_provenance(_SEED + 100 + 10 * len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            review_input_manifest=case.packet.input_manifest,
            case_excerpt_refs=frozenset(
                item.source_ref for item in case.items if item.section == "excerpt"
            ),
        )


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in cast(Mapping[str, object], value).items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in cast(Sequence[object], value)]
    return value


def _json(value: object) -> str:
    """One canonical spelling of a wire value, whichever (frozen) container types hold it."""

    return json.dumps(_thaw(value), sort_keys=True)


def _draft(event: int, name: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "event_id": protocol_id("evt_", event),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-10-12T12:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _check(app: Any, started: Any, frontier: Any, tail: int) -> CheckCommitResult:
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", tail)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(frontier),
                "mode": "semantic_required",
                "max_findings": "5",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    return checked


async def _observed_rerun(app: Any, started: Any, frontier: Any) -> tuple[Any, str, str]:
    """Commit the production materialization of one Codex shell re-run of ``_COMMAND``."""

    commitment = requested_command_identity(_COMMAND)
    assert commitment is not None
    captured_id = protocol_id("obj_", _SEED + 40)
    output = b"3 passed, 0 failed\n"
    envelope = ObservationEnvelope(
        session_commitment="hmac-sha256:" + "cd" * 32,
        event_kind="PostToolUse",
        source_identity="hook:w6-rerun",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 41, "hmac-sha256:" + "ab" * 32, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-10-12T12:05:00.000Z"),
        structural_payload=JsonObject(
            {
                # The keys the Codex hook mapping derives from a recorded ``PostToolUse`` payload
                # (``exit_status`` is the mapping's own fact, not a host field).
                "tool_name": "Bash",
                "tool_call_id": "call-w6-rerun",
                "hook_name": "PostToolUse",
                "result_status": "success",
                "success": True,
                "exit_status": 0,
                "command_commitment": commitment,
                "command_composition": "single",
            }
        ),
        content_object_refs=(captured_id,),
        gap_codes=(),
    )
    batch = materialize_observation_envelope(
        envelope,
        task_id=started.task_id,
        captured_content=(
            ObservationContentManifest(
                object_id=captured_id,
                envelope_digest="sha256:" + "b" * 64,
                content_kind=ObservationContentKind.TOOL_OUTPUT,
                part_index=0,
                part_count=1,
                redacted=False,
                content_digest="sha256:" + "a" * 64,
                content_bytes=len(output),
            ),
        ),
    )
    assert batch.skip_reason is None
    ledger, objects = next(iter(app.runtime.resources.values()))
    now = app.clock.now_utc()
    captured = await objects.finalize(
        await objects.stage(
            ObjectSource(data=output, declared_size=len(output)),
            ObjectMetadata(ObjectKind.CAPTURED_CONTENT, "text/plain", started.task_id, now),
            object_id=captured_id,
        )
    )
    entries: list[AppendEntry] = []
    for item in batch.drafts:
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(item.draft.schema.name), started.task_id, now
        )
        ref = await objects.finalize(
            await objects.stage(
                ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                metadata,
            )
        )
        entries.append(
            AppendEntry(
                item.draft,
                observation_author(),
                ref,
                ref.commitment,
                metadata.media_type,
                ref.plaintext_size,
                batch.channel,
                batch.coverage,
                item.projection_status,
            )
        )
    appended = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", _SEED + 42),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            int(frontier.sequence),
            tuple(entries),
            None,
            (captured,),
        )
    )
    names = {item.draft.schema.name: item.draft.payload for item in batch.drafts}
    evidence = cast(EvidenceRecordedPayload, names["evidence_recorded"])
    result = names["result_recorded"]
    return appended.result_frontier, str(getattr(result, "result_id")), str(evidence.evidence_id)


async def test_an_observed_rerun_answers_the_request_on_the_next_check() -> None:
    app, _policy = await build_projection_application("optional", seed=_SEED, max_findings=5)
    reviewer = _Reviewer()
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(_SEED, title="Observed re-run supply"))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", _SEED + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    _draft(
                        _SEED + 2,
                        "action_recorded",
                        {
                            "action_id": _ACTION,
                            "action_kind": "command",
                            "description": "Ran the unit tests",
                            "command": _COMMAND,
                        },
                    ),
                    _draft(
                        _SEED + 4,
                        "result_recorded",
                        {"result_id": _TARGET, "action_id": _ACTION, "outcome": "failure"},
                    ),
                    _draft(
                        _SEED + 6,
                        "claim_recorded",
                        {
                            "claim_id": protocol_id("clm_", _SEED + 7),
                            "claim_kind": "completion",
                            "statement": "The unit tests pass.",
                            "supporting_refs": [_TARGET],
                        },
                    ),
                ],
            }
        )
    )
    first = await _check(app, started, published.result_frontier, _SEED + 10)
    assert [(item.kind, item.target_refs) for item in first.missing_for_assessment] == [
        ("verification_output", (_TARGET,))
    ]

    frontier, observed_result, observed_output = await _observed_rerun(
        app, started, first.result_frontier
    )
    reviewed = len(reviewer.cases)
    second = await _check(app, started, frontier, _SEED + 50)

    # The next packet lists the observed result and its captured output as supplied since.
    prior = next(
        item
        for item in reviewer.cases[reviewed].items
        if item.item_id == "prior-missing-for-assessment"
    )
    assert observed_result.encode() in prior.content and observed_output.encode() in prior.content
    # This hermetic reviewer builds the case without loading any captured bytes (no
    # ``CapturedSemanticContent``), so the observed output is omitted as not recorded: the packet
    # named the observed rows but never carried the captured output, as when Private or the
    # repository-excerpt gate withholds it. The repeat is not dropped as already supplied for
    # material the reviewer could not see; the item stays the agent's, and the result's lead says
    # to publish the output, even after a re-run.
    excerpts = {
        item.source_ref for item in reviewer.cases[reviewed].items if item.section == "excerpt"
    }
    assert observed_output not in excerpts
    assert [(item.kind, item.availability) for item in second.missing_for_assessment] == [
        ("verification_output", "agent_suppliable")
    ]
    assert "semantic_missing_already_supplied" not in second.coverage.known_gaps
    lead = check_internal_json(second)["agent_next"]
    assert type(lead) is str and lead.startswith("Next: supply_missing_input")
    assert f"verification_output for {_TARGET}" in lead
    assert "result_recorded whose action_id is the target's action" in lead
    assert "Publish it even after a re-run" in lead
    assert "counts only once it reaches the reviewer" in lead

    # A lost or cut result is recovered from the operation page: it carries the same verdict,
    # lead, next action and missing items a same-id resend returns (RC6a, W6).
    replay = await _check(app, started, frontier, _SEED + 50)
    assert replay.outcome == "replayed"
    replayed = check_internal_json(replay)
    status = await app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", _SEED + 55)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": protocol_id("req_", _SEED + 50)},
            }
        )
    )
    assert isinstance(status.page, StatusOperationPageModel)
    outcome = status.page.check_outcome
    assert outcome is not None
    page = outcome.model_dump(mode="json", exclude_none=True)
    assert page["agent_next"] == replayed["agent_next"] == lead
    assert page["verdict"] == replayed["verdict"]
    assert page["semantic_conclusion"] == "insufficient_packet"
    assert _json(page["overall_next"]) == _json(replayed["overall_next"])
    assert _json(page["missing_for_assessment"]) == _json(replayed["missing_for_assessment"])
    assert [(item.kind, item.availability) for item in outcome.missing_for_assessment] == [
        ("verification_output", "agent_suppliable")
    ]

    # The agent publishes the output as the lead says; the next repeat is already supplied.
    supplied = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", _SEED + 60)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(second.result_frontier),
                "event_drafts": [
                    _draft(
                        _SEED + 61,
                        "result_recorded",
                        {
                            "result_id": protocol_id("res_", _SEED + 62),
                            "action_id": _ACTION,
                            "outcome": "success",
                            "summary": "3 passed, 0 failed",
                        },
                    )
                ],
            }
        )
    )
    third = await _check(app, started, supplied.result_frontier, _SEED + 70)
    # #1118 unit 4 (AIM-5): two insufficient reviews in a row with no edit since stop the round
    # for a required check too. Publishing the output does not re-arm it, so this check skips the
    # unchanged redispatch and reads incomplete_check instead of asking a third time.
    assert third.semantic_status is SemanticStatus.NOT_REQUESTED
    assert "semantic_review_skipped_insufficient_packet" in third.coverage.known_gaps
    assert third.verdict.value == "incomplete_check"
