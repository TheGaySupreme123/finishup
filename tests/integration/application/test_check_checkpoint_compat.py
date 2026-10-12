"""Replay compatibility for persisted local-result checkpoints (issue #340).

A checkpoint written before a finding-wording change must replay as "superseded — recompute"
on the same request id, never as non-retryable ``STORAGE_CORRUPT``; a checkpoint whose content
is actually broken must stay corrupt.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import NoReturn, cast

import pytest

from builders.ledger_adapters import MemoryObjects, ownership_fence
from builders.start_application import (
    MemoryStartRuntime,
    StartTestClock,
    protocol_id,
    start_composition,
    start_request,
)
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.service import Application, VerificationPolicy
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.values import Frontier, session_id
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import (
    CheckCommitResult,
    CheckPhase,
    OperationLease,
    OperationState,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import CheckRequest, FrontierModel, PublishWorkRequest

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_STALE_WORDING_MARKER = " [pre-upgrade wording]"


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _CheckRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing."""

    async def route(self, command: RouteCommand) -> TaskRuntime:
        assert command.writer_id is not None
        task_id, resources = next(iter(self.resources.items()))
        ledger, objects = resources
        assert (command.session_id, command.writer_id) in self.owners
        return TaskRuntime(
            task_id,
            command.session_id,
            command.writer_id,
            frozenset(
                {
                    RuntimeCapability.WRITE,
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                }
            ),
            ledger,
            objects,
            cast(ImporterPort, _IdleImporter()),
            "0.1.0",
            "0.1.0",
            "0.1",
            "1.0.0",
            ownership_fence(),
        )


async def _semantic_disabled(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("semantic_evaluator_called_in_deterministic_mode")


def _unused(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("privacy_or_receipt_path_reached_in_checkpoint_compat_test")


def _request_base(request_id: str) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


@dataclass(slots=True)
class _WedgedCheck:
    app: Application
    clock: StartTestClock
    ledger: MemoryLedgerAdapter
    objects: MemoryObjects
    writer_id: str
    request: CheckRequest


async def _wedge_check_at_local_ready(monkeypatch: pytest.MonkeyPatch) -> _WedgedCheck:
    """Drive one local check to a durable LOCAL_READY checkpoint, then crash it."""

    start_app, start_runtime, clock, catalog = start_composition()
    runtime = _CheckRuntime(clock, start_runtime.ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=start_runtime.ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, object()),
        status_cursor_key=b"checkpoint-compat-cursor-key",
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_disabled,
        disclosure_scope_for=_unused,
        receipt_version_resolver=_unused,
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )

    started = await app.start(start_request(910, title="Checkpoint compat"))
    obligation_id = protocol_id("obl_", 911)
    obligation_event_id = protocol_id("evt_", 913)
    publish_wire = {
        **_request_base(protocol_id("req_", 912)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": (
            {
                "event_id": obligation_event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Publish a result for the checkpoint-compat exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "requested_items": ({"item_kind": "change", "value": "compat-result"},),
                    "status": "open",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            {
                "event_id": protocol_id("evt_", 918),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:01.000Z",
                "causal_parents": (obligation_event_id,),
                "payload": {
                    "claim_id": protocol_id("clm_", 919),
                    "claim_kind": "completion",
                    "statement": "The checkpoint-compat workflow is complete.",
                    "supporting_refs": (obligation_id,),
                    "obligation_refs": (obligation_id,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))

    check_wire = {
        **_request_base(protocol_id("req_", 914)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    check_request = CheckRequest.model_validate(check_wire)
    ledger, objects = runtime.resources[started.task_id]
    advance = ledger.advance_check_phase
    crash_pending = True

    async def crash_after_local_ready(
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease:
        nonlocal crash_pending
        replacement = await advance(lease, expected_phase, next_phase, durable_object_ref)
        if crash_pending and next_phase is CheckPhase.LOCAL_READY:
            crash_pending = False
            raise RuntimeError("simulated_post_local_ready_crash")
        return replacement

    monkeypatch.setattr(ledger, "advance_check_phase", crash_after_local_ready)
    with pytest.raises(PublicOperationError) as failure:
        await app.check(check_request)
    assert failure.value.code is PublicErrorCode.INTERNAL_ERROR
    monkeypatch.setattr(ledger, "advance_check_phase", advance)

    record = await ledger.lookup_operation(started.writer_id, check_request.request_id)
    assert record is not None
    assert record.state is OperationState.PENDING
    assert record.phase is CheckPhase.LOCAL_READY
    assert record.resume_object_ref is not None
    assert record.resume_object_ref.metadata.kind is ObjectKind.DETERMINISTIC_RESULT
    return _WedgedCheck(app, clock, ledger, objects, started.writer_id, check_request)


async def _swap_checkpoint(
    wedged: _WedgedCheck,
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    """Replace the durable checkpoint with a mutated re-canonicalized copy."""

    record = await wedged.ledger.lookup_operation(wedged.writer_id, wedged.request.request_id)
    assert record is not None
    ref = record.resume_object_ref
    assert ref is not None
    raw = b"".join([chunk async for chunk in wedged.objects.open_verified(ref)])
    source = cast(dict[str, JsonValue], strict_json_parse(raw))
    mutate(source)
    data = canonical_encode(source)
    staged = await wedged.objects.stage(
        ObjectSource(data=data, declared_size=len(data)),
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            ref.metadata.task_id,
            wedged.clock.now_utc(),
        ),
    )
    swapped_ref = await wedged.objects.finalize(staged)
    key = (wedged.writer_id, wedged.request.request_id)
    state = wedged.ledger._state  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    row = state.operations[key]
    state.operations[key] = (replace(row[0], resume_object_ref=swapped_ref), row[1])


def _mark_stale_wording(source: dict[str, JsonValue]) -> None:
    assessments = cast(list[JsonValue], source["assessments"])
    for raw_assessment in assessments:
        finding = cast(dict[str, JsonValue], cast(dict[str, JsonValue], raw_assessment)["finding"])
        finding["detail"] = cast(str, finding["detail"]) + _STALE_WORDING_MARKER


def _remove_text_contract_stamp(source: dict[str, JsonValue]) -> None:
    del source["text_contract_digest"]


def _use_prior_text_contract(source: dict[str, JsonValue]) -> None:
    assert source["text_contract_digest"] != "sha256:" + "0" * 64
    source["text_contract_digest"] = "sha256:" + "0" * 64


def _break_policy_executions(source: dict[str, JsonValue]) -> None:
    source["policy_executions"] = [{"policy_id": "work-integrity"}]


def _break_assessments(source: dict[str, JsonValue]) -> None:
    source["assessments"] = [{}]


async def test_pre_stamp_checkpoint_with_old_wording_recomputes_on_the_same_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A checkpoint written before the text-contract stamp existed replays as superseded."""

    wedged = await _wedge_check_at_local_ready(monkeypatch)

    def to_pre_stamp_format(source: dict[str, JsonValue]) -> None:
        del source["text_contract_digest"]
        _mark_stale_wording(source)

    await _swap_checkpoint(wedged, to_pre_stamp_format)
    wedged.clock.advance(61)

    checked = await wedged.app.check(wedged.request)
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    assert all(_STALE_WORDING_MARKER not in finding.detail for finding in checked.findings)


async def test_stamped_checkpoint_from_different_wording_recomputes_on_the_same_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A checkpoint stamped under a different text contract replays as superseded."""

    wedged = await _wedge_check_at_local_ready(monkeypatch)

    def restamp_from_older_contract(source: dict[str, JsonValue]) -> None:
        assert source["text_contract_digest"] != "sha256:" + "0" * 64
        source["text_contract_digest"] = "sha256:" + "0" * 64
        _mark_stale_wording(source)

    await _swap_checkpoint(wedged, restamp_from_older_contract)
    wedged.clock.advance(61)

    checked = await wedged.app.check(wedged.request)
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    assert all(_STALE_WORDING_MARKER not in finding.detail for finding in checked.findings)


async def test_uncorpused_wording_drift_under_a_current_stamp_still_recomputes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Text drift the contract digest failed to cover is superseded, not corrupt."""

    wedged = await _wedge_check_at_local_ready(monkeypatch)
    await _swap_checkpoint(wedged, _mark_stale_wording)
    wedged.clock.advance(61)

    checked = await wedged.app.check(wedged.request)
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    assert all(_STALE_WORDING_MARKER not in finding.detail for finding in checked.findings)


async def test_broken_checkpoint_content_stays_storage_corrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Supersession must not swallow genuine corruption under a current stamp."""

    wedged = await _wedge_check_at_local_ready(monkeypatch)

    await _swap_checkpoint(wedged, _break_policy_executions)
    wedged.clock.advance(61)

    with pytest.raises(PublicOperationError) as corrupt:
        await wedged.app.check(wedged.request)
    assert corrupt.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert corrupt.value.retryable is False


@pytest.mark.parametrize(
    ("stamp_mutator", "content_mutator"),
    (
        pytest.param(_remove_text_contract_stamp, _break_policy_executions, id="legacy-policy"),
        pytest.param(_use_prior_text_contract, _break_policy_executions, id="mismatched-policy"),
        pytest.param(_remove_text_contract_stamp, _break_assessments, id="legacy-assessments"),
        pytest.param(_use_prior_text_contract, _break_assessments, id="mismatched-assessments"),
    ),
)
async def test_malformed_superseded_checkpoint_content_stays_storage_corrupt(
    monkeypatch: pytest.MonkeyPatch,
    stamp_mutator: Callable[[dict[str, JsonValue]], None],
    content_mutator: Callable[[dict[str, JsonValue]], None],
) -> None:
    """Supersession cannot hide malformed legacy or mismatched-stamp content."""

    wedged = await _wedge_check_at_local_ready(monkeypatch)

    def mutate(source: dict[str, JsonValue]) -> None:
        stamp_mutator(source)
        content_mutator(source)

    await _swap_checkpoint(wedged, mutate)
    wedged.clock.advance(61)

    with pytest.raises(PublicOperationError) as corrupt:
        await wedged.app.check(wedged.request)
    assert corrupt.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert corrupt.value.retryable is False
