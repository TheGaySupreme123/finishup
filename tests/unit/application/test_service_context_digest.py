"""Service-side fencing for coordination context digests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import fields, replace
from typing import Any, cast

import pytest

from builders.replay import replay_records
from yoetz.application import service as service_module
from yoetz.application.coordination import InMemoryCoordinationStore
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.projects import ProjectApplication
from yoetz.application.service import Application, VerificationPolicy
from yoetz.domain.coordination import (
    CoordinationDetection,
    CoordinationDisposition,
    CoordinationObligationState,
    OverlapKind,
)
from yoetz.domain.events import (
    AcceptedEvent,
    CoordinationContextRecordedPayload,
    CoordinationDispositionRecordedPayload,
    EventSchema,
    EvidenceRecordedPayload,
    ProjectionLocator,
    RedactionState,
    RuntimeProfile,
    accepted_record_digest_preimage,
    encode_payload,
    media_type_for,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    actor_id,
    event_id,
    evidence_id,
    obligation_id,
    project_id,
    task_id,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand
from yoetz.ports.start_catalog import (
    StartCatalogPort,
    TaskRoute,
    TaskRouteState,
    TaskSourceProvenance,
)
from yoetz.protocol.canonical import canonical_digest, canonical_encode, entry_digest
from yoetz.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import PublishWorkRequest

pytestmark = pytest.mark.anyio

_TASK = "tsk_30000004-0000-4000-8000-000000000001"
_COUNTERPART = "tsk_30000004-0000-4000-8000-000000000002"
_SESSION = "ses_30000004-0000-4000-8000-000000000004"
_PROJECT = "prj_30000004-0000-4000-8000-000000000005"
_DETECTION = "evt_30000004-0000-4000-8000-000000000007"
_OTHER_DETECTION = "evt_30000004-0000-4000-8000-000000000008"
_OBLIGATION = "obl_30000004-0000-4000-8000-000000000009"
_WRITER = "wri_30000004-0000-4000-8000-000000000010"
_EVIDENCE = "evd_20000002-0000-4000-8000-000000000104"
_RESOURCE = "sha256:" + "1" * 64
_CONTEXT = "sha256:" + "2" * 64
_OLDER_CONTEXT = "sha256:" + "3" * 64
_CROSS_IDENTITY_CONTEXT = "sha256:" + "4" * 64
_WRONG_CONTEXT = "sha256:" + "5" * 64
_WORKSPACE = "hmac-sha256:" + "6" * 64
_EXTERNAL = "hmac-sha256:" + "7" * 64
_REPOSITORY = "hmac-sha256:" + "8" * 64


def _deny(_request: object) -> bool:
    return False


class _Ledger:
    def __init__(self, records: tuple[AcceptedEvent, ...]) -> None:
        self.records = records

    async def load_events(self, session_id: str) -> AsyncIterator[AcceptedEvent]:
        assert session_id == _SESSION
        for record in self.records:
            yield record


class _RoutedRuntime:
    def __init__(self, ledger: _Ledger) -> None:
        self.session_id = _SESSION
        self.ledger = ledger


class _Runtime:
    def __init__(self, records: tuple[AcceptedEvent, ...]) -> None:
        self.routed = _RoutedRuntime(_Ledger(records))
        self.route_calls = 0
        self.released: list[_RoutedRuntime] = []

    async def route(self, command: RouteCommand) -> _RoutedRuntime:
        assert command.session_id == _SESSION
        assert command.access is RouteAccess.PAYLOAD_READ
        self.route_calls += 1
        return self.routed

    async def release(self, runtime: _RoutedRuntime) -> None:
        self.released.append(runtime)


class _StartCatalog:
    def __init__(self, route: TaskRoute) -> None:
        self.route = route

    async def resolve_route(self, session_id: str) -> TaskRoute:
        assert session_id == _SESSION
        return self.route

    async def session_binding(self, session_id: str) -> None:
        assert session_id == _SESSION
        return None


class _Detector:
    def __init__(self, store: InMemoryCoordinationStore) -> None:
        self.store = store
        self.mirror_calls = 0

    async def disposition(
        self,
        detection_id: str,
        task_id: str,
        *,
        disposition: str,
    ) -> None:
        assert detection_id == _DETECTION
        assert task_id == _TASK
        assert disposition == CoordinationDisposition.SHARED_WORK.value
        self.mirror_calls += 1


class _ProjectCatalog:
    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance:
        assert task_id == _TASK
        route = _route()
        return TaskSourceProvenance(
            task_id,
            _WORKSPACE,
            _EXTERNAL,
            _REPOSITORY,
            route.route_generation,
            route.route_identity_digest,
        )


class _Projects:
    def __init__(self, store: InMemoryCoordinationStore) -> None:
        self.detector = _Detector(store)
        self.coordination_runtime = type(
            "_CoordinationRuntime",
            (),
            {"detector": self.detector},
        )()
        self.catalog = _ProjectCatalog()
        self.admit_calls = 0

    async def admit(self, **kwargs: object) -> object:
        assert kwargs == {
            "source_task_id": _TASK,
            "source_workspace_commitment": _WORKSPACE,
            "project": _PROJECT,
            "expected_generation": 1,
        }
        self.admit_calls += 1
        return object()


def _route() -> TaskRoute:
    return TaskRoute(
        _TASK,
        _SESSION,
        f"tasks/{_TASK}",
        1,
        TaskRouteState.ACTIVE,
        canonical_digest(
            {"task_id": _TASK, "bundle_relpath": f"tasks/{_TASK}", "route_generation": 1}
        ),
    )


def _context_payload(
    context_digest: str,
    *,
    detection_id: str = _DETECTION,
    project_value: str = _PROJECT,
) -> CoordinationContextRecordedPayload:
    return CoordinationContextRecordedPayload(
        detection_id=event_id(detection_id),
        project_id=project_id(project_value),
        membership_generation=1,
        left_task_id=task_id(_TASK),
        right_task_id=task_id(_COUNTERPART),
        recipient_task_id=task_id(_TASK),
        counterpart_task_id=task_id(_COUNTERPART),
        source_task_id=task_id(_COUNTERPART),
        overlap_kind=OverlapKind.PHYSICAL,
        resource_identities=(_RESOURCE,),
        resource_count=1,
        source_repository_commitment=_REPOSITORY,
        source_workspace_commitment=_WORKSPACE,
        source_route_generation=1,
        source_attributable_paths=True,
        context_digest=context_digest,
    )


def _accepted_context(
    payload: CoordinationContextRecordedPayload,
    *,
    sequence: int,
    event_number: int,
) -> AcceptedEvent:
    """Build a validating accepted record from the frozen replay envelope."""

    base = cast(AcceptedEvent, replay_records("projection-rebuild")[0])
    schema = EventSchema("coordination_context_recorded", "1.0.0")
    encoded = encode_payload(payload)
    values: dict[str, Any] = {field.name: getattr(base, field.name) for field in fields(base)}
    values.update(
        {
            "event_id": f"evt_30000004-0000-4000-8000-{event_number:012d}",
            "task_id": _TASK,
            "session_id": _SESSION,
            "schema": schema,
            "author": Actor(
                actor_id("yoetz:observation-coordinator"),
                ActorType.HARNESS,
                AuthorshipAssurance.HARNESS_OBSERVED,
            ),
            "ledger": replace(
                base.ledger,
                ingestion_sequence=sequence,
                previous_entry_digest=("genesis" if sequence == 1 else "sha256:" + "9" * 64),
            ),
            "operation_id": f"req_30000004-0000-4000-8000-{event_number:012d}",
            "causal_parents": (),
            "publication_channel": PublicationChannel.ENGINE_DERIVED,
            "coverage": coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
            "payload_ref": replace(
                base.payload_ref,
                media_type=media_type_for(schema.name),
                plaintext_size=len(canonical_encode(encoded)),
                commitment="hmac-sha256:" + "a" * 64,
            ),
            "redaction": RedactionState.PRESENT,
            "artifact_refs": (),
            "evidence_refs": (),
            "payload": payload,
            "projection_locator": ProjectionLocator(
                schema,
                None,
                canonical_digest(encoded),
            ),
        }
    )
    draft = object.__new__(AcceptedEvent)
    for key, value in values.items():
        object.__setattr__(draft, key, value)
    values["entry_digest"] = entry_digest(accepted_record_digest_preimage(draft))
    return AcceptedEvent(**{field.name: values[field.name] for field in fields(base) if field.init})


def _evidence_record() -> AcceptedEvent:
    for record in replay_records("all-event-families"):
        if not isinstance(record, AcceptedEvent):
            continue
        payload = record.payload
        if isinstance(payload, EvidenceRecordedPayload):
            assert payload.evidence_id == _EVIDENCE
            return record
    raise AssertionError("frozen replay fixture has no evidence record")


def _disposition(context_digest: str | None) -> CoordinationDispositionRecordedPayload:
    return CoordinationDispositionRecordedPayload(
        detection_id=event_id(_DETECTION),
        project_id=project_id(_PROJECT),
        membership_generation=1,
        recipient_task_id=task_id(_TASK),
        obligation_id=obligation_id(_OBLIGATION),
        disposition=CoordinationDisposition.SHARED_WORK,
        evidence_refs=(evidence_id(_EVIDENCE),),
        context_digest=context_digest,
    )


def _request(payload: CoordinationDispositionRecordedPayload) -> PublishWorkRequest:
    return PublishWorkRequest.model_construct(
        session_id=_SESSION,
        writer_id=_WRITER,
        task_id=_TASK,
        event_drafts=(
            {
                "schema": {"name": "coordination_disposition_recorded", "version": "1.0.0"},
                "payload": encode_payload(payload),
            },
        ),
    )


def _application(
    runtime: _Runtime,
    start_catalog: _StartCatalog,
    projects: _Projects,
) -> Application:
    return Application(
        start_catalog=cast(StartCatalogPort, start_catalog),
        publish_responses=cast(PublishResponseCatalogPort, object()),
        runtime=cast(BundleRuntimePort, runtime),
        clock=cast(ClockPort, object()),
        ids=cast(IdPort, object()),
        verification_policy=VerificationPolicy(),
        privacy=cast(PrivacyCoordinator, object()),
        status_cursor_key=b"context-digest-test",
        waiver_policy_digest="sha256:" + "0" * 64,
        semantic_evaluator=cast(Any, object()),
        disclosure_scope_for=cast(Any, object()),
        receipt_version_resolver=cast(Any, object()),
        waiver_authorizer=cast(Callable[[object], bool], _deny),
        import_publication_authorizer=cast(Callable[[object], bool], _deny),
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest={},
        project_application=cast(ProjectApplication, projects),
        enforce_repository_identity=False,
    )


def _composition(
    records: tuple[AcceptedEvent, ...],
) -> tuple[Application, _Runtime, _Projects]:
    detection = CoordinationDetection(
        _DETECTION,
        _PROJECT,
        1,
        _TASK,
        _COUNTERPART,
        OverlapKind.PHYSICAL,
        (_RESOURCE,),
        _COUNTERPART,
        obligation_declared=True,
    )
    obligation = CoordinationObligationState(
        _DETECTION,
        _TASK,
        declared=True,
        obligation_id=obligation_id(_OBLIGATION),
    )
    store = InMemoryCoordinationStore()
    store.detections[_DETECTION] = detection
    store.obligations[(_DETECTION, _TASK)] = obligation
    runtime = _Runtime(records)
    projects = _Projects(store)
    return _application(runtime, _StartCatalog(_route()), projects), runtime, projects


@pytest.mark.parametrize("case", ("missing", "older", "cross_identity", "wrong"))
async def test_invalid_context_digest_is_rejected_before_status_mirroring(
    case: str,
) -> None:
    evidence = _evidence_record()
    current = _accepted_context(_context_payload(_CONTEXT), sequence=11, event_number=101)
    if case == "missing":
        records = (evidence,)
        supplied = _CONTEXT
    elif case == "older":
        older = _accepted_context(_context_payload(_OLDER_CONTEXT), sequence=10, event_number=102)
        records = (older, current, evidence)
        supplied = _OLDER_CONTEXT
    elif case == "cross_identity":
        cross_identity = _accepted_context(
            _context_payload(_CROSS_IDENTITY_CONTEXT, detection_id=_OTHER_DETECTION),
            sequence=12,
            event_number=103,
        )
        records = (cross_identity, evidence)
        supplied = _CROSS_IDENTITY_CONTEXT
    else:
        records = (current, evidence)
        supplied = _WRONG_CONTEXT

    app, runtime, projects = _composition(records)

    with pytest.raises(PublicOperationError) as failure:
        await app.publish_work(_request(_disposition(supplied)))

    assert failure.value.code is PublicErrorCode.INVALID_REQUEST
    assert failure.value.safe_details == {
        "reason_code": "coordination_detection_mismatch",
        "continuation": "lineage_state_refresh",
    }
    assert runtime.route_calls == 1
    assert runtime.released == [runtime.routed]
    assert projects.admit_calls == 1
    assert projects.detector.mirror_calls == 0


@pytest.mark.parametrize("context_digest", (_CONTEXT, None))
async def test_matching_or_omitted_context_digest_is_supported_and_mirrored(
    monkeypatch: pytest.MonkeyPatch,
    context_digest: str | None,
) -> None:
    evidence = _evidence_record()
    current = _accepted_context(_context_payload(_CONTEXT), sequence=11, event_number=104)
    app, runtime, projects = _composition((current, evidence))
    result = object()

    async def execute(_app: Application, _request: PublishWorkRequest) -> object:
        return result

    monkeypatch.setattr(service_module, "execute_publish_work", execute)

    assert await app.publish_work(_request(_disposition(context_digest))) is result
    assert runtime.route_calls == 1
    assert runtime.released == [runtime.routed]
    assert projects.admit_calls == 1
    assert projects.detector.mirror_calls == 1
