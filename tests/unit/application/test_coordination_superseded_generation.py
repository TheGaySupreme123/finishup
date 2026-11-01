"""Unit locks for closing superseded coordination contexts (issue #842).

The composed READY scenarios live in the observation conformance suite. These tests pin the pure
pieces: the monotonic supersession predicate, the frozen-case rule that a ``revoked`` closure
retires exactly the delivery it names in every check scope, and the writer's refusal to close a
current generation or to close a closure.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import cast

import pytest

from builders.ledger_adapters import FixedIds
from builders.policy_cases import evt, make_case, obl, obligation_record, record
from finishup.application.coordination import (
    CoordinationDetector,
    CoordinationRuntime,
    InMemoryCoordinationStore,
    LedgerCoordinationInputProvider,
    RoutedCoordinationContextWriter,
    coordination_generation_superseded,
)
from finishup.application.projects import InMemoryProjectCatalog, ProjectApplication
from finishup.domain.coordination import CoordinationError, CoordinationGapCode, OverlapKind
from finishup.domain.events import (
    CoordinationContextRecordedPayload,
    CoordinationObligationDeclaredPayload,
    ObligationPublishedPayload,
    ObligationStatus,
)
from finishup.domain.findings import FindingKind
from finishup.kernel.deterministic_checks import DeterministicAssessment, DeterministicCase
from finishup.protocol.ids import IdKind, new_id

_TASK_ONE = "tsk_20000000-0000-4000-8000-000000000001"
_TASK_TWO = "tsk_20000000-0000-4000-8000-000000000002"


def _commitment(seed: str) -> str:
    return "hmac-sha256:" + hashlib.sha256(seed.encode()).hexdigest()


class _RefuseRuntime:
    """A task runtime that must never be opened by the path under test."""

    async def route(self, _command: object) -> object:
        raise AssertionError("no task runtime may be opened")

    async def release(self, _runtime: object) -> None:
        return None


def _allow_coordination_source(*_args: object) -> bool:
    return True


def _application(catalog: InMemoryProjectCatalog) -> ProjectApplication:
    return ProjectApplication(
        catalog,
        ids=FixedIds(),
        workspace_consent=lambda _workspace: True,
        coordination_source_authorizer=_allow_coordination_source,
    )


def _runtime(app: ProjectApplication) -> CoordinationRuntime:
    return CoordinationRuntime(
        app,
        CoordinationDetector(app, InMemoryCoordinationStore()),
        LedgerCoordinationInputProvider(app, _RefuseRuntime()),  # type: ignore[arg-type]
    )


def _context(project: str, *, overlap: OverlapKind = OverlapKind.PLAN, generation: int = 1):
    return CoordinationContextRecordedPayload(
        detection_id=evt(1),
        project_id=project,
        membership_generation=generation,
        left_task_id=_TASK_ONE,  # type: ignore[arg-type]
        right_task_id=_TASK_TWO,  # type: ignore[arg-type]
        recipient_task_id=_TASK_ONE,  # type: ignore[arg-type]
        counterpart_task_id=_TASK_TWO,  # type: ignore[arg-type]
        source_task_id=_TASK_TWO,  # type: ignore[arg-type]
        overlap_kind=overlap,
        resource_identities=("sha256:" + "a" * 64,),
        resource_count=1,
        source_repository_commitment=_commitment("repository"),
        source_workspace_commitment=_commitment("workspace"),
        source_route_generation=1,
        source_attributable_paths=overlap is not OverlapKind.PLAN,
        context_digest="sha256:" + "c" * 64,
    )


def _closure(context: CoordinationContextRecordedPayload) -> CoordinationContextRecordedPayload:
    return replace(
        context,
        resource_identities=(),
        resource_count=0,
        source_attributable_paths=False,
        gap_codes=(CoordinationGapCode.REVOKED,),
        context_digest="sha256:" + "d" * 64,
    )


def _case(
    contexts: dict[int, CoordinationContextRecordedPayload], project: str
) -> DeterministicCase:
    """A frozen recipient case: open obligation 2, context(s), and the declaration at 4."""

    obligation = ObligationPublishedPayload(obl(1), "Coordinate", "Decision", ObligationStatus.OPEN)
    declaration = CoordinationObligationDeclaredPayload(
        detection_id=evt(1),
        project_id=project,
        membership_generation=1,
        recipient_task_id=_TASK_ONE,  # type: ignore[arg-type]
        obligation_id=obl(1),
    )
    base = make_case(
        obligations={obl(1): obligation_record(obligation, 2)},
        extra_refs=(evt(4), *(evt(number) for number in contexts)),
    )
    projection = replace(
        base.projection,
        coordination_contexts={
            evt(number): record(payload, number) for number, payload in contexts.items()
        },
        coordination_declarations={evt(4): record(declaration, 4)},
    )
    return replace(base, projection=projection)


async def _assess(
    runtime: CoordinationRuntime, case: DeterministicCase, *, scoped_to: int | None = None
) -> tuple[DeterministicAssessment, ...]:
    result = await runtime.assessments_for_check(
        _TASK_ONE,
        case,
        scope_roots=frozenset() if scoped_to is None else frozenset({str(evt(scoped_to))}),
        whole_case=scoped_to is None,
    )
    return cast(tuple[DeterministicAssessment, ...], result)


@pytest.mark.anyio
async def test_supersession_is_any_later_generation_or_dissolution() -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    project = (await catalog.ensure_repository_project(_commitment("repository"))).project_id
    assert await coordination_generation_superseded(app, project, 1) is False
    await catalog.advance_project_generation(project, reason="revoke")
    assert await coordination_generation_superseded(app, project, 1) is True
    assert await coordination_generation_superseded(app, project, 2) is False
    await catalog.dissolve_project(project)
    # Dissolution retires even the generation it was recorded under.
    assert await coordination_generation_superseded(app, project, 3) is True


@pytest.mark.anyio
async def test_supersession_is_never_inferred_from_missing_project_state() -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    unknown = "prj_" + new_id(IdKind.TASK).removeprefix("tsk_")
    assert await coordination_generation_superseded(app, unknown, 1) is False

    class _NoProjectState:
        pass

    blind = cast(ProjectApplication, type("_Blind", (), {"catalog": _NoProjectState()})())
    assert await coordination_generation_superseded(blind, unknown, 1) is False


@pytest.mark.anyio
@pytest.mark.parametrize("scoped", (False, True))
async def test_revoked_closure_retires_the_delivery_in_every_check_scope(scoped: bool) -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    project = (await catalog.ensure_repository_project(_commitment("repository"))).project_id
    runtime = _runtime(app)
    context = _context(project)
    scope = 3 if scoped else None

    live = await _assess(runtime, _case({3: context}, project), scoped_to=scope)
    assert [item.candidate.kind for item in live] == [FindingKind.COORDINATION_OVERLAP]
    assert live[0].candidate.subject_refs == (evt(3),)

    # A scoped check may name only the original delivery; the closure still retires it.
    closed = await _assess(
        runtime, _case({3: context, 6: _closure(context)}, project), scoped_to=scope
    )
    assert closed == ()


@pytest.mark.anyio
@pytest.mark.parametrize("field", ("detection_id", "membership_generation", "counterpart"))
async def test_revoked_closure_never_retires_another_delivery(field: str) -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    project = (await catalog.ensure_repository_project(_commitment("repository"))).project_id
    runtime = _runtime(app)
    context = _context(project)
    closure = _closure(context)
    if field == "detection_id":
        closure = replace(closure, detection_id=evt(99))
    elif field == "membership_generation":
        closure = replace(closure, membership_generation=2)
    else:
        closure = replace(
            closure,
            left_task_id=_TASK_ONE,  # type: ignore[arg-type]
            right_task_id="tsk_20000000-0000-4000-8000-000000000003",  # type: ignore[arg-type]
            counterpart_task_id="tsk_20000000-0000-4000-8000-000000000003",  # type: ignore[arg-type]
            source_task_id="tsk_20000000-0000-4000-8000-000000000003",  # type: ignore[arg-type]
        )
    assessed = await _assess(runtime, _case({3: context, 6: closure}, project))
    assert [item.candidate.kind for item in assessed] == [FindingKind.COORDINATION_OVERLAP]
    assert assessed[0].candidate.subject_refs == (evt(3),)


@pytest.mark.anyio
async def test_writer_closes_nothing_for_a_current_generation_or_a_closure() -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    project = (await catalog.ensure_repository_project(_commitment("repository"))).project_id
    writer = RoutedCoordinationContextWriter(app, _RefuseRuntime())  # type: ignore[arg-type]
    context = _context(project, overlap=OverlapKind.PHYSICAL)
    # The generation is current, so no task runtime is opened and nothing is appended.
    assert await writer.record_superseded_context(context) is None
    with pytest.raises(CoordinationError):
        await writer.record_superseded_context(_closure(context))


@pytest.mark.anyio
async def test_reconciliation_skips_tasks_without_an_active_route() -> None:
    catalog = InMemoryProjectCatalog()
    app = _application(catalog)
    runtime = _runtime(app)
    runtime.detector.context_writer = RoutedCoordinationContextWriter(
        app,
        _RefuseRuntime(),  # type: ignore[arg-type]
    )
    assert await runtime.retire_superseded_contexts(_TASK_ONE) == ()
