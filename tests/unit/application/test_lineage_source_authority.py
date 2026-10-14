"""Adversarial C9 source-authority checks for the frozen-lineage gate."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from finishup.application.lineage_coordinator import (
    LINEAGE_CHANNELS,
    LineageSourceAuthorization,
    PrivacyLineageSourceGate,
    SourceGateDecision,
    authorize_recorded_lineage,
)
from finishup.domain.coordination import LineageAcceptance, LineageOrigin, SessionHealth, WorkState
from finishup.domain.privacy import DataClass
from finishup.domain.values import Frontier, event_id, receipt_id, task_id
from finishup.kernel.lineage import (
    ChildDependencySnapshot,
    ChildRollup,
    LineageEvaluation,
    LineageRollupState,
)
from finishup.ports.privacy import PrivacyPolicyStorePort
from finishup.ports.start_catalog import StartCatalogPort, TaskSourceProvenance
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel
from finishup.protocol.models import DataCategory, LineageProvenanceRestriction

_PARENT = str(task_id("tsk_00000000-0000-4000-8000-000000000101"))
_CHILD = str(task_id("tsk_00000000-0000-4000-8000-000000000102"))
_WORKSPACE_A = "hmac-sha256:" + "a" * 64
_WORKSPACE_B = "hmac-sha256:" + "b" * 64
_REPOSITORY_A = "hmac-sha256:" + "c" * 64
_REPOSITORY_B = "hmac-sha256:" + "d" * 64
_INSTALLATION = "ins_00000000-0000-4000-8000-000000000101"
_ROUTE_PARENT = "sha256:" + "1" * 64
_ROUTE_CHILD = "sha256:" + "2" * 64


class _PolicyStore:
    async def effective_policy(self, _scope: object) -> object:
        # This is intentionally only the source policy surface the C9 gate is allowed to inspect.
        return SimpleNamespace(
            policy=SimpleNamespace(
                agent_context_categories=(
                    DataCategory.BOUNDED_STRUCTURAL_METADATA,
                    DataCategory.FINDING_SUMMARY,
                ),
                agent_context_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
            )
        )


class _GrantAdmission:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.generations: list[int] = []

    async def current_generation(self, project: str) -> int:
        del project
        return 7

    async def admit(
        self,
        *,
        source_task_id: str,
        source_workspace_commitment: str,
        project: str,
        expected_generation: int,
        cross_repository: bool,
    ) -> object:
        del source_task_id, source_workspace_commitment, project, cross_repository
        self.generations.append(expected_generation)
        return SimpleNamespace(allowed=self.allowed)


class _Catalog:
    def __init__(self, parent: TaskSourceProvenance, child: TaskSourceProvenance) -> None:
        self.values = {parent.task_id: parent, child.task_id: child}

    async def task_source_provenance(self, value: str) -> TaskSourceProvenance | None:
        return self.values.get(value)


def _provenance(
    task: str,
    workspace: str,
    repository: str,
    route: str,
    generation: int = 1,
) -> TaskSourceProvenance:
    return TaskSourceProvenance(task, workspace, workspace, repository, generation, route)


def _request(
    *,
    parent: TaskSourceProvenance,
    child: TaskSourceProvenance,
) -> LineageSourceAuthorization:
    return LineageSourceAuthorization(
        _PARENT,
        _CHILD,
        child,
        parent_provenance=parent,
    )


@pytest.mark.anyio
async def test_same_repository_lineage_uses_accepted_source_authority_without_project_consent() -> (
    None
):
    """A cooperative accepted child is C9-authorized without project membership/observation consent."""

    parent = _provenance(_PARENT, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_PARENT)
    child = _provenance(_CHILD, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_CHILD)
    gate = PrivacyLineageSourceGate(cast(PrivacyPolicyStorePort, _PolicyStore()), _INSTALLATION)

    decision = await gate(_request(parent=parent, child=child))

    assert decision.allowed is True
    assert decision.restrictions == ()


@pytest.mark.anyio
async def test_cross_repository_lineage_requires_current_dynamic_project_generation_grant() -> None:
    parent = _provenance(_PARENT, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_PARENT)
    child = _provenance(_CHILD, _WORKSPACE_B, _REPOSITORY_B, _ROUTE_CHILD)

    denied_without_membership = await PrivacyLineageSourceGate(
        cast(PrivacyPolicyStorePort, _PolicyStore()),
        _INSTALLATION,
    )(_request(parent=parent, child=child))
    assert denied_without_membership.allowed is False
    assert denied_without_membership.restrictions == (LineageProvenanceRestriction.TASK_SCOPE,)

    admission = _GrantAdmission()
    gate = PrivacyLineageSourceGate(
        cast(PrivacyPolicyStorePort, _PolicyStore()),
        _INSTALLATION,
        project_admission=admission,
        project_resolver=_resolve_project,
    )
    allowed = await gate(_request(parent=parent, child=child))
    assert allowed.allowed is True
    assert admission.generations == [7, 7]

    admission.allowed = False
    revoked = await gate(_request(parent=parent, child=child))
    assert revoked.allowed is False
    assert revoked.restrictions == (LineageProvenanceRestriction.TASK_SCOPE,)


@pytest.mark.anyio
async def test_semantic_reauthorization_rejects_a_cached_manifest_after_route_replacement() -> None:
    parent = _provenance(_PARENT, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_PARENT)
    child = _provenance(_CHILD, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_CHILD)
    manifest_event = event_id("evt_00000000-0000-4000-8000-000000000101")
    frontier = Frontier(4, "sha256:" + "e" * 64)
    snapshot = ChildDependencySnapshot(
        child_task_id=task_id(_CHILD),
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
        work_state=WorkState.CLOSED,
        session_health=SessionHealth.ENDED,
        child_frontier=frontier,
        child_check_id=manifest_event,
        child_receipt_id=receipt_id("rcp_00000000-0000-4000-8000-000000000101"),
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        findings=(),
        lineage_authority_revision="1",
        child_check_subject_frontier=frontier,
        manifest_event_id=manifest_event,
    )
    evaluation = LineageEvaluation(
        children=(
            ChildRollup(
                task_id(_CHILD),
                LineageRollupState.CLEAN,
                "known",
                manifest_event_id=manifest_event,
                tested_manifest_ref=manifest_event,
            ),
        ),
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        gaps=(),
        manifest_digest="sha256:" + "f" * 64,
        snapshots=(snapshot,),
    )

    gate_allowed = True

    async def gate(request: LineageSourceAuthorization) -> SourceGateDecision:
        assert request.channel == "child_structural_input"
        if gate_allowed:
            return SourceGateDecision(True)
        return SourceGateDecision(
            False,
            (LineageProvenanceRestriction.CATEGORY_RESTRICTED,),
        )

    catalog_impl = _Catalog(parent, child)
    catalog = cast(StartCatalogPort, catalog_impl)
    allowed = await authorize_recorded_lineage(_PARENT, evaluation, catalog, gate)
    assert allowed.allowed is True

    gate_allowed = False
    revoked_policy = await authorize_recorded_lineage(_PARENT, evaluation, catalog, gate)
    assert revoked_policy.allowed is False
    assert revoked_policy.restrictions == (LineageProvenanceRestriction.CATEGORY_RESTRICTED,)

    catalog_impl.values[_CHILD] = _provenance(
        _CHILD, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_PARENT, generation=2
    )
    replaced = await authorize_recorded_lineage(_PARENT, evaluation, catalog, gate)
    assert replaced.allowed is False
    assert replaced.restrictions == (LineageProvenanceRestriction.TASK_SCOPE,)


def _project() -> str:
    # Resolver output is service-owned catalog identity; caller supplied labels never reach it.
    return "prj_00000000-0000-4000-8000-000000000101"


async def _resolve_project(parent_task_id: str, child_task_id: str) -> str:
    del parent_task_id, child_task_id
    return _project()


def test_c9_channel_set_is_closed_and_canonical() -> None:
    assert LINEAGE_CHANNELS == (
        "child_structural_input",
        "manifest_disclosure",
        "service_child_read",
    )
    with pytest.raises(ValueError):
        LineageSourceAuthorization(
            _PARENT,
            _CHILD,
            _provenance(_CHILD, _WORKSPACE_A, _REPOSITORY_A, _ROUTE_CHILD),
            channels=("service_child_read",),
        )
