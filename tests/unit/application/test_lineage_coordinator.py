"""Coordinator-side guards for frozen manifest capture."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import cast

import pytest

from yoetz.application.lineage_coordinator import LineageManifestCoordinator
from yoetz.domain.events import LedgerRecord
from yoetz.domain.values import task_id
from yoetz.ports.clock import ClockPort
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ids import IdPort
from yoetz.ports.importer import ImporterPort
from yoetz.ports.ledger import LedgerPort
from yoetz.ports.objects import ObjectStorePort
from yoetz.ports.runtime import (
    BundleRuntimePort,
    OwnershipFence,
    TaskRuntime,
)
from yoetz.ports.start_catalog import StartCatalogPort
from yoetz.protocol.ids import IdKind

pytestmark = pytest.mark.anyio


class _Clock:
    def now_utc(self):
        from datetime import UTC, datetime

        return datetime(2026, 9, 5, 12, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def new(self, kind: IdKind) -> str:
        del kind
        return "evt_00000000-0000-4000-8000-000000000999"


class _Ledger:
    async def load_events(
        self, _session_id: str, *, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        del through
        if False:
            yield cast(LedgerRecord, None)


class _Catalog:
    async def list_child_task_ids(self, _parent_task_id: str) -> tuple[str, ...]:
        raise RuntimeError("inventory_unavailable")


def _runtime() -> TaskRuntime:
    return TaskRuntime(
        task_id=task_id("tsk_00000000-0000-4000-8000-000000000901"),
        session_id="ses_00000000-0000-4000-8000-000000000901",
        writer_id="wri_00000000-0000-4000-8000-000000000901",
        capabilities=frozenset({RuntimeCapability.STRUCTURAL_READ}),
        ledger=cast(LedgerPort, _Ledger()),
        objects=cast(ObjectStorePort, object()),
        importer=cast(ImporterPort, object()),
        projection_version="1.0.0",
        engine_version="1.0.0",
        protocol_version="0.1",
        bundle_schema_version="1.0.0",
        fence=OwnershipFence(
            "svc_00000000-0000-4000-8000-000000000901",
            1,
            1,
            "0123456789abcdef",
        ),
    )


async def test_inventory_failure_does_not_replace_a_recorded_manifest_with_empty_state() -> None:
    coordinator = LineageManifestCoordinator(
        runtime=cast(BundleRuntimePort, object()),
        catalog=cast(StartCatalogPort, _Catalog()),
        clock=cast(ClockPort, _Clock()),
        ids=cast(IdPort, _Ids()),
    )

    result = await coordinator.sweep(_runtime())

    assert result.inventory_read_gap is True
    assert result.changed is False
    assert result.append_result is None
    assert result.manifest.source_event_id is None
    assert result.manifest.children == ()


@pytest.mark.parametrize(
    ("disposition", "flagged"),
    (
        (None, False),
        ("acknowledged_not_done", False),
        ("self_verified", True),
    ),
)
def test_child_snapshot_carries_self_verified_only_for_a_self_verified_finding(
    disposition: str | None, flagged: bool
) -> None:
    """Issue #984 (ADR-034): the frozen child row says "self-verified", never "resolved"."""

    from dataclasses import replace

    from builders.policy_cases import evd, finding_record, fnd, obl, record
    from yoetz.application.lineage_coordinator import (
        _child_finding_snapshot,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.events import ResponseRecordedPayload
    from yoetz.domain.findings import (
        FINDING_KIND_TRAITS,
        Finding,
        FindingKind,
        FindingOrigin,
        ResponseDisposition,
    )
    from yoetz.domain.values import Frontier
    from yoetz.kernel.projections import empty_projection_state
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel

    digest = "sha256:" + "4" * 64
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    finding = Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A completion claim covers an open obligation.",
        detail="Resolve or revise the obligation before claiming completion.",
        subject_refs=(obl(1),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(3, digest),
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        provenance=None,
    )
    responses = {}
    if disposition is not None:
        responses[fnd(1)] = record(
            ResponseRecordedPayload(
                fnd(1),
                Frontier(4, digest),
                ResponseDisposition(disposition),
                "Ran the suite myself; output recorded as evidence.",
                evidence_refs=(evd(1),),
            ),
            9,
        )
    projection = replace(
        empty_projection_state(),
        frontier=20,
        head_digest=digest,
        findings={fnd(1): finding_record(finding, 4)},
        responses=responses,
    )
    snapshot = _child_finding_snapshot(projection, fnd(1), finding)
    assert (snapshot.self_verified, snapshot.resolved, snapshot.actionable) == (
        flagged,
        False,
        True,
    )


def test_child_snapshots_roll_a_linked_pair_up_once_and_never_inherit_resolution() -> None:
    """Issue #996 (B2): parent and child agree. A self-verified pair is one row; a duplicate of
    a resolved finding stays an open row of its own (resolution is never inherited)."""

    from dataclasses import replace

    from builders.policy_cases import evd, evt, finding_record, fnd, obl, record
    from yoetz.application.lineage_coordinator import (
        _child_finding_snapshots,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.events import ResponseRecordedPayload
    from yoetz.domain.findings import (
        FINDING_KIND_TRAITS,
        Finding,
        FindingKind,
        FindingOrigin,
        ResponseDisposition,
    )
    from yoetz.domain.values import Frontier
    from yoetz.kernel.projections import empty_projection_state
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel

    digest = "sha256:" + "4" * 64
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS

    def finding(number: int) -> Finding:
        return Finding(
            finding_id=fnd(number),
            kind=kind,
            origin=FindingOrigin.DETERMINISTIC,
            priority=FINDING_KIND_TRAITS[kind][0],
            summary="A completion claim covers an open obligation.",
            detail="Resolve or revise the obligation before claiming completion.",
            subject_refs=(obl(number),),
            policy_id="work-integrity",
            policy_version="0.1.0",
            subject_frontier=Frontier(3, digest),
            coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
            provenance=None,
        )

    link = record(
        ResponseRecordedPayload(
            fnd(2),
            Frontier(6, digest),
            ResponseDisposition.DUPLICATE_OF,
            duplicate_of_finding_id=fnd(1),
        ),
        10,
    )
    verified = record(
        ResponseRecordedPayload(
            fnd(1),
            Frontier(4, digest),
            ResponseDisposition.SELF_VERIFIED,
            "Ran the suite myself; output recorded as evidence.",
            evidence_refs=(evd(1),),
        ),
        9,
    )
    base = replace(empty_projection_state(), frontier=20, head_digest=digest)
    pair = replace(
        base,
        findings={fnd(1): finding_record(finding(1), 4), fnd(2): finding_record(finding(2), 6)},
        responses={fnd(1): verified, fnd(2): link},
    )
    rows = _child_finding_snapshots(pair)
    assert [(row.finding_id, row.self_verified, row.resolved) for row in rows] == [
        (fnd(1), True, False)
    ]

    resolved_root = replace(
        base,
        findings={
            fnd(1): finding_record(finding(1), 4, resolved_by_check_event_id=evt(9)),
            fnd(2): finding_record(finding(2), 6),
        },
        responses={fnd(2): link},
    )
    rows = _child_finding_snapshots(resolved_root)
    assert [(row.finding_id, row.resolved) for row in rows] == [(fnd(1), True), (fnd(2), False)]
