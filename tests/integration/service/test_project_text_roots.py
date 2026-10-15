"""Catalog project-text pointers remain GC roots for their owning task only."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import apsw
import pytest

from finishup.adapters.sqlite.migrations import initialize_bundle, initialize_catalog
from finishup.domain.coordination import ProjectTextRef
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.service.ready_composition import (
    _BundleInspection,  # pyright: ignore[reportPrivateUsage]
    _root_snapshot,  # pyright: ignore[reportPrivateUsage]
)


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 19, 9, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 0.0


@pytest.mark.anyio
async def test_catalog_project_and_coordination_refs_root_owned_objects() -> None:
    task = new_id(IdKind.TASK)
    other_task = new_id(IdKind.TASK)
    bundle = apsw.Connection(":memory:")
    catalog = apsw.Connection(":memory:")
    try:
        initialize_bundle(
            bundle,
            {
                "task_id": task,
                "owner_generation": "1",
                "owner_nonce": "test-owner-nonce-0001",
                "route_generation": "1",
                "route_identity_digest": canonical_digest({"route": "owned"}),
            },
        )
        initialize_catalog(catalog)
        now = "2026-07-19T09:00:00.000Z"
        catalog.executemany(
            "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, route_generation, "
            "active_route_identity_digest, state, created_at, updated_at) "
            "VALUES(?, ?, ?, 1, ?, 'active', ?, ?)",
            (
                (
                    task,
                    new_id(IdKind.SESSION),
                    f"tasks/{task}",
                    canonical_digest({"route": "owned"}),
                    now,
                    now,
                ),
                (
                    other_task,
                    new_id(IdKind.SESSION),
                    f"tasks/{other_task}",
                    canonical_digest({"route": "other"}),
                    now,
                    now,
                ),
            ),
        )
        project = new_id(IdKind.PROJECT)
        owned = ProjectTextRef(
            new_id(IdKind.OBJECT),
            canonical_digest({"content": "owned"}),
            5,
            task,
            1,
            canonical_digest({"envelope": "owned"}),
        )
        foreign = ProjectTextRef(
            new_id(IdKind.OBJECT),
            canonical_digest({"content": "foreign"}),
            7,
            other_task,
            1,
            canonical_digest({"envelope": "foreign"}),
        )
        catalog.execute(
            "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
            "membership_generation, created_at, dissolved_at, title_ref_canonical, "
            "description_ref_canonical) VALUES(?, 'general', NULL, 1, 1, ?, NULL, ?, ?)",
            (project, now, canonical_encode(owned.as_wire()), canonical_encode(foreign.as_wire())),
        )
        detection = new_id(IdKind.EVENT)
        catalog.execute(
            "INSERT INTO coordination_detections("
            "detection_id, project_id, membership_generation, left_task_id, right_task_id, "
            "overlap_kind, resource_identities_json, counterpart_task_id, advice_only, "
            "obligation_declared, addressed, generation_valid, detail_ref_json, resolved) "
            "VALUES(?, ?, 1, ?, ?, 'integration', ?, ?, 1, 0, 0, 1, ?, 0)",
            (
                detection,
                project,
                task,
                other_task,
                canonical_encode([canonical_digest({"resource": "src/a.py"})]).decode("utf-8"),
                other_task,
                canonical_encode(owned.as_wire()).decode("utf-8"),
            ),
        )
        inspection = SimpleNamespace(
            recovery_state=SimpleNamespace(
                task_id=task,
                route_identity_digest=canonical_digest({"route": "owned"}),
                route_generation=1,
                owner_generation=1,
                privacy_root_generation=0,
                privacy_root_digest=canonical_digest(()),
            )
        )
        inspection_value = cast(_BundleInspection, inspection)

        snapshot = await _root_snapshot(inspection_value, bundle, _Clock(), catalog)

        assert snapshot.live_object_ids == (owned.object_id,)
    finally:
        catalog.close(force=True)
        bundle.close(force=True)
