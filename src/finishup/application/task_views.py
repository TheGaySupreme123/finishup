"""Read-only lineage views from catalog identity and parent-recorded dependencies."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from finishup.application.projects import ProjectApplication, ProjectCommandError, ProjectStatus
from finishup.application.status_faults import (
    StatusFault,
    StatusFaultStage,
    record_status_member_unavailable,
    status_stage,
)
from finishup.domain.coordination import LineageAcceptance, SessionHealth
from finishup.domain.events import AcceptedEvent, ReceiptRecordedPayload
from finishup.domain.values import Frontier
from finishup.kernel.lineage import evaluate_lineage, lineage_manifest_from_records
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.host_lineage import (
    HostLineageRegistryError,
    HostLineageRegistryPort,
    HostLineageRegistryReason,
)
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.start_catalog import StartCatalogPort, TaskLineage, TaskRouteState
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    StatusLineageAnnotationModel,
    StatusLineageChildModel,
    StatusProjectCoverageModel,
    StatusProjectDetectionModel,
    StatusProjectMemberModel,
    StatusProjectReceiptModel,
)


@dataclass(frozen=True, slots=True)
class LineageStatusSnapshot:
    """Internal snapshot, before applying the public response's page size limit."""

    parent_task_id: str | None
    children: tuple[StatusLineageChildModel, ...]
    annotations: tuple[StatusLineageAnnotationModel, ...] = ()
    # Internal status gaps are promoted to the response envelope by the status application.  They
    # stay out of the nested page wire shape so the frozen lineage page schema remains closed.
    known_gaps: tuple[str, ...] = ()

    def as_wire(self) -> dict[str, object]:
        return {
            "parent_task_id": self.parent_task_id,
            "children": [item.model_dump(mode="json") for item in self.children],
            "annotations": [item.model_dump(mode="json") for item in self.annotations],
            "known_gaps": list(self.known_gaps),
        }


async def lineage_status_page(
    catalog: StartCatalogPort,
    runtime: TaskRuntime,
    frontier: Frontier,
    *,
    permitted_children: frozenset[str] | None = None,
    host_lineage_registry: HostLineageRegistryPort | None = None,
    correlation_id: str | None = None,
) -> LineageStatusSnapshot:
    """Never upgrade current catalog state into an unrecorded clean child result."""

    parent = await catalog.task_lineage(runtime.task_id)
    if parent is None:
        raise PublicOperationError(
            PublicErrorCode.SESSION_NOT_FOUND, "The task lineage was not found.", False
        )
    with status_stage(StatusFaultStage.REPLAY):
        records = tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    runtime.session_id, through=frontier.sequence
                )
            ]
        )
        manifest = lineage_manifest_from_records(records)
        rollups = {str(item.child_task_id): item for item in evaluate_lineage(manifest).children}
        snapshots = {str(item.child_task_id): item for item in manifest.children}
    children: list[StatusLineageChildModel] = []
    for child_id in await catalog.list_child_task_ids(runtime.task_id):
        if permitted_children is not None and child_id not in permitted_children:
            continue
        child = await catalog.task_lineage(child_id)
        if child is None or child.parent_task_id != runtime.task_id:
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT, "The child lineage is inconsistent.", False
            )
        assert child.origin is not None
        assert child.acceptance is not None
        sessions = await catalog.task_session_states(child_id)
        health = SessionHealth.CONTACT_LOST
        if any(session.health is SessionHealth.ACTIVE for session in sessions):
            health = SessionHealth.ACTIVE
        elif sessions and all(session.health is SessionHealth.ENDED for session in sessions):
            health = SessionHealth.ENDED
        rollup = rollups.get(child_id)
        snapshot = snapshots.get(child_id)
        child_route = await catalog.task_route(child_id)
        blocking: tuple[str, ...] = ()
        self_verified = 0
        state = "annotation"
        if child.acceptance is LineageAcceptance.ACCEPTED:
            if child_route is None or child_route.state is TaskRouteState.QUARANTINED:
                state = "unavailable"
                blocking = ("lineage_child_unavailable",)
            elif rollup is None or snapshot is None:
                state = "unavailable"
                blocking = ("lineage_manifest_not_recorded",)
            elif (
                snapshot.origin.value != child.origin.value
                or snapshot.acceptance.value != child.acceptance.value
                or snapshot.work_state.value != child.work_state.value
                or snapshot.session_health.value != health.value
            ):
                state = "unavailable"
                blocking = ("lineage_manifest_state_changed",)
            else:
                state = rollup.state.value
                blocking = rollup.blockers
                self_verified = len(rollup.self_verified_finding_ids)
        with status_stage(StatusFaultStage.MODEL):
            children.append(
                StatusLineageChildModel.model_validate(
                    {
                        "task_id": child.task_id,
                        "parent_task_id": child.parent_task_id,
                        "origin": child.origin.value,
                        "acceptance": child.acceptance.value,
                        "work_state": child.work_state.value,
                        "session_health": health.value,
                        "depth": str(child.depth),
                        "rollup_state": state,
                        "blocking_conditions": blocking,
                        # Issue #984 (S2): present only when the child has self-verified
                        # findings, so status agrees with the receipt's insufficient_coverage.
                        **(
                            {"self_verified_finding_count": str(self_verified)}
                            if self_verified
                            else {}
                        ),
                    }
                )
            )
    annotations: tuple[StatusLineageAnnotationModel, ...] = ()
    if host_lineage_registry is not None:
        try:
            observed: list[StatusLineageAnnotationModel] = []
            after: str | None = None
            while True:
                annotation_records = await host_lineage_registry.list_provisional_annotations(
                    runtime.task_id,
                    correlation_id=correlation_id,
                    limit=100,
                    after_correlation_id=after,
                )
                if not annotation_records:
                    break
                identities = tuple(item.correlation_id for item in annotation_records)
                if identities != tuple(sorted(set(identities))) or (
                    after is not None and identities[0] <= after
                ):
                    raise ValueError("host_lineage_annotation_order_invalid")
                for item in annotation_records:
                    if (
                        item.parent_task_id != runtime.task_id
                        or not item.provisional
                        or (correlation_id is not None and item.correlation_id != correlation_id)
                    ):
                        raise ValueError("host_lineage_annotation_scope_invalid")
                    observed.append(
                        StatusLineageAnnotationModel.model_validate(dict(item.as_status_wire()))
                    )
                after = identities[-1]
                if len(annotation_records) < 100:
                    break
            annotations = tuple(observed)
        except HostLineageRegistryError as exc:
            if exc.reason is HostLineageRegistryReason.STORAGE_CORRUPT:
                raise StatusFault(
                    StatusFaultStage.REPLAY, "Host lineage status is inconsistent."
                ) from exc
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE,
                "Host lineage status is temporarily unavailable.",
                True,
            ) from exc
        except (TypeError, ValueError) as exc:
            # Registry rows failed their stored-order, scope, or annotation shape: invalid stored
            # state. The status boundary records the class and origin under the public id.
            raise StatusFault(
                StatusFaultStage.REPLAY, "Host lineage status is inconsistent."
            ) from exc
    return LineageStatusSnapshot(
        parent_task_id=parent.parent_task_id,
        children=tuple(children),
        annotations=annotations,
    )


@dataclass(frozen=True, slots=True)
class ProjectStatusSnapshot:
    """Admitted project facts before response pagination and text disclosure."""

    metadata: dict[str, JsonValue]
    members: tuple[StatusProjectMemberModel, ...]
    lineage: LineageStatusSnapshot
    detections: tuple[StatusProjectDetectionModel, ...]
    receipts: tuple[StatusProjectReceiptModel, ...]
    gaps: tuple[str, ...]
    coverage: tuple[StatusProjectCoverageModel, ...] = ()

    def as_wire(self) -> dict[str, JsonValue]:
        return {
            **self.metadata,
            "members": [item.model_dump(mode="json") for item in self.members],
            "lineage": cast(JsonValue, self.lineage.as_wire()),
            "detections": [item.model_dump(mode="json") for item in self.detections],
            "receipts": [item.model_dump(mode="json") for item in self.receipts],
            "gaps": list(self.gaps),
            "coverage": [item.model_dump(mode="json") for item in self.coverage],
        }


async def project_status_snapshot(
    projects: ProjectApplication,
    catalog: StartCatalogPort,
    bundles: BundleRuntimePort,
    requester: TaskRuntime,
    frontier: Frontier,
    *,
    selected_task_id: str | None,
    project_id: str | None,
    host_lineage_registry: HostLineageRegistryPort | None = None,
    correlation_id: str | None = None,
    request_id: str | None = None,
) -> ProjectStatusSnapshot | LineageStatusSnapshot:
    """Read only admitted sources and revalidate consent after every source has been read.

    One member that cannot be read or projected is disclosed as ``project_member_unavailable``
    and recorded under ``request_id``; it never fails the other members' view (issue #840).
    Project-level rows (detections, coverage) and the page itself still fail the request with a
    classified public error.
    """

    async def admitted(generation: int | None = None) -> ProjectStatus | TaskLineage:
        try:
            return await projects.project_view_for(
                requester.task_id,
                selected_task_id=selected_task_id,
                project=project_id,
                expected_generation=generation,
            )
        except ProjectCommandError as exc:
            raise PublicOperationError(
                PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
                "The project view is not authorized at this membership generation.",
                False,
            ) from exc

    view = await admitted()
    if isinstance(view, TaskLineage):
        if selected_task_id is not None and selected_task_id != requester.task_id:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT, "The task selector is inconsistent.", False
            )
        return await lineage_status_page(
            catalog,
            requester,
            frontier,
            host_lineage_registry=host_lineage_registry,
            correlation_id=correlation_id,
        )
    generation = view.project.membership_generation
    task_ids = frozenset(item.task_id for item in view.memberships if item.task_id is not None)
    members: list[StatusProjectMemberModel] = []
    children: dict[str, StatusLineageChildModel] = {}
    receipts: list[StatusProjectReceiptModel] = []
    gaps: set[str] = set()
    own_lineage: TaskLineage | None = None
    for identifier in sorted(task_ids):
        member_runtime: TaskRuntime | None = None
        member_receipt: StatusProjectReceiptModel | None = None
        tree: LineageStatusSnapshot | None = None
        try:
            lineage = await catalog.task_lineage(identifier)
            sessions = await catalog.task_session_states(identifier)
            route = await catalog.task_route(identifier)
            if lineage is None:
                gaps.add("project_member_unavailable")
                continue
            if identifier == requester.task_id:
                own_lineage = lineage
            health = SessionHealth.CONTACT_LOST
            if any(item.health is SessionHealth.ACTIVE for item in sessions):
                health = SessionHealth.ACTIVE
            elif sessions and all(item.health is SessionHealth.ENDED for item in sessions):
                health = SessionHealth.ENDED
            latest_session = max(
                sessions, key=lambda item: (item.changed_at, item.session_id), default=None
            )
            with status_stage(StatusFaultStage.MODEL):
                member = StatusProjectMemberModel.model_validate(
                    {
                        "task_id": identifier,
                        "actor_id": None if latest_session is None else latest_session.actor_id,
                        "work_state": lineage.work_state.value,
                        "session_health": health.value,
                        "parent_task_id": lineage.parent_task_id,
                    }
                )
            members.append(member)
            if route is None or route.state is TaskRouteState.QUARANTINED:
                gaps.add("project_member_unavailable")
                continue
            member_runtime = (
                requester
                if identifier == requester.task_id
                else await bundles.route(
                    RouteCommand(
                        route.session_id,
                        None,
                        RouteAccess.PAYLOAD_READ,
                        frozenset(
                            {RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}
                        ),
                    )
                )
            )
            if member_runtime.task_id != identifier:
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The project member route is inconsistent.",
                    False,
                )
            member_frontier = await member_runtime.ledger.load_frontier()
            tree = await lineage_status_page(
                catalog,
                member_runtime,
                member_frontier,
                permitted_children=task_ids,
            )
            latest_receipt: ReceiptRecordedPayload | None = None
            with status_stage(StatusFaultStage.REPLAY):
                async for record in member_runtime.ledger.load_events(
                    member_runtime.session_id, through=member_frontier.sequence
                ):
                    if record.task_id != identifier:
                        raise PublicOperationError(
                            PublicErrorCode.STORAGE_CORRUPT,
                            "The project member ledger is inconsistent.",
                            False,
                        )
                    if isinstance(record, AcceptedEvent) and isinstance(
                        record.payload, ReceiptRecordedPayload
                    ):
                        latest_receipt = record.payload
            if latest_receipt is not None:
                with status_stage(StatusFaultStage.MODEL):
                    member_receipt = StatusProjectReceiptModel.model_validate(
                        {
                            "task_id": identifier,
                            "receipt_id": latest_receipt.receipt_id,
                            # ``Frontier.as_wire`` is a deeply frozen ``JsonObject``; the strict
                            # nested ``FrontierModel`` admits only a plain mapping.  Passing the
                            # frozen object rejected every member with a recorded receipt and
                            # blinded the whole project view (issue #840).
                            "frontier": dict(latest_receipt.subject_frontier.as_wire().items()),
                            "conclusion": latest_receipt.conclusion_code.value,
                        }
                    )
        except (PublicOperationError, StatusFault, TypeError, ValueError) as exc:
            record_status_member_unavailable(exc, request_id=request_id)
            gaps.add("project_member_unavailable")
            continue
        finally:
            if member_runtime is not None and member_runtime is not requester:
                await bundles.release(member_runtime)
        # Admit one member's lineage and receipt rows together, only after both were read.
        children.update((item.task_id, item) for item in tree.children)
        if member_receipt is not None:
            receipts.append(member_receipt)
    latest = await admitted(generation)
    if (
        not isinstance(latest, ProjectStatus)
        or frozenset(item.task_id for item in latest.memberships if item.task_id is not None)
        != task_ids
    ):
        raise PublicOperationError(
            PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED, "Project source authority changed.", False
        )
    detection_rows: list[StatusProjectDetectionModel] = []
    for item in latest.detections:
        wire: dict[str, object] = dict(item)
        # The project application keeps the internal snapshot deeply frozen.  Normalize only the
        # nested omission mapping at this strict model boundary; this preserves the exact marker
        # while allowing the public model's ``OmittedContentModel`` branch to validate it.
        resource_paths = wire.get("resource_paths")
        if isinstance(resource_paths, Mapping):
            wire["resource_paths"] = dict(cast(Mapping[str, object], resource_paths).items())
        # Coordination domain rows use integers internally; the closed status wire uses the
        # canonical integer-string representation shared by every public projection.
        resource_count = wire.get("resource_count")
        if type(resource_count) is int:
            wire["resource_count"] = str(resource_count)
        with status_stage(StatusFaultStage.MODEL):
            detection_rows.append(StatusProjectDetectionModel.model_validate(wire))
    detections = tuple(detection_rows)
    detections = tuple(item for item in detections if set(item.task_ids) <= task_ids)
    with status_stage(StatusFaultStage.MODEL):
        coverage_rows = tuple(
            StatusProjectCoverageModel.model_validate(dict(item)) for item in latest.coverage
        )
    coverage = tuple(item for item in coverage_rows if item.task_id in task_ids)
    descriptor = latest.project
    metadata: dict[str, JsonValue] = {
        "project_id": descriptor.project_id,
        "kind": descriptor.kind.value,
        "membership_generation": str(generation),
        "grant_state": None if latest.grant is None else latest.grant.state.value,
    }
    # These are structural owner/route pointers only. The final client projection hydrates the
    # exact values under each source owner's policy for the resolved human or agent sink.
    for field, reference in (
        ("title", descriptor.title_ref),
        ("description", descriptor.description_ref),
    ):
        if reference is not None:
            metadata[f"{field}_ref"] = dict(reference.as_wire().items())
    return ProjectStatusSnapshot(
        metadata,
        tuple(members),
        LineageStatusSnapshot(
            None if own_lineage is None else own_lineage.parent_task_id,
            tuple(children[key] for key in sorted(children)),
        ),
        detections,
        tuple(receipts),
        tuple(sorted(gaps)),
        coverage,
    )
