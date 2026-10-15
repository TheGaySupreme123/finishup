"""Service-side freezing of direct-child lineage manifests.

The coordinator is the only application component in the rollup path that may open a child
bundle.  It reads a child through the ready runtime's least-authority route, applies an explicit
source authorization gate, and writes one aggregate ``child_dependencies_recorded`` event to the
parent ledger when the structural facts changed.  Checks and receipts consume the resulting
parent rows through :mod:`finishup.kernel.lineage`; they never call this module.

No user text crosses this boundary.  The request passed to ``source_gate`` names the three C9
lineage channels so the gate can apply the child's own source restrictions to each channel before
the service stamps a manifest.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Final, Protocol, cast

from finishup.application.ledger_snapshot import projection_for_records
from finishup.application.unit_of_work import (
    PreparedMutation,
    abandon_preappend_objects,
    run_prepared_append,
)
from finishup.domain.coordination import (
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from finishup.domain.events import (
    AcceptedEvent,
    CheckRecordedPayload,
    ChildDependenciesRecordedPayload,
    EventDraft,
    EventSchema,
    LedgerRecord,
    ReceiptRecordedPayload,
    encode_payload,
    media_type_for,
)
from finishup.domain.events import (
    ChildDependencySnapshot as WireChildDependencySnapshot,
)
from finishup.domain.events import (
    ChildFindingSnapshot as WireChildFindingSnapshot,
)
from finishup.domain.findings import FINDING_KIND_TRAITS, Finding
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    DataClass,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    EventId,
    FindingId,
    Frontier,
    actor_id,
    task_id,
    timestamp_from_datetime,
)
from finishup.kernel.finding_todo import (
    FindingTodoState,
    duplicate_counting_id,
    finding_todo_state,
)
from finishup.kernel.lineage import (
    LineageEvaluation,
    LineageManifest,
    lineage_manifest_from_records,
    manifest_from_payload,
)
from finishup.kernel.projections import ProjectionState
from finishup.ports.clock import ClockPort
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ids import IdPort
from finishup.ports.ledger import (
    AppendCommand,
    AppendEntry,
    AppendResult,
    OperationKind,
    ProjectionView,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource, StagedObject
from finishup.ports.privacy import PrivacyPolicyStorePort
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.start_catalog import (
    SessionBinding,
    SessionState,
    StartCatalogPort,
    TaskLineage,
    TaskRoute,
    TaskRouteState,
    TaskSourceProvenance,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.ids import IdKind
from finishup.protocol.models import (
    DataCategory,
    LineageProvenanceRestriction,
    LineageReadGapReason,
)

__all__ = [
    "LINEAGE_CHANNELS",
    "LineageManifestCoordinator",
    "LineageProjectAdmission",
    "LineageProjectResolver",
    "PrivacyLineageSourceGate",
    "LineageSourceAuthorization",
    "LineageSourceGate",
    "LineageSweepResult",
    "SourceGateDecision",
    "authorize_recorded_lineage",
]


_LINEAGE_EVENT_SCHEMA_VERSION: Final = "1.0.0"
_LINEAGE_OPERATION_DOMAIN: Final = "yoetz/lineage-manifest-operation/v1"
_LINEAGE_EVENT_DOMAIN: Final = "yoetz/lineage-manifest-event/v1"

# C9's three accepted channels.  The tuple is canonical and intentionally contains no caller
# supplied text; a source gate receives the complete set on every child read.
LINEAGE_CHANNELS: Final = (
    "child_structural_input",
    "manifest_disclosure",
    "service_child_read",
)


def _invalid() -> ValueError:
    return ValueError("lineage_coordinator_invalid")


def _stable_id(kind: IdKind, digest: str) -> str:
    """Derive a UUIDv4-shaped id from a manifest digest for retry-safe appends."""

    raw = bytearray(bytes.fromhex(digest.removeprefix("sha256:")[:32]))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    prefix = {
        IdKind.EVENT: "evt_",
        IdKind.REQUEST: "req_",
    }[kind]
    return prefix + str(uuid.UUID(bytes=bytes(raw)))


def _cleared_retained_gaps(
    records: Iterable[LedgerRecord], latest_check_event: object, candidates: set[str]
) -> frozenset[str]:
    """Retained-only gap codes a later check cleared: the rule the child's receipt applies.

    Mirrors ``application.receipt._historical_gaps`` (issue #1017): among the checks recorded up
    to the latest tested one, a code an earlier check carried and the latest no longer carries.
    """

    if not candidates or latest_check_event is None:
        return frozenset()
    checks: list[CheckRecordedPayload] = []
    for record in records:
        if type(record.payload) is CheckRecordedPayload:
            checks.append(record.payload)
        if record.event_id == latest_check_event:
            break
    else:
        return frozenset()
    if not checks:
        return frozenset()
    return frozenset(
        code
        for code in candidates
        if code not in checks[-1].coverage.known_gaps
        and any(code in check.coverage.known_gaps for check in checks[:-1])
    )


def _coverage_with_gaps(coverage: Coverage, gaps: Iterable[str]) -> Coverage:
    # Projection gaps carry subject identities for deterministic replay (for example
    # ``missing_ref:<event>:<target>``), while Coverage is a closed public code set.  Preserve the
    # category in the frozen child fact without leaking the replay marker into a wire coverage
    # field whose grammar intentionally admits only bounded tokens.
    categories = {
        "missing_ref:": "missing_ref",
        "unknown_event:": "unknown_event",
        "redacted_event:": "redacted_event",
        "redacted_object:": "redacted_object",
    }
    normalized = tuple(
        next(
            (code for prefix, code in categories.items() if gap.startswith(prefix)),
            gap,
        )
        for gap in gaps
    )
    additions = tuple(sorted(set(normalized) - set(coverage.known_gaps), key=str.encode))
    if not additions:
        return coverage
    freshness = coverage.ledger_freshness
    if freshness is LedgerFreshness.CURRENT:
        freshness = LedgerFreshness.PARTIAL
    return Coverage(
        coverage.publication_channels,
        coverage.authorship_assurance,
        coverage.artifact_observation,
        coverage.evidence_immutability,
        freshness,
        coverage.check_types,
        tuple(sorted((*coverage.known_gaps, *additions), key=str.encode)),
    )


def _child_finding_snapshot(
    projection: ProjectionState, finding_key: FindingId, finding: Finding
) -> WireChildFindingSnapshot:
    """Freeze one child finding for the parent's dependency manifest."""

    priority, actionable = FINDING_KIND_TRAITS[finding.kind]
    # Deliberately strict (issue #905): a child's ``rejection_accepted`` or
    # ``acknowledged_not_done`` row stays actionable and unresolved here; neither ``actionable``
    # nor ``resolved`` may be bent to mean "withdrawn", and the child's own receipt discloses
    # the terminal state. A ``self_verified`` row (issue #984, ADR-034) also stays actionable and
    # unresolved, and carries ``self_verified`` so the parent rolls it up as "self-verified by
    # the child agent; FinishUP could not prove it": never clean, never parent work. ``resolved``
    # reads the same to-do predicate as the child's own receipt (``receipt._finding_states``).
    todo = finding_todo_state(projection, finding_key)
    resolved = todo is FindingTodoState.VERIFIED_RESOLVED
    record = projection.findings[finding_key]
    return WireChildFindingSnapshot(
        finding_id=finding.finding_id,
        kind=finding.kind,
        origin=finding.origin,
        priority=priority,
        actionable=actionable,
        resolved=resolved,
        resolution_event_id=record.resolved_by_check_event_id if resolved else None,
        self_verified=(not resolved and actionable and todo is FindingTodoState.SELF_VERIFIED),
    )


def _child_finding_snapshots(projection: ProjectionState) -> tuple[WireChildFindingSnapshot, ...]:
    """Freeze every readable child finding in id order, a linked pair once (issue #996).

    A linked duplicate the child's readiness counts with its earlier finding
    (``finding_todo.duplicate_counting_id``) is that finding's row, so a self-verified or
    acknowledged pair rolls up to the parent once, as the child's own readiness counts it.
    """

    rows: list[WireChildFindingSnapshot] = []
    for finding_key, finding_record in sorted(
        projection.findings.items(), key=lambda item: str(item[0]).encode("ascii")
    ):
        finding = finding_record.payload
        if type(finding) is not Finding:
            raise _invalid()
        if duplicate_counting_id(projection, finding_key) != finding_key:
            continue
        rows.append(_child_finding_snapshot(projection, finding_key, finding))
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class LineageSourceAuthorization:
    """Closed source-policy input for one service-side child read."""

    parent_task_id: str
    child_task_id: str
    provenance: TaskSourceProvenance
    channels: tuple[str, ...] = LINEAGE_CHANNELS
    parent_provenance: TaskSourceProvenance | None = None
    channel: str = "service_child_read"

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "parent_task_id", str(task_id(self.parent_task_id)))
            object.__setattr__(self, "child_task_id", str(task_id(self.child_task_id)))
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if type(self.provenance) is not TaskSourceProvenance:
            raise _invalid()
        channels = tuple(self.channels)
        if channels != LINEAGE_CHANNELS:
            raise _invalid()
        if (
            self.parent_provenance is not None
            and type(self.parent_provenance) is not TaskSourceProvenance
        ):
            raise _invalid()
        if type(self.channel) is not str or self.channel not in LINEAGE_CHANNELS:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SourceGateDecision:
    """Service policy result.  ``allowed`` covers all three C9 channels together."""

    allowed: bool
    restrictions: tuple[LineageProvenanceRestriction, ...] = ()

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool or type(self.restrictions) is not tuple:
            raise _invalid()
        if any(type(item) is not LineageProvenanceRestriction for item in self.restrictions):
            raise _invalid()
        expected = tuple(
            sorted(set(self.restrictions), key=lambda item: item.value.encode("ascii"))
        )
        if self.restrictions != expected:
            raise _invalid()


class LineageSourceGate(Protocol):
    """Explicit source authorization seam; absence is fail-closed."""

    def __call__(
        self, request: LineageSourceAuthorization
    ) -> SourceGateDecision | Awaitable[SourceGateDecision]: ...


class LineageProjectAdmission(Protocol):
    """Increment-B project/grant admission used only for cross-repository lineage."""

    async def current_generation(self, project: str) -> int: ...

    async def admit(
        self,
        *,
        source_task_id: str,
        source_workspace_commitment: str,
        project: str,
        expected_generation: int,
        cross_repository: bool,
    ) -> object: ...


class LineageProjectResolver(Protocol):
    """Resolve the one current project shared by two source tasks."""

    async def __call__(self, parent_task_id: str, child_task_id: str) -> str | None: ...


@dataclass(slots=True)
class PrivacyLineageSourceGate:
    """Concrete C9 gate backed by the existing privacy policy authority.

    The gate authorizes bounded structural metadata and finding identities through the same
    workspace/task policy that governs agent context.  It also checks both source and parent
    repository commitments, so increment-A lineage cannot become a cross-repository disclosure.
    Accepted cooperative lineage is its own service authority: host observation capture consent is
    deliberately not consulted here.  Revoking observation capture stops new observed events; it
    does not silently revoke an accepted child publication or erase already recorded ledger facts.
    Cross-repository lineage instead requires the explicit current project generation grant below.
    The caller must inject the ready service's policy store and installation identity; there is no
    permissive fallback when either authority is absent.
    """

    policies: PrivacyPolicyStorePort
    installation_id: str
    project_admission: LineageProjectAdmission | None = None
    project_id: str | None = None
    project_resolver: LineageProjectResolver | None = None

    async def __call__(self, request: LineageSourceAuthorization) -> SourceGateDecision:
        if type(request) is not LineageSourceAuthorization:
            raise _invalid()
        parent = request.parent_provenance
        source = request.provenance
        if parent is None:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
        # A missing repository commitment is a legitimate deterministic/local lineage case when
        # both sides are equally unbound.  Treat only an asymmetric commitment or a mismatch as
        # a cross-scope disclosure.  Worktree-specific workspace commitments may differ for tasks
        # in the same repository; the repository commitment is the increment-A boundary.
        if (parent.repository_privacy_commitment is None) != (
            source.repository_privacy_commitment is None
        ):
            return SourceGateDecision(False, (LineageProvenanceRestriction.TASK_SCOPE,))
        if (
            parent.repository_privacy_commitment is not None
            and parent.repository_privacy_commitment != source.repository_privacy_commitment
        ):
            project = self.project_id
            if project is None and self.project_resolver is not None:
                try:
                    project = await self.project_resolver(
                        request.parent_task_id,
                        request.child_task_id,
                    )
                except Exception:
                    project = None
            if self.project_admission is None or project is None:
                return SourceGateDecision(False, (LineageProvenanceRestriction.TASK_SCOPE,))
            try:
                generation = await self.project_admission.current_generation(project)
                for task, provenance in (
                    (request.parent_task_id, parent),
                    (request.child_task_id, source),
                ):
                    admission = await self.project_admission.admit(
                        source_task_id=task,
                        source_workspace_commitment=(provenance.workspace_ref_commitment or ""),
                        project=project,
                        expected_generation=generation,
                        cross_repository=True,
                    )
                    if getattr(admission, "allowed", False) is not True:
                        return SourceGateDecision(
                            False,
                            (LineageProvenanceRestriction.TASK_SCOPE,),
                        )
            except Exception:
                return SourceGateDecision(False, (LineageProvenanceRestriction.TASK_SCOPE,))
        if source.workspace_ref_commitment is None:
            return SourceGateDecision(False, (LineageProvenanceRestriction.TASK_SCOPE,))
        if (
            parent.repository_privacy_commitment is None
            and parent.workspace_ref_commitment != source.workspace_ref_commitment
        ):
            return SourceGateDecision(False, (LineageProvenanceRestriction.TASK_SCOPE,))
        scope = AuthorizationScope(
            AuthorizationScopeKind.TASK,
            self.installation_id,
            source.workspace_ref_commitment,
            source.task_id,
        )
        effective = await self.policies.effective_policy(scope)
        policy = effective.policy
        restrictions: set[LineageProvenanceRestriction] = set()
        required_categories = {
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.FINDING_SUMMARY,
        }
        if not required_categories.issubset(set(policy.agent_context_categories)):
            restrictions.add(LineageProvenanceRestriction.CATEGORY_RESTRICTED)
        if DataClass.PUBLIC_STRUCTURAL not in set(policy.agent_context_data_classes):
            restrictions.add(LineageProvenanceRestriction.CATEGORY_RESTRICTED)

        ordered = tuple(sorted(restrictions, key=lambda item: item.value.encode("ascii")))
        return SourceGateDecision(not ordered, ordered)


async def authorize_recorded_lineage(
    parent_task_id: str,
    evaluation: LineageEvaluation,
    catalog: StartCatalogPort,
    source_gate: LineageSourceGate | None,
) -> SourceGateDecision:
    """Re-authorize recorded child input immediately before semantic dispatch.

    The manifest is immutable check input, but its disclosure authority is live.  Resolve current
    source provenance and route generation at the admission boundary so a cached manifest cannot
    survive a source revocation or route replacement.  This helper never opens a child bundle;
    the coordinator's service-side sweep is the only code that does that.
    """

    if type(evaluation) is not LineageEvaluation or source_gate is None:
        return SourceGateDecision(
            False,
            (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
        )
    try:
        parent_provenance = await catalog.task_source_provenance(parent_task_id)
    except Exception:
        parent_provenance = None
    if parent_provenance is None:
        return SourceGateDecision(
            False,
            (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
        )
    snapshots_by_child = {snapshot.child_task_id: snapshot for snapshot in evaluation.snapshots}
    for child in evaluation.children:
        snapshot = snapshots_by_child.get(child.child_task_id)
        if snapshot is None:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
        # Pending and rejected relationships are annotations.  Their identity may remain in the
        # parent manifest, but C9 acceptance does not authorize child-derived semantic input.
        if snapshot.acceptance is not LineageAcceptance.ACCEPTED:
            continue
        try:
            provenance = await catalog.task_source_provenance(str(snapshot.child_task_id))
        except Exception:
            provenance = None
        if provenance is None or provenance.task_id != snapshot.child_task_id:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
        # The sweep stamps the current route generation as the lineage authority revision.  A
        # changed route means the recorded child facts no longer have the same source authority.
        # The frozen wire field is an opaque authority revision token.  READY binds it to the
        # exact catalog route generation, but the comparison stays string based so a future
        # service authority can use a different closed revision vocabulary without changing old
        # manifests.
        if str(provenance.route_generation) != snapshot.lineage_authority_revision:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.TASK_SCOPE,),
            )
        request = LineageSourceAuthorization(
            parent_task_id,
            str(snapshot.child_task_id),
            provenance,
            parent_provenance=parent_provenance,
            channel="child_structural_input",
        )
        try:
            result = source_gate(request)
            if inspect.isawaitable(result):
                result = await result
            if type(result) is not SourceGateDecision:
                raise _invalid()
        except Exception:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
        if not result.allowed or result.restrictions:
            return SourceGateDecision(
                False,
                result.restrictions or (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
    return SourceGateDecision(True)


@dataclass(frozen=True, slots=True)
class LineageSweepResult:
    """Result of one parent manifest sweep."""

    manifest: LineageManifest
    changed: bool
    append_result: AppendResult | None = None
    inventory_read_gap: bool = False

    def __post_init__(self) -> None:
        if type(self.manifest) is not LineageManifest or type(self.changed) is not bool:
            raise _invalid()
        if self.append_result is not None and type(self.append_result) is not AppendResult:
            raise _invalid()
        if type(self.inventory_read_gap) is not bool:
            raise _invalid()


@dataclass(slots=True)
class LineageManifestCoordinator:
    """Freeze direct-child state into the parent ledger under an explicit source gate."""

    runtime: BundleRuntimePort
    catalog: StartCatalogPort
    clock: ClockPort
    ids: IdPort
    source_gate: LineageSourceGate | None = None

    async def sweep(self, parent_runtime: TaskRuntime) -> LineageSweepResult:
        """Build and, only when changed, append the parent aggregate manifest."""

        if type(parent_runtime) is not TaskRuntime or parent_runtime.writer_id is None:
            raise _invalid()
        parent_records = await self._load_records(parent_runtime)
        current = lineage_manifest_from_records(parent_records)
        try:
            child_ids_raw = await self.catalog.list_child_task_ids(parent_runtime.task_id)
        except Exception:
            # An inventory failure cannot be represented by an empty aggregate: doing so would
            # erase every previously accepted child and make the parent look clean. Preserve the
            # last recorded manifest and return a closed maintenance diagnostic instead; the next
            # successful sweep will append the authoritative replacement.
            return LineageSweepResult(current, False, inventory_read_gap=True)
        try:
            child_ids = tuple(
                sorted(
                    {str(task_id(value)) for value in child_ids_raw},
                    key=str.encode,
                )
            )
        except TypeError, ValueError:
            # A malformed inventory result is an authority read failure.  Treating it as an
            # empty list would erase the last accepted aggregate and fabricate a clean parent.
            return LineageSweepResult(current, False, inventory_read_gap=True)
        snapshots: list[WireChildDependencySnapshot] = []
        for child_id in child_ids:
            try:
                snapshots.append(await self._snapshot(parent_runtime.task_id, child_id))
            except Exception:
                # A malformed catalog row must remain visible as a bounded unreadable child;
                # one bad child cannot suppress the other direct dependencies from the aggregate.
                snapshots.append(
                    self._unavailable(
                        child_id,
                        None,
                        None,
                        (LineageReadGapReason.UNREADABLE,),
                    )
                )
        payload = ChildDependenciesRecordedPayload(
            tuple(
                snapshot
                for snapshot in sorted(
                    snapshots,
                    key=lambda item: str(item.child_task_id).encode("ascii"),
                )
            )
        )
        candidate = manifest_from_payload(payload)
        # The empty baseline is not an observed aggregate.  The first successful sweep must
        # still record an empty ``children`` event so a parent ledger can prove that inventory was
        # performed; otherwise a later receipt cannot distinguish "no children" from "never
        # swept".  Once an aggregate exists, identical sweeps remain idempotent.
        if current.source_event_id is not None and candidate.digest == current.digest:
            return LineageSweepResult(current, False)
        append_result = await self._append(parent_runtime, payload, parent_records)
        refreshed = await self._load_records(parent_runtime)
        manifest = lineage_manifest_from_records(refreshed)
        return LineageSweepResult(manifest, True, append_result)

    async def sweep_parent_of(self, child_task_id: str) -> LineageSweepResult | None:
        """Refresh the direct parent after a child event reaches this service.

        A child hook can arrive while its parent is still active.  In that case the service may
        route the parent itself and record the child's new frontier without asking the child to
        write across bundles.  If the parent has no active route, the next parent-side sweep will
        catch up; the absence is deliberately not turned into a fabricated manifest event.
        """

        try:
            child = await self.catalog.task_lineage(child_task_id)
        except Exception:
            return None
        if child is None or child.parent_task_id is None:
            return None
        return await self.sweep_task(str(child.parent_task_id))

    async def sweep_task(self, task_id_value: str) -> LineageSweepResult | None:
        """Record the current aggregate for one active task, including an empty baseline.

        Maintenance must distinguish "inventory was observed and had no children" from
        "inventory has never run".  This route-bound helper is only used by the service-owned
        maintenance hook; checks and receipts never call it.
        """

        try:
            route = await self.catalog.task_route(task_id_value)
            if route is None or route.state is not TaskRouteState.ACTIVE:
                return None
            binding = await self.catalog.session_binding(route.session_id)
            if binding is None or binding.task_id != task_id_value:
                return None
            task_runtime = await self.runtime.route(
                RouteCommand(
                    route.session_id,
                    binding.writer_id,
                    RouteAccess.WRITE,
                    frozenset(
                        {
                            RuntimeCapability.STRUCTURAL_READ,
                            RuntimeCapability.PAYLOAD_READ,
                            RuntimeCapability.WRITE,
                        }
                    ),
                )
            )
        except Exception:
            return None
        try:
            return await self.sweep(task_runtime)
        except Exception:
            return None
        finally:
            try:
                await self.runtime.release(task_runtime)
            except Exception:
                pass

    @staticmethod
    async def _load_records(runtime: TaskRuntime) -> tuple[LedgerRecord, ...]:
        records: list[LedgerRecord] = []
        async for record in runtime.ledger.load_events(runtime.session_id):
            records.append(record)
        return tuple(records)

    async def _authorize(
        self,
        parent_task_id: str,
        child_task_id: str,
        provenance: TaskSourceProvenance | None,
    ) -> SourceGateDecision:
        """Run the required source gate; a missing/failing gate never defaults to allow."""

        if provenance is None or self.source_gate is None:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )
        if provenance.task_id != child_task_id:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.TASK_SCOPE,),
            )
        try:
            parent_provenance = await self.catalog.task_source_provenance(parent_task_id)
        except Exception:
            parent_provenance = None
        request = LineageSourceAuthorization(
            parent_task_id,
            child_task_id,
            provenance,
            parent_provenance=parent_provenance,
            channel="service_child_read",
        )
        try:
            result = self.source_gate(request)
            if inspect.isawaitable(result):
                result = await result
            if type(result) is not SourceGateDecision:
                raise _invalid()
            return result
        except Exception:
            return SourceGateDecision(
                False,
                (LineageProvenanceRestriction.AUTHORIZATION_MISSING,),
            )

    async def _snapshot(
        self, parent_task_id: str, child_task_id: str
    ) -> WireChildDependencySnapshot:
        """Read one child under a service route, degrading to a named closed gap on failure."""

        lineage: TaskLineage | None = None
        provenance: TaskSourceProvenance | None = None
        route: TaskRoute | None = None
        binding: SessionBinding | None = None
        session: SessionState | None = None
        try:
            lineage = await self.catalog.task_lineage(child_task_id)
            provenance = await self.catalog.task_source_provenance(child_task_id)
            route = await self.catalog.task_route(child_task_id)
            if route is not None:
                session = await self.catalog.task_session_state(route.session_id)
                binding = await self.catalog.session_binding(route.session_id)
        except Exception:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.UNREADABLE,),
            )

        decision = await self._authorize(parent_task_id, child_task_id, provenance)
        if provenance is None:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.MISSING,),
                decision.restrictions,
            )
        if route is None or lineage is None:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.MISSING,),
                decision.restrictions,
            )
        if route.state is TaskRouteState.QUARANTINED:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.QUARANTINED,),
                decision.restrictions,
            )
        if route.state is not TaskRouteState.ACTIVE or session is None or binding is None:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.UNREADABLE,),
                decision.restrictions,
            )
        if (
            binding.task_id != child_task_id
            or provenance.route_generation != route.route_generation
            or route.parent_task_id != lineage.parent_task_id
            or route.origin != lineage.origin
            or route.acceptance != lineage.acceptance
            or route.work_state != lineage.work_state
        ):
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.UNREADABLE,),
                decision.restrictions,
            )
        if lineage.acceptance is not LineageAcceptance.ACCEPTED:
            # C9 channel authority starts at acceptance.  Keep pending/rejected relationships
            # visible as lifecycle annotations, but do not open a child bundle to copy findings
            # into a parent manifest before the parent has accepted the dependency.
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.NOT_AUTHORIZED,),
                decision.restrictions,
                session_health=session.health,
            )
        if not decision.allowed or decision.restrictions:
            restrictions = decision.restrictions or (
                LineageProvenanceRestriction.AUTHORIZATION_MISSING,
            )
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.NOT_AUTHORIZED,),
                restrictions,
                session_health=session.health,
            )
        try:
            child_runtime = await self.runtime.route(
                RouteCommand(
                    route.session_id,
                    binding.writer_id,
                    RouteAccess.PAYLOAD_READ,
                    frozenset(
                        {
                            RuntimeCapability.STRUCTURAL_READ,
                            RuntimeCapability.PAYLOAD_READ,
                        }
                    ),
                )
            )
        except Exception:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.UNREADABLE,),
                session_health=session.health,
            )
        try:
            return await self._read_child(
                child_task_id,
                lineage,
                route,
                session,
                child_runtime,
            )
        except Exception:
            return self._unavailable(
                child_task_id,
                lineage,
                route,
                (LineageReadGapReason.UNREADABLE,),
                session_health=session.health,
            )
        finally:
            try:
                await self.runtime.release(child_runtime)
            except Exception:
                pass

    async def _read_child(
        self,
        child_task_id: str,
        lineage: TaskLineage,
        route: TaskRoute,
        session: SessionState,
        child_runtime: TaskRuntime,
    ) -> WireChildDependencySnapshot:
        if (
            child_runtime.task_id != child_task_id
            or child_runtime.session_id != route.session_id
            or RuntimeCapability.STRUCTURAL_READ not in child_runtime.capabilities
            or RuntimeCapability.PAYLOAD_READ not in child_runtime.capabilities
        ):
            raise _invalid()
        records = await self._load_records(child_runtime)
        if any(record.task_id != child_task_id for record in records):
            raise _invalid()
        projection = await projection_for_records(
            child_runtime.ledger,
            child_runtime.session_id,
            (
                Frontier(records[-1].ledger.ingestion_sequence, records[-1].entry_digest)
                if records
                else Frontier(0, "genesis")
            ),
            records,
        )
        current_frontier = await child_runtime.ledger.load_frontier()
        if (
            projection.frontier != current_frontier.sequence
            or projection.head_digest != current_frontier.head_digest
        ):
            raise _invalid()
        # A quarantined/rebuild-required projection cannot provide a complete frozen fact.  Replay
        # is still the source of truth for a healthy child, while this check rejects a stale
        # materialized projection before the coordinator stamps it.
        stored = await child_runtime.ledger.load_projection(
            child_runtime.session_id,
            ProjectionView.CANDIDATE_FINDINGS,
        )
        if stored is None or type(stored.state) is not ProjectionState:
            raise _invalid()
        if (
            stored.frontier != current_frontier
            or stored.lag != 0
            or stored.rebuild_required
            or stored.state.frontier != projection.frontier
            or stored.state.head_digest != projection.head_digest
        ):
            raise _invalid()

        coverage = (
            projection.latest_tested_state.coverage
            if projection.latest_tested_state
            else coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
        )
        coverage = _coverage_with_gaps(coverage, projection.coverage_gaps)
        live_codes = set(coverage.known_gaps)
        retained: set[str] = set()
        for _finding_key, finding_record in sorted(
            projection.findings.items(), key=lambda item: str(item[0]).encode("ascii")
        ):
            finding = finding_record.payload
            if type(finding) is not Finding:
                raise _invalid()
            retained.update(finding.coverage.known_gaps)
        # Issue #1017: a gap only a retained finding still carries, that an earlier check carried
        # and the child's latest tested check no longer does, is history in the child's receipt;
        # it must not bound the parent either.
        cleared = _cleared_retained_gaps(
            records,
            None
            if projection.latest_tested_state is None
            else projection.latest_tested_state.source_check_event_id,
            retained - live_codes,
        )
        coverage = _coverage_with_gaps(coverage, sorted(retained - cleared, key=str.encode))
        findings = list(_child_finding_snapshots(projection))

        receipt_id_value = None
        for record in records:
            if type(record) is AcceptedEvent and type(record.payload) is ReceiptRecordedPayload:
                receipt_id_value = record.payload.receipt_id
            elif (
                type(record) is AcceptedEvent
                and record.schema.name == "receipt_recorded"
                and record.payload is None
            ):
                raise _invalid()
        latest = projection.latest_tested_state
        # ``receipt_recorded`` is deliberately immaterial to check freshness.  A child receipt
        # therefore advances the bundle frontier without invalidating the qualifying check that
        # the parent is rolling up.  Record the latest tested subject frontier in that case so a
        # child receipt does not manufacture a stale-check gap; a material event leaves the live
        # frontier in place and is caught by the equality check in the pure evaluator.
        child_frontier = current_frontier
        if (
            latest is not None
            and projection.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
        ):
            child_frontier = latest.subject_frontier
        return WireChildDependencySnapshot(
            child_task_id=task_id(child_task_id),
            origin=cast(LineageOrigin, lineage.origin),
            acceptance=cast(LineageAcceptance, lineage.acceptance),
            work_state=lineage.work_state,
            session_health=session.health,
            child_frontier=child_frontier,
            child_check_id=None if latest is None else latest.source_check_event_id,
            child_check_subject_frontier=None if latest is None else latest.subject_frontier,
            child_receipt_id=receipt_id_value,
            coverage=coverage,
            findings=tuple(sorted(findings, key=lambda item: str(item.finding_id).encode("ascii"))),
            lineage_authority_revision=route.route_generation,
            membership_generation=await self._membership_generation(child_task_id),
        )

    async def _membership_generation(self, task: str) -> int | None:
        """Capture optional project generation without making project membership lineage authority."""

        list_projects = getattr(self.catalog, "list_task_project_ids", None)
        project_state = getattr(self.catalog, "project_state", None)
        if not callable(list_projects) or not callable(project_state):
            return None
        try:
            generations: list[int] = []
            project_ids = await cast(Callable[[str], Awaitable[tuple[str, ...]]], list_projects)(
                task
            )
            for project_identifier in project_ids:
                state = await cast(Callable[[str], Awaitable[object]], project_state)(
                    project_identifier
                )
                generation = getattr(state, "membership_generation", None)
                if type(generation) is int and generation > 0:
                    generations.append(generation)
            return max(generations) if generations else None
        except Exception:
            return None

    def _unavailable(
        self,
        child_task_id: str,
        lineage: TaskLineage | None,
        route: TaskRoute | None,
        read_gaps: tuple[LineageReadGapReason, ...],
        restrictions: tuple[LineageProvenanceRestriction, ...] = (),
        *,
        session_health: SessionHealth = SessionHealth.ENDED,
    ) -> WireChildDependencySnapshot:
        origin = (
            lineage.origin
            if lineage is not None and lineage.origin is not None
            else route.origin
            if route is not None and route.origin is not None
            else LineageOrigin.HOST_OBSERVED
        )
        acceptance = (
            lineage.acceptance
            if lineage is not None and lineage.acceptance is not None
            else route.acceptance
            if route is not None and route.acceptance is not None
            else LineageAcceptance.PENDING
        )
        work_state = (
            lineage.work_state
            if lineage is not None
            else route.work_state
            if route is not None
            else WorkState.OPEN
        )
        revision = route.route_generation if route is not None else 1
        return WireChildDependencySnapshot(
            child_task_id=task_id(child_task_id),
            origin=origin,
            acceptance=acceptance,
            work_state=work_state,
            session_health=session_health,
            child_frontier=None,
            child_check_id=None,
            child_check_subject_frontier=None,
            child_receipt_id=None,
            coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
            findings=(),
            lineage_authority_revision=revision,
            read_gap_reasons=tuple(
                sorted(set(read_gaps), key=lambda item: item.value.encode("ascii"))
            ),
            provenance_restrictions=tuple(
                sorted(set(restrictions), key=lambda item: item.value.encode("ascii"))
            ),
        )

    async def _append(
        self,
        parent_runtime: TaskRuntime,
        payload: ChildDependenciesRecordedPayload,
        parent_records: tuple[LedgerRecord, ...],
    ) -> AppendResult:
        manifest = manifest_from_payload(payload)
        request_digest_value = canonical_digest(
            {
                "domain": _LINEAGE_OPERATION_DOMAIN,
                "parent_task_id": parent_runtime.task_id,
                "manifest_digest": manifest.digest,
            }
        )
        operation_id = _stable_id(IdKind.REQUEST, request_digest_value)
        event_id_value = _stable_id(
            IdKind.EVENT,
            canonical_digest(
                {
                    "domain": _LINEAGE_EVENT_DOMAIN,
                    "parent_task_id": parent_runtime.task_id,
                    "manifest_digest": manifest.digest,
                }
            ),
        )
        occurred_at = timestamp_from_datetime(self.clock.now_utc())
        causal: tuple[EventId, ...] = () if not parent_records else (parent_records[-1].event_id,)
        writer_id = parent_runtime.writer_id
        if writer_id is None:
            raise _invalid()
        draft = EventDraft(
            cast(EventId, event_id_value),
            EventSchema("child_dependencies_recorded", _LINEAGE_EVENT_SCHEMA_VERSION),
            occurred_at,
            causal,
            payload,
            (),
            (),
        )
        payload_bytes = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD,
            media_type_for("child_dependencies_recorded"),
            parent_runtime.task_id,
            self.clock.now_utc(),
        )
        staged_objects: list[StagedObject] = []
        refs: list[ObjectRef] = []
        try:
            staged = await parent_runtime.objects.stage(
                ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)),
                metadata,
            )
            staged_objects.append(staged)
            ref = await parent_runtime.objects.finalize(staged)
            refs.append(ref)
            entry = AppendEntry(
                draft,
                Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                ref,
                ref.commitment,
                metadata.media_type,
                ref.plaintext_size,
                PublicationChannel.ENGINE_DERIVED,
                coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
                "projected",
            )
            command = AppendCommand(
                parent_runtime.task_id,
                parent_runtime.session_id,
                writer_id,
                operation_id,
                OperationKind.PUBLISH_WORK,
                request_digest_value,
                None,
                (entry,),
            )
            prepared = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                parent_runtime.objects,
                tuple(staged_objects),
                component="application.lineage_coordinator",
                operation="lineage_manifest_object_abandon_failed",
                request_id=operation_id,
            )
            raise
        return await run_prepared_append(parent_runtime.ledger, prepared)
