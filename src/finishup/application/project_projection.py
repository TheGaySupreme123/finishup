"""Final source authorization for a project status response.

Project text is hydrated only for the resolved client sink. The ordinary client projection then
applies the recipient policy and scans the exact bytes before anything leaves the service.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, cast

from finishup.application.projects import ProjectApplication, ProjectCommandError, ProjectStatus
from finishup.domain.coordination import CoordinationErrorCode, ProjectTextRef
from finishup.domain.privacy import (
    AuthorizationScope,
    CandidateContextItem,
    DataCategory,
    LocalDisclosureSink,
)
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ProjectTextRefModel


def source_denied_project_items(
    source: Mapping[str, JsonValue], scope: AuthorizationScope
) -> tuple[CandidateContextItem, ...]:
    """Make source omissions auditable through the normal recipient projection decision.

    Only the exact marker produced by the trusted hydrator is accepted. The candidate contains
    no denied title or description bytes, and its producer restriction cannot authorize content.
    """

    page = source.get("page")
    if not isinstance(page, Mapping):
        return ()
    omitted = {
        "omitted": True,
        "category": "task_description",
        "reason": "local_disclosure_not_authorized",
    }
    return tuple(
        CandidateContextItem(
            f"project-source-denied-{field}",
            DataCategory.TASK_DESCRIPTION,
            scope,
            f"/page/{field}",
            b"null",
            source_disclosure_permitted=False,
        )
        for field in ("title", "description")
        if page.get(field) == omitted
    )


async def hydrate_project_status_text(
    projects: ProjectApplication,
    source: dict[str, JsonValue],
    sink: LocalDisclosureSink,
) -> dict[str, JsonValue]:
    """Bind both source text fields to the references in this exact status snapshot."""

    page = source.get("page")
    requester = source.get("task_id")
    if not isinstance(page, Mapping) or type(requester) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    project_id = page.get("project_id")
    generation = page.get("membership_generation")
    if type(project_id) is not str or type(generation) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    result = dict(page.items())
    fields: tuple[Literal["title", "description"], ...] = ("title", "description")
    for field in fields:
        raw_reference = page.get(f"{field}_ref")
        if raw_reference is None:
            if field in page:
                raise ControlError("privacy_projection_unavailable", retryable=True)
            continue
        # Internal control JSON uses the frozen ``JsonObject`` mapping.  Pydantic's closed
        # models intentionally accept plain JSON dictionaries only at this boundary, so copy the
        # structural reference without altering any value or allowing caller-supplied text.
        model = ProjectTextRefModel.model_validate(
            dict(raw_reference.items()) if isinstance(raw_reference, Mapping) else raw_reference
        )
        reference = ProjectTextRef(
            model.object_id,
            model.content_digest,
            model.plaintext_size,
            model.owner_task_id,
            int(model.route_generation),
            model.envelope_digest,
        )
        try:
            value = await projects.project_text_for_sink(
                requester,
                project=project_id,
                field=field,
                sink=sink,
                expected_generation=int(generation),
                expected_reference=reference,
            )
        except ProjectCommandError as exc:
            if exc.code is not CoordinationErrorCode.CONSENT_REQUIRED:
                raise ControlError("privacy_projection_unavailable", retryable=True) from exc
            result[field] = {
                "omitted": True,
                "category": "task_description",
                "reason": "local_disclosure_not_authorized",
            }
        else:
            if value is None:
                raise ControlError("privacy_projection_unavailable", retryable=True)
            result[field] = value
    return {**source, "page": result}


async def hydrate_project_status_coordination_resources(
    projects: ProjectApplication,
    source: dict[str, JsonValue],
    sink: LocalDisclosureSink,
) -> dict[str, JsonValue]:
    """Hydrate source-owned overlap paths for the final recipient sink.

    The internal project snapshot carries only an omission marker for each encrypted detection
    detail.  This pass resolves the marker after the requester, both participants, current
    project generation, source consent, and source-owner policy have all been checked by the
    application boundary.  A denied or unavailable detail remains an explicit bounded omission.
    """

    page = source.get("page")
    requester = source.get("task_id")
    if not isinstance(page, Mapping) or type(requester) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    project_id = page.get("project_id")
    generation = page.get("membership_generation")
    detections = page.get("detections")
    if (
        type(project_id) is not str
        or type(generation) is not str
        or type(detections) not in {tuple, list}
    ):
        raise ControlError("privacy_projection_unavailable", retryable=True)
    hydrated: list[JsonValue] = []
    for raw in cast(Sequence[JsonValue], detections):
        if not isinstance(raw, Mapping):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        row = dict(raw.items())
        if "resource_paths" not in row:
            hydrated.append(row)
            continue
        detection_id = row.get("detection_id")
        if type(detection_id) is not str:
            raise ControlError("privacy_projection_unavailable", retryable=True)
        try:
            detail = await projects.coordination_resource_detail_for(
                requester,
                project=project_id,
                detection_id=detection_id,
                sink=sink,
                expected_generation=int(generation),
            )
        except ProjectCommandError as exc:
            if exc.code not in {
                CoordinationErrorCode.CONSENT_REQUIRED,
                CoordinationErrorCode.GRANT_REQUIRED,
                CoordinationErrorCode.GRANT_REVOKED,
                CoordinationErrorCode.GENERATION_MISMATCH,
            }:
                raise ControlError("privacy_projection_unavailable", retryable=True) from exc
            detail = None
        if detail is None or detail.resource_paths is None:
            row["resource_paths"] = {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            }
        else:
            row["resource_paths"] = detail.resource_paths
        hydrated.append(row)
    return {**source, "page": {**dict(page.items()), "detections": hydrated}}


async def hydrate_status_advice_coordination_resources(
    projects: ProjectApplication,
    source: dict[str, JsonValue],
    sink: LocalDisclosureSink,
) -> dict[str, JsonValue]:
    """Hydrate the exact coordination selector carried by each advice recipient row."""

    page = source.get("page")
    requester = source.get("task_id")
    if not isinstance(page, Mapping) or type(requester) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    typed_page = cast(Mapping[str, JsonValue], page)
    items = typed_page.get("items")
    if type(items) not in {tuple, list}:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    hydrated: list[dict[str, JsonValue]] = []
    for raw in cast(Sequence[JsonValue], items):
        if not isinstance(raw, Mapping):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        row = dict(cast(Mapping[str, JsonValue], raw).items())
        detection_id = row.get("coordination_detection_id")
        if detection_id is None:
            hydrated.append(row)
            continue
        project_id = row.get("coordination_project_id")
        generation = row.get("coordination_membership_generation")
        counterpart = row.get("coordination_counterpart_task_id")
        if (
            type(project_id) is not str
            or type(detection_id) is not str
            or type(generation) is not str
            or type(counterpart) is not str
        ):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        try:
            detail = await projects.coordination_resource_detail_for(
                requester,
                project=project_id,
                detection_id=detection_id,
                sink=sink,
                expected_generation=int(generation),
            )
        except ProjectCommandError as exc:
            if exc.code not in {
                CoordinationErrorCode.CONSENT_REQUIRED,
                CoordinationErrorCode.GRANT_REQUIRED,
                CoordinationErrorCode.GRANT_REVOKED,
                CoordinationErrorCode.GENERATION_MISMATCH,
            }:
                raise ControlError("privacy_projection_unavailable", retryable=True) from exc
            detail = None
        if (
            detail is None
            or detail.resource_paths is None
            or detail.counterpart_task_id != counterpart
        ):
            row["coordination_resource_paths"] = {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            }
        else:
            row["coordination_resource_paths"] = detail.resource_paths
        hydrated.append(row)
    return {
        **source,
        "page": {**dict(typed_page.items()), "items": cast(JsonValue, hydrated)},
    }


async def revalidate_status_advice_sources(
    projects: ProjectApplication,
    source: Mapping[str, JsonValue],
    sink: LocalDisclosureSink,
) -> None:
    """Ensure coordination paths did not change while the advice response was projected."""

    materialized = await hydrate_status_advice_coordination_resources(
        projects,
        dict(source.items()),
        sink,
    )
    page = source.get("page")
    refreshed_page = materialized.get("page")
    if not isinstance(page, Mapping) or not isinstance(refreshed_page, Mapping):
        raise ControlError("privacy_projection_unavailable", retryable=True)
    typed_page = cast(Mapping[str, JsonValue], page)
    page_items = typed_page.get("items")
    requester = source.get("task_id")
    if type(requester) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    source_selectors: set[tuple[str, str, int, str]] = set()
    if type(page_items) not in {tuple, list}:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    for raw_item in cast(Sequence[JsonValue], page_items):
        if not isinstance(raw_item, Mapping):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        item = cast(Mapping[str, JsonValue], raw_item)
        detection_id = item.get("coordination_detection_id")
        if detection_id is None:
            continue
        item_project = item.get("coordination_project_id")
        item_generation = item.get("coordination_membership_generation")
        counterpart = item.get("coordination_counterpart_task_id")
        if (
            type(item_project) is not str
            or type(detection_id) is not str
            or type(item_generation) is not str
            or type(counterpart) is not str
        ):
            raise ControlError("privacy_projection_unavailable", retryable=True)
        try:
            numeric_generation = int(item_generation)
        except ValueError as exc:
            raise ControlError("privacy_projection_unavailable", retryable=True) from exc
        source_selectors.add((item_project, detection_id, numeric_generation, counterpart))
    try:
        current_project_ids = await projects.catalog.list_task_project_ids(requester)
    except ProjectCommandError as exc:
        raise ControlError("privacy_projection_unavailable", retryable=True) from exc
    current_selectors: set[tuple[str, str, int, str]] = set()
    for current_project in current_project_ids:
        try:
            advice_rows = await projects.coordination_advice_for(
                requester,
                project=current_project,
            )
        except ProjectCommandError as exc:
            raise ControlError("privacy_projection_unavailable", retryable=True) from exc
        for advice in advice_rows:
            if advice.target_task_id != requester:
                continue
            current_selectors.add(
                (
                    advice.project_id,
                    advice.detection_id,
                    advice.membership_generation,
                    advice.counterpart_task_id,
                )
            )
    # Advice pages are request-limited and carry no cursor for rows beyond that bound.  Every
    # selector emitted in this page must still be an exact current tuple; newer rows may exist
    # outside the page and do not invalidate the already-bounded response.
    if not source_selectors <= current_selectors:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    if canonical_encode(page.get("items")) != canonical_encode(refreshed_page.get("items")):
        raise ControlError("privacy_projection_unavailable", retryable=True)


async def revalidate_project_status_sources(
    projects: ProjectApplication,
    source: Mapping[str, JsonValue],
    sink: LocalDisclosureSink,
) -> None:
    """Refuse a response if authority changed while the client projection was preparing."""

    page = source.get("page")
    requester = source.get("task_id")
    if not isinstance(page, Mapping) or type(requester) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    project_id = page.get("project_id")
    generation = page.get("membership_generation")
    if type(project_id) is not str or type(generation) is not str:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    try:
        current = await projects.project_view_for(
            requester,
            project=project_id,
            expected_generation=int(generation),
        )
    except ProjectCommandError as exc:
        raise ControlError("privacy_projection_unavailable", retryable=True) from exc
    if not isinstance(current, ProjectStatus):
        raise ControlError("privacy_projection_unavailable", retryable=True)
    admitted = {item.task_id for item in current.memberships if item.task_id is not None}

    def task_ids(value: JsonValue) -> set[str]:
        if isinstance(value, Mapping):
            found: set[str] = set()
            for key, child in value.items():
                if key == "task_id" and type(child) is str:
                    found.add(child)
                elif key == "task_ids" and isinstance(child, (list, tuple)):
                    found.update(item for item in child if type(item) is str)
                else:
                    found.update(task_ids(child))
            return found
        if isinstance(value, (tuple, list)):
            return set[str]().union(*(task_ids(child) for child in value))
        return set()

    # Ref owners and parent references describe durable provenance and can outlive membership;
    # selected member, child, detection and receipt rows require current source admission.
    visible = {
        key: page[key]
        for key in ("members", "lineage", "detections", "coverage", "receipts")
        if key in page
    }
    if not task_ids(cast(JsonValue, visible)) <= admitted:
        raise ControlError("privacy_projection_unavailable", retryable=True)
    for field, reference in (
        ("title", current.project.title_ref),
        ("description", current.project.description_ref),
    ):
        expected = page.get(f"{field}_ref")
        if isinstance(expected, Mapping):
            expected = dict(expected.items())
        if expected != (None if reference is None else dict(reference.as_wire().items())):
            raise ControlError("privacy_projection_unavailable", retryable=True)
    rechecked = await hydrate_project_status_text(projects, dict(source.items()), sink)
    rechecked = await hydrate_project_status_coordination_resources(projects, rechecked, sink)
    if rechecked != source:
        raise ControlError("privacy_projection_unavailable", retryable=True)
