"""Every public result model with a nested collection must project from a real internal result.

Two projection defects of the same class shipped in a row. PR #50 fixed a phantom null on
``publish_work``'s accepted events; the class survived and reappeared as nested findings that the
strict closed models could not accept at all, on ``check``. Each fix was verified against the one
operation that had been observed failing, so nothing ever asked whether the *rest* of the public
surface projected.

This sweep asks. It runs one realistic workflow through the real ready composition and projects
every public result model — and every status view — asserting that each nested collection the
models declare is present and populated in the response the caller receives. A vacuous pass is the
failure mode that let this class live, so an expectation that names a collection also requires it
to be non-empty.

The sweep deliberately states its invariant structurally: *nested collections project*. It never
names the internal container type that happened to break, because the next instance of this class
will arrive wearing a different type.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

import pytest

from builders.projection_workflow import (
    STATUS_VIEWS,
    ProjectionWorkflow,
    project_case,
    run_projection_workflow,
)
from finishup.protocol.canonical import JsonValue

pytestmark = pytest.mark.anyio


# Every nested collection the public result models declare, as a JSON pointer into the projected
# wire body. ``populated`` says whether this workflow must produce at least one element: where it
# is True an empty collection is a sweep failure, because an empty collection proves nothing about
# nested projection.
_EXPECTATIONS: tuple[tuple[str, str, bool], ...] = (
    ("start", "/compact", True),
    ("publish_work", "/accepted_events", True),
    ("check", "/findings", True),
    ("check", "/policy_executions", True),
    ("respond", "/accepted_event", True),
    ("respond", "/response/evidence", True),
    ("receipt", "/document", True),
    ("receipt", "/versions/policy_versions", True),
    ("receipt", "/versions/schema_versions", True),
    # The compact view carries two collections nested one level inside its single page item; both
    # are populated by the sweep workflow (an open obligation, and the finding ``check`` raised).
    ("status/compact", "/page/items", True),
    ("status/compact", "/page/items/0/open_obligations", True),
    ("status/compact", "/page/items/0/unanswered_findings", True),
    ("status/assignment", "/page/items", True),
    ("status/evidence", "/page/items", True),
    ("status/findings", "/page/items", True),
    ("status/history", "/page/items", True),
    ("status/obligations", "/page/items", True),
    # The operation view is the one page that is a single recovery record rather than a list; its
    # nested collection is the accepted events of the operation being recovered.
    ("status/operation", "/page/accepted_events", True),
    ("status/versions", "/page/items", True),
    # Advice and candidate findings are populated by the observation pipeline, which a
    # provider-free workflow never runs. Their pages must still project — an empty page is a
    # nested collection too, and it is the shape the daemon returns today.
    ("status/advice", "/page/items", False),
    ("status/candidate_findings", "/page/items", False),
)


def _resolve(body: Mapping[str, JsonValue], pointer: str) -> JsonValue:
    """Resolve one RFC 6901 pointer against a projected wire body."""

    current: JsonValue = body
    for segment in pointer.removeprefix("/").split("/"):
        if isinstance(current, Mapping):
            source = cast(Mapping[str, JsonValue], current)
            assert segment in source, f"{pointer}: {segment!r} missing"
            current = source[segment]
            continue
        assert isinstance(current, Sequence) and not isinstance(current, str), (
            f"{pointer}: {segment!r} does not address a mapping or an array"
        )
        items = cast(Sequence[JsonValue], current)
        assert segment.isdecimal() and int(segment) < len(items), f"{pointer}: {segment!r} missing"
        current = items[int(segment)]
    return current


@pytest.fixture(scope="module")
async def workflow() -> ProjectionWorkflow:
    """Run the shared workflow once for the whole sweep."""

    return await run_projection_workflow()


async def test_the_sweep_covers_every_status_view() -> None:
    """A new status view must arrive with an expectation, not silently unswept."""

    swept = {label.removeprefix("status/") for label, _, _ in _EXPECTATIONS if "/" in label}
    assert swept >= set(STATUS_VIEWS)


@pytest.mark.parametrize(("label", "pointer", "populated"), _EXPECTATIONS)
async def test_nested_collections_project(
    workflow: ProjectionWorkflow, label: str, pointer: str, populated: bool
) -> None:
    """The named nested collection survives the public result model, for real material."""

    seed = 1600 + 4 * _EXPECTATIONS.index((label, pointer, populated))
    projected = await project_case(workflow.app, workflow.case(label), seed)

    assert projected["ok"] is True
    value = _resolve(projected, pointer)
    assert value is not None, f"{label}{pointer} projected as null"
    if isinstance(value, Mapping):
        assert cast(Mapping[str, JsonValue], value), f"{label}{pointer} projected empty"
        return
    assert isinstance(value, Sequence) and not isinstance(value, str), (
        f"{label}{pointer} is neither a nested object nor an array"
    )
    if populated:
        assert cast(Sequence[JsonValue], value), f"{label}{pointer} projected empty"


async def test_every_case_the_workflow_builds_projects(workflow: ProjectionWorkflow) -> None:
    """No public result model may fail to project — including any the table has not reached yet."""

    for offset, case in enumerate(workflow.cases):
        projected = await project_case(workflow.app, case, 1800 + 4 * offset)
        assert projected["ok"] is True, case.label
