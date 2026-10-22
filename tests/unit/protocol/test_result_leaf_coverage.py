"""Every result leaf the models can emit must classify to exactly one rule.

``classify_result_leaf`` raises ``invalid_json_pointer`` when a leaf matches zero rules or more
than one exact rule. That call sits inside the post-commit projection window, so a registry gap
does not degrade gracefully: it converts an already-durable operation into a failure the caller
cannot replay away. ``_build_result_leaf_rules`` guards itself with a hardcoded rule count, which
detects that rules were added or removed but cannot detect that a *model* grew a field no rule
covers. This derives the leaf space from the models themselves and closes that hole.
"""

from __future__ import annotations

import types
from typing import Annotated, ForwardRef, Union, cast, get_args, get_origin, get_type_hints

import pytest
from pydantic.fields import FieldInfo

import finishup.protocol.models as models

_STATUS_VIEW_BY_PAGE_MODEL = {
    "StatusAdvicePageModel": "advice",
    "StatusAssignmentPageModel": "assignment",
    "StatusCandidateFindingsPageModel": "candidate_findings",
    "StatusCompactPageModel": "compact",
    "StatusEvidencePageModel": "evidence",
    "StatusFindingsPageModel": "findings",
    "StatusHistoryPageModel": "history",
    "StatusObligationsPageModel": "obligations",
    "StatusResultsPageModel": "results",
    "StatusOperationPageModel": "operation",
    "StatusVersionsPageModel": "versions",
    "StatusLineagePageModel": "lineage",
    "StatusProjectPageModel": "project",
    "StatusCoveragePageModel": "coverage",
}


def _is_model(annotation: object) -> bool:
    closed = getattr(models, "_ClosedModel")
    return isinstance(annotation, type) and issubclass(annotation, closed)


def _field_annotations(model: type) -> dict[str, object]:
    """Each declared field's annotation, with forward references resolved (#1184).

    ``FieldInfo.annotation`` stays an unevaluated ``ForwardRef`` for a field whose model is
    defined later in ``models.py`` (``CheckSuccessModel.closure_readiness``) until pydantic first
    rebuilds the model, so reading it made the walk depend on what ran earlier in the process.
    The module's own namespace resolves every such reference deterministically.
    """

    hints = get_type_hints(model, include_extras=True)
    fields = cast(dict[str, FieldInfo], getattr(model, "model_fields"))
    return {name: hints[name] for name in fields}


def _leaf_patterns(
    annotation: object,
    path: tuple[str, ...],
    collected: set[tuple[str, ...]],
    depth: int = 0,
) -> None:
    """Collect every leaf pointer pattern the annotation can produce, arrays as ``*``."""

    # An unresolved reference would collapse a whole model subtree into one opaque leaf that the
    # registry happens to cover, so the guard would silently skip it; fail loudly instead.
    assert not isinstance(annotation, (str, ForwardRef)), (
        f"unresolved annotation {annotation!r} at /{'/'.join(path)}"
    )

    if depth > 12:  # the deepest real result nests well under this
        raise AssertionError("result_model_nesting_deeper_than_expected")
    origin = get_origin(annotation)
    if origin is Annotated:
        _leaf_patterns(get_args(annotation)[0], path, collected, depth)
        return
    if origin in (Union, types.UnionType):
        for member in get_args(annotation):
            if member is type(None):
                continue
            _leaf_patterns(member, path, collected, depth)
        return
    if origin is tuple:
        _leaf_patterns(get_args(annotation)[0], (*path, "*"), collected, depth + 1)
        return
    if _is_model(annotation):
        model = cast(type, annotation)
        model_fields = cast(dict[str, FieldInfo], getattr(model, "model_fields"))
        for name, resolved in _field_annotations(model).items():
            wire_name = model_fields[name].serialization_alias or name
            _leaf_patterns(resolved, (*path, wire_name), collected, depth + 1)
        return
    collected.add(path)


def _matching_rules(
    method: str,
    segments: tuple[str, ...],
    *,
    status_view: str | None = None,
    event_selector: tuple[str, str] | str | None = None,
) -> str:
    """Mirror classify_result_leaf's rule selection for one pointer pattern."""

    shape_matches = getattr(models, "_shape_matches")
    # Array positions are ``*`` here and ``None`` in the classifier's per-shape key.
    shape = tuple(None if segment == "*" else segment for segment in segments)
    contextual = [
        rule
        for rule in getattr(models, "_RESULT_LEAF_RULES")
        if rule.method == method
        and (rule.status_view is None or rule.status_view == status_view)
        and (rule.event_selector is None or rule.event_selector == event_selector)
    ]
    exact = [rule for rule in contextual if "*" not in rule.segments and shape_matches(rule, shape)]
    if len(exact) > 1:
        return "ambiguous"
    if exact:
        return "covered"
    wildcard = [rule for rule in contextual if "*" in rule.segments and shape_matches(rule, shape)]
    if len(wildcard) == 1:
        return "covered"
    return "uncovered" if not wildcard else "ambiguous"


def _status_page_models() -> dict[str, object]:
    page_union = getattr(models, "StatusPage")
    resolved = page_union.__value__ if hasattr(page_union, "__value__") else page_union
    found: dict[str, object] = {}
    for member in get_args(resolved):
        model = get_args(member)[0] if get_origin(member) is Annotated else member
        found[model.__name__] = model
    return found


def test_status_page_models_are_exactly_the_known_views() -> None:
    # If a view is added without a mapping, the coverage test below would silently skip it.
    assert set(_status_page_models()) == set(_STATUS_VIEW_BY_PAGE_MODEL)


@pytest.mark.parametrize(
    ("method", "model_name"),
    [
        ("start", "StartSuccessModel"),
        ("check", "CheckSuccessModel"),
        ("respond", "RespondSuccessModel"),
        ("receipt", "ReceiptSuccessModel"),
    ],
)
def test_every_result_leaf_classifies_to_exactly_one_rule(method: str, model_name: str) -> None:
    patterns: set[tuple[str, ...]] = set()
    _leaf_patterns(getattr(models, model_name), (), patterns)
    assert patterns, "model produced no leaves"
    uncovered = sorted(
        "/" + "/".join(pattern)
        for pattern in patterns
        if _matching_rules(method, pattern) != "covered"
    )
    assert uncovered == [], f"{method} result leaves without exactly one rule: {uncovered}"


def test_a_forward_referenced_subtree_is_walked_not_collapsed() -> None:
    """#1184: ``closure_readiness`` names a model defined later in ``models.py``.

    The walk must reach its leaves in any process state, not record ``/closure_readiness`` as
    one opaque leaf that a registry rule happens to cover.
    """

    patterns: set[tuple[str, ...]] = set()
    _leaf_patterns(getattr(models, "CheckSuccessModel"), (), patterns)
    readiness = {pattern for pattern in patterns if pattern[0] == "closure_readiness"}
    assert ("closure_readiness",) not in readiness
    assert ("closure_readiness", "state") in readiness
    assert ("closure_readiness", "finding_counts", "to_do") in readiness


def test_every_status_leaf_classifies_to_exactly_one_rule_in_every_view() -> None:
    common: set[tuple[str, ...]] = set()
    _leaf_patterns(getattr(models, "StatusSuccessModel"), (), common)
    common = {pattern for pattern in common if pattern[0] != "page"}
    assert common, "status success model produced no common leaves"

    uncovered: list[str] = []
    for model_name, model in _status_page_models().items():
        view = _STATUS_VIEW_BY_PAGE_MODEL[model_name]
        page_patterns: set[tuple[str, ...]] = set()
        _leaf_patterns(model, ("page",), page_patterns)
        for pattern in sorted(common | page_patterns):
            if _matching_rules("status", pattern, status_view=view) != "covered":
                uncovered.append(f"{view}:/" + "/".join(pattern))
    assert uncovered == [], f"status leaves without exactly one rule: {uncovered}"


def test_every_publish_event_family_classifies_its_summary() -> None:
    summary = ("accepted_events", "*", "summary")
    known = set(getattr(models, "_PUBLISH_SUMMARY_CATEGORY")) | set(
        getattr(models, "_PUBLISH_FIXED_SUMMARY")
    )
    assert known, "no publish summary selectors registered"
    uncovered = sorted(
        f"{name}@{version}"
        for name, version in known
        if _matching_rules("publish_work", summary, event_selector=(name, version)) != "covered"
    )
    assert uncovered == [], f"publish families without a summary rule: {uncovered}"
    # An unrecognised family still classifies, through the explicit opaque selector.
    assert _matching_rules("publish_work", summary, event_selector="<opaque>") == "covered"


def test_publish_result_leaves_other_than_summary_classify() -> None:
    patterns: set[tuple[str, ...]] = set()
    _leaf_patterns(getattr(models, "PublishWorkSuccessModel"), (), patterns)
    _leaf_patterns(getattr(models, "PublishWorkAcceptedProjectionUnavailableModel"), (), patterns)
    uncovered = sorted(
        "/" + "/".join(pattern)
        for pattern in patterns
        if pattern != ("accepted_events", "*", "summary")
        and _matching_rules("publish_work", pattern) != "covered"
    )
    assert uncovered == [], f"publish_work result leaves without exactly one rule: {uncovered}"
