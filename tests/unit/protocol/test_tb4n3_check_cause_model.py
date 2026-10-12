"""``closure_readiness.check_cause`` is closed, optional and bound to the token it explains.

tb4n3 RC-6 (issue #1029, owner lineage rule): a derived readiness token carries the record it rests
on. The field is omitted, never null, and only appears beside ``check_not_applicable`` (superseded)
or the bounding ``check_current_as_of_earlier_frontier``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from yoetz.protocol.models import StatusClosureReadinessModel
from yoetz.protocol.readiness_text import check_cause_sentence

_EVENT = "evt_00000000-0000-4000-8000-000000000001"
_CHECK = "evt_00000000-0000-4000-8000-000000000002"


def _cause(**changes: Any) -> dict[str, Any]:
    return {
        "effect": "superseded",
        "event_id": _EVENT,
        "ledger_sequence": "12",
        "check_event_id": _CHECK,
        "check_subject_frontier": "9",
        "family": "action_recorded",
        "material_class": "edit_or_write",
        "rule": "observed_counting_edit",
        "tool": "apply_patch",
        **changes,
    }


def _readiness(actionable: tuple[str, ...], **fields: Any) -> dict[str, Any]:
    return {
        "declared_obligation_count": "1",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": ("coverage_gaps_declared",),
        "state": "action_required",
        "gap_classification_version": "6",
        "agent_actionable": actionable,
        "standing_limitations": (),
        "acknowledged_not_done": (),
        "acknowledged_not_done_count": "0",
        **fields,
    }


def test_a_cause_beside_its_token_validates() -> None:
    model = StatusClosureReadinessModel.model_validate(
        _readiness(("check_not_applicable",), check_cause=_cause())
    )
    assert model.check_cause is not None and model.check_cause.tool == "apply_patch"


def test_the_tool_is_optional_but_never_null() -> None:
    without = _cause()
    del without["tool"]
    StatusClosureReadinessModel.model_validate(
        _readiness(("check_not_applicable",), check_cause=without)
    )
    with pytest.raises(ValidationError):
        StatusClosureReadinessModel.model_validate(
            _readiness(("check_not_applicable",), check_cause=_cause(tool=None))
        )


def test_a_bounding_cause_sits_beside_the_standing_code() -> None:
    model = StatusClosureReadinessModel.model_validate(
        _readiness(
            (),
            state="ready_with_limitations",
            standing_limitations=("check_current_as_of_earlier_frontier",),
            check_cause=_cause(effect="bounds_conclusion", material_class="other"),
        )
    )
    assert model.check_cause is not None and model.check_cause.effect == "bounds_conclusion"


@pytest.mark.parametrize(
    ("fields", "cause"),
    (
        # No listed token at all.
        ({}, _cause()),
        # A superseded cause needs check_not_applicable as WORK, not a standing code.
        ({"standing_limitations": ("check_not_applicable",)}, _cause()),
        # A bounding cause needs the standing disclosure, not agent work.
        (
            {"agent_actionable": ("check_current_as_of_earlier_frontier",)},
            _cause(effect="bounds_conclusion"),
        ),
        ({}, _cause(effect="bounds_conclusion")),
    ),
)
def test_a_cause_without_the_token_it_explains_is_refused(
    fields: dict[str, Any], cause: dict[str, Any]
) -> None:
    base = _readiness(fields.pop("agent_actionable", ()), **fields)
    if not base["agent_actionable"] and base["state"] == "action_required":
        base["state"] = "ready_with_limitations"
    with pytest.raises(ValidationError):
        StatusClosureReadinessModel.model_validate({**base, "check_cause": cause})


@pytest.mark.parametrize(
    "bad",
    (
        {"material_class": "anything"},
        {"effect": "other"},
        {"ledger_sequence": "01"},
        {"event_id": "not-an-event"},
        {"rule": "Has Spaces"},
        {"tool": "/etc/passwd rm -rf"},
        {"extra": "field"},
    ),
)
def test_the_cause_is_a_closed_set_of_tokens(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        StatusClosureReadinessModel.model_validate(
            _readiness(("check_not_applicable",), check_cause=_cause(**bad))
        )


def test_the_frozen_sentence_names_the_record_the_check_and_the_rule() -> None:
    sentence = check_cause_sentence(
        effect="superseded",
        event_id=_EVENT,
        ledger_sequence="12",
        check_subject_frontier="9",
        family="action_recorded",
        material_class="edit_or_write",
        rule="observed_counting_edit",
        tool="apply_patch",
    )
    assert sentence == (
        "Why check_not_applicable: an observed edit via apply_patch (ledger record 12, "
        f"{_EVENT}) was recorded after the check at subject frontier 9 "
        "(rule observed_counting_edit). Re-run check after your last change."
    )
    with pytest.raises(ValueError):
        check_cause_sentence(
            effect="nope",
            event_id=_EVENT,
            ledger_sequence="1",
            check_subject_frontier="1",
            family="action_recorded",
            material_class="other",
            rule="r",
        )
