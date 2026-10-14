"""The check's continuation tokens are one closed set on every surface that names them.

Owner decision 2026-10-12 (#1024): when the only remaining agent work is a reviewer's limitation
request the agent has not answered, the check says ``disclose_limitations`` (on the task-level
``overall_next.action`` and the finding checklist ``next``) instead of the repair token
``work_open_findings``. A wire value added in one place and not another is the half fix this round
exists to prevent, so the model literals, the port dataclasses, the committed schema, the MCP
summary allowlists and the CLI wording must all carry exactly the same values.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args

import pytest

from finishup.cli.render import _CHECKLIST_NEXT_TEXT  # pyright: ignore[reportPrivateUsage]
from finishup.mcp.summaries import _CHECKLIST_NEXT as MCP_CHECKLIST_NEXT
from finishup.ports import ledger as ports
from finishup.protocol.models import CheckFindingChecklistModel, CheckOverallNextModel

_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "schemas"
    / "operations"
    / "check-result-1.4.0.schema.json"
)
_REF = "fnd_59000000-0000-4000-8000-000000000001"


def _schema_defs() -> dict[str, Any]:
    document = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    return document["$defs"]


def _model_literal(model: type, field: str) -> frozenset[str]:
    annotation = model.model_fields[field].annotation  # type: ignore[attr-defined]
    return frozenset(get_args(annotation))


def test_the_checklist_next_values_are_the_same_set_on_every_surface() -> None:
    expected = frozenset(
        {
            "decide_at_budget",
            "disclose_limitations",
            "request_receipt",
            "request_ruling",
            "work_open_findings",
        }
    )
    assert _model_literal(CheckFindingChecklistModel, "next") == expected
    assert frozenset(get_args(ports.ChecklistNext)) == expected
    assert ports._CHECKLIST_NEXT == expected
    assert frozenset(_schema_defs()["finding_checklist"]["properties"]["next"]["enum"]) == expected
    assert MCP_CHECKLIST_NEXT == expected
    # The CLI words every value except the receipt-free defaults it composes itself.
    assert frozenset(_CHECKLIST_NEXT_TEXT) == expected


def test_the_overall_next_actions_are_the_same_set_on_every_surface() -> None:
    expected = frozenset(
        {
            "supply_missing_input",
            "work_open_findings",
            "disclose_limitations",
            "request_ruling",
            "review_recorded_work",
            "request_receipt",
        }
    )
    assert _model_literal(CheckOverallNextModel, "action") == expected
    assert frozenset(get_args(ports.OverallNextAction)) == expected
    assert ports._OVERALL_NEXT_ACTIONS == expected
    defs = _schema_defs()["overall_next"]
    assert frozenset(defs["properties"]["action"]["enum"]) == expected
    # The schema rule that demands an action_required status and at least one target names the
    # same target-bearing actions the models and the port dataclass demand.
    targeted = {
        frozenset(rule["if"]["properties"]["action"]["enum"])
        for rule in defs["allOf"]
        if "enum" in rule["if"]["properties"].get("action", {})
    }
    assert targeted == {
        frozenset(
            {"work_open_findings", "disclose_limitations", "request_ruling", "review_recorded_work"}
        )
    }


@pytest.mark.parametrize("action", ["disclose_limitations", "work_open_findings"])
def test_a_target_bearing_action_needs_action_required_and_a_target(action: str) -> None:
    ok = CheckOverallNextModel.model_validate(
        {"status": "action_required", "action": action, "target_refs": [_REF]}
    )
    assert ok.action == action
    bad_bodies: tuple[dict[str, Any], ...] = (
        {"status": "ready_with_limitations", "action": action, "target_refs": [_REF]},
        {"status": "action_required", "action": action, "target_refs": []},
    )
    for bad in bad_bodies:
        with pytest.raises(ValueError):
            CheckOverallNextModel.model_validate(bad)
    # The port dataclass the application builds agrees with the public model.
    built = ports.CheckOverallNext("action_required", action, (_REF,))  # type: ignore[arg-type]
    assert built.action == action
    with pytest.raises(ValueError):
        ports.CheckOverallNext("action_required", action, ())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ports.CheckOverallNext("ready", action, (_REF,))  # type: ignore[arg-type]
