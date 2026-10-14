"""The nonterminal CHECK branch must be recoverable and must not look like a conclusion.

The supervised run produced a check whose only honest content was "a human must approve" — with
no pending id, no command, and no way back. This branch exists so that result is actionable, and
these tests hold the two properties that make it so: it carries the exact command, and it carries
nothing a caller could mistake for a verdict.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import uuid
from typing import Any, Final, cast

import pytest
from pydantic import ValidationError

from finishup.cli.render import render_human_awaiting_human
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import (
    CheckAwaitingHumanModel,
    CheckResultModel,
    CheckSuccessModel,
    StatusOperationPageModel,
)
from finishup.protocol.schemas import validate_schema_instance

_PENDING: Final = f"ppr_{uuid.uuid4()}"
_REQUEST: Final = f"req_{uuid.uuid4()}"
_INSTRUCTION: Final = "Run the command, then replay this exact check request with the same id."


def _privacy_projection() -> dict[str, Any]:
    """Every projected success body carries one, including this nonterminal branch."""

    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": f"egr_{uuid.uuid4()}",
        "policy_id": f"pvy_{uuid.uuid4()}",
        "policy_version": "1",
        "policy_digest": "sha256:" + "0" * 64,
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": "hmac-sha256:" + "1" * 64,
    }


def _frontier() -> dict[str, Any]:
    return {"sequence": "4", "head_digest": "sha256:" + "2" * 64}


def _continuation(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "privacy_disclosure_decision",
        "pending_id": _PENDING,
        "expires_at": "2026-08-05T13:00:00.000Z",
        "command": ["finishup", "privacy", "decide-disclosure", _PENDING],
        "replay_request_id": _REQUEST,
        "instruction": _INSTRUCTION,
    }
    body.update(overrides)
    return body


def _repository_grant_continuation(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "repository_privacy_setup",
        "command": ["finishup", "--privacy"],
        "replay_request_id": _REQUEST,
        "instruction": (
            "Use the trusted local privacy ceremony, then replay this exact request id."
        ),
    }
    body.update(overrides)
    return body


def _awaiting(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "ok": True,
        "state": "awaiting_human",
        "task_id": f"tsk_{uuid.uuid4()}",
        "session_id": f"ses_{uuid.uuid4()}",
        "writer_id": f"wri_{uuid.uuid4()}",
        "subject_frontier": _frontier(),
        "result_frontier": _frontier(),
        "semantic_status": "awaiting_human",
        "semantic_reason": "human_approval_required",
        "continuation": _continuation(),
        "privacy_projection": _privacy_projection(),
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "yoetz/0.1.0",
            "policy_packs": ["research-evidence/0.1.0", "work-integrity/0.1.0"],
        },
    }
    body.update(overrides)
    return body


def test_the_awaiting_branch_validates_and_discriminates_on_state() -> None:
    result = CheckResultModel.model_validate(_awaiting())

    assert type(result.root) is CheckAwaitingHumanModel
    assert result.root.semantic_status == "awaiting_human"
    assert result.root.continuation.pending_id == _PENDING


def test_the_awaiting_input_branch_validates_and_discriminates_on_state() -> None:
    result = CheckResultModel.model_validate(
        _awaiting(
            state="awaiting_input",
            semantic_status="awaiting_input",
            semantic_reason="review_input_required",
            continuation={
                "kind": "review_input_required",
                "command": ["finishup", "publish-work", "--input", "PATH"],
                "replay_request_id": _REQUEST,
                "instruction": "Supply the statement, then replay this exact request.",
            },
        )
    )

    assert type(result.root) is CheckAwaitingHumanModel
    assert result.root.state == "awaiting_input"
    assert result.root.semantic_reason == "review_input_required"
    assert result.root.continuation.kind == "review_input_required"

    rendered = render_human_awaiting_human(result.root)
    assert "awaiting_input (review_input_required)" in rendered
    assert "complete review input" in rendered
    assert "finishup publish-work --input PATH" in rendered
    assert "awaiting_human (human_approval_required)" not in rendered


def test_the_branch_carries_the_exact_command_the_user_must_run() -> None:
    result = CheckResultModel.model_validate(_awaiting())
    assert type(result.root) is CheckAwaitingHumanModel

    assert result.root.continuation.command == (
        "finishup",
        "privacy",
        "decide-disclosure",
        _PENDING,
    )


def test_completed_check_operation_page_carries_withheld_item_identity() -> None:
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "complete",
            "operation_kind": "check",
            "semantic_withheld_items": [
                {"item_id": "excerpt-heuristic", "reason": "never_send_heuristic"}
            ],
        }
    )
    items = page.semantic_withheld_items
    assert items is not None
    assert items[0].item_id == "excerpt-heuristic"
    assert items[0].reason == "never_send_heuristic"


def test_old_completed_check_operation_page_omits_withheld_items() -> None:
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "complete",
            "operation_kind": "check",
        }
    )
    assert page.semantic_withheld_items is None


def test_missing_repository_grant_carries_standing_setup_without_one_use_fields() -> None:
    result = CheckResultModel.model_validate(
        _awaiting(continuation=_repository_grant_continuation())
    )
    assert type(result.root) is CheckAwaitingHumanModel

    continuation = result.root.continuation
    assert continuation.kind == "repository_privacy_setup"
    assert continuation.command == ("finishup", "--privacy")
    assert continuation.pending_id is None
    assert continuation.expires_at is None


@pytest.mark.parametrize(
    "continuation",
    (_continuation(), _repository_grant_continuation()),
)
def test_both_continuation_schema_branches_accept_only_their_exact_commands(
    continuation: dict[str, Any],
) -> None:
    valid = _awaiting(continuation=continuation)
    validate_schema_instance("check-result", "1.0.0", cast(JsonValue, valid))
    invalid = _awaiting(
        continuation={**continuation, "command": ["x"] * len(continuation["command"])}
    )
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("check-result", "1.0.0", cast(JsonValue, invalid))


@pytest.mark.parametrize("field", ("pending_id", "expires_at"))
def test_standing_repository_grant_rejects_one_use_confirmation_fields(field: str) -> None:
    value = _PENDING if field == "pending_id" else "2026-08-05T13:00:00.000Z"
    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(
            _awaiting(continuation=_repository_grant_continuation(**{field: value}))
        )


@pytest.mark.parametrize("field", ("pending_id", "expires_at"))
def test_one_use_confirmation_requires_its_pending_identity_and_expiry(field: str) -> None:
    continuation = _continuation()
    del continuation[field]
    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(_awaiting(continuation=continuation))


def test_the_branch_returns_no_verdict_and_no_coverage() -> None:
    """A nonterminal result must offer nothing to conclude from."""

    result = CheckResultModel.model_validate(_awaiting())
    root = result.root

    # privacy_projection is deliberately not in this list: it describes how this body was
    # disclosed, not what the check concluded.
    for field in ("verdict", "findings", "coverage", "semantic_provenance", "suppressed_count"):
        assert not hasattr(root, field), f"{field} must not appear on a suspended check"


def test_a_command_that_does_not_match_the_pending_id_is_rejected() -> None:
    """The command is the whole point; a mismatched one sends the user to approve nothing."""

    other = f"ppr_{uuid.uuid4()}"
    body = _awaiting(
        continuation=_continuation(
            command=["finishup", "privacy", "decide-disclosure", other],
        )
    )

    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(body)


@pytest.mark.parametrize(
    "command",
    (
        ["finishup", "privacy", "decide-disclosure"],
        ["finishup", "privacy", "decide-policy", _PENDING],
        ["sh", "-c", "decide-disclosure", _PENDING],
    ),
)
def test_only_the_fixed_disclosure_command_is_admitted(command: list[str]) -> None:
    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(_awaiting(continuation=_continuation(command=command)))


def test_the_continuation_must_name_the_request_to_replay() -> None:
    """Replaying a different request abandons the proposal the user just approved."""

    body = _awaiting(
        continuation=_continuation(replay_request_id=f"req_{uuid.uuid4()}"),
    )

    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(body)


def test_a_terminal_check_still_validates_and_declares_complete() -> None:
    """The added discriminator must not disturb the ordinary branch."""

    from unit.protocol.test_models_and_schemas import (  # pyright: ignore[reportMissingImports]
        _check_result_wire,
    )

    result = CheckResultModel.model_validate(_check_result_wire())
    assert type(result.root) is CheckSuccessModel
    assert result.root.state == "complete"


_REDACTED_WIRE: Final = [
    {
        "disposition": "value_replaced",
        "item_id": "excerpt-a",
        "lines": [3, 7],
        "source_ref": "evd_10000000-0000-4000-8000-000000000021",
    },
    {"disposition": "item_withheld", "item_id": "excerpt-heuristic", "lines": [2]},
]


def test_check_result_and_operation_page_accept_redacted_value_refs_and_lines() -> None:
    """PL2-1 (issue #982): bounded structural entries validate on both public shapes."""

    from unit.protocol.test_models_and_schemas import (  # pyright: ignore[reportMissingImports]
        _check_result_wire,
    )

    result = CheckResultModel.model_validate(
        {**_check_result_wire(), "semantic_redacted_values": _REDACTED_WIRE}
    )
    assert type(result.root) is CheckSuccessModel
    assert result.root.semantic_redacted_values[0].lines == (3, 7)
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "complete",
            "operation_kind": "check",
            "semantic_redacted_values": _REDACTED_WIRE,
        }
    )
    assert page.semantic_redacted_values is not None
    assert page.semantic_redacted_values[1].source_ref is None


@pytest.mark.parametrize(
    "entry",
    (
        {"disposition": "value_replaced", "item_id": "x", "lines": [3, 1]},
        {"disposition": "value_replaced", "item_id": "x", "lines": [0]},
        {"disposition": "value_replaced", "item_id": "x", "lines": [1], "value": "s3cr3t"},
        {"disposition": "value_replaced", "item_id": "x", "lines": [1], "source_ref": "a/b"},
        {"disposition": "other", "item_id": "x", "lines": [1]},
    ),
)
def test_redacted_value_entries_reject_anything_but_bounded_structure(
    entry: dict[str, Any],
) -> None:
    from unit.protocol.test_models_and_schemas import (  # pyright: ignore[reportMissingImports]
        _check_result_wire,
    )

    with pytest.raises(ValidationError):
        CheckResultModel.model_validate(
            {**_check_result_wire(), "semantic_redacted_values": [entry]}
        )


def test_operation_status_returns_the_same_continuation_for_a_pending_check() -> None:
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "pending",
            "operation_kind": "check",
            "continuation": _continuation(),
        }
    )

    assert page.continuation is not None
    assert page.continuation.pending_id == _PENDING
    assert page.continuation.command[3] == _PENDING


def test_operation_status_recovers_the_same_standing_repository_grant_handoff() -> None:
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "pending",
            "operation_kind": "check",
            "continuation": _repository_grant_continuation(),
        }
    )

    assert page.continuation is not None
    assert page.continuation.kind == "repository_privacy_setup"
    assert page.continuation.replay_request_id == _REQUEST


def test_operation_status_rejects_a_continuation_for_another_request() -> None:
    with pytest.raises(ValidationError):
        StatusOperationPageModel.model_validate(
            {
                "operation_request_id": _REQUEST,
                "found": True,
                "state": "pending",
                "operation_kind": "check",
                "continuation": _continuation(replay_request_id=f"req_{uuid.uuid4()}"),
            }
        )


def test_operation_status_returns_no_continuation_for_other_states() -> None:
    page = StatusOperationPageModel.model_validate(
        {
            "operation_request_id": _REQUEST,
            "found": True,
            "state": "complete",
            "operation_kind": "check",
        }
    )

    assert page.continuation is None


@pytest.mark.parametrize(
    ("state", "kind"),
    (("complete", "check"), ("pending", "receipt"), ("quarantined", "check")),
)
def test_a_continuation_outside_a_pending_check_is_rejected(state: str, kind: str) -> None:
    """Only a suspended check has one; anywhere else it would be a false instruction."""

    with pytest.raises(ValidationError):
        StatusOperationPageModel.model_validate(
            {
                "operation_request_id": _REQUEST,
                "found": True,
                "state": state,
                "operation_kind": kind,
                "continuation": _continuation(),
            }
        )
