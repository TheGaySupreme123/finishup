"""Declarations select exact custom runs without changing global verification gates."""

from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, command_identity_for
from builders.policy_cases import act, make_case, obl, obligation_record, plan_record, record, res
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
)
from finishup.domain.observation_selection import command_is_verification
from finishup.kernel.observed_failures import command_identity
from finishup.kernel.task_facts import register_command_identity_key
from finishup.kernel.verification_capture import (
    command_is_declared_verification,
    verification_capture_command,
)


@pytest.fixture(autouse=True)
def installation_key():
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@pytest.mark.parametrize("command", ("python stress.py", "python - <<'PY'\nassert 2 + 2 == 4\nPY"))
def test_plan_selects_exact_custom_command_only(command: str) -> None:
    obligation = ObligationPublishedPayload(
        obl(1),
        "Check the result",
        "An independent check",
        ObligationStatus.OPEN,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, command),),
    )
    action = ActionRecordedPayload(
        act(1), ActionKind.COMMAND, "Run the custom check", command=command_identity_for(command)
    )
    projection = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1),)), 2)},
        obligations={obl(1): obligation_record(obligation, 1)},
        actions={act(1): record(action, 3)},
    ).projection
    identity = command_identity(action.command)
    assert identity is not None
    assert verification_capture_command(projection, identity) == command
    assert command_is_declared_verification(str(act(1)), projection)
    assert not command_is_verification(command)
    assert (
        verification_capture_command(
            projection, str(command_identity(command_identity_for(command + " --other")))
        )
        is None
    )
    assert verification_capture_command(replace(projection, plans={}), identity) is None
    assert (
        verification_capture_command(
            replace(
                projection,
                obligations={
                    obl(1): replace(projection.obligations[obl(1)], payload=None, redacted=True)
                },
            ),
            identity,
        )
        is None
    )
    register_command_identity_key(None)
    assert verification_capture_command(projection, identity) is None


def test_manifest_selects_only_its_readable_command() -> None:
    action = ActionRecordedPayload(
        act(1), ActionKind.COMMAND, "Run the custom check", command="python stress.py"
    )
    result = ResultRecordedPayload(
        res(1),
        act(1),
        ResultOutcome.SUCCESS,
        verification=ResultVerification(
            "Output is stable", VerificationDataSource.INDEPENDENT, 3, 0
        ),
    )
    projection = make_case(
        actions={act(1): record(action, 1)},
        results={res(1): record(result, 2)},
    ).projection
    assert command_is_declared_verification(str(act(1)), projection)
    assert not command_is_declared_verification(str(act(2)), projection)
    commitment = command_identity(command_identity_for("python stress.py"))
    assert commitment is not None
    assert verification_capture_command(projection, commitment) == "python stress.py"
    assert not command_is_declared_verification(
        str(act(1)),
        replace(
            projection,
            results={res(1): replace(projection.results[res(1)], payload=None, redacted=True)},
        ),
    )
