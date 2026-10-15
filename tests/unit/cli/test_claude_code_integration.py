from __future__ import annotations

import pytest

from finishup.cli.claude_code_integration import (
    _operation_exit_code,  # pyright: ignore[reportPrivateUsage]
)
from finishup.ports.plugin_artifacts import PluginOperationState


@pytest.mark.parametrize(
    ("state", "expected"),
    (
        (PluginOperationState.COMPLETED, 0),
        (PluginOperationState.OUTCOME_UNKNOWN, 4),
        (PluginOperationState.IN_PROGRESS, 1),
        (PluginOperationState.NOT_STARTED, 1),
    ),
)
def test_plugin_operation_state_has_an_honest_process_exit(
    state: PluginOperationState, expected: int
) -> None:
    assert _operation_exit_code(state) == expected
