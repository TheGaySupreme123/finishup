"""The CLI names a hello its own service closed instead of blaming another installation (#1040).

tb4n5 (wdm-design, Git 2.25): ``yoetz service status`` exited 20 with ``service_incompatible``,
naming the service's own pid and version, and told the operator to run ``yoetz service restart``,
which cannot replace an identical holder.
"""

from __future__ import annotations

import pytest

from yoetz.cli.bootstrap import control_failure
from yoetz.ports.control import ControlError
from yoetz.protocol.canonical import JsonValue

_CORRELATION = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.mark.parametrize(
    ("phase", "says"),
    [
        ("handshake", "'yoetz service diagnostics'"),
        ("handshake_git_version", "older than 2.25"),
    ],
)
def test_a_failed_handshake_is_its_own_line_and_payload(phase: str, says: str) -> None:
    printed: list[str] = []
    payloads: list[JsonValue] = []
    error = ControlError(
        "service_unavailable", retryable=False, phase=phase, correlation_id=_CORRELATION
    )

    code = control_failure(
        error, json_output=True, stderr_writer=printed.append, stdout_writer=payloads.append
    )

    assert code == 20
    assert len(printed) == 1
    line = printed[0]
    assert line.startswith("service_unavailable: service_handshake_failed: ")
    assert says in line
    assert f"correlation_id {_CORRELATION}" in line
    assert "different Yoetz installation" not in line
    assert "replace it with this installation's service" not in line
    if phase == "handshake_git_version":
        # The registry directive follows, exactly as the MCP continuation names it.
        assert "system Git" in line.split("\n", 1)[1]
    assert payloads == [
        {
            "ok": False,
            "public_code": "SERVICE_UNAVAILABLE",
            "reason": "service_handshake_failed",
            "phase": phase,
            "retryable": False,
            "correlation_id": _CORRELATION,
        }
    ]
