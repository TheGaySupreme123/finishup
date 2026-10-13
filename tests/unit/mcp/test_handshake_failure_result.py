"""A hello closed by this installation's own service is never called another installation (#1040).

tb4n5 (wdm-design, Git 2.25): every bridge call failed with ``service_incompatible`` naming the
service's own pid and version, and the remedy (``yoetz service restart``) could not replace an
identical holder. The client now classifies such a close as a failed handshake; these cases hold
the agent-facing result to it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

import yoetz.mcp.server as bridge
from yoetz.ports.control import ControlError
from yoetz.protocol.errors import PublicErrorCode

_CORRELATION = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_REQUEST = "req_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def diagnostic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    ("phase", "continuation", "says"),
    [
        ("handshake", None, "yoetz service diagnostics"),
        ("handshake_git_version", "system_git_upgrade_required", "older than 2.25"),
    ],
)
def test_a_failed_handshake_reaches_the_agent_as_itself(
    phase: str, continuation: str | None, says: str
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError(
            "service_unavailable", retryable=False, phase=phase, correlation_id=_CORRELATION
        ),
        request_id=_REQUEST,
        operation="start",
    )

    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    # The client's own record of the close; never a second id.
    assert error["correlation_id"] == _CORRELATION
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "service_handshake_failed"
    assert details["phase"] == phase
    assert details.get("continuation") == continuation
    message = cast(str, error["message"])
    assert says in message
    rendered = json.dumps(structured) + "".join(
        getattr(item, "text", "") for item in result.content
    )
    assert "service_incompatible" not in rendered
    assert "different Yoetz installation" not in rendered
    assert "`yoetz service restart`" not in rendered
