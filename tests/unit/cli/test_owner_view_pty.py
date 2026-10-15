"""r3 F1: a real pseudo-terminal never selects the owner's receipt view.

An agent harness (Codex ``exec_command``, ``script``, ``pty.spawn``) gives the CLI a controlling
pseudo-terminal in the foreground process group, which satisfies every terminal test. The child
below runs under a real ``pty.fork`` and drives the real ``finishup receipt`` workflow function; only
the service transport is a stub, which resolves the disclosure sink exactly as the service does
from the presentation the CLI asked for. Nothing here monkeypatches the terminal predicate.
"""

from __future__ import annotations

import json
import os
import pty
import sys
import textwrap

import pytest

_CHILD = textwrap.dedent(
    """
    import asyncio, json, sys
    import finishup.cli.app as cli_app
    from finishup.application.service import ClientProjectionContext, resolve_client_disclosure_sink
    from finishup.cli.privacy_setup import _output_is_controlling_tty
    from finishup.ports.control import ControlClientKind, ControlError, ProjectionRenderMode
    from finishup.protocol.models import ReceiptRequest

    seen = []

    async def build(client_kind=ControlClientKind.CLI, *, projection_render_mode=(
            ProjectionRenderMode.MACHINE_READABLE), output_is_controlling_tty=False, **_kw):
        asked = ClientProjectionContext(
            client_kind, projection_render_mode, output_is_controlling_tty)
        # The most a hello from this terminal could claim, forged or not.
        forged = ClientProjectionContext(
            client_kind, ProjectionRenderMode.HUMAN_READABLE, _output_is_controlling_tty())
        seen.append([resolve_client_disclosure_sink(asked).value,
                     resolve_client_disclosure_sink(forged).value])
        raise ControlError("service_unavailable", retryable=True)

    cli_app.build_service_client = build
    request = sys.argv[1]
    asyncio.run(cli_app._call_workflow("receipt", ReceiptRequest, None, request, False, None))
    print("RESULT " + json.dumps({"tty": _output_is_controlling_tty(), "sinks": seen}))
    """
)

_REQUEST = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-0000000000a1",
    "actor": {"actor_id": "harness:pty", "actor_type": "harness"},
    "client": {"kind": "yoetz_cli", "version": "0.3.0", "integration": "local_cli"},
    "task_id": "tsk_00000000-0000-4000-8000-0000000000a2",
    "session_id": "ses_00000000-0000-4000-8000-0000000000a3",
    "writer_id": "wri_00000000-0000-4000-8000-0000000000a4",
    "expected_frontier": {"sequence": "3", "head_digest": "sha256:" + "1" * 64},
    "format": "markdown",
    "include": "full",
    "redaction_profile": "full_local",
}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pseudo-terminals only")
def test_a_real_pty_receipt_call_stays_agent_facing() -> None:
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            os.execv(sys.executable, [sys.executable, "-c", _CHILD, json.dumps(_REQUEST)])
        finally:
            os._exit(127)
    output = bytearray()
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    text = output.decode("utf-8", "replace")
    assert os.waitstatus_to_exitcode(status) == 0, text
    lines = [row for row in text.splitlines() if row.startswith("RESULT ")]
    assert len(lines) == 1, text
    (line,) = lines
    result = json.loads(line.removeprefix("RESULT "))
    # The pseudo-terminal is real: every terminal predicate holds ...
    assert result["tty"] is True
    # ... and still neither what the CLI asks for nor the most a forged hello can claim selects
    # the owner's view.
    assert result["sinks"] == [["agent_context", "agent_context"]]
