"""``finishup start --task-statement-file`` records the user's request verbatim (issue #908)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.cli.app import (
    _start_request_model,  # pyright: ignore[reportPrivateUsage]
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import MAX_TASK_STATEMENT_BYTES, StartRequest

_REQUEST = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_90800000-0000-4000-8000-000000000001",
    "actor": {"actor_id": "harness:test", "actor_type": "harness"},
    "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
    "mode": "create",
    "task_title": "termenv truncation",
    "requested_view": "compact",
}
_STATEMENT = 'Under Ascii, Style.Truncate returns plain text without tail;\n  keep "quotes".\n'


def test_file_text_becomes_the_statement_byte_for_byte(tmp_path: Path) -> None:
    path = tmp_path / "request.txt"
    path.write_bytes(_STATEMENT.encode("utf-8"))

    model = _start_request_model(None, json.dumps(_REQUEST), str(path))

    assert type(model) is StartRequest
    assert model.task_statement == _STATEMENT
    assert _start_request_model(None, json.dumps(_REQUEST), None).task_statement is None  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "case", ["already_in_request", "empty", "too_large", "not_utf8", "two_stdin_readers"]
)
def test_ambiguous_or_unbounded_statement_input_is_refused(tmp_path: Path, case: str) -> None:
    path = tmp_path / "request.txt"
    request = dict(_REQUEST)
    input_path: str | None = None
    inline: str | None = json.dumps(request)
    statement_path = str(path)
    path.write_bytes(_STATEMENT.encode("utf-8"))
    if case == "already_in_request":
        inline = json.dumps({**request, "task_statement": "other words"})
    elif case == "empty":
        path.write_bytes(b"")
    elif case == "too_large":
        path.write_bytes(b"a" * (MAX_TASK_STATEMENT_BYTES + 1))
    elif case == "not_utf8":
        path.write_bytes(b"\xff\xfe")
    else:
        input_path, inline, statement_path = "-", None, "-"
    with pytest.raises((ProtocolValueError, ValueError)):
        _start_request_model(input_path, inline, statement_path)
