"""Bounded file ingestion refuses unsafe reads and never claims an observed test run."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from tests.unit.protocol.test_models_and_schemas import (
    _publish_result_wire,  # pyright: ignore[reportPrivateUsage]
)
from typer.testing import CliRunner

from finishup.cli import app as cli_module
from finishup.cli import test_record
from finishup.cli.test_record import TestRecordError, prepare_test_record
from finishup.domain.events import EventSchema, ResultRecordedPayload, decode_payload
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import PublishWorkRequest, PublishWorkResult


def _request() -> dict[str, Any]:
    return {
        "request_id": "req_00000000-0000-4000-8000-000000000001",
        "session_id": "ses_00000000-0000-4000-8000-000000000002",
        "writer_id": "wri_00000000-0000-4000-8000-000000000003",
        "expected_frontier": [],
        "event_drafts": [
            {
                "event_id": "evt_00000000-0000-4000-8000-000000000004",
                "schema": {"name": "result_recorded", "version": "1.0.0"},
                "payload": {
                    "result_id": "res_00000000-0000-4000-8000-000000000005",
                    "action_id": "act_00000000-0000-4000-8000-000000000006",
                    "outcome": "failure",
                    "summary": "Original caller summary.",
                    "verification": {
                        "criterion_quote": "all named cases pass",
                        "data_source": "own_generated",
                        "tuned_on_these_cases": False,
                    },
                },
            }
        ],
    }


def _files(root: Path, raw: bytes = b'{"cases":3,"failing":1,"worst":"0.2"}') -> None:
    (root / "test.py").write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
    (root / "results.json").write_bytes(raw)


def _prepare(root: Path, request: Mapping[str, JsonValue] | None = None) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        prepare_test_record(
            _request() if request is None else request,
            test_file="test.py",
            results_file="results.json",
            workspace=root,
        ),
    )


def test_ingests_exact_report_and_source_without_mutating_identity_or_running(
    tmp_path: Path,
) -> None:
    raw = b'{ "cases":3, "failing":1, "worst":"0.2", "failing_cases":["case-2"] }\n'
    _files(tmp_path, raw)
    request = _request()
    before = json.dumps(request)
    prepared = _prepare(tmp_path, request)
    assert json.dumps(request) == before
    assert {key: value for key, value in prepared.items() if key != "event_drafts"} == {
        key: value for key, value in request.items() if key != "event_drafts"
    }
    draft = prepared["event_drafts"][0]
    assert draft["event_id"] == request["event_drafts"][0]["event_id"]
    result = decode_payload(EventSchema("result_recorded", "1.1.0"), draft["payload"])
    assert isinstance(result, ResultRecordedPayload)
    assert result.verification is not None
    assert result.verification.cases == 3
    assert result.verification.failing == 1
    assert result.verification.worst == "0.2"
    assert result.verification.tuned_on_these_cases is False
    assert result.verification.test_file == "test.py"
    assert result.verification.results_file == "results.json"
    assert result.verification.report_digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert result.summary is not None
    assert raw.decode() in result.summary
    assert (tmp_path / "test.py").read_text() in result.summary
    assert "Original caller summary." in result.summary
    assert "Caller-asserted" in result.summary
    assert "execution and report origin are not observed" in result.summary


@pytest.mark.parametrize(
    "raw",
    [
        b'{"cases":1,"cases":2,"failing":0}',
        b'{"cases":true,"failing":0}',
        b'{"cases":1,"failing":false}',
        b'{"cases":1.0,"failing":0}',
        b'{"cases":NaN,"failing":0}',
        b'{"cases":Infinity,"failing":0}',
        b'{"cases":1,"failing":2}',
        b'{"cases":-1,"failing":0}',
        b'{"cases":9007199254740992,"failing":0}',
        b'{"cases":1}',
        b'{"cases":1,"failing":0,"extra":"do not echo"}',
        b'{"cases":1,"failing":0,"worst":2}',
        b'{"cases":1,"failing":0,"worst":null}',
        b'{"cases":1,"failing":0,"failing_cases":["impossible"]}',
        b'{"cases":2,"failing":2,"failing_cases":["same","same"]}',
        b'{"cases":1,"failing":1,"failing_cases":[{}]}',
        b"[]",
        b"\xff",
    ],
)
def test_rejects_invalid_report_without_echoing_content(tmp_path: Path, raw: bytes) -> None:
    _files(tmp_path, raw)
    with pytest.raises(TestRecordError, match="^test_record_report_invalid$"):
        _prepare(tmp_path)


@pytest.mark.parametrize(
    "operand",
    [
        "/outside",
        "../outside",
        "a/../b",
        "a//b",
        "a\\b",
        "C:/b",
        ".git/config",
        ".env",
        "x/credentials/report.json",
        "key.PEM",
        "bad\nname",
    ],
)
def test_rejects_unsafe_operands_before_reading(tmp_path: Path, operand: str) -> None:
    _files(tmp_path)
    with pytest.raises(TestRecordError, match="^test_record_path_invalid$"):
        prepare_test_record(
            _request(), test_file=operand, results_file="results.json", workspace=tmp_path
        )


@pytest.mark.parametrize(
    "kind", ["file_link", "directory_link", "workspace_link", "fifo", "directory", "hardlink"]
)
def test_refuses_links_and_special_files(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _files(root)
    workspace, test_file = root, "test.py"
    if kind == "file_link":
        (root / "link").symlink_to(root / "test.py")
        test_file = "link"
    elif kind == "directory_link":
        (root / "link").symlink_to(root, target_is_directory=True)
        test_file = "link/test.py"
    elif kind == "workspace_link":
        workspace = tmp_path / "link"
        workspace.symlink_to(root, target_is_directory=True)
    elif kind == "fifo":
        os.mkfifo(root / "fifo")
        test_file = "fifo"
    elif kind == "directory":
        test_file = "nested"
        (root / test_file).mkdir()
    else:
        os.link(root / "test.py", root / "alias")
    with pytest.raises(TestRecordError, match="^test_record_file_unsafe$"):
        prepare_test_record(
            _request(), test_file=test_file, results_file="results.json", workspace=workspace
        )


@pytest.mark.parametrize("member", ["test.py", "results.json"])
def test_rejects_oversize_without_reading_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, member: str
) -> None:
    _files(tmp_path)
    maximum = (
        test_record.MAX_TEST_FILE_BYTES
        if member == "test.py"
        else test_record.MAX_RESULTS_FILE_BYTES
    )
    (tmp_path / member).write_bytes(b"x" * (maximum + 1))
    original = os.read

    def guarded_read(descriptor: int, count: int) -> bytes:
        assert os.fstat(descriptor).st_size <= maximum
        return original(descriptor, count)

    monkeypatch.setattr(test_record.os, "read", guarded_read)
    with pytest.raises(TestRecordError, match="^test_record_file_too_large$"):
        _prepare(tmp_path)


def test_rejects_file_modified_during_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _files(tmp_path)
    original = os.read
    changed = False

    def changing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        content = original(descriptor, count)
        if not changed:
            changed = True
            (tmp_path / "test.py").write_text("changed", encoding="utf-8")
        return content

    monkeypatch.setattr(test_record.os, "read", changing_read)
    with pytest.raises(TestRecordError, match="^test_record_file_changed$"):
        _prepare(tmp_path)


def test_rejects_ancestor_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _files(root)
    original = os.read
    changed = False

    def changing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        content = original(descriptor, count)
        if not changed:
            changed = True
            root.rename(tmp_path / "old")
            root.mkdir()
            _files(root)
        return content

    monkeypatch.setattr(test_record.os, "read", changing_read)
    with pytest.raises(TestRecordError, match="^test_record_file_changed$"):
        _prepare(root)


def test_script_excerpt_is_utf8_bounded_and_explicitly_clipped(tmp_path: Path) -> None:
    _files(tmp_path, b'{"cases":0,"failing":0}')
    script = ("# \u05d0\u05d1\u05d2\n" * 1_000).encode()
    (tmp_path / "test.py").write_bytes(script)
    prepared = _prepare(tmp_path)
    payload = prepared["event_drafts"][0]["payload"]
    assert "(excerpt clipped)" in payload["summary"]
    assert "sha256:" + hashlib.sha256(script).hexdigest() in payload["summary"]
    assert len(payload["summary"].encode()) <= 8_192
    assert "worst" not in payload["verification"]


def test_existing_summary_is_preserved_or_refused_without_truncation(tmp_path: Path) -> None:
    _files(tmp_path)
    request = _request()
    request["event_drafts"][0]["payload"]["summary"] = "\u05d0" * 4_096
    with pytest.raises(TestRecordError, match="^test_record_summary_too_large$"):
        _prepare(tmp_path, request)


@pytest.mark.parametrize("count", [0, 2])
def test_requires_exactly_one_result_draft(tmp_path: Path, count: int) -> None:
    request = _request()
    request["event_drafts"] *= count
    with pytest.raises(TestRecordError, match="^test_record_requires_one_result$"):
        _prepare(tmp_path, request)


@pytest.mark.parametrize(
    "declaration",
    [
        None,
        {},
        {"criterion_quote": "criterion"},
        {"criterion_quote": "", "data_source": "unknown"},
        {"criterion_quote": "criterion", "data_source": "observed"},
    ],
)
def test_requires_explicit_valid_criterion_and_data_source(
    tmp_path: Path, declaration: Any
) -> None:
    _files(tmp_path)
    request = _request()
    request["event_drafts"][0]["payload"]["verification"] = declaration
    with pytest.raises(TestRecordError, match="^test_record_request_invalid$"):
        _prepare(tmp_path, request)


@pytest.mark.parametrize("script", [b"\xff", b"script\x00bytes"])
def test_refuses_nontext_source(tmp_path: Path, script: bytes) -> None:
    _files(tmp_path)
    (tmp_path / "test.py").write_bytes(script)
    with pytest.raises(TestRecordError, match="^test_record_(?:request_invalid|file_unsafe)$"):
        _prepare(tmp_path)


def test_other_drafts_and_schema_fields_are_preserved_for_normal_validation(tmp_path: Path) -> None:
    _files(tmp_path)
    request = _request()
    request["event_drafts"][0]["schema"]["unexpected"] = "must still fail normal validation"
    other = {
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "payload": {"command": "caller text"},
    }
    request["event_drafts"].insert(0, other)
    prepared = _prepare(tmp_path, request)
    assert prepared["event_drafts"][0] == other
    assert (
        prepared["event_drafts"][1]["schema"]["unexpected"] == "must still fail normal validation"
    )


def test_missing_file_is_refused_without_path_or_os_error(tmp_path: Path) -> None:
    with pytest.raises(TestRecordError, match="^test_record_file_unsafe$"):
        _prepare(tmp_path)


@pytest.mark.parametrize("refused", [False, True])
def test_record_test_cli_validates_manifest_before_contacting_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: bool
) -> None:
    _files(tmp_path)
    monkeypatch.chdir(tmp_path)
    request = _request()
    request.update(
        protocol_version="0.1",
        schema_version="1.0.0",
        actor={"actor_id": "harness:test", "actor_type": "harness"},
        client={"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    request["event_drafts"][0]["payload"]["evidence_refs"] = []
    request["event_drafts"][0].update(
        occurred_at="2026-10-21T00:00:00.000Z",
        causal_parents=[],
        artifact_refs=[],
        evidence_refs=[],
    )
    calls: list[PublishWorkRequest] = []
    connections: list[bool] = []
    closed: list[bool] = []

    class Client:
        async def publish_work(
            self, prepared: PublishWorkRequest, *, deadline_ms: int | None
        ) -> PublishWorkResult:
            del deadline_ms
            calls.append(prepared)
            return PublishWorkResult.model_validate(_publish_result_wire())

        async def close(self) -> None:
            closed.append(True)

    async def connect() -> Client:
        connections.append(True)
        return Client()

    monkeypatch.setattr(cli_module, "build_service_client", connect)
    result = CliRunner().invoke(
        cli_module.app,
        [
            "record-test",
            "--test-file",
            "../private-file" if refused else "test.py",
            "--results-file",
            "results.json",
            "--request",
            json.dumps(request),
            "--json",
        ],
    )
    if refused:
        assert result.exit_code != 0
        assert not connections
        assert not calls
        assert "private-file" not in result.output
    else:
        assert result.exit_code == 0, (result.output, result.exception)
        assert connections == [True]
        assert closed == [True]
        assert len(calls) == 1
        prepared = calls[0].model_dump(mode="python", by_alias=True)
        verification = prepared["event_drafts"][0]["payload"]["verification"]
        assert verification["cases"] == 3
        assert verification["failing"] == 1
        assert verification["test_file"] == "test.py"
        assert verification["results_file"] == "results.json"
        assert verification["report_digest"].startswith("sha256:")
        assert prepared["request_id"] == request["request_id"]
