"""`closure-prepare --output` saves the complete result instead of printing it (issue #916).

Agents re-ran a 16-55 s `closure-prepare` two to four times per attempt to pull different fields
out of ~1 MB of stdout. The file holds the exact bytes the command prints without `--output`, so
the saved inventory can be queried as often as needed without re-reading any status page.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.closure as closure
import finishup.config.paths as paths
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.service.client import ServiceClient

_SESSION = "ses_0f62968e-d590-4a19-90c0-a6a0deea32ac"
_WRITER = "wri_27cc27e7-45c1-490b-8a98-8132de8c4840"
_RESULT: dict[str, JsonValue] = {
    "preparatory_only": True,
    "frontier": {"sequence": "998", "head_digest": "sha256:" + "a" * 64},
    "closure_readiness": {"state": "not_ready"},
    "inventory": {
        "obligations": [{"obligation_id": "obl_1", "description": "Ünïcode ✓"}],
        "results": [],
        "evidence": [{"evidence_id": "evd_1"}, {"evidence_id": "evd_2"}],
        "findings": [],
        "history": [{"event_id": "evt_1"}],
    },
    "request": None,
    "notes": ["Nothing was published or judged."],
}


@pytest.fixture(autouse=True)
def no_singleton_stamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def state_dir(**_kwargs: object) -> Path:
        return tmp_path / "state"

    monkeypatch.setattr(paths, "state_dir", state_dir)


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """A connected client whose preparation returns ``_RESULT``; records that it was closed."""

    closed: list[bool] = []

    class Client:
        async def status(self, _request: object) -> None:
            raise AssertionError("prepare_closure is replaced in this test")

        async def close(self) -> None:
            closed.append(True)

    async def connect() -> ServiceClient:
        return cast(ServiceClient, Client())

    async def prepare(*_args: object) -> dict[str, JsonValue]:
        return dict(_RESULT)

    monkeypatch.setattr(cli, "build_service_client", connect)
    monkeypatch.setattr(closure, "prepare_closure", prepare)
    return closed


def _invoke(*extra: str) -> tuple[int, bytes, str]:
    result = CliRunner().invoke(
        cli.app,
        ["closure-prepare", "--session-id", _SESSION, "--writer-id", _WRITER, *extra],
    )
    return result.exit_code, result.stdout_bytes, result.stderr


def test_without_output_the_complete_result_is_printed(prepared: list[bool]) -> None:
    code, stdout, _ = _invoke()
    assert code == 0
    assert stdout == canonical_encode(_RESULT) + b"\n"
    assert prepared == [True]


def test_output_saves_exactly_the_printed_bytes_and_prints_a_summary(
    prepared: list[bool], tmp_path: Path
) -> None:
    target = tmp_path / "closure.json"
    target.write_bytes(b"stale inventory from an earlier frontier")
    code, stdout, _ = _invoke("--output", str(target))
    assert code == 0
    saved = target.read_bytes()
    assert saved == canonical_encode(_RESULT) + b"\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(path.name for path in tmp_path.iterdir()) == ["closure.json"]
    summary = json.loads(stdout)
    assert summary == {
        "preparatory_only": True,
        "output": str(target),
        "bytes": len(saved),
        "sha256": f"sha256:{hashlib.sha256(saved).hexdigest()}",
        "frontier": _RESULT["frontier"],
        "inventory_rows": {
            "obligations": 1,
            "results": 0,
            "evidence": 2,
            "findings": 0,
            "history": 1,
        },
        "operation": None,
    }
    assert prepared == [True]


def test_relative_output_is_reported_as_an_absolute_path(
    prepared: list[bool], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del prepared
    monkeypatch.chdir(tmp_path)
    code, stdout, _ = _invoke("--output", "closure.json")
    assert code == 0
    assert json.loads(stdout)["output"] == str(tmp_path / "closure.json")
    assert (tmp_path / "closure.json").read_bytes() == canonical_encode(_RESULT) + b"\n"


@pytest.mark.parametrize("where", ["missing_directory", "directory_target"])
def test_unwritable_output_names_the_remediation_and_leaves_nothing_behind(
    prepared: list[bool], tmp_path: Path, where: str
) -> None:
    target = tmp_path / "missing" / "closure.json"
    if where == "directory_target":
        target = tmp_path / "existing-directory"
        target.mkdir()
    code, stdout, stderr = _invoke("--output", str(target))
    assert code == 2
    assert stdout == b""
    assert stderr.startswith("closure_output_unwritable: Nothing was saved.")
    expected = ["existing-directory"] if where == "directory_target" else []
    assert sorted(path.name for path in tmp_path.iterdir() if path.name != "state") == expected
    if where == "directory_target":
        assert list(target.iterdir()) == []
    assert prepared == [True]


def test_an_interrupted_save_leaves_neither_a_partial_file_nor_a_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "closure.json"
    target.write_bytes(b"previous inventory")

    def interrupted(*_args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(closure.os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        closure.write_prepared_output(_RESULT, target)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["closure.json"]
    assert target.read_bytes() == b"previous inventory"


def _record_durability_steps(
    monkeypatch: pytest.MonkeyPatch, directory_error: int | None = None
) -> list[tuple[str, str]]:
    """Record the save's fsync and rename order; optionally fail the directory flush."""

    steps: list[tuple[str, str]] = []
    real_fsync = closure.os.fsync
    real_replace = closure.os.replace

    def fsync(descriptor: int) -> None:
        info = closure.os.fstat(descriptor)
        if stat.S_ISDIR(info.st_mode):
            steps.append(("fsync", f"directory:{info.st_ino}"))
            if directory_error is not None:
                raise OSError(directory_error, closure.os.strerror(directory_error))
        else:
            steps.append(("fsync", "file"))
        real_fsync(descriptor)

    def replace(source: object, destination: object) -> None:
        steps.append(("replace", Path(cast(str, destination)).name))
        real_replace(cast(str, source), cast(str, destination))

    monkeypatch.setattr(closure.os, "fsync", fsync)
    monkeypatch.setattr(closure.os, "replace", replace)
    return steps


def test_output_flushes_the_file_then_renames_then_flushes_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-003's durable sequence: a crash after the printed summary cannot lose the rename."""

    target = tmp_path / "closure.json"
    target.write_bytes(b"previous inventory")
    steps = _record_durability_steps(monkeypatch)
    closure.write_prepared_output(_RESULT, target)
    assert steps == [
        ("fsync", "file"),
        ("replace", "closure.json"),
        ("fsync", f"directory:{tmp_path.stat().st_ino}"),
    ]
    assert target.read_bytes() == canonical_encode(_RESULT) + b"\n"


def test_a_filesystem_that_cannot_flush_a_directory_still_saves(
    prepared: list[bool], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del prepared
    target = tmp_path / "closure.json"
    steps = _record_durability_steps(monkeypatch, directory_error=closure.errno.EINVAL)
    code, stdout, _ = _invoke("--output", str(target))
    assert code == 0
    assert json.loads(stdout)["output"] == str(target)
    assert target.read_bytes() == canonical_encode(_RESULT) + b"\n"
    assert [step for step, _ in steps] == ["fsync", "replace", "fsync"]


def test_a_failed_directory_flush_says_the_file_was_replaced_but_may_not_survive(
    prepared: list[bool], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rename already happened, so the error must not claim that nothing was saved."""

    del prepared
    target = tmp_path / "closure.json"
    _record_durability_steps(monkeypatch, directory_error=closure.errno.EIO)
    code, stdout, stderr = _invoke("--output", str(target))
    assert code == 2
    assert stdout == b""
    assert stderr.startswith("closure_output_not_durable: The file was replaced")
    assert target.read_bytes() == canonical_encode(_RESULT) + b"\n"
    assert sorted(path.name for path in tmp_path.iterdir() if path.name != "state") == [
        "closure.json"
    ]


@pytest.mark.parametrize(
    ("reason", "remedy"),
    [
        # tb4n2 retro S (N2-2): a draft the composer's own request model refuses is a typed
        # preparation failure with a way forward, never an internal error (issue #1023).
        ("closure_draft_invalid", "Publish the change yourself with publish_work"),
        ("closure_evidence_unavailable", "result ids (res_) go in result_ids"),
    ],
)
def test_a_preparation_refusal_prints_its_remediation(
    monkeypatch: pytest.MonkeyPatch, reason: str, remedy: str
) -> None:
    closed: list[bool] = []

    class Client:
        async def status(self, _request: object) -> None:
            raise AssertionError("prepare_closure is replaced in this test")

        async def close(self) -> None:
            closed.append(True)

    async def connect() -> ServiceClient:
        return cast(ServiceClient, Client())

    async def refuse(*_args: object) -> dict[str, JsonValue]:
        raise ValueError(reason)

    monkeypatch.setattr(cli, "build_service_client", connect)
    monkeypatch.setattr(closure, "prepare_closure", refuse)
    code, stdout, stderr = _invoke()
    assert code == 2
    assert stdout == b""
    assert stderr.startswith(f"{reason}: ")
    assert remedy in stderr
    assert reason in closure.PREPARATION_REMEDIATIONS
    assert closed == [True]
