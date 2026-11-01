"""A failed connection leaves nothing pending and names its diagnostic record (#1280)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import finishup.cli.app as cli
import finishup.cli.host_connection as host_connection
import finishup.service.elevated_bootstrap as elevated


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(elevated, "state_dir", lambda: root)
    monkeypatch.setattr(host_connection, "refuse_unservable_runtime", lambda: None)
    monkeypatch.setattr(host_connection, "select_artifact_user_presence", lambda: None)
    return root


def _plan(digest: str) -> object:
    return SimpleNamespace(
        digest=digest,
        unchanged=False,
        body={"action": "connect", "preview_digest": digest},
    )


def _crash(*_args: object, **_kwargs: object) -> object:
    raise RuntimeError("unexpected")


def test_a_failed_apply_withdraws_the_approval_it_prepared(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(host_connection, "apply_connection", _crash)
    digest = "sha256:" + "c" * 64

    with pytest.raises(RuntimeError):
        host_connection.apply_selected(cast(host_connection.ConnectionPlan, _plan(digest)), None)

    assert elevated.load_pending() is None


def test_a_failed_apply_keeps_an_approval_another_request_prepared(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "sha256:" + "d" * 64
    earlier = elevated.prepare_pending("plugin_artifact_apply", target_digest=digest)
    monkeypatch.setattr(host_connection, "apply_connection", _crash)

    with pytest.raises(RuntimeError):
        host_connection.apply_selected(cast(host_connection.ConnectionPlan, _plan(digest)), None)

    kept = elevated.load_pending()
    assert kept is not None and kept.pending_id == earlier.pending_id


def test_an_unexpected_command_failure_names_its_diagnostic_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)

    def raising(**_kwargs: object) -> None:
        raise KeyError("/private/user/path")

    monkeypatch.setattr(cli, "app", raising)

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 70
    line = capsys.readouterr().err.strip().splitlines()[-1]
    assert line.startswith("internal_error: the command could not be completed; correlation: err_")
    assert "/private/user/path" not in line
    correlation = line.rsplit(" ", 1)[1]
    records = diagnostics.lookup_diagnostic_records(correlation)
    assert records and records[-1]["operation"] == "command_failed"
    assert all("/private/user/path" not in str(record) for record in records)
