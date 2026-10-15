"""State-capture CLI structural failure reporting."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.adapters import git_subject_state
from finishup.cli.app import app

_RUNNER = CliRunner()


@pytest.mark.parametrize(
    ("reason", "remediation_fragment"),
    [
        ("unsafe_root", "fully resolved path"),
        ("git_config_limit_exceeded", "bounded 1 MiB safety scan"),
    ],
)
def test_structural_limitation_is_not_reported_as_invalid_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    remediation_fragment: str,
) -> None:
    def _fail(_workspace: Path) -> object:
        raise ValueError(reason)

    monkeypatch.setattr(git_subject_state, "open_local_workspace", _fail)
    result = _RUNNER.invoke(app, ["state", "capture", "--workspace", str(tmp_path), "--json"])

    assert result.exit_code == 2
    assert result.output.startswith(f"{reason}:")
    assert remediation_fragment in result.output
    assert "invalid_request" not in result.output


def test_unknown_value_error_remains_a_usage_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(_workspace: Path) -> object:
        raise ValueError("untrusted detail")

    monkeypatch.setattr(git_subject_state, "open_local_workspace", _fail)
    result = _RUNNER.invoke(app, ["state", "capture", "--workspace", str(tmp_path), "--json"])

    assert result.exit_code == 2
    assert result.output == "invalid_request: the command input is invalid\n"
    assert "untrusted detail" not in result.output
