"""A refused service start must name the condition that refused it.

The 2026-08-13 dogfood run failed here: a live-but-unresponsive daemon held the singleton, the
correct ``service_already_running`` refusal reached the CLI's blanket exception handler, and the
operator was told ``internal_error: the command could not be completed``. The agent concluded the
service had died and could not be restarted, and abandoned the session's completion sequence.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import yoetz.cli.app as cli
import yoetz.config.paths as paths
import yoetz.service.daemon as daemon_module
from yoetz.cli.exits import LIFECYCLE_PUBLIC_CODES, exit_code_for
from yoetz.protocol.errors import PublicErrorCode
from yoetz.service.lifecycle import LifecycleError

_MAPPED_REASONS = tuple(sorted(LIFECYCLE_PUBLIC_CODES))


def _redirect_state_dir(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Keep the holder-pid probe off this machine's real installation."""

    def state_dir(**_kwargs: object) -> Path:
        return root

    monkeypatch.setattr(paths, "state_dir", state_dir)


@pytest.fixture
def no_singleton_stamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _redirect_state_dir(monkeypatch, tmp_path)


@pytest.mark.usefixtures("no_singleton_stamp")
@pytest.mark.parametrize("reason", _MAPPED_REASONS)
def test_lifecycle_error_maps_to_a_truthful_token_and_exit(
    reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(**_kwargs: object) -> None:
        raise LifecycleError(reason)

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert result.exit_code == exit_code_for(LIFECYCLE_PUBLIC_CODES[reason])
    assert result.exit_code == 20
    # The bounded token stays first, exactly as every other operator-facing failure line does.
    assert result.stderr.startswith(reason)
    assert "internal_error" not in result.stderr


@pytest.mark.usefixtures("no_singleton_stamp")
def test_service_already_running_names_the_commands_that_can_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(**_kwargs: object) -> None:
        raise LifecycleError("service_already_running")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert "yoetz service status" in result.stderr
    assert "yoetz service stop" in result.stderr


@pytest.mark.usefixtures("no_singleton_stamp")
def test_invalid_transition_alone_stays_an_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one lifecycle reason that names our own defect must not be dressed up as an outcome."""

    def refuse(**_kwargs: object) -> None:
        raise LifecycleError("invalid_transition")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert result.exit_code == exit_code_for(PublicErrorCode.INTERNAL_ERROR)
    assert "internal_error" in result.stderr


def test_holder_pid_is_reported_when_the_lock_stamp_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from yoetz.protocol.canonical import canonical_encode

    stamp = canonical_encode({"instance_id": "svc", "pid": os.getpid()}) + b"\n"
    lock = tmp_path / "service.lock"
    lock.write_bytes(stamp)
    # The daemon creates this owner-only; the probe refuses anything wider.
    lock.chmod(0o600)
    _redirect_state_dir(monkeypatch, tmp_path)

    def refuse(**_kwargs: object) -> None:
        raise LifecycleError("service_already_running")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert f"holder pid {os.getpid()}" in result.stderr


def test_main_catch_all_never_reports_a_lifecycle_error_as_internal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _redirect_state_dir(monkeypatch, tmp_path)

    def raising(**_kwargs: object) -> None:
        raise LifecycleError("service_draining")

    monkeypatch.setattr(cli, "app", raising)

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 20
    captured = capsys.readouterr().err
    assert "service_draining" in captured
    assert "internal_error" not in captured


_STARTUP_ID = "err_11111111-2222-4333-8444-555555555555"


@pytest.fixture
def startup_ring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import yoetz.observability.diagnostics as diagnostics

    _redirect_state_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def test_unexpected_startup_failure_prints_stage_class_origin_and_id(
    startup_ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The conda-image line was only ``internal_error``; the cause was unrecoverable (#1040)."""

    from yoetz.service.startup_failure import ServiceStartupError, StartupFailure

    seen: list[object] = []

    def fail(**kwargs: object) -> None:
        seen.append(kwargs.get("startup_correlation_id"))
        raise ServiceStartupError(
            StartupFailure(
                stage="activation",
                reason="exception_not_implemented_error",
                correlation_id=_STARTUP_ID,
                origin="yoetz.adapters.control.unix_socket:434",
            )
        )

    monkeypatch.setattr(daemon_module, "main", fail)
    result = CliRunner().invoke(
        cli.app, ["service", "run", "--startup-correlation-id", _STARTUP_ID]
    )

    assert seen == [_STARTUP_ID]
    assert result.exit_code == exit_code_for(PublicErrorCode.INTERNAL_ERROR) == 70
    assert result.stderr.startswith(
        "internal_error: the service could not start (stage: activation; "
        "exception_not_implemented_error; at yoetz.adapters.control.unix_socket:434); "
        f"correlation_id {_STARTUP_ID}"
    )
    assert "the command could not be completed" not in result.stderr
    assert "Traceback" not in result.stderr


def test_a_service_module_that_cannot_load_is_an_import_stage_failure(
    startup_ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from yoetz.observability.diagnostics import lookup_diagnostic_records

    monkeypatch.setitem(sys.modules, "yoetz.service.daemon", None)
    result = CliRunner().invoke(
        cli.app, ["service", "run", "--startup-correlation-id", _STARTUP_ID]
    )

    assert result.exit_code == 70
    assert "internal_error: the service could not start (stage: import; " in result.stderr
    assert "exception_module_not_found_error" in result.stderr
    (record,) = lookup_diagnostic_records(_STARTUP_ID, root=startup_ring)
    assert record["phase"] == "import"
    assert record["reason"] == "exception_module_not_found_error"


def test_an_invalid_startup_correlation_id_is_a_usage_error(
    startup_ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(**_kwargs: object) -> None:
        raise AssertionError("daemon must not start")

    monkeypatch.setattr(daemon_module, "main", never)
    result = CliRunner().invoke(
        cli.app, ["service", "run", "--startup-correlation-id", "../not-an-id"]
    )

    assert result.exit_code == 2
    assert "../not-an-id" not in result.stderr


def test_configuration_refusal_names_its_reason_like_every_other_command(
    startup_ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.config.models import ConfigError

    def refuse(**_kwargs: object) -> None:
        raise ConfigError("unknown_config_env_var", safe_name="YOETZ_PRIVATE_NAME")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert result.exit_code == 2
    assert result.stderr == "invalid_request: unknown_config_env_var\n"
