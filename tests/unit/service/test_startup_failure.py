"""Every service startup failure is recorded with its stage and exception class (#1040).

On ``condaforge/miniforge3:24.9.2-0`` the service exited 70 at startup with only
``internal_error: the command could not be completed`` on its log, and the agent's ``start`` was
told the service was merely not running. These cases hold the typed record that replaces that:
the stage, the reviewed exception-class token, the ``yoetz`` origin and one correlation id that the
foreground line, the durable ring and a spawning process all share.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

import yoetz.observability.diagnostics as diagnostics
import yoetz.service.daemon as daemon_module
from yoetz.config.installation import InstanceIdentityError
from yoetz.config.models import ConfigError, LoggingConfig, YoetzConfig
from yoetz.config.paths import PathSafetyError
from yoetz.observability.diagnostics import append_diagnostic_record, lookup_diagnostic_records
from yoetz.observability.logging import LogMode
from yoetz.protocol.errors import SERVICE_STARTUP_PHASES
from yoetz.service.lifecycle import LifecycleError
from yoetz.service.startup_failure import (
    SERVICE_STARTUP_STAGES,
    ServiceStartupError,
    StartupFailure,
    read_startup_failure,
    record_startup_failure,
    spawned_startup_failure,
)

_SPAWN_ID = "err_11111111-2222-4333-8444-555555555555"


@pytest.fixture
def ring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _raise_not_implemented() -> None:
    raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")


def _caught_not_implemented() -> NotImplementedError:
    try:
        _raise_not_implemented()
    except NotImplementedError as exc:
        return exc
    raise AssertionError("unreachable")


def test_stages_match_the_protocol_phase_vocabulary() -> None:
    assert frozenset(SERVICE_STARTUP_STAGES) == SERVICE_STARTUP_PHASES


def test_unexpected_failure_is_recorded_under_the_spawner_id(ring: Path) -> None:
    failure = record_startup_failure(
        _caught_not_implemented(), stage="activation", correlation_id=_SPAWN_ID
    )

    assert failure.correlation_id == _SPAWN_ID
    assert failure.stage == "activation"
    assert failure.reason == "exception_not_implemented_error"
    assert failure.reason_code is None
    # Raised from test code: no ``yoetz`` frame, so no origin is claimed.
    assert failure.origin is None
    (record,) = lookup_diagnostic_records(_SPAWN_ID, root=ring)
    assert record["component"] == "service.daemon"
    assert record["operation"] == "service_startup_failed"
    assert record["phase"] == "activation"
    assert record["reason"] == "exception_not_implemented_error"
    assert "reason_code" not in record
    assert read_startup_failure(_SPAWN_ID) == failure


def test_typed_refusal_keeps_its_own_token(ring: Path) -> None:
    failure = record_startup_failure(
        PathSafetyError("path_contains_symlink"),
        stage="composition",
        reason_code="path_contains_symlink",
    )

    (record,) = lookup_diagnostic_records(failure.correlation_id, root=ring)
    assert record["reason"] == "exception_path_safety_error"
    assert record["reason_code"] == "path_contains_symlink"
    assert record["phase"] == "composition"
    recorded = read_startup_failure(failure.correlation_id)
    assert recorded is not None
    assert recorded.reason_code == "path_contains_symlink"


def test_an_invalid_spawner_id_is_replaced_not_trusted(ring: Path) -> None:
    failure = record_startup_failure(
        RuntimeError("private /path text"), stage="composition", correlation_id="not-an-id"
    )

    assert failure.correlation_id.startswith("err_")
    assert failure.correlation_id != "not-an-id"
    assert lookup_diagnostic_records(failure.correlation_id, root=ring)
    assert "private" not in (ring / diagnostics.DIAGNOSTIC_FILENAME).read_text()


def test_the_foreground_line_names_stage_class_origin_and_id() -> None:
    failure = StartupFailure(
        stage="activation",
        reason="exception_not_implemented_error",
        correlation_id=_SPAWN_ID,
        origin="yoetz.adapters.control.unix_socket:434",
    )

    assert failure.line() == (
        "internal_error: the service could not start (stage: activation; "
        "exception_not_implemented_error; at yoetz.adapters.control.unix_socket:434); "
        f"correlation_id {_SPAWN_ID}; read it with "
        f"'yoetz service diagnostics --correlation-id {_SPAWN_ID}'"
    )
    serving = StartupFailure(stage="serving", reason="exception_os_error", correlation_id=_SPAWN_ID)
    assert serving.line().startswith(
        "internal_error: the service stopped unexpectedly (stage: serving; exception_os_error)"
    )


def test_read_back_ignores_records_the_writer_cannot_produce(ring: Path) -> None:
    append_diagnostic_record(
        correlation_id=_SPAWN_ID,
        component="service.daemon",
        operation="service_startup_failed",
        reason="exception_made_up_error",
        phase="activation",
        root=ring,
    )
    append_diagnostic_record(
        correlation_id=_SPAWN_ID,
        component="service.daemon",
        operation="service_startup_failed",
        reason="exception_os_error",
        phase="not_a_stage",
        root=ring,
    )
    append_diagnostic_record(
        correlation_id=_SPAWN_ID,
        component="mcp.bridge",
        operation="public_error",
        reason="exception_os_error",
        phase="activation",
        root=ring,
    )

    assert read_startup_failure(_SPAWN_ID) is None


def test_spawned_startup_failure_reads_only_startup_phases(ring: Path) -> None:
    assert spawned_startup_failure(None, _SPAWN_ID) is None
    assert spawned_startup_failure("handler", _SPAWN_ID) is None
    assert spawned_startup_failure("activation", None) is None
    # A record that cannot be read back still names the stage the control error carried.
    assert spawned_startup_failure("activation", _SPAWN_ID) == StartupFailure(
        stage="activation", reason="exception_unavailable", correlation_id=_SPAWN_ID
    )


def _patch_run_service(
    monkeypatch: pytest.MonkeyPatch,
    *,
    load: object = None,
    composition: object = None,
    daemon: object = None,
) -> None:
    def default_load(
        overrides: Mapping[str, str], env: Mapping[str, str], path: Path | None
    ) -> YoetzConfig:
        del overrides, env, path
        return YoetzConfig()

    async def default_composition(*, _config: YoetzConfig) -> object:
        del _config
        return object()

    def configure(config: LoggingConfig, mode: LogMode) -> None:
        del config, mode

    monkeypatch.setattr(daemon_module, "load_config", load or default_load)
    monkeypatch.setattr(daemon_module, "configure_logging", configure)
    monkeypatch.setattr(
        daemon_module, "_production_composition", composition or default_composition
    )
    if daemon is not None:
        monkeypatch.setattr(daemon_module, "ServiceDaemon", daemon)


class _FailingDaemon:
    started = False

    def __init__(self, *, _composition: object) -> None:
        del _composition

    async def serve(self) -> None:
        _raise_not_implemented()


class _FailingAfterStartDaemon(_FailingDaemon):
    async def serve(self) -> None:
        self.started = True
        raise OSError("connection dropped")


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("stage", "reason"),
    [
        ("configuration", "exception_runtime_error"),
        ("composition", "exception_runtime_error"),
        ("activation", "exception_not_implemented_error"),
        ("serving", "exception_os_error"),
    ],
)
async def test_run_service_names_the_stage_that_failed(
    stage: str, reason: str, ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_load(
        overrides: Mapping[str, str], env: Mapping[str, str], path: Path | None
    ) -> YoetzConfig:
        del overrides, env, path
        raise RuntimeError("configuration exploded")

    async def failing_composition(*, _config: YoetzConfig) -> object:
        del _config
        raise RuntimeError("composition exploded")

    if stage == "configuration":
        _patch_run_service(monkeypatch, load=failing_load)
    elif stage == "composition":
        _patch_run_service(monkeypatch, composition=failing_composition)
    elif stage == "activation":
        _patch_run_service(monkeypatch, daemon=_FailingDaemon)
    else:
        _patch_run_service(monkeypatch, daemon=_FailingAfterStartDaemon)

    with pytest.raises(ServiceStartupError) as raised:
        await daemon_module.run_service(_SPAWN_ID)

    failure = raised.value.failure
    assert failure.stage == stage
    assert failure.reason == reason
    assert failure.correlation_id == _SPAWN_ID
    # The innermost yoetz frame of a failure raised beneath run_service is run_service itself.
    assert failure.origin is not None
    assert failure.origin.startswith("yoetz.service.daemon:")
    assert raised.value.__cause__ is not None
    (record,) = lookup_diagnostic_records(_SPAWN_ID, root=ring)
    assert record["phase"] == stage
    assert record["reason"] == reason
    assert record["origin"] == failure.origin
    assert read_startup_failure(_SPAWN_ID) == failure


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("refusal", "token"),
    [
        (PathSafetyError("path_contains_symlink"), "path_contains_symlink"),
        (InstanceIdentityError("instance_expired"), "instance_expired"),
        (ConfigError("unknown_config_env_var"), "unknown_config_env_var"),
        (LifecycleError("vault_locked"), "vault_locked"),
    ],
)
async def test_typed_refusals_are_recorded_and_reraised_unchanged(
    refusal: Exception, token: str, ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*, _config: YoetzConfig) -> object:
        del _config
        raise refusal

    _patch_run_service(monkeypatch, composition=refuse)

    with pytest.raises(type(refusal)) as raised:
        await daemon_module.run_service(_SPAWN_ID)

    assert raised.value is refusal
    (record,) = lookup_diagnostic_records(_SPAWN_ID, root=ring)
    assert record["reason_code"] == token
    assert record["phase"] == "composition"


@pytest.mark.anyio
async def test_invalid_transition_is_an_unexpected_failure(
    ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*, _config: YoetzConfig) -> object:
        del _config
        raise LifecycleError("invalid_transition")

    _patch_run_service(monkeypatch, composition=refuse)

    with pytest.raises(ServiceStartupError) as raised:
        await daemon_module.run_service(_SPAWN_ID)

    assert raised.value.failure.reason == "exception_lifecycle_error"
    assert raised.value.failure.reason_code is None


@pytest.mark.anyio
async def test_losing_the_singleton_race_is_not_a_startup_failure(
    ring: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*, _config: YoetzConfig) -> object:
        del _config
        raise LifecycleError("service_already_running")

    _patch_run_service(monkeypatch, composition=refuse)

    with pytest.raises(LifecycleError):
        await daemon_module.run_service(_SPAWN_ID)

    assert lookup_diagnostic_records(_SPAWN_ID, root=ring) == ()
    assert not (ring / diagnostics.DIAGNOSTIC_FILENAME).exists()


def test_startup_module_stays_import_light() -> None:
    """The CLI records an import-stage failure with it before the daemon could load."""

    probe = (
        "import sys, json, yoetz.service.startup_failure\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('yoetz.service.'))))"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe
        (sys.executable, "-I", "-c", probe),
        capture_output=True,
        check=True,
        timeout=60,
    )
    assert json.loads(completed.stdout) == ["yoetz.service.startup_failure"]
