"""`service status` must not prescribe a start that is guaranteed to refuse.

"Nothing is listening" and "something is listening and silent" arrive on the same wire reason but
need opposite next steps. Sending an operator from an unresponsive-but-live daemon to
`yoetz service run` produced a pair of commands that each pointed at the other.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import yoetz.cli.app as cli
import yoetz.config.paths as paths
import yoetz.service.client as client_module
from yoetz.ports.control import ControlError
from yoetz.protocol.errors import PublicErrorCode
from yoetz.service.client import ServiceClient


def _status_stderr(monkeypatch: pytest.MonkeyPatch, error: ControlError) -> tuple[int, str]:
    async def refuse(*_args: object, **_kwargs: object) -> ServiceClient:
        raise error

    monkeypatch.setattr(cli, "build_service_client", refuse)
    result = CliRunner().invoke(cli.app, ["service", "status"])
    return result.exit_code, result.stderr


@pytest.fixture(autouse=True)
def no_singleton_stamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def state_dir(**_kwargs: object) -> Path:
        return tmp_path

    monkeypatch.setattr(paths, "state_dir", state_dir)


def test_unresponsive_daemon_and_absent_daemon_get_different_next_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    silent_code, silent = _status_stderr(monkeypatch, client_module._AcceptedServiceUnresponsive())
    absent_code, absent = _status_stderr(
        monkeypatch, ControlError("service_unavailable", retryable=True)
    )

    assert silent_code == absent_code == 20
    assert silent.startswith("service_unavailable:")
    assert "did not answer" in silent
    assert "yoetz service stop" in silent
    # The one command the old guidance prescribed here is the one that must refuse.
    assert "Do not run 'yoetz service run'" in silent
    assert "under your selected user supervisor" not in silent

    assert absent.startswith("service_unavailable:")
    assert "run 'yoetz service run' under your selected user supervisor" in absent
    assert "did not answer" not in absent


def test_unresponsive_guidance_names_the_holder_pid_when_the_stamp_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from yoetz.protocol.canonical import canonical_encode

    lock = tmp_path / "service.lock"
    lock.write_bytes(canonical_encode({"instance_id": "svc", "pid": os.getpid()}) + b"\n")
    # The daemon creates this owner-only; the probe refuses anything wider.
    lock.chmod(0o600)

    _code, guidance = _status_stderr(monkeypatch, client_module._AcceptedServiceUnresponsive())

    assert f"holder pid {os.getpid()}" in guidance


def test_other_control_failures_keep_their_existing_guidance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, guidance = _status_stderr(monkeypatch, ControlError("vault_locked"))

    assert code == 20
    assert guidance.startswith(PublicErrorCode.VAULT_LOCKED.value.lower())
    assert "yoetz service unlock" in guidance


@pytest.mark.parametrize("failure_stage", ["connect", "status"])
def test_closure_prepare_uses_control_remediation_and_closes_client(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    closed = False

    class RefusingClient:
        async def status(self, _request: object) -> None:
            raise ControlError("vault_locked")

        async def close(self) -> None:
            nonlocal closed
            closed = True

    async def connect() -> ServiceClient:
        if failure_stage == "connect":
            raise ControlError("vault_locked")
        return cast(ServiceClient, RefusingClient())

    monkeypatch.setattr(cli, "build_service_client", connect)
    result = CliRunner().invoke(
        cli.app,
        [
            "closure-prepare",
            "--session-id",
            "ses_0f62968e-d590-4a19-90c0-a6a0deea32ac",
            "--writer-id",
            "wri_27cc27e7-45c1-490b-8a98-8132de8c4840",
        ],
    )
    assert result.exit_code == 20
    assert result.stderr.startswith("vault_locked:")
    assert "yoetz service unlock" in result.stderr
    assert closed is (failure_stage == "status")


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("closure_obligation_not_open", "Remove the non-open obligation"),
        ("closure_unattempted_items", "Account for genuine attempts"),
        ("private unexpected exception text", "invalid_request: the command input is invalid"),
    ],
)
def test_closure_prepare_renders_only_registered_remediations(
    monkeypatch: pytest.MonkeyPatch, reason: str, expected: str
) -> None:
    async def refuse() -> ServiceClient:
        raise ValueError(reason)

    monkeypatch.setattr(cli, "build_service_client", refuse)
    result = CliRunner().invoke(
        cli.app, ["closure-prepare", "--session-id", "session", "--writer-id", "writer"]
    )
    assert result.exit_code == 2
    assert expected in result.stderr
    assert "private unexpected exception text" not in result.stderr


def test_incompatible_service_status_json_names_reason_holder_and_correlation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

    lock = tmp_path / "service.lock"
    lock.write_bytes(
        canonical_encode(
            {
                "instance_id": "svc_00000000-0000-4000-8000-000000000001",
                "pid": os.getpid(),
                "service_version": "0.1.0",
                "schema_manifest_digest": "sha256:" + "a" * 64,
            }
        )
        + b"\n"
    )
    lock.chmod(0o600)

    async def refuse(*_args: object, **_kwargs: object) -> ServiceClient:
        raise ControlError("service_incompatible", retryable=True)

    monkeypatch.setattr(cli, "build_service_client", refuse)

    def record_correlation(**_kwargs: object) -> str:
        return "err_00000000-0000-4000-8000-000000000099"

    monkeypatch.setattr(
        "yoetz.observability.logging.record_public_error_without_raising",
        record_correlation,
    )
    result = CliRunner().invoke(cli.app, ["service", "status", "--json"])
    assert result.exit_code == 20
    assert "service_incompatible" in result.stderr
    assert "correlation_id err_" in result.stderr
    payload = cast(dict[str, JsonValue], strict_json_parse(result.stdout.encode("utf-8")))
    assert payload["ok"] is False
    assert payload["reason"] == "service_incompatible"
    assert payload["public_code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert payload["correlation_id"] == "err_00000000-0000-4000-8000-000000000099"
    holder = cast(dict[str, JsonValue], payload["holder"])
    assert holder["pid"] == os.getpid()
    assert holder["schema_manifest_digest"] == "sha256:" + "a" * 64


@pytest.mark.parametrize(
    ("holder_version", "expected", "absent"),
    [
        # An in-place update is waiting for the next session; nothing is broken (#820).
        ("0.0.1", "Yoetz was updated", "different Yoetz installation"),
        ("99.0.0", "different Yoetz installation", "Yoetz was updated"),
    ],
)
def test_incompatible_service_status_names_a_pending_update_only_for_an_older_holder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    holder_version: str,
    expected: str,
    absent: str,
) -> None:
    import os

    from yoetz.protocol.canonical import canonical_encode

    lock = tmp_path / "service.lock"
    lock.write_bytes(
        canonical_encode(
            {
                "instance_id": "svc_00000000-0000-4000-8000-000000000001",
                "pid": os.getpid(),
                "service_version": holder_version,
                "schema_manifest_digest": "sha256:" + "a" * 64,
            }
        )
        + b"\n"
    )
    lock.chmod(0o600)

    def record_correlation(**_kwargs: object) -> str:
        return "err_00000000-0000-4000-8000-000000000099"

    monkeypatch.setattr(
        "yoetz.observability.logging.record_public_error_without_raising",
        record_correlation,
    )
    code, stderr = _status_stderr(monkeypatch, ControlError("service_incompatible", retryable=True))
    assert code == 20
    assert expected in stderr
    assert absent not in stderr
    assert "yoetz service restart" in stderr
    assert f"service version {holder_version}" in stderr


def test_a_service_that_failed_to_start_is_named_not_prescribed_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A command whose on-demand start failed names the stage and class (#1040)."""

    import yoetz.observability.diagnostics as diagnostics
    from yoetz.service.startup_failure import record_startup_failure

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    startup_id = "err_11111111-2222-4333-8444-555555555555"
    record_startup_failure(
        NotImplementedError("chmod: follow_symlinks unavailable on this platform"),
        stage="activation",
        correlation_id=startup_id,
    )
    code, stderr = _status_stderr(
        monkeypatch,
        ControlError(
            "service_unavailable", retryable=False, correlation_id=startup_id, phase="activation"
        ),
    )

    assert code == 20
    assert stderr.startswith(
        "service_unavailable: the local service exited while starting "
        "(stage: activation; exception_not_implemented_error); "
        f"correlation_id {startup_id}"
    )
    assert "under your selected user supervisor" not in stderr


def test_service_status_names_a_runtime_another_account_can_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.cli.runtime_refusal as refusal

    def refused() -> tuple[str, str]:
        return (
            "release_runtime_group_writable",
            refusal.foreign_write_refusal("release_runtime_group_writable", hook=False),
        )

    monkeypatch.setattr(refusal, "installed_runtime_refusal_text", refused)
    code, err = _status_stderr(monkeypatch, ControlError("service_unavailable", retryable=True))
    assert code == 20
    assert err.startswith("release_runtime_group_writable: ")
    assert "chmod -R go-w " in err
    # A supervisor start would hit the same refusal; it is not the next step.
    assert "under your selected user supervisor" not in err


def test_service_status_names_a_runtime_another_account_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.cli.runtime_refusal as refusal
    from yoetz.adapters import release_runtime

    monkeypatch.setattr(
        release_runtime,
        "installed_runtime_refusal",
        lambda: release_runtime.ReleaseRuntimeError("release_runtime_not_owned"),
    )
    assert refusal.installed_runtime_refusal_text() == (
        "release_runtime_not_owned",
        refusal.not_owned_refusal(hook=False),
    )
    code, err = _status_stderr(monkeypatch, ControlError("service_unavailable", retryable=True))
    assert code == 20
    assert err.startswith("release_runtime_not_owned: ")
    assert "must belong to the account running Yoetz" in err
    assert "under your selected user supervisor" not in err


def test_runtime_probe_is_silent_for_a_source_checkout() -> None:
    from yoetz.cli.runtime_refusal import installed_runtime_refusal_text

    # Tests run from the checkout: no installed runtime exists to refuse.
    assert installed_runtime_refusal_text() is None


def test_start_timeout_and_a_starting_holder_name_the_slow_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from yoetz.cli import bootstrap

    printed: list[str] = []
    payloads: list[object] = []
    code = bootstrap.control_failure(
        ControlError("service_unavailable", retryable=True, phase="handshake_timeout"),
        json_output=True,
        stderr_writer=printed.append,
        stdout_writer=payloads.append,
    )
    assert code == 20
    assert printed[0].startswith("service_unavailable: service_handshake_timeout: ")
    assert "under your selected user supervisor" not in printed[0]
    # The one-time compile covers timestamp bytecode too, not only an install without bytecode.
    assert "expected, not a failure" in printed[0]
    assert "no reusable hash-verified bytecode" in printed[0]
    assert json.loads(json.dumps(payloads[0]))["reason"] == "service_handshake_timeout"

    # Nothing accepted yet, but a live process stamped the singleton: still starting.
    monkeypatch.setattr(bootstrap, "_singleton_holder_pid", lambda: 4242)
    _, err = _status_stderr(monkeypatch, ControlError("service_unavailable", retryable=True))
    assert err.startswith("service_unavailable: service_handshake_timeout: ")
    assert "(holder pid 4242)" in err
