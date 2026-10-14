"""Operation-specific setup order without grants, secrets or live service access."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from tests.builders.privacy_policies import local_only_policy

from finishup.cli import setup
from finishup.cli import setup_readiness as module
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.setup_readiness import SetupReadiness


@pytest.mark.anyio
@pytest.mark.parametrize(
    "state,mode,reason,command",
    [
        (None, None, "service_unavailable", ["service", "restart"]),
        ("starting", None, "service_not_ready", ["service", "status"]),
        ("draining", None, "service_not_ready", ["service", "status"]),
        ("locked", "uninitialized", "vault_uninitialized", ["setup", "vault"]),
        ("locked", "passphrase", "vault_locked", ["service", "unlock"]),
        ("locked", "os_keyring", "vault_locked", ["service", "unlock"]),
    ],
)
async def test_first_unmet_prerequisite_stops_probing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str | None,
    mode: str | None,
    reason: str,
    command: list[str],
) -> None:
    async def service() -> dict[str, JsonValue]:
        return {"reachable": state is not None, "state": state, "vault_mode": mode}

    async def forbidden(*_args: object) -> None:
        raise AssertionError("must not proceed past unmet service/vault prerequisite")

    monkeypatch.setattr(setup, "_service_reachability", service)
    monkeypatch.setattr(module, "get_privacy_setup_snapshot", forbidden)
    result = await module.installation_readiness(tmp_path, "local")
    assert result["reason"] == reason
    assert result["arguments"] == command


@pytest.mark.anyio
@pytest.mark.parametrize("grant", ["missing", "granted"])
async def test_local_use_needs_no_provider_but_review_requires_binding_first(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    grant: str,
) -> None:
    async def service() -> dict[str, JsonValue]:
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    async def snapshot(project: Path) -> SimpleNamespace:
        assert project == tmp_path
        return SimpleNamespace(grant_state=grant, composed_policy=local_only_policy())

    def forbidden() -> None:
        raise AssertionError("local use must not read provider login")

    monkeypatch.setattr(setup, "_service_reachability", service)
    monkeypatch.setattr(module, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(module, "configured_bindings", forbidden)
    local = await module.installation_readiness(tmp_path, "local")
    assert local.get("reason") == ("repository_grant_required" if grant == "missing" else None)
    monkeypatch.setattr(module, "configured_bindings", lambda: (None, None))
    review = await module.installation_readiness(tmp_path, "review")
    assert review["reason"] == "provider_binding_required"
    assert review["arguments"] == ["--set"]


def test_connection_only_skips_service_and_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def forbidden(*_args: object) -> None:
        raise AssertionError("installing an integration does not need a provider or vault")

    monkeypatch.setattr(module, "installation_readiness", forbidden)
    monkeypatch.setattr(module, "isolated_root", lambda: None)
    module.setup_next(
        operation="connection",
        host=None,
        executable=None,
        config_root=None,
        project=tmp_path,
        route="strict",
        json_output=True,
    )
    report = json.loads(capsys.readouterr().out)
    validate_schema_instance("setup-readiness", "1.0.0", report)
    assert report["reason"] == "host_selection_required"
    assert report["connection_observed"] is False


def test_continuation_quotes_and_pins_runtime_project_and_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "bin with space" / "finishup"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o700)
    project = tmp_path / "project $(never-execute)"
    root = tmp_path / "isolated ' root"
    monkeypatch.setattr(module, "invoking_launcher", lambda: str(launcher))
    monkeypatch.setattr(module, "isolated_root", lambda: root)
    command = module.continuation(["service", "unlock"], project=project)
    assert shlex.split(command) == [
        "cd",
        str(project),
        "&&",
        "env",
        f"FINISHUP_ISOLATED_ROOT={root}",
        str(launcher.resolve()),
        "service",
        "unlock",
    ]


def test_readiness_golden_contract() -> None:
    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "fixtures/integrations/setup-readiness.case.json").read_bytes())
    validate_schema_instance("setup-readiness", "1.0.0", payload)


def test_readiness_contract_bounds_reason_and_fact_inventory() -> None:
    base: dict[str, JsonValue] = {
        "schema": "yoetz.setup-readiness/1",
        "operation": "local",
        "reason": "ready",
        "project": "/workspace/project",
        "inspected_config_root": None,
        "next_command": None,
        "facts": {},
    }
    with pytest.raises(ValidationError):
        SetupReadiness.model_validate({**base, "reason": "caller-authored"})
    with pytest.raises(ValidationError):
        SetupReadiness.model_validate({**base, "facts": {str(index): index for index in range(33)}})


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-cli", "cursor-ide"])
def test_vault_setup_continuation_is_storage_only_and_reports_selected_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    from typing import cast

    from finishup.adapters.integrations.host_discovery import HostInstallation, SetupHost
    from finishup.cli import host_connection

    selected = HostInstallation(
        cast(SetupHost, host), tmp_path / host, "1.0.0", tmp_path / "home", host
    )

    def select(*_args: object) -> HostInstallation:
        return selected

    async def needs_vault(*_args: object) -> dict[str, JsonValue]:
        return {"reason": "vault_uninitialized", "arguments": ["setup", "vault"]}

    monkeypatch.setattr(host_connection, "select_installation", select)
    monkeypatch.setattr(module, "installation_readiness", needs_vault)
    monkeypatch.setattr(module, "isolated_root", lambda: None)
    module.setup_next(
        operation="local",
        host=host,
        executable=selected.executable,
        config_root=selected.config_root,
        project=tmp_path,
        route="strict",
        json_output=True,
    )
    report = json.loads(capsys.readouterr().out)
    args = shlex.split(report["next_command"])
    assert args[-2:] == ["setup", "vault"]
    assert report["inspected_config_root"] == str(selected.config_root)
    assert "--accept" not in args


@pytest.mark.anyio
async def test_storage_only_ceremony_stops_before_provider_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("storage-only setup must never configure a provider")

    monkeypatch.setattr("finishup.cli.provider_binding.prompt_provider_endpoint_binding", forbidden)
    service: dict[str, JsonValue] = {
        "reachable": True,
        "state": "ready",
        "vault_mode": "passphrase",
    }
    observed, provider = await setup._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
        service,
        storage_only=True,
    )
    assert observed["state"] == "ready"
    assert provider == {"binding": "skipped", "credential": "skipped"}


@pytest.mark.anyio
async def test_storage_only_keyring_unlock_uses_existing_confidential_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def unlock() -> None:
        calls.append("retry_keyring")

    async def ready() -> dict[str, JsonValue]:
        return {"reachable": True, "state": "ready", "vault_mode": "os_keyring"}

    monkeypatch.setattr("finishup.cli.unlock.retry_keyring", unlock)
    monkeypatch.setattr(setup, "_service_reachability", ready)
    observed, _provider = await setup._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
        {"reachable": True, "state": "locked", "vault_mode": "os_keyring"},
        storage_only=True,
    )
    assert calls == ["retry_keyring"]
    assert observed["state"] == "ready"


@pytest.mark.anyio
async def test_storage_only_command_refuses_noninteractive_before_service_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: False)

    async def forbidden(**_kwargs: object) -> None:
        raise AssertionError("noninteractive callers must not start services or handle secrets")

    monkeypatch.setattr(setup, "_service_reachability", forbidden)
    assert await setup.run_vault_setup() == 2


def test_module_continuation_preserves_venv_interpreter_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = str(tmp_path / "venv" / "bin" / "python")
    monkeypatch.setattr(module, "invoking_launcher", lambda: (interpreter, "-m", "finishup"))
    monkeypatch.setattr(module, "isolated_root", lambda: None)
    assert shlex.split(module.continuation(["setup", "vault"])) == [
        interpreter,
        "-m",
        "finishup",
        "setup",
        "vault",
    ]


@pytest.mark.parametrize("json_output", [True, False])
def test_setup_status_next_names_the_background_advice_setting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
) -> None:
    """Issue #888: setup status shows the effective background-advice state and its reason."""

    from finishup.config import load as config_load
    from finishup.config.models import FinishUpConfig

    async def ready(_project: Path, _operation: str) -> dict[str, JsonValue]:
        return {"service": {"reachable": True, "state": "ready", "vault_mode": "passphrase"}}

    monkeypatch.setattr(module, "installation_readiness", ready)
    monkeypatch.setattr(module, "isolated_root", lambda: None)

    def _load(*_args: object) -> FinishUpConfig:
        return FinishUpConfig()

    monkeypatch.setattr(config_load, "load_config", _load)
    module.setup_next(
        operation="review",
        host=None,
        executable=None,
        config_root=None,
        project=tmp_path,
        route="policy",
        json_output=json_output,
    )
    output = capsys.readouterr().out
    if json_output:
        report = json.loads(output)
        validate_schema_instance("setup-readiness", "1.0.0", report)
        assert report["facts"]["background_advice"] == {
            "enabled": True,
            "reason": "default_enabled",
        }
    else:
        assert "Background AI-powered advice: on by default" in output
        # The reverse switch is named; the turn-on hint belongs only to an owner's ``false``.
        assert "semantic_advice_enabled = false" in output
        assert "= true" not in output
