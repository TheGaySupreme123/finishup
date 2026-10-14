"""Installation-folder naming on human surfaces, and the folder refusal's report (ADR-048).

Every case runs against XDG roots under ``tmp_path``; nothing reads or writes a real user
directory, and no service is started.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.cli.exits import (
    INSTANCE_PUBLIC_CODES,
    LOCAL_REASONS,
    UPGRADING_FROM_YOETZ_GUIDE,
    remediation_message,
)
from finishup.cli.service_installation import (
    LEGACY_FOLDERS_NOTE,
    installation_folders,
    installation_naming_line,
    path_refusal_agent_message,
    path_refusal_failure,
)
from finishup.config.paths import ISOLATED_ROOT_ENV, LEGACY_ISOLATED_ROOT_ENV, PathSafetyError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.recovery import continuation_for_local_reason


def _xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "xdg"
    for name in ("data", "config", "cache", "state", "runtime"):
        (base / name).mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(base / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base / "runtime"))
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    monkeypatch.delenv(LEGACY_ISOLATED_ROOT_ENV, raising=False)
    return base


def _catalog(base: Path, app_name: str) -> None:
    directory = base / "data" / app_name
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    (directory / "catalog.sqlite3").write_bytes(b"")


def test_a_new_installation_needs_no_naming_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch)

    assert installation_folders() == "finishup"
    assert installation_naming_line() is None


def test_an_installation_adopted_in_place_says_so_and_where_to_read_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _catalog(base, "yoetz")

    assert installation_folders() == "legacy_yoetz"
    line = installation_naming_line()
    assert line == LEGACY_FOLDERS_NOTE
    assert "Yoetz-era folders in place" in line
    assert "Nothing was moved" in line
    assert line.endswith(UPGRADING_FROM_YOETZ_GUIDE)
    assert UPGRADING_FROM_YOETZ_GUIDE.endswith("docs/usage/upgrading.md#upgrading-from-yoetz")
    # The line names no local path.
    assert str(tmp_path) not in line
    # Reading the naming creates nothing under the new name.
    assert not (base / "data" / "finishup").exists()


def test_an_isolated_root_is_named_as_such_whatever_the_ambient_folders_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _catalog(base, "yoetz")
    _catalog(base, "finishup")
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(LEGACY_ISOLATED_ROOT_ENV, str(root))

    assert installation_folders() == "isolated"
    assert installation_naming_line() is None


def test_ambiguous_folders_raise_for_callers_and_never_become_a_status_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _catalog(base, "yoetz")
    _catalog(base, "finishup")

    with pytest.raises(PathSafetyError) as caught:
        installation_folders()
    assert caught.value.reason_code == "installation_root_ambiguous"
    assert installation_naming_line() is None


@pytest.mark.parametrize("json_output", [False, True])
def test_the_folder_refusal_names_its_token_remedy_and_continuation(json_output: bool) -> None:
    errors: list[str] = []
    payloads: list[JsonValue] = []

    code = path_refusal_failure(
        "installation_root_ambiguous",
        json_output=json_output,
        stderr_writer=errors.append,
        stdout_writer=payloads.append,
    )

    assert code == 20
    assert len(errors) == 1
    text = errors[0]
    first, *rest = text.splitlines()
    assert first.startswith("installation_root_ambiguous: FinishUP found its folders under both")
    # A lone settings file counts as an installation: the remedy says which folders must stay
    # and what to do with the settings file, without naming a path.
    assert "vault and catalog are this installation's data and must stay" in first
    assert "move that file into the folders that hold the vault and catalog" in first
    # Two real installations or a leftover lock still have a non-destructive way out.
    assert "move the other name's folders aside without deleting them" in first
    assert first.endswith(UPGRADING_FROM_YOETZ_GUIDE)
    assert "Continuation: local_state_repair" in rest
    assert "service_unavailable" not in text
    if json_output:
        assert len(payloads) == 1
        payload = payloads[0]
        assert isinstance(payload, dict)
        assert payload["ok"] is False
        assert payload["public_code"] == PublicErrorCode.STORAGE_UNSAFE.value
        assert payload["reason"] == "installation_root_ambiguous"
        assert payload["retryable"] is False
        recovery = payload["recovery"]
        assert isinstance(recovery, dict)
        assert recovery["continuation"] == "local_state_repair"
        json.dumps(payload)
    else:
        assert payloads == []


def test_an_isolation_root_conflict_reports_through_the_same_shape() -> None:
    errors: list[str] = []

    code = path_refusal_failure(
        "isolation_root_conflict",
        json_output=False,
        stderr_writer=errors.append,
        stdout_writer=lambda _value: None,
    )

    assert code == 20
    assert errors[0].startswith("isolation_root_conflict: ")
    assert "pin" in errors[0]
    assert "Continuation: instance_identity_repair" in errors[0]


def test_two_isolation_root_spellings_that_disagree_get_a_non_destructive_remedy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The instance is healthy; only the environment disagrees. Nothing may direct an agent to
    # dispose it.
    _xdg(tmp_path, monkeypatch)
    for name, leaf in ((ISOLATED_ROOT_ENV, "new"), (LEGACY_ISOLATED_ROOT_ENV, "old")):
        (tmp_path / leaf).mkdir(mode=0o700)
        monkeypatch.setenv(name, str(tmp_path / leaf))
    with pytest.raises(PathSafetyError) as caught:
        installation_folders()
    assert caught.value.reason_code == "isolation_root_env_conflict"

    errors: list[str] = []
    payloads: list[JsonValue] = []
    code = path_refusal_failure(
        "isolation_root_env_conflict",
        json_output=True,
        stderr_writer=errors.append,
        stdout_writer=payloads.append,
    )

    assert code == 20
    first, *rest = errors[0].splitlines()
    assert first.startswith("isolation_root_env_conflict: FINISHUP_ISOLATED_ROOT and the older")
    assert "unset YOETZ_ISOLATED_ROOT" in first
    assert str(tmp_path) not in errors[0]
    assert "Continuation: config_correction_required" in rest
    assert "instance_identity_repair" not in errors[0]
    payload = payloads[0]
    assert isinstance(payload, dict)
    recovery = payload["recovery"]
    assert isinstance(recovery, dict)
    assert recovery["continuation"] == "config_correction_required"


@pytest.mark.parametrize(
    "reason",
    [
        "isolation_root_invalid",
        "path_contains_symlink",
        "path_in_repository",
        "path_in_sync_folder",
        "path_not_owned",
        "path_shared_temp",
        "permissions_too_broad",
    ],
)
def test_every_folder_refusal_token_names_a_remedy_and_a_continuation(reason: str) -> None:
    errors: list[str] = []
    payloads: list[JsonValue] = []

    path_refusal_failure(
        reason, json_output=True, stderr_writer=errors.append, stdout_writer=payloads.append
    )

    assert "cannot be used as requested" not in errors[0]
    assert remediation_message(reason) is not None
    assert continuation_for_local_reason(reason) is not None
    payload = payloads[0]
    assert isinstance(payload, dict)
    assert "recovery" in payload


def test_the_status_naming_note_goes_to_stderr_only_for_a_legacy_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli.service_installation import report_installation_naming

    base = _xdg(tmp_path, monkeypatch)
    written: list[str] = []
    report_installation_naming(written.append)
    assert written == []

    _catalog(base, "yoetz")
    report_installation_naming(written.append)
    assert written == [LEGACY_FOLDERS_NOTE]


def test_the_agent_message_names_the_token_and_ends_with_the_remedy() -> None:
    message = path_refusal_agent_message("installation_root_ambiguous")

    assert "FinishUP's local folders cannot be used safely (installation_root_ambiguous)" in message
    assert "nothing was recorded" in message
    assert "do not run service lifecycle commands" in message
    remedy = remediation_message("installation_root_ambiguous")
    assert remedy is not None
    assert message.endswith(f"Tell the user: {remedy}")


def test_new_local_reasons_have_a_remedy_a_code_and_a_continuation() -> None:
    assert INSTANCE_PUBLIC_CODES["installation_root_ambiguous"] is PublicErrorCode.STORAGE_UNSAFE
    assert continuation_for_local_reason("installation_root_ambiguous") == "local_state_repair"
    assert continuation_for_local_reason("config_env_conflict") == "config_correction_required"
    assert {"installation_root_ambiguous", "config_env_conflict"} <= LOCAL_REASONS
    conflict = remediation_message("config_env_conflict")
    assert conflict is not None
    assert "YOETZ_" in conflict
    assert "FINISHUP_" in conflict
