"""The credential-store decision is reported with its reason, not just as absent (issue #721)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from keyring.backends.fail import Keyring as FailKeyring
from keyring.backends.null import Keyring as NullKeyring
from keyring.backends.SecretService import Keyring as SecretServiceKeyring

from finishup.adapters.keys import os_keyring
from finishup.adapters.keys.os_keyring import describe_vault_keyring_backend


def test_fail_backend_reads_as_no_store_and_names_the_linux_requirement() -> None:
    report = describe_vault_keyring_backend(backend=FailKeyring(), system="Linux")

    assert report.approved is False
    assert report.reason == "keyring_unavailable"
    assert report.backend_id == "keyring.backends.fail.Keyring"
    assert "Secret Service" in report.requirement
    assert "WSL 2" in report.requirement
    assert "passphrase" in report.requirement


def test_unapproved_backend_is_named_not_offered() -> None:
    report = describe_vault_keyring_backend(backend=NullKeyring(), system="Darwin")

    assert report.approved is False
    assert report.reason == "backend_not_approved"
    assert report.backend_id == "keyring.backends.null.Keyring"
    assert report.requirement == "macOS Keychain"


def test_secret_service_backend_is_the_approved_linux_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os_keyring, "_secret_service_available", lambda: True)
    report = describe_vault_keyring_backend(backend=SecretServiceKeyring(), system="Linux")

    assert report.approved is True
    assert report.reason == "approved"
    assert report.as_json() == {
        "approved": True,
        "backend_id": "keyring.backends.SecretService.Keyring",
        "reason": "approved",
        "requirement": report.requirement,
    }


@pytest.mark.parametrize("system", ["FreeBSD", "Windows", ""])
def test_other_platforms_get_the_generic_requirement(system: str) -> None:
    report = describe_vault_keyring_backend(backend=FailKeyring(), system=system)

    assert report.requirement == "macOS Keychain or a Freedesktop Secret Service"


def test_live_probe_never_raises() -> None:
    report = describe_vault_keyring_backend()

    assert report.reason in {"approved", "keyring_unavailable", "backend_not_approved"}
    assert report.approved is (report.reason == "approved")


@pytest.mark.parametrize(
    "failure", [1, OSError("private backend error"), subprocess.TimeoutExpired("probe", 10)]
)
def test_unavailable_secret_service_is_never_offered(
    monkeypatch: pytest.MonkeyPatch, failure: int | Exception
) -> None:
    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == 10
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        if isinstance(failure, Exception):
            raise failure
        return subprocess.CompletedProcess("probe", failure)

    monkeypatch.setattr(os_keyring.subprocess, "run", run)
    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: SecretServiceKeyring())
    report = describe_vault_keyring_backend(system="Linux")
    assert report.approved is False
    assert report.reason == "keyring_unavailable"
    assert "private" not in str(report.as_json())


def test_secret_service_probe_does_not_import_workspace_or_pythonpath_modules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "imported"
    (tmp_path / "keyring.py").write_text(
        "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    describe_vault_keyring_backend(backend=SecretServiceKeyring(), system="Linux")
    assert not marker.exists()
