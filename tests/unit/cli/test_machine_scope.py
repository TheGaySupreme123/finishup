"""Machine-scope construction resolves the configured installation bundle (issue #517).

``finishup privacy show`` used to read the installation marker from the fixed platform state
directory, so an explicit ``storage.data_dir`` bundle made the read miss, and the miss was
converted into a ``ControlError`` reason the closed control vocabulary does not admit — the CLI
then masked the constructor's own failure as a generic ``internal_error`` exit 70. These tests
pin the repaired contract: the marker is resolved through the same canonical bundle the service
uses, and every local construction failure is one bounded, actionable, pathless diagnostic
raised before any service request.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from finishup.cli import provider_status as module
from finishup.cli.provider_status import MachineScopeError, machine_scope_request
from finishup.config.models import ConfigError, FinishUpConfig, StorageConfig
from finishup.config.paths import PathSafetyError
from finishup.protocol.canonical import JsonValue, canonical_encode

_INSTALLATION_ID = "ins_50000000-0000-4000-8000-000000000001"


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    data_dir: Path | None = None,
) -> tuple[Path, list[Path | None]]:
    """Bind config and bundle resolution to a test cell; return (bundle, observed data dirs)."""

    config = FinishUpConfig(profile="strict-local", storage=StorageConfig(data_dir=data_dir))

    def _load(*_args: object) -> FinishUpConfig:
        return config

    monkeypatch.setattr(module, "load_config", _load)
    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700, exist_ok=True)
    observed: list[Path | None] = []

    def _bundle_root(*, _data_dir: Path | None = None) -> Path:
        observed.append(_data_dir)
        return bundle

    monkeypatch.setattr(module, "bundle_root", _bundle_root)
    return bundle, observed


def _write_marker(bundle: Path, text: str) -> None:
    marker = bundle / "installation-state.json"
    marker.write_text(text)
    marker.chmod(0o600)


def _valid_marker(*, installation_id: object = _INSTALLATION_ID) -> str:
    body = {
        "installation_id": installation_id,
        "mode_binding_digest": "sha256:" + ("a" * 64),
        "root_envelope_base64": None,
        "schema_version": "1",
        "vault_mode": "os_keyring",
    }
    record_digest = (
        "sha256:"
        + hashlib.sha256(
            b"yoetz/installation-state/v1\x00" + canonical_encode(cast(JsonValue, body))
        ).hexdigest()
    )
    return (
        canonical_encode(cast(JsonValue, {**body, "record_digest": record_digest})).decode() + "\n"
    )


def test_default_configuration_reads_marker_from_default_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle, observed = _wire(monkeypatch, tmp_path)
    _write_marker(bundle, _valid_marker())

    request = machine_scope_request()

    assert observed == [None]
    assert dict(request) == {
        "schema_version": "1.0.0",
        "scope": {"kind": "machine", "installation_id": _INSTALLATION_ID},
    }


def test_explicit_data_dir_resolves_the_configured_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An explicit [storage].data_dir must reach bundle resolution exactly as configured."""

    configured = tmp_path / "configured-bundle"
    bundle, observed = _wire(monkeypatch, tmp_path, data_dir=configured)
    _write_marker(bundle, _valid_marker())

    request = machine_scope_request()

    assert observed == [configured]
    scope = cast(dict[str, object], dict(request)["scope"])
    assert scope["installation_id"] == _INSTALLATION_ID


def test_missing_marker_is_a_bounded_local_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _wire(monkeypatch, tmp_path)

    with pytest.raises(MachineScopeError) as caught:
        machine_scope_request()

    assert caught.value.reason == "installation_marker_missing"


@pytest.mark.parametrize(
    "marker",
    [
        "not json at all",
        json.dumps(["not", "an", "object"]),
        json.dumps({"schema_version": "1"}),
        _valid_marker(installation_id=""),
        _valid_marker(installation_id="not-an-installation-id"),
        _valid_marker(installation_id=7),
        _valid_marker().replace('"record_digest":"sha256:', '"record_digest":"sha256:0', 1),
    ],
    ids=[
        "not_json",
        "not_object",
        "id_absent",
        "id_empty",
        "id_malformed",
        "id_not_string",
        "digest_mismatch",
    ],
)
def test_malformed_marker_is_a_bounded_local_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, marker: str
) -> None:
    bundle, _ = _wire(monkeypatch, tmp_path)
    _write_marker(bundle, marker)

    with pytest.raises(MachineScopeError) as caught:
        machine_scope_request()

    assert caught.value.reason == "installation_marker_invalid"


def test_unsafe_bundle_is_a_bounded_local_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _wire(monkeypatch, tmp_path, data_dir=tmp_path / "unsafe")

    def _refuse(*, _data_dir: Path | None = None) -> Path:
        raise PathSafetyError("path_contains_symlink")

    monkeypatch.setattr(module, "bundle_root", _refuse)

    with pytest.raises(MachineScopeError) as caught:
        machine_scope_request()

    assert caught.value.reason == "installation_bundle_unavailable"


def test_unloadable_config_is_a_bounded_local_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _refuse(*_args: object) -> FinishUpConfig:
        raise ConfigError("config_unreadable")

    monkeypatch.setattr(module, "load_config", _refuse)

    with pytest.raises(MachineScopeError) as caught:
        machine_scope_request()

    assert caught.value.reason == "installation_bundle_unavailable"


def test_machine_scope_reason_set_is_closed() -> None:
    with pytest.raises(ValueError):
        MachineScopeError("some_new_reason")
    with pytest.raises(ValueError):
        MachineScopeError(cast(str, None))


def test_failures_disclose_no_paths_and_carry_actionable_remediation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The diagnostic surface is the closed reason plus a fixed remediation — never a path."""

    _wire(monkeypatch, tmp_path)

    with pytest.raises(MachineScopeError) as caught:
        machine_scope_request()

    error = caught.value
    assert str(error) == error.reason
    assert str(tmp_path) not in str(error)
    assert str(tmp_path) not in error.remediation
    assert error.remediation
    assert "finishup" in error.remediation
