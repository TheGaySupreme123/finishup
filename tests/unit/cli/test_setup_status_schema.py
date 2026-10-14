"""Schema and golden-vector checks for the read-only setup status envelope."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.cli import setup
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.setup_status import SetupStatus


def test_setup_status_golden_vector_matches_schema() -> None:
    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "fixtures/integrations/setup-status.case.json").read_bytes())
    validate_schema_instance("setup-status", "2.0.0", payload)


def test_setup_status_schema_rejects_unknown_envelope_fields() -> None:
    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "fixtures/integrations/setup-status.case.json").read_bytes())
    payload["unexpected"] = True
    with pytest.raises(ProtocolValueError, match="schema_instance_invalid"):
        validate_schema_instance("setup-status", "2.0.0", payload)


@pytest.mark.anyio
async def test_setup_status_output_is_validated_as_assembled_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI producer must keep its assembled report inside the published /2 contract."""

    async def unavailable_service(*, start_if_absent: bool = False) -> dict[str, object]:
        assert start_if_absent is False
        return {"reachable": False, "state": None, "vault_mode": None}

    from finishup.cli import host_connection

    def empty_installation_rows(_project: Path | None = None) -> list[JsonValue]:
        return []

    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: ())
    monkeypatch.setattr(setup, "_service_reachability", unavailable_service)
    monkeypatch.setattr(setup, "setup_marker_present", lambda: False)
    monkeypatch.setattr(host_connection, "installation_rows", empty_installation_rows)

    assert await setup.setup_status(json_output=True) == 0
    report = json.loads(capsys.readouterr().out)
    validate_schema_instance("setup-status", "2.0.0", report)
    SetupStatus.model_validate(report)
    assert report["schema"] == "yoetz.setup-status/2"
