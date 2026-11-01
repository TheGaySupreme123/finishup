"""Pinned Codex registration/startup capability evidence.

Non-live cells prove isolated config-profile digests, no real-HOME mutation, and that
unfrozen Codex profiles cannot claim startup support. Live cells require
``FINISHUP_LIVE_CODEX=1`` and exercise real Codex registration/startup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    codex_profiles_frozen,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_CANDIDATE_VERSION = "0.139.0"

_CASE_CONFIG = CapabilityCase(
    case_id="CFG-001",
    requirement_id="ADR-005.mcp-registration",
    claim_id="E-002.config-startup",
    capability_family="codex_config_startup",
    required_observation_codes=frozenset(
        {
            "config_profile_bound",
            "home_isolation_held",
            "preexisting_entry_preserved",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "config_profile_bound",
            "home_isolation_held",
            "preexisting_entry_preserved",
            "required_policy_encoded",
            "profiles_frozen",
        }
    ),
)

_CASE_LIVE = CapabilityCase(
    case_id="CFG-LIVE-001",
    requirement_id="ADR-005.mcp-registration",
    claim_id="E-002.config-startup-live",
    capability_family="codex_config_startup",
    required_observation_codes=frozenset({"codex_version_matched"}),
    allowed_observation_codes=frozenset(
        {
            "codex_version_matched",
            "cold_start_bounded",
            "diagnostic_gate_before_stdin",
            "live_authorized",
        }
    ),
)


def _optional_required_profiles() -> tuple[str, str]:
    """Return digests for optional vs required MCP registration profiles (path-free)."""

    base = {
        "channel": "codex_mcp_stdio",
        "command_tokens": ("finishup", "mcp", "serve"),
        "cwd_policy": "project_root",
        "env_policy": "none",
        "server_name": "finishup",
    }
    optional = canonical_digest({**base, "required": False})
    required = canonical_digest({**base, "required": True})
    return optional, required


def test_isolated_optional_and_required_config_profiles_are_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    isolated_home = tmp_path / "home"
    isolated_home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(isolated_home))
    monkeypatch.setenv("CODEX_HOME", str(isolated_home / ".codex"))

    optional_digest, required_digest = _optional_required_profiles()
    assert optional_digest != required_digest

    preexisting = isolated_home / ".codex" / "config.toml"
    preexisting.parent.mkdir(parents=True, mode=0o700)
    preexisting.write_text(
        '[mcp_servers.other]\ncommand = "true"\nargs = []\n',
        encoding="ascii",
    )
    before = preexisting.read_bytes()

    # Capability harness writes only under the isolated root; never mutates real HOME.
    profile_root = isolated_home / ".codex" / "finishup-capability"
    profile_root.mkdir(parents=True, mode=0o700)
    (profile_root / "optional.profile").write_text(optional_digest + "\n", encoding="ascii")
    (profile_root / "required.profile").write_text(required_digest + "\n", encoding="ascii")
    assert preexisting.read_bytes() == before
    assert Path.home() == isolated_home

    fixture_digest = canonical_digest(
        {"optional": optional_digest, "required": required_digest, "kind": "config_profile"}
    )
    context = runtime_capability_context(
        fixture_digest=fixture_digest,
        test_revision=_TEST_REVISION,
        config_profile_digest=optional_digest,
        external_tool="codex",
        external_version=_CANDIDATE_VERSION,
        integration_channel="codex_mcp_stdio",
        protocol_version="2025-11-25",
    )
    evidence = record_and_write(
        _CASE_CONFIG,
        context,
        (
            Observation("config_profile_bound", digest_value=optional_digest),
            Observation("home_isolation_held", boolean_value=True),
            Observation("preexisting_entry_preserved", boolean_value=True),
            Observation("required_policy_encoded", digest_value=required_digest),
            Observation("profiles_frozen", boolean_value=codex_profiles_frozen()),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS
    assert evidence.context.config_profile_digest == optional_digest


def test_unfrozen_codex_profiles_cannot_claim_startup_support(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    optional_digest, _required = _optional_required_profiles()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"unfrozen-startup-cell"),
        test_revision=_TEST_REVISION,
        config_profile_digest=optional_digest,
        external_tool="codex",
        external_version=_CANDIDATE_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if codex_profiles_frozen():
        pytest.skip("Codex profiles are frozen; live startup cells own the pass path")
    evidence = record_and_write(
        CapabilityCase(
            case_id="CFG-002",
            requirement_id="ADR-005.mcp-registration",
            claim_id="E-002.config-startup",
            capability_family="codex_config_startup",
            required_observation_codes=frozenset({"profiles_frozen"}),
            allowed_observation_codes=frozenset({"profiles_frozen", "home_isolation_held"}),
        ),
        context,
        (
            Observation("profiles_frozen", boolean_value=False),
            Observation("home_isolation_held", boolean_value=True),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("codex_profiles_unfrozen",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
    assert "codex_profiles_unfrozen" in evidence.reasons


@pytest.mark.live
def test_live_codex_registration_and_startup(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    optional_digest, _required = _optional_required_profiles()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-config-startup"),
        test_revision=_TEST_REVISION,
        config_profile_digest=optional_digest,
        external_tool="codex",
        external_version=_CANDIDATE_VERSION,
        integration_channel="codex_mcp_stdio",
        protocol_version="2025-11-25",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    if not codex_profiles_frozen():
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (
                Observation("live_authorized", boolean_value=True),
                Observation("codex_version_matched", boolean_value=False),
            ),
            EvidenceOutcome.UNSUPPORTED,
            ("codex_profiles_unfrozen",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail(
        "live Codex registration/startup is authorized and profiles are frozen; "
        "implement the isolated HOME/codex mcp get/add matrix before claiming pass"
    )
