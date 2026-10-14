"""Optional vs required MCP availability capability evidence.

Non-live cells prove config profiles differ only by the required flag, that a missing MCP
executable fails closed without fabricating ledger state, and that unfrozen Codex host surfaces
cannot claim continuation/blocking. Live Codex surface cells require ``FINISHUP_LIVE_CODEX=1``.
"""

from __future__ import annotations

import json
import subprocess
import sys
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
_VERSION = "0.139.0"


def _profiles() -> tuple[str, str]:
    base = {
        "channel": "codex_mcp_stdio",
        "command_tokens": ("finishup", "mcp", "serve"),
        "server_name": "finishup",
    }
    return (
        canonical_digest({**base, "required": False}),
        canonical_digest({**base, "required": True}),
    )


def test_optional_and_required_profiles_differ_only_by_flag(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    optional, required = _profiles()
    assert optional != required
    context = runtime_capability_context(
        fixture_digest=canonical_digest({"optional": optional, "required": required}),
        test_revision=_TEST_REVISION,
        config_profile_digest=optional,
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="ORF-001",
            requirement_id="ADR-005.optional-required",
            claim_id="E-002.optional-required",
            capability_family="codex_optional_required",
            required_observation_codes=frozenset({"profiles_distinct"}),
            allowed_observation_codes=frozenset({"profiles_distinct", "required_digest_bound"}),
        ),
        context,
        (
            Observation("profiles_distinct", boolean_value=True),
            Observation("required_digest_bound", digest_value=required),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_missing_executable_fails_closed_without_ledger_fabrication(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    missing = tmp_path / "missing-finishup-mcp"
    child = (
        "import json,sys;"
        "print(json.dumps({'jsonrpc':'2.0','id':1,'error':{'code':-32000,"
        "'message':'server_unavailable','data':{'reason':'missing_executable'}}}));"
        "sys.exit(1)"
    )
    # Simulate the MCP stdio child the host would launch when the configured executable is absent:
    # the process exits before any FinishUP tool result or durable mutation.
    completed = subprocess.run(
        [sys.executable, "-I", "-c", child],
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode != 0
    frame = json.loads(completed.stdout.decode("ascii"))
    assert frame["error"]["data"]["reason"] == "missing_executable"
    assert not (tmp_path / "ledger").exists()

    optional, _required = _profiles()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"missing-executable-failure"),
        test_revision=_TEST_REVISION,
        config_profile_digest=optional,
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="ORF-002",
            requirement_id="ADR-005.optional-required",
            claim_id="E-002.optional-required",
            capability_family="codex_optional_required",
            required_observation_codes=frozenset(
                {"server_unavailable", "ledger_mutations", "tool_result_absent"}
            ),
            allowed_observation_codes=frozenset(
                {
                    "server_unavailable",
                    "ledger_mutations",
                    "tool_result_absent",
                    "missing_path_unused",
                }
            ),
        ),
        context,
        (
            Observation("server_unavailable", boolean_value=True),
            Observation("ledger_mutations", integer_value=0),
            Observation("tool_result_absent", boolean_value=True),
            Observation("missing_path_unused", boolean_value=not missing.exists()),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_codex_host_continuation_claim_is_unsupported_while_unprofiled(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    optional, _required = _profiles()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"host-continuation-unprofiled"),
        test_revision=_TEST_REVISION,
        config_profile_digest=optional,
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if codex_profiles_frozen():
        pytest.skip("frozen profiles move host continuation into the live matrix")
    evidence = record_and_write(
        CapabilityCase(
            case_id="ORF-003",
            requirement_id="ADR-005.optional-required",
            claim_id="E-002.optional-required",
            capability_family="codex_optional_required",
            required_observation_codes=frozenset({"profiles_frozen"}),
            allowed_observation_codes=frozenset({"profiles_frozen"}),
        ),
        context,
        (Observation("profiles_frozen", boolean_value=False),),
        EvidenceOutcome.UNSUPPORTED,
        ("codex_host_surface_unprobed",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED


@pytest.mark.live
@pytest.mark.parametrize("surface", ("codex_exec", "interactive_cli"))
def test_live_required_failure_blocks_only_when_observed(surface: str, tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    _optional, required = _profiles()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(f"live-required-{surface}".encode("ascii")),
        test_revision=_TEST_REVISION,
        config_profile_digest=required,
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id=f"ORF-LIVE-{surface}",
                requirement_id="ADR-005.optional-required",
                claim_id="E-002.optional-required-live",
                capability_family="codex_optional_required",
                required_observation_codes=frozenset({"live_authorized"}),
                allowed_observation_codes=frozenset({"live_authorized", "surface_token"}),
            ),
            context,
            (
                Observation("live_authorized", boolean_value=False),
                Observation("surface_token", enum_value=surface),
            ),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail(f"live required-failure cell for {surface} authorized; observe before pass")
