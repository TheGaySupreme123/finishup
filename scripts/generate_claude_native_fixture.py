"""Write the reviewed Claude native child-hook capability fixture.

The fixture records installed-host evidence separately from FinishUP activation and public
workflow evidence.  The native child run uses a bounded loopback provider, so this generator
deliberately keeps the production-auth and receipt limits in the fixture (their recorded
tokens keep the frozen ``yoetz_`` spelling, ADR-048).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_PATH = _ROOT / "fixtures/agent-plugins/claude-code-cli-native-project-2.1.261.case.json"
_MANIFEST_PATH = _ROOT / "fixtures/manifest.json"
_FIXTURE_ID = "CLAUDE-261-001"


def _fixture() -> dict[str, Any]:
    return {
        "architecture": "arm64",
        "case_id": "claude-code-cli-native-project-2.1.261-macos-arm64",
        "capability_status": "native_child_hooks_bounded_proven",
        "claude_code_version": "2.1.261",
        "default_enabled": True,
        "delivery": "claude --plugin-dir (isolated evidence-only plugin)",
        "execution": "local_process",
        "format_profile": "claude_code_plugin_native",
        "host_surface": "claude_code",
        "hook_delivery": {
            "SessionStart": "delivered_success",
            "SessionEnd": "delivered_success",
            "SubagentStart": "delivered_success",
            "SubagentStop": "delivered_success",
        },
        "hook_events": [
            "PermissionDenied",
            "PostToolUse",
            "PostToolUseFailure",
            "SessionEnd",
            "SessionStart",
            "Stop",
            "SubagentStart",
            "SubagentStop",
        ],
        "native_child_probe": {
            "child_lifecycle": "started_completed",
            "child_spawn_depth": 1,
            "child_tool": "Agent",
            "payload_fields": {
                "SubagentStart": [
                    "agent_id",
                    "agent_type",
                    "cwd",
                    "hook_event_name",
                    "session_id",
                    "transcript_path",
                ],
                "SubagentStop": [
                    "agent_id",
                    "agent_transcript_path",
                    "agent_type",
                    "cwd",
                    "hook_event_name",
                    "permission_mode",
                    "session_id",
                    "transcript_path",
                ],
            },
            "provider": "bounded_loopback_anthropic_messages",
            "parent_tool_identifier": "absent_from_native_payload",
        },
        "model_use": "loopback_synthetic_only",
        "observation_evidence": "native_hook_payload_only",
        "proof_limits": [
            "loopback_provider_is_not_real_model_use",
            "native_hook_delivery_does_not_prove_yoetz_activation",
            "production_auth_unavailable_in_isolated_home",
            "yoetz_public_start_publish_check_receipt_not_reached",
            "pinned_2.1.241_profile_not_promoted_by_neighboring_version",
            "transcript_and_path_fields_are_not_correlation_proof",
        ],
        "schema": "yoetz.claude-code-host-fixture/2",
        "scope": "explicit_user",
        "yoetz_probe": {
            "mcp_runtime": "connected_before_authentication_failure",
            "model_use": "blocked_authentication",
            "production_auth": {"auth_method": "none", "logged_in": False},
        },
    }


def _refresh_manifest(data: bytes) -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    members = {str(item["path"]): item for item in manifest["members"]}
    relative = _FIXTURE_PATH.relative_to(_ROOT / "fixtures").as_posix()
    import hashlib

    members[relative] = {
        "byte_length": len(data),
        "fixture_id": _FIXTURE_ID,
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    manifest["members"] = sorted(
        members.values(), key=lambda item: str(item["path"]).encode("ascii")
    )
    _MANIFEST_PATH.write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> None:
    data = json.dumps(_fixture(), sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    _FIXTURE_PATH.write_bytes(data)
    _refresh_manifest(data)
    print(_FIXTURE_PATH)


if __name__ == "__main__":
    main()
