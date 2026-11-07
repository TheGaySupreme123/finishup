"""Own the control 2.10 workspace-binding golden vectors (ADR-051) and their manifest members.

CTL-2100 is a hello bound by a workspace locator (today's local shape), CTL-2101 a hello bound by a
workspace claim that offers a workspace agent, CTL-2102 the claim-bound hello-result, and
CTL-2103 to CTL-2105 one ``workspace_call``/``workspace_reply`` exchange per operation family
(git, reads, observation), each with an answered call and a typed non-answer, and CTL-2106 a
claim-bound ``observation_ingest`` call carrying the client's attestation (ADR-051 decision 12),
encoded by the domain codec. Every frame is
validated against the active control envelopes, and every call's arguments and reply's result
are encoded by the operation catalog, so a drift in either fails ``--check``. No vector holds a
live manifest digest, path on this machine, clock reading or random value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Final, cast

from finishup.domain.observation import (
    ObservationClientAttestation,
    ObservationClientRoute,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationSource,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
    approval_commitment,
    approved_check_result_digest,
)
from finishup.ports.change_capture import (
    ChangeMetadataEntry,
    CheckChangeMetadata,
    TaskChangeBase,
)
from finishup.ports.control import WorkspaceCall, WorkspaceReply
from finishup.ports.workspace_agent import (
    WORKSPACE_OPERATION_CATALOG,
    WORKSPACE_OPERATION_NAMES,
    ApprovedCheckRun,
    CaptureMetadataArguments,
    OpenWorkspaceArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    outcome_for_reason,
    workspace_handle_for_claim,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    workspace_call_frame,
    workspace_reply_frame,
)

_MANIFEST_RELATIVE: Final = Path("fixtures/manifest.json")
_MEDIA_TYPE: Final = "application/vnd.yoetz.fixture-case+json"
_CONTROL_SCHEMA: Final = "2.10.0"
_SERVICE_INSTANCE_ID: Final = "svc_00000000-0000-4000-8000-000000000210"
# A fixed, well-formed digest: the vectors pin frame shapes, not one installation's manifest.
_MANIFEST_DIGEST: Final = "sha256:" + "5" * 64
_NONCE: Final = "1f" * 32
_CLAIM_DIGEST: Final = "sha256:" + "c1a1" * 16
_WORKTREE_DIGEST: Final = "sha256:" + "d2b2" * 16
_COMMITMENT: Final = "hmac-sha256:" + "0a1b2c3d4e5f6071" + "8" * 48
_HANDLE: Final = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_DIGEST)
_REMOTE: Final = "rws_" + "2" * 32
_SHA_STATE: Final = "sha256:" + "3" * 64
_CONTROLS: Final = {
    "clock": "fixture_supplied",
    "external_io": "forbidden",
    "network": "forbidden",
    "randomness": "fixture_supplied",
}
_MINIMUM_VERSIONS: Final = {
    "control_schema": _CONTROL_SCHEMA,
    "fixture_contract": "1.0.0",
    "protocol": "1.0",
}


def _rpc(sequence: int) -> str:
    return f"rpc_00000000-0000-4000-8000-{sequence:012x}"


def _frame_facts(frame: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Validate one frame against the active envelopes and record its canonical identity."""

    payload = canonical_encode(frame)
    if canonical_encode(decode_control_frame(encode_control_frame(frame))) != payload:
        raise ValueError("fixture_frame_not_round_trip")
    return {
        "canonical_byte_length": len(payload),
        "canonical_hex": payload.hex(),
        "canonical_sha256": canonical_digest(frame),
    }


def _hello(**extra: JsonValue) -> dict[str, JsonValue]:
    return {
        "client_kind": "mcp_bridge",
        "client_version": "0.3.0",
        "connection_nonce": _NONCE,
        "presentation_context": {
            "output_is_controlling_tty": False,
            "render_mode": "machine_readable",
        },
        "protocol_version": "1.0",
        "schema_manifest_digest": _MANIFEST_DIGEST,
        **extra,
    }


def _hello_result() -> dict[str, JsonValue]:
    status: dict[str, JsonValue] = {
        "capabilities": ["workflow"],
        "protocol_version": "1.0",
        "service_generation": "1",
        "service_instance_id": _SERVICE_INSTANCE_ID,
        "service_version": "0.3.0",
        "session_monitor": "unavailable",
        "state": "ready",
        "state_reason": "none",
        "vault_mode": "os_keyring",
    }
    return {
        "allowed_methods": ["check", "publish_work", "receipt", "respond", "start", "status"],
        "protocol_version": "1.0",
        "schema_manifest_digest": _MANIFEST_DIGEST,
        "service_generation": "1",
        "service_instance_id": _SERVICE_INSTANCE_ID,
        "service_version": "0.3.0",
        "status": status,
        "workspace_binding": "client_claim",
        "workspace_handle": _HANDLE,
    }


def _call(sequence: int, operation: WorkspaceOperation, arguments: object) -> WorkspaceCall:
    spec = WORKSPACE_OPERATION_CATALOG[operation]
    return WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=_rpc(sequence),
        service_instance_id=_SERVICE_INSTANCE_ID,
        service_generation="1",
        operation=operation.value,
        arguments=cast(Any, spec.encode_arguments(arguments)),
        deadline_ms=5_000,
    )


def _answered(call: WorkspaceCall, result: object) -> WorkspaceReply:
    spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation(call.operation)]
    return WorkspaceReply(
        kind="workspace_reply",
        protocol_version="1.0",
        call_id=call.call_id,
        outcome="ok",
        result=spec.encode_result(result),
        reason=None,
    )


def _declined(call: WorkspaceCall, reason: str) -> WorkspaceReply:
    return WorkspaceReply(
        kind="workspace_reply",
        protocol_version="1.0",
        call_id=call.call_id,
        outcome=outcome_for_reason(reason),
        result=None,
        reason=reason,
    )


def _exchange(vector_id: str, call: WorkspaceCall, reply: WorkspaceReply) -> dict[str, Any]:
    return {
        "call": workspace_call_frame(call),
        "reply": workspace_reply_frame(reply),
        "vector_id": vector_id,
    }


def _git_exchanges() -> list[dict[str, Any]]:
    metadata = _call(
        0x2103_01,
        WorkspaceOperation.CAPTURE_METADATA,
        CaptureMetadataArguments(_HANDLE, TaskChangeBase("sha1", "a" * 40)),
    )
    listing = CheckChangeMetadata(
        base="task_start",
        entries=(
            ChangeMetadataEntry("M", "src/app.py"),
            ChangeMetadataEntry("R", "src/new_name.py", False, "src/old_name.py"),
            ChangeMetadataEntry("??", "notes/draft.md", True),
        ),
        tracked_files=2,
        untracked_files=1,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )
    base = _call(0x2103_02, WorkspaceOperation.READ_TASK_BASE, WorkspaceOnlyArguments(_HANDLE))
    return [
        _exchange("git-capture-metadata-answered", metadata, _answered(metadata, listing)),
        _exchange("git-task-base-not-git", base, _declined(base, "not_git")),
    ]


def _reads_exchanges() -> list[dict[str, Any]]:
    text = _call(
        0x2104_01,
        WorkspaceOperation.READ_TEXT_BENEATH,
        ReadTextBeneathArguments("/srv/dev/project", "src/app.py", ("/srv/dev/.finishup",)),
    )
    outside = _call(
        0x2104_02,
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        ReadOutsideInputsArguments(("/srv/shared/data",), ("/etc/hosts",), 4),
    )
    return [
        _exchange(
            "reads-text-beneath-answered",
            text,
            _answered(text, (b"print('hello')\n", 15)),
        ),
        _exchange("reads-outside-not-admitted", outside, _declined(outside, "root_not_admitted")),
    ]


def _observation_exchanges() -> list[dict[str, Any]]:
    opened = _call(
        0x2105_01,
        WorkspaceOperation.OPEN_WORKSPACE,
        OpenWorkspaceArguments(_HANDLE, True),
    )
    argv = ("pytest", "-q")
    approval = ApprovedCheckApproval(
        approval_id="unit",
        argv=argv,
        allow_network=False,
        timeout_seconds=30.0,
        approval_commitment=approval_commitment("unit", argv, allow_network=False),
    )
    output = b"2 passed\n"
    output_digest = "sha256:" + hashlib.sha256(output).hexdigest()
    result = ApprovedCheckResult(
        status=ApprovedCheckStatus.PASSED,
        outcome=ApprovedCheckOutcome.SUCCESS,
        exit_status=0,
        output_digest=output_digest,
        output_bytes=len(output),
        subject_state_digest=_SHA_STATE,
        approval_commitment=approval.approval_commitment,
        result_digest=approved_check_result_digest(
            ApprovedCheckStatus.PASSED,
            ApprovedCheckOutcome.SUCCESS,
            0,
            output_digest,
            len(output),
            _SHA_STATE,
            approval.approval_commitment,
            812,
        ),
        duration_ms=812,
    )
    check = _call(
        0x2105_02,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(_REMOTE, approval, _SHA_STATE, _SHA_STATE),
    )
    refused = _call(
        0x2105_03,
        WorkspaceOperation.RUN_APPROVED_CHECK,
        RunApprovedCheckArguments(_REMOTE, approval, _SHA_STATE),
    )
    return [
        _exchange("observation-open-workspace-answered", opened, _answered(opened, _REMOTE)),
        _exchange(
            "observation-approved-check-answered",
            check,
            _answered(check, ApprovedCheckRun(result, output, False)),
        ),
        _exchange(
            "observation-approved-check-not-approved",
            refused,
            _declined(refused, "check_not_approved"),
        ),
    ]


def _attested_ingest() -> dict[str, JsonValue]:
    """A claim-bound hook row with the client's attestation; the commitments are the client's."""

    session = "hmac-sha256:" + "5e" * 32
    request = ObservationIngestRequest(
        codex_session_id="claude-session-2106",
        envelope=ObservationEnvelope(
            session_commitment=session,
            event_kind="PostToolUse",
            source_identity="hook:claude-session-2106:1",
            source=ObservationSource.CLAUDE_HOOK,
            cursor=ObservationCursor(1, 0, 1, session, "claude-code-hooks-ordinary-v2"),
            receipt_time=Timestamp("2026-11-05T12:00:00.000Z"),
            structural_payload=JsonObject({}),
            content_object_refs=(),
            gap_codes=(),
        ),
        client_attestation=ObservationClientAttestation(
            consent="active",
            granted_at=Timestamp("2026-11-05T11:00:00.000Z"),
            content_capture_profiles=("claude-code-ordinary-observation-v1",),
            authority_generation="sha256:" + "a6" * 32,
            check_policy_digest="sha256:" + "c4" * 32,
            route=ObservationClientRoute(
                task_id="tsk_00000000-0000-4000-8000-000000002106",
                session_id="ses_00000000-0000-4000-8000-000000002106",
                writer_id="wri_00000000-0000-4000-8000-000000002106",
            ),
        ),
    )
    return {
        "body": cast(JsonValue, observation_ingest_request_to_json(request)),
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": _rpc(2106),
        "service_generation": "1",
        "service_instance_id": _SERVICE_INSTANCE_ID,
    }


def _single_frame_fixture(
    fixture_id: str,
    schema_name: str,
    frame: dict[str, JsonValue],
    requirement: str,
    purpose: str,
) -> dict[str, Any]:
    return {
        "controls": _CONTROLS,
        "expected": {"schema_name": schema_name, **_frame_facts(frame)},
        "fixture_id": fixture_id,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"frame": frame},
        "minimum_versions": _MINIMUM_VERSIONS,
        "owns_requirements": ["ADR-051", requirement],
        "purpose": purpose,
    }


def _exchange_fixture(
    fixture_id: str, family: str, exchanges: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "controls": _CONTROLS,
        "expected": {
            "family": family,
            "vectors": [
                {
                    "call": _frame_facts(item["call"]),
                    "reply": _frame_facts(item["reply"]),
                    "vector_id": item["vector_id"],
                }
                for item in exchanges
            ],
        },
        "fixture_id": fixture_id,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"vectors": exchanges},
        "minimum_versions": _MINIMUM_VERSIONS,
        "owns_requirements": ["ADR-051", f"ADR-051:workspace-agent-{family}"],
        "purpose": (
            f"Freeze one answered and one declined workspace-agent exchange of the {family} "
            "family on control 2.10: catalog-encoded arguments and result, and a closed reason."
        ),
    }


def _fixtures() -> tuple[tuple[str, str, dict[str, Any]], ...]:
    return (
        (
            "CTL-2100",
            "canonical/control-hello-locator-2.10.case.json",
            _single_frame_fixture(
                "CTL-2100",
                "control-hello",
                _hello(workspace_locator={"path": "/srv/dev/project", "schema_version": "1.0.0"}),
                "ADR-051:locator-hello-unchanged",
                "A hello bound by a workspace locator keeps its pre-2.10 members on control 2.10.",
            ),
        ),
        (
            "CTL-2101",
            "canonical/control-hello-claim-2.10.case.json",
            _single_frame_fixture(
                "CTL-2101",
                "control-hello",
                _hello(
                    workspace_agent={
                        "max_reply_bytes": 6_291_456,
                        "operations": list(WORKSPACE_OPERATION_NAMES),
                        "schema_version": "1.0.0",
                    },
                    workspace_claim={
                        "digest": _CLAIM_DIGEST,
                        "identity_kind": "git_common_root",
                        "schema_version": "1.0.0",
                        "worktree": _WORKTREE_DIGEST,
                    },
                ),
                "ADR-051:workspace-claim-hello",
                (
                    "A hello names its workspace by a keyed claim and its worktree by a keyed "
                    "digest, never a path, and offers an agent."
                ),
            ),
        ),
        (
            "CTL-2102",
            "canonical/control-hello-result-claim-2.10.case.json",
            _single_frame_fixture(
                "CTL-2102",
                "control-hello-result",
                _hello_result(),
                "ADR-051:claim-hello-result",
                "A claim-bound session's answer names its binding and its worktree's handle.",
            ),
        ),
        (
            "CTL-2103",
            "canonical/control-workspace-git-2.10.case.json",
            _exchange_fixture("CTL-2103", "git", _git_exchanges()),
        ),
        (
            "CTL-2104",
            "canonical/control-workspace-reads-2.10.case.json",
            _exchange_fixture("CTL-2104", "reads", _reads_exchanges()),
        ),
        (
            "CTL-2105",
            "canonical/control-workspace-observation-2.10.case.json",
            _exchange_fixture("CTL-2105", "observation", _observation_exchanges()),
        ),
        (
            "CTL-2106",
            "canonical/control-observation-ingest-attested-2.10.case.json",
            _single_frame_fixture(
                "CTL-2106",
                "control-request",
                _attested_ingest(),
                "ADR-051:observation-client-attestation",
                (
                    "A claim-bound observation_ingest carries the client's own consent, content "
                    "fence, trusted policy digest and mapped route, and no path."
                ),
            ),
        ),
    )


def _rendered() -> tuple[dict[Path, bytes], bytes]:
    root = Path(__file__).resolve().parents[1]
    files: dict[Path, bytes] = {}
    manifest = json.loads((root / _MANIFEST_RELATIVE).read_bytes())
    members = list(manifest["members"])
    owned = {path for _, path, _ in _fixtures()}
    owned_ids = {fixture_id for fixture_id, _, _ in _fixtures()}
    kept = [item for item in members if item["path"] not in owned]
    if any(item["fixture_id"] in owned_ids for item in kept):
        raise ValueError("fixture_id_already_owned")
    for fixture_id, path, document in _fixtures():
        data = canonical_encode(cast(JsonValue, document))
        files[root / "fixtures" / path] = data
        kept.append(
            {
                "byte_length": len(data),
                "fixture_id": fixture_id,
                "media_type": _MEDIA_TYPE,
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    manifest["members"] = sorted(kept, key=lambda item: str(item["path"]).encode())
    return files, json.dumps(manifest).encode() + b"\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    files, manifest = _rendered()
    manifest_path = root / _MANIFEST_RELATIVE
    if args.write:
        for path, data in files.items():
            path.write_bytes(data)
        manifest_path.write_bytes(manifest)
        print("control handshake fixtures written")
        return 0
    stale = [
        path.relative_to(root).as_posix()
        for path, data in files.items()
        if not path.exists() or path.read_bytes() != data
    ]
    if manifest_path.read_bytes() != manifest:
        stale.append(_MANIFEST_RELATIVE.as_posix())
    if stale:
        print("control handshake fixtures are stale:", file=sys.stderr)
        for item in stale:
            print(f"  {item}", file=sys.stderr)
        return 1
    print("control handshake fixtures and manifest are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
