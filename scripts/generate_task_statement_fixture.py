"""Generate the owned task-statement vectors without modifying earlier fixture members (#908).

The case pins three contracts:

* the statement-bearing event payloads beside their frozen predecessors, as canonical bytes and
  digests (session_opened 1.1.0/1.2.0, session_resumed 1.1.0/1.2.0, plan_published and
  plan_revised 1.0.0/1.1.0);
* start request identity: a request without a statement keeps the digest it had before the field
  existed, and the statement is part of identity when present;
* the privacy-policy wire: an approval of a preset made before the ``task_statement`` section keeps
  its released 1.1.0 bytes and identity digest, and the current preset encodes as 1.2.0. The
  Expanded pair also pins the excerpt count: 16 under 1.1.0, the protocol maximum under 1.2.0
  (issue #907 Phase 1b).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.adapters.privacy.local_enforcer import estimated_token_count
from finishup.application.start import _request_digest  # pyright: ignore[reportPrivateUsage]
from finishup.domain.events import (
    ClientKind,
    EventSchema,
    IntegrationKind,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
    SessionResumedPayload,
    decode_payload,
    encode_payload,
)
from finishup.domain.privacy import EgressChannel, ReviewSelectionPolicy
from finishup.domain.values import Frontier, obligation_id
from finishup.ports.start_catalog import (
    StartCommand,
    StartIdentityCommitments,
    StartIdentityInput,
    StartMode,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import StartRequestModel

_RELATIVE = "canonical/task-statement.case.json"
_ID = "TSK-001"
_POLICY_SOURCES: tuple[tuple[str, str], ...] = (
    ("privacy/PRIV-003-minimal-external.case.json", "minimal_external"),
    ("privacy/PRIV-004-trusted-provider.case.json", "expanded"),
)
_STATEMENT = (
    "Under Ascii, Style.Truncate returns plain text without tail; Output.Truncate returns text "
    "with tail. Do not emit ANSI escapes."
)
_AMENDED = _STATEMENT + " Zero-width runes count as width 0."


def _event_vectors() -> list[dict[str, Any]]:
    frontier = Frontier(4, "sha256:" + "4" * 64)
    obligation = obligation_id("obl_90800000-0000-4000-8000-000000000001")
    opened = SessionOpenedPayload(
        "termenv truncation",
        ClientKind.COOPERATIVE_AGENT,
        "0.1.0",
        IntegrationKind.COOPERATIVE_MCP,
        RuntimeProfile.TEST_FAKE,
    )
    resumed = SessionResumedPayload(
        ClientKind.COOPERATIVE_AGENT,
        "0.1.0",
        IntegrationKind.COOPERATIVE_MCP,
        RuntimeProfile.TEST_FAKE,
        frontier,
    )
    published = PlanPublishedPayload(1, "Agent plan: truncate by display width.", (obligation,))
    revised = PlanRevisedPayload(
        2, 1, "The user amended the request.", "Agent plan: count zero-width runes.", ()
    )
    rows: list[tuple[str, str, Any]] = [
        ("session_opened", "1.1.0", opened),
        ("session_opened", "1.2.0", replace(opened, task_statement=_STATEMENT)),
        ("session_resumed", "1.1.0", resumed),
        ("session_resumed", "1.2.0", replace(resumed, task_statement=_AMENDED)),
        ("plan_published", "1.0.0", published),
        ("plan_published", "1.1.0", replace(published, task_statement=_STATEMENT)),
        ("plan_revised", "1.0.0", revised),
        ("plan_revised", "1.1.0", replace(revised, task_statement=_AMENDED)),
    ]
    vectors: list[dict[str, Any]] = []
    for family, version, payload in rows:
        encoded = encode_payload(payload)
        if decode_payload(EventSchema(family, version), encoded) != payload:
            raise ValueError("task_statement_vector_round_trip_failed")
        vectors.append(
            {
                "family": family,
                "schema_version": version,
                "carries_task_statement": payload.task_statement is not None,
                "payload": encoded,
                "canonical_hex": canonical_encode(encoded).hex(),
                "digest": canonical_digest(encoded),
            }
        )
    return vectors


def _start_identity() -> dict[str, Any]:
    title_commitment = "hmac-sha256:" + "1" * 64
    commitments: dict[str, JsonValue] = {
        "title_commitment": title_commitment,
        "workspace_ref_commitment": None,
        "external_ref_commitment": None,
    }
    repository_privacy_commitment = "hmac-sha256:" + "2" * 64
    base: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_90800000-0000-4000-8000-000000000001",
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        "mode": "create",
        "task_title": "termenv truncation",
        "requested_view": "compact",
    }
    variants: list[dict[str, Any]] = []
    for variant_id, statement in (
        ("without-statement", None),
        ("with-statement", _STATEMENT),
        ("with-amended-statement", _AMENDED),
    ):
        wire = dict(base) if statement is None else {**base, "task_statement": statement}
        request = StartRequestModel.model_validate(wire)
        command = StartCommand(
            operation_id=request.request_id,
            request_digest="sha256:" + "0" * 64,
            mode=StartMode.CREATE,
            identity_input=StartIdentityInput(task_title=request.task_title),
            identity_commitments=StartIdentityCommitments(title_commitment, None, None),
            repository_privacy_commitment=repository_privacy_commitment,
        )
        variants.append(
            {
                "variant_id": variant_id,
                "request": wire,
                "request_digest": _request_digest(request, command),
            }
        )
    return {
        "identity_commitments": commitments,
        "repository_privacy_commitment": repository_privacy_commitment,
        "variants": variants,
    }


def _privacy_policy_wire(root: Path) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    for path, key in _POLICY_SOURCES:
        source = json.loads((root / "fixtures" / path).read_bytes())
        released = decode_privacy_policy_canonical(
            canonical_encode(source["input"]["policies"][key])
        )
        for preset_version in ("1.1.0", "1.2.0"):
            policy = replace(
                released,
                review_selection=ReviewSelectionPolicy.for_profile(
                    released.review_context_profile, preset_version=preset_version
                ),
            )
            wire = encode_privacy_policy_json(policy)
            identity = {name: value for name, value in wire.items() if name != "policy_digest"}
            vectors.append(
                {
                    "source": f"{path}#/input/policies/{key}",
                    "review_context_profile": policy.review_context_profile.value,
                    "preset_version": preset_version,
                    "schema_version": wire["schema_version"],
                    "review_sections": sorted(policy.review_selection.sections),
                    "max_excerpts": policy.review_selection.max_excerpts,
                    "wire": wire,
                    "canonical_digest": canonical_digest(cast(JsonValue, wire)),
                    "identity_digest": canonical_digest(cast(JsonValue, identity)),
                }
            )
    return {"vectors": vectors}


def _privacy_policy_byte_ceiling_wire(root: Path) -> dict[str, Any]:
    """The review channel's byte ceiling at and above the pre-1.3.0 bound (#1118).

    262,144 bytes keeps the version the review selection needs; 524,288 bytes (the sized reviewer
    exchange bound, which setup now writes) is expressible only in 1.3.0. 1.3.0 inherits the
    1.2.0 presets, so a raised ceiling pairs with the current preset vocabulary only.
    """

    vectors: list[dict[str, Any]] = []
    for path, key in _POLICY_SOURCES:
        source = json.loads((root / "fixtures" / path).read_bytes())
        released = decode_privacy_policy_canonical(
            canonical_encode(source["input"]["policies"][key])
        )
        for preset_version in ("1.1.0", "1.2.0"):
            for max_bytes in (262_144, 524_288):
                if preset_version == "1.1.0" and max_bytes > 262_144:
                    continue
                policy = replace(
                    released,
                    review_selection=ReviewSelectionPolicy.for_profile(
                        released.review_context_profile, preset_version=preset_version
                    ),
                    channel_policies=tuple(
                        replace(
                            channel,
                            max_bytes=max_bytes,
                            max_tokens=estimated_token_count(max_bytes),
                        )
                        if channel.channel is EgressChannel.LLM_INFERENCE
                        else channel
                        for channel in released.channel_policies
                    ),
                )
                wire = encode_privacy_policy_json(policy)
                vectors.append(
                    {
                        "source": f"{path}#/input/policies/{key}",
                        "review_context_profile": policy.review_context_profile.value,
                        "preset_version": preset_version,
                        "llm_max_bytes": max_bytes,
                        "schema_version": wire["schema_version"],
                        "wire": wire,
                        "canonical_digest": canonical_digest(cast(JsonValue, wire)),
                    }
                )
    return {"vectors": vectors}


def document(root: Path) -> dict[str, Any]:
    identity = _start_identity()
    return {
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "fixture_id": _ID,
        "purpose": (
            "Pin the task-statement event versions, start request identity without a statement, "
            "and the privacy-policy wire before and after the task_statement section and the "
            "Expanded excerpt count, and the review channel byte ceiling above 262,144 bytes "
            "that only privacy-policy 1.3.0 expresses."
        ),
        "minimum_versions": {"fixture_contract": "1.0.0", "protocol": "1.0"},
        "owns_requirements": [
            "ISSUE-908/task-statement",
            "ISSUE-907/excerpt-count",
            "ISSUE-1118/policy-byte-ceiling",
        ],
        "controls": {
            "clock": "fixture_supplied",
            "ids": "fixture_supplied",
            "network": "forbidden",
            "external_io": "forbidden",
            "randomness": "forbidden",
        },
        "input": {
            "event_vectors": _event_vectors(),
            "start_request_identity": identity,
            "privacy_policy_wire": _privacy_policy_wire(root),
            "privacy_policy_byte_ceiling_wire": _privacy_policy_byte_ceiling_wire(root),
        },
        "expected": {
            # The digest a statement-free start had before the field existed (origin/0.3 at
            # dda53ae2); the statement joins request identity only when present.
            "statement_free_start_digest": identity["variants"][0]["request_digest"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose --write or --check")
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(document(root))
    target = root / "fixtures" / _RELATIVE
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    unrelated = [member for member in manifest["members"] if member["path"] != _RELATIVE]
    if any(member["fixture_id"] == _ID for member in unrelated):
        raise ValueError("fixture_identity_conflict")
    member = {
        "fixture_id": _ID,
        "path": _RELATIVE,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    existing = [item for item in manifest["members"] if item["path"] == _RELATIVE]
    if args.check:
        if not target.is_file() or target.read_bytes() != data or existing != [member]:
            raise ValueError("task_statement_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("task statement fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
