"""Generate the advice assembly and category-denial vectors for issue #1019."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from yoetz.application.observation_advice import minimized_semantic_evidence_packet
from yoetz.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    observation_advice_to_candidate_context,
)
from yoetz.domain.findings import FINDING_KIND_TRAITS, FindingKind
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ProviderBinding,
    ReviewContextProfile,
)
from yoetz.kernel.policies.observation_advice import ObservationAdviceCandidate
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)

_PATH: Final = "canonical/advice-egress-1.1.0.case.json"
_FIXTURE_ID: Final = "CAN-019"


def document() -> dict[str, JsonValue]:
    packet = canonical_encode(
        cast(
            JsonValue,
            minimized_semantic_evidence_packet(
                (
                    ObservationAdviceCandidate(
                        FindingKind.FAILED_WORK_OMITTED,
                        "failed_command_unresolved",
                        "resolve_failed_command",
                        ("hook:one",),
                        FINDING_KIND_TRAITS[FindingKind.FAILED_WORK_OMITTED][0],
                        "fixture",
                    ),
                ),
                "sha256:" + "a" * 64,
                coverage_gaps=("source_lag",),
                finding_summaries=("Recorded summary",),
            ),
        )
    )
    commitment = "hmac-sha256:" + "b" * 64
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        "ins_40000000-0000-4000-8000-000000000001",
        commitment,
        "tsk_40000000-0000-4000-8000-000000000002",
    )
    attempt = ObservationAdviceSemanticAttempt(
        "fixture-attempt",
        commitment,
        "ses_40000000-0000-4000-8000-000000000003",
        "basis",
        canonical_digest(strict_json_parse(packet)),
        ("source_lag",),
        packet,
        "running",
        1,
    )
    candidate = observation_advice_to_candidate_context(
        attempt,
        request_id="req_40000000-0000-4000-8000-000000000004",
        scope=scope,
        provider_binding=ProviderBinding(
            "fixture", "fixture/model", "fixture-external", "1.0.0", "external"
        ),
        # The recommended Assisted profile, which includes finding prose. The egress pipeline
        # refuses an advice envelope naming any profile other than the effective one (#1019 r3).
        review_context_profile=ReviewContextProfile.ASSISTED,
        include_finding_prose=True,
    )
    # The builder envelope is the golden vector; runtime tests apply the real classifier and
    # approval filter to it, with the denial expectations pinned independently below.
    return cast(
        dict[str, JsonValue],
        {
            "fixture_id": _FIXTURE_ID,
            "fixture_schema": "yoetz.fixture-case/1.0.0",
            "fixture_version": "1.0.0",
            "minimum_versions": {
                "egress_receipt_schema": "1.1.0",
                "engine": "0.3.0",
                "protocol": "0.1",
            },
            "owns_requirements": [
                "ISSUE-1019:automatic-advice-review",
                "ADR-009:category-denial-honesty",
            ],
            "purpose": "Freeze the approved advice envelope and distinguish omitted content from category denial.",
            "controls": {
                "clock": "fixture_supplied",
                "external_io": "forbidden",
                "network": "forbidden",
                "randomness": "forbidden",
            },
            "input": {
                "packet": strict_json_parse(packet),
                "candidate_items": [
                    {
                        "item_id": item.item_id,
                        "category": item.category.value,
                        "plaintext": item.plaintext.decode(),
                    }
                    for item in candidate.items
                ],
            },
            "expected": {
                "all_categories_approved": {
                    "retained_item_ids": [
                        "observation-advice-packet",
                        "observation-advice-summaries",
                    ],
                    "blocked_categories": [],
                },
                "summary_category_denied": {
                    "retained_item_ids": ["observation-advice-packet"],
                    "blocked_categories": ["finding_summary"],
                },
                "malformed_approved_envelope": {
                    "safe_failure_reason": "insufficient_approved_context",
                    "blocked_categories": [],
                },
                "request_scope_refused": {
                    "safe_failure_reason": "scope_mismatch",
                    "blocked_categories": [],
                },
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(document())
    target, manifest_path = root / "fixtures" / _PATH, root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    member = {
        "fixture_id": _FIXTURE_ID,
        "path": _PATH,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    unrelated = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == _FIXTURE_ID for item in unrelated):
        raise ValueError("fixture_identity_conflict")
    if args.check:
        if (
            not target.is_file()
            or target.read_bytes() != data
            or [item for item in manifest["members"] if item["path"] == _PATH] != [member]
        ):
            raise ValueError("advice_egress_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("advice egress fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
