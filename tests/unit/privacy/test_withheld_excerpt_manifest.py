"""#979: a withheld evidence excerpt keeps the review input manifest valid and ``review_phase``.

TB4 tb4v2 (pretrain-shard-corruption): partial redaction withheld one evidence excerpt of a closing
review, the check recorded ``semantic_provider_input_manifest_invalid``, and the review was not
recorded as ``final``. The prior-finding case of the same defect is pinned in
``test_semantic_case_prior_findings``; these cases pin the evidence-excerpt one end to end: the
minimized packet, the same packet inside the reviewer conversation (#1118, the production path),
and the phase the check records.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.check import _review_phase  # pyright: ignore[reportPrivateUsage]
from finishup.application.reviewer_run import reviewer_catalog, reviewer_first_exchange
from finishup.application.semantic_case import (
    build_semantic_case,
    review_packet_disclosure_result,
)
from finishup.domain.privacy import (
    PrivacyDecision,
    PrivacyOutcome,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.ports.semantic import reviewer_packet_bytes
from finishup.protocol.canonical import JsonValue, strict_json_parse
from unit.application.test_egress_origin_operation import (
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
)

# A launcher log whose last line holds a credential-like assignment: the heuristic flags the item.
_LAUNCHER_OUTPUT = b"launcher: shard 7 verified\nbot_token = x9Fq2LmZ7vRt4KpW8sYd3NcB6hJe1QaU\n"
_EXCERPT = "excerpt-evd_10000000-0000-4000-8000-000000000001"


def _withheld_packet(*, final: bool) -> bytes:
    frozen, captured, scope = _captured_case_values(_LAUNCHER_OUTPUT)
    case = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
        final_review=final,
    )
    enforcer = LocalPrivacyEnforcer()
    policy = _Store()._policy  # pyright: ignore[reportPrivateUsage]
    classified = enforcer.classify(
        _candidate(case), EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    )
    flagged = {item.candidate.item_id for item in classified.items if item.heuristic_findings}
    assert _EXCERPT in flagged
    # The excerpt is not approved, so minimization withholds it whole (never_send_heuristic).
    approved = tuple(
        sorted(
            item.candidate.item_id
            for item in classified.items
            if item.candidate.item_id != _EXCERPT
        )
    )
    minimized = enforcer.minimize_and_scan(
        classified, PrivacyDecision(approved, (), PrivacyOutcome.COMPLETED, None)
    )
    assert minimized.withheld_item_ids == (_EXCERPT,)
    assert b"x9Fq2LmZ7vRt4KpW8sYd3NcB6hJe1QaU" not in minimized.prepared_bytes
    return minimized.prepared_bytes


def _manifest(packet: bytes) -> dict[str, JsonValue]:
    document = cast(dict[str, JsonValue], strict_json_parse(packet))
    review_packet = cast(dict[str, JsonValue], document["review_packet"])
    omissions = cast(list[dict[str, JsonValue]], review_packet["omissions"])
    assert any(row.get("reason") == "never_send_heuristic" for row in omissions)
    return cast(dict[str, JsonValue], review_packet["provider_input_manifest"])


@pytest.mark.parametrize("final", (True, False))
def test_a_withheld_excerpt_keeps_the_manifest_valid_and_its_phase(final: bool) -> None:
    packet = _withheld_packet(final=final)
    result = review_packet_disclosure_result(packet)
    assert result.failure is None
    assert result.disclosure is not None
    assert result.disclosure.provider_input_manifest is not None
    # The provider-bound view keeps exactly the phase the composed case named.
    document = cast(dict[str, JsonValue], strict_json_parse(packet))
    composed = cast(dict[str, JsonValue], document["review_packet"])["review_input_manifest"]
    phase = cast(dict[str, JsonValue], composed)["review_phase"]
    assert phase in {"final", "routine"}
    assert _manifest(packet)["review_phase"] == phase
    if final:
        assert phase == "final"
    # The section names the loss in its closed vocabulary, never the packet row's own reason.
    evidence = cast(dict[str, JsonValue], _manifest(packet)["caller_evidence"])
    assert evidence["status"] == "withheld"
    assert cast(list[JsonValue], evidence["omitted_refs"]) == [
        "evd_10000000-0000-4000-8000-000000000001"
    ]
    reasons = cast(list[JsonValue], evidence["omission_reasons"])
    assert reasons == ["redacted_never_send"]


def test_the_same_packet_inside_the_reviewer_conversation_reads_the_same() -> None:
    packet = _withheld_packet(final=True)
    conversation = reviewer_first_exchange(packet, reviewer_catalog((), 0))
    carried = reviewer_packet_bytes(conversation)
    assert carried is not None and carried == packet
    result = review_packet_disclosure_result(carried)
    assert result.failure is None
    assert result.disclosure is not None
    manifest = result.disclosure.provider_input_manifest
    assert manifest is not None and manifest.get("review_phase") == "final"


def test_the_check_records_the_phase_the_packet_named() -> None:
    from finishup.application.semantic_case import (
        _decode_review_input_manifest,  # pyright: ignore[reportPrivateUsage]
    )

    packet = _withheld_packet(final=True)
    document = cast(dict[str, JsonValue], strict_json_parse(packet))
    composed = cast(dict[str, JsonValue], document["review_packet"])["review_input_manifest"]
    manifest = _decode_review_input_manifest(composed, expected_phase="composed")
    assert manifest is not None and manifest.review_phase == "final"
    request = SimpleNamespace(final_review=False)
    frozen = cast(Any, SimpleNamespace(case=SimpleNamespace(projection=None)))
    evaluation = cast(Any, SimpleNamespace(review_input_manifest=manifest))
    # The recorded phase comes from the manifest, never re-derived from the request.
    assert _review_phase(cast(Any, request), frozen, evaluation) == "final"
