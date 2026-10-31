"""#1138 (records part): a privacy-boundary refusal names its stage, item and class everywhere.

TB4 full-sol: every AI-powered review of data-anonymization and production-planning was refused
before dispatch because FinishUP's own placeholder was re-detected once the reviewer conversation
nested the packet a second time. The privacy receipt said ``prepared_case`` with no item, the
final receipt said only "not run" and "1 model exchange", and every later check sent the same
content to be refused the same way. The scanner itself is the privacy workstream's (#1248); these
cases pin the records: what refused, where, in which item, and that it is not resent unchanged.
"""

from __future__ import annotations

import json
from copy import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest

from builders.replay import replay_records
from finishup.adapters.privacy.catalog import (
    _network_receipt_from_bytes,  # pyright: ignore[reportPrivateUsage]
    _receipt_bytes,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.check import (
    _review_skip_decision,  # pyright: ignore[reportPrivateUsage]
    _semantic_evaluation,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.egress import (
    PrivacyCoordinator,
    ReviewerExchangeFrame,
    SemanticEgressBlocked,
)
from finishup.application.privacy_control import encode_privacy_receipt_view
from finishup.application.semantic_case import build_semantic_case
from finishup.cli.app import _receipt_refusal_lines  # pyright: ignore[reportPrivateUsage]
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    EvidenceDigestProvenance,
    EvidenceRecordedPayload,
    LedgerRecord,
)
from finishup.domain.privacy import (
    CredentialHeuristic,
    ForbiddenDataKind,
    PrivacyOutcome,
    PrivacyReason,
    ReceiptSecretScanStage,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.receipts import (
    SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP,
    privacy_block_sentence,
)
from finishup.domain.reviewer_reads import ReviewerRecord, render_reviewer_lines
from finishup.kernel.finding_resolution import SEMANTIC_ONLY_GAPS
from finishup.kernel.gap_effect import GAP_EFFECT_TABLE
from finishup.kernel.review_round import privacy_block_standing
from finishup.mcp.summaries import (
    _check_lead_variants,  # pyright: ignore[reportPrivateUsage]
)
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.clock import ClockPort
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ids import IdPort
from finishup.ports.ledger import CheckPhase
from finishup.ports.privacy import (
    HumanAuthorityCapability,
    NetworkEgressReceiptView,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import Deadline, decode_reviewer_exchange, encode_reviewer_exchange
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.redacted_values import SemanticRedactedValue
from finishup.protocol.schemas import validate_schema_instance
from unit.application.test_egress_origin_operation import (
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _DELIVERABLE_DIFF,  # pyright: ignore[reportPrivateUsage]
    _Audit,  # pyright: ignore[reportPrivateUsage]
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_review_privacy_labels import (
    _evaluate,  # pyright: ignore[reportPrivateUsage]
)

# The TB4 production-planning shape: a nested YAML password followed by an indented line. The
# value is replaced in place in the packet; the conversation's second encoding used to re-detect
# FinishUP's own placeholder and refuse the whole review (#1138, #1248 P-D1).
_NESTED_YAML = b"db:\n  password: hunter2\n  role: admin\n"
_EXCERPT = "excerpt-evd_10000000-0000-4000-8000-000000000001"
# A synthetic match only the reviewer-conversation scan reports, so a conversation-stage hit can
# be placed in exactly one item (or in FinishUP's frame) without a credential-shaped literal.
_PLANTED = b"conversation-only-match-4821"


class _ConversationScanEnforcer(LocalPrivacyEnforcer):
    """The shipped enforcer, whose exact-byte scan also reports ``_PLANTED`` as a heuristic.

    Classification and minimization use the module scanner, which never sees ``_PLANTED`` as a
    match, so the planted bytes reach the conversation like any unflagged content.
    """

    def scan_exact_bytes(
        self,
        data: bytes,
        *,
        credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED,
        marker_spans: tuple[tuple[int, int], ...] = (),
    ) -> tuple[ForbiddenDataKind, ...]:
        found = super().scan_exact_bytes(
            data, credential_heuristic=credential_heuristic, marker_spans=marker_spans
        )
        if credential_heuristic is CredentialHeuristic.ENFORCED and _PLANTED in data:
            return tuple(
                sorted({*found, ForbiddenDataKind.API_CREDENTIAL}, key=lambda k: k.value.encode())
            )
        return found


async def _evaluate_conversation(
    content: bytes,
    *,
    enforcer: LocalPrivacyEnforcer | None = None,
    frame_text: str = "review the packet",
) -> tuple[object, _Audit]:
    frozen, captured, scope = _captured_case_values(content)
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
        final_review=True,
    )
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store()),
        enforcer or LocalPrivacyEnforcer(),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "8" * 64, 1, "passphrase", 1, True
        ),
    )

    def render(packet: bytes) -> bytes:
        return encode_reviewer_exchange((("system", frame_text), ("user", packet.decode())))

    result = await coordinator.evaluate_semantic(
        _candidate(case),
        Deadline(datetime(2026, 10, 8, 17, 8, tzinfo=UTC), 61.0),
        exchange=ReviewerExchangeFrame("application/vnd.finishup.reviewer-final+json", render),
    )
    return result, audit


def _blocked(result: object) -> tuple[SemanticRedactedValue, ...]:
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason) == (
        PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        PrivacyReason.NEVER_SEND_DETECTED,
    )
    return tuple(item for item in result.redacted_values if item.disposition == "review_blocked")


def _prepared(result: object, audit: _Audit) -> bytes:
    # The audit fake stops at preparation: reaching it means no privacy stage refused the case.
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.AUDIT_FAILED
    assert not [item for item in result.redacted_values if item.disposition == "review_blocked"]
    (proposal,) = audit.prepared
    return proposal.minimized.prepared_bytes


@pytest.mark.anyio
async def test_the_tb4_nested_yaml_shape_reaches_the_reviewer_with_its_marker() -> None:
    # #1248 P-D1: FinishUP's own marker never produces a hit, so the conversation goes on.
    result, audit = await _evaluate_conversation(_NESTED_YAML)
    conversation = _prepared(result, audit)
    packet = json.loads(decode_reviewer_exchange(conversation)[1][1])
    (excerpt,) = [item for item in packet["items"] if item["item_id"] == _EXCERPT]
    marker = EGRESS_CREDENTIAL_PLACEHOLDER.decode()
    assert f"  password: {marker}\n  role: admin\n" in excerpt["content"]
    assert b"hunter2" not in conversation


@pytest.mark.anyio
async def test_a_conversation_hit_in_one_item_withholds_that_item_and_the_review_goes_on() -> None:
    # #1248 P-D2: the hit withholds the one item it sat in, named, and nothing else.
    content = b"notes: " + _PLANTED + b"\n"
    result, audit = await _evaluate_conversation(content, enforcer=_ConversationScanEnforcer())
    conversation = _prepared(result, audit)
    assert _PLANTED not in conversation
    assert isinstance(result, SemanticEgressBlocked)
    assert _EXCERPT in result.withheld_item_ids
    (withheld,) = [item for item in result.redacted_values if item.item_id == _EXCERPT]
    assert withheld.disposition == "item_withheld"
    (proposal,) = audit.prepared
    assert _EXCERPT in proposal.minimized.withheld_item_ids
    assert _EXCERPT not in proposal.minimized.included_item_ids
    assert proposal.minimized.included_item_ids
    # The packet the reviewer reads says the item was withheld for a credential-like value.
    packet = json.loads(decode_reviewer_exchange(conversation)[1][1])
    assert _EXCERPT not in {item["item_id"] for item in packet["items"]}
    assert "never_send_heuristic" in json.dumps(packet)


@pytest.mark.anyio
async def test_a_conversation_refusal_names_its_stage_its_item_and_its_class() -> None:
    # The same item match, now also in FinishUP's frame, which must be sent as it is: withholding
    # the item cannot clear the frame, so the whole case is refused and the item is named.
    content = b"notes: " + _PLANTED + b"\n"
    result, audit = await _evaluate_conversation(
        content,
        enforcer=_ConversationScanEnforcer(),
        frame_text="review the packet " + _PLANTED.decode(),
    )
    (blocked,) = _blocked(result)
    assert (blocked.item_id, blocked.stage, blocked.match_class) == (
        _EXCERPT,
        "reviewer_exchange",
        "heuristic",
    )
    (receipt,) = audit.receipts
    assert receipt.counts.final_bytes == 0
    scan = receipt.secret_scan
    assert scan.stage is ReceiptSecretScanStage.REVIEWER_EXCHANGE
    assert (scan.match_class, scan.match_item_ids, scan.passed) == ("heuristic", (_EXCERPT,), False)
    assert scan.match_count >= 1
    # Stored, wire and schema forms all carry it; the owner's CLI names it.
    stored = _receipt_bytes(receipt)
    assert _network_receipt_from_bytes(stored) == receipt
    view = NetworkEgressReceiptView("network_egress", receipt)
    body = cast(dict[str, JsonValue], encode_privacy_receipt_view(view)["receipt"])
    wire_scan = cast(dict[str, JsonValue], body["secret_scan"])
    assert wire_scan["stage"] == "reviewer_exchange"
    assert wire_scan["match_class"] == "heuristic"
    assert tuple(cast(tuple[str, ...], wire_scan["match_item_ids"])) == (_EXCERPT,)
    validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))
    (line,) = _receipt_refusal_lines((view,))
    assert f"reviewer_exchange scan by a heuristic match in {_EXCERPT}" in line


@pytest.mark.anyio
async def test_a_match_no_item_explains_names_the_packet_structure() -> None:
    result, audit = await _evaluate(secret_in_frame=True)
    (blocked,) = _blocked(result)
    assert (blocked.item_id, blocked.stage, blocked.match_class) == (
        "review-packet",
        "reviewer_exchange",
        "high_confidence",
    )
    (receipt,) = audit.receipts
    assert receipt.secret_scan.match_class == "high_confidence"
    assert receipt.secret_scan.match_item_ids == ()


@pytest.mark.anyio
async def test_a_classification_refusal_names_the_item_with_a_concrete_finding() -> None:
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store()),
        LocalPrivacyEnforcer(),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "8" * 64, 1, "passphrase", 1, True
        ),
    )
    result = await coordinator.evaluate_semantic(
        _candidate(_semantic_case(_DELIVERABLE_DIFF, with_aws_key=True)),
        Deadline(datetime(2026, 10, 8, 17, 8, tzinfo=UTC), 61.0),
    )
    (blocked,) = _blocked(result)
    assert (blocked.item_id, blocked.stage, blocked.match_class) == (
        _EXCERPT,
        "candidate",
        "high_confidence",
    )
    (receipt,) = audit.receipts
    assert receipt.secret_scan.stage is ReceiptSecretScanStage.CANDIDATE
    assert receipt.secret_scan.match_item_ids == (_EXCERPT,)


def test_the_blocked_entry_round_trips_and_validates_on_the_check_contract() -> None:
    blocked = SemanticRedactedValue(
        _EXCERPT,
        "review_blocked",
        (3,),
        "evd_10000000-0000-4000-8000-000000000001",
        "reviewer_exchange",
        "heuristic",
    )
    wire = blocked.as_wire()
    assert wire["stage"] == "reviewer_exchange"
    assert SemanticRedactedValue.from_wire(wire) == blocked
    with pytest.raises(ValueError):
        SemanticRedactedValue(_EXCERPT, "review_blocked", ())
    with pytest.raises(ValueError):
        SemanticRedactedValue(_EXCERPT, "value_replaced", (), None, "candidate", "heuristic")
    document = json.loads(
        __import__("importlib.resources", fromlist=["files"])
        .files("finishup.resources")
        .joinpath("schemas/operations/check-result-1.7.0.schema.json")
        .read_bytes()
    )
    value = document["$defs"]["semantic_redacted_value"]
    assert value["properties"]["disposition"]["enum"] == [
        "item_withheld",
        "review_blocked",
        "value_replaced",
    ]
    assert value["then"] == {"required": ["stage", "match_class"]}


def test_the_receipt_sentence_names_the_block_as_one() -> None:
    blocked = SemanticRedactedValue(
        _EXCERPT,
        "review_blocked",
        (3,),
        "evd_10000000-0000-4000-8000-000000000001",
        "reviewer_exchange",
        "heuristic",
    )
    sentence = privacy_block_sentence((blocked,))
    assert sentence.startswith("AI-powered review was blocked at the privacy boundary")
    assert "heuristic credential-like match in" in sentence
    assert "reviewer_exchange (reviewer conversation) scan" in sentence
    assert "will not help" in sentence
    skipped = privacy_block_sentence((blocked,), skipped=True)
    assert SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP in skipped
    unattributed = privacy_block_sentence(
        (
            SemanticRedactedValue(
                "review-packet", "review_blocked", (), None, "candidate", "high_confidence"
            ),
        )
    )
    assert "FinishUP's own packet structure (review-packet)" in unattributed
    assert "high-confidence" in unattributed
    assert "did not record which item" in privacy_block_sentence(())


def test_an_exchange_that_was_never_sent_shows_no_model_exchange_line() -> None:
    assert render_reviewer_lines(ReviewerRecord(0, (), "reviewer_exchange_not_sent", None)) == ()
    (line,) = render_reviewer_lines(ReviewerRecord(1, (), "deadline", None))
    assert "1 model exchange; ended early: deadline" in line


def test_the_mcp_check_lead_names_the_block_and_that_resending_will_not_help() -> None:
    blocked = SemanticRedactedValue(
        _EXCERPT, "review_blocked", (), None, "reviewer_exchange", "heuristic"
    ).as_wire()
    source: dict[str, JsonValue] = {
        "findings": [],
        "suppressed_count": "0",
        "semantic_redacted_values": [cast(JsonValue, blocked)],
        "coverage": {"known_gaps": []},
    }
    lead = _check_lead_variants(source, "insufficient_coverage", "blocked_forbidden_data", "x")[0]
    assert lead.startswith("AI-powered review blocked at the privacy boundary by " + _EXCERPT)
    assert "sending the same content again will not help" in lead


# -- no unchanged re-dispatch ------------------------------------------------------------------

_CHECK = next(
    record.payload
    for record in replay_records("all-event-families")
    if type(record.payload) is CheckRecordedPayload
)
_BLOCKED_VALUE = SemanticRedactedValue(
    _EXCERPT, "review_blocked", (), None, "reviewer_exchange", "heuristic"
)


def _check(
    status: SemanticStatus,
    reason: SemanticReason,
    *,
    gaps: tuple[str, ...] = (),
    final: bool = False,
) -> object:
    payload = copy(_CHECK)
    object.__setattr__(payload, "semantic_status", status)
    object.__setattr__(payload, "semantic_reason", reason)
    object.__setattr__(
        payload,
        "semantic_redacted_values",
        (_BLOCKED_VALUE,) if status is SemanticStatus.BLOCKED_FORBIDDEN_DATA else (),
    )
    object.__setattr__(payload, "coverage", SimpleNamespace(known_gaps=gaps))
    object.__setattr__(
        payload,
        "review_input_manifest",
        {"review_phase": "final" if final else "routine"},
    )
    return SimpleNamespace(schema=SimpleNamespace(name="check_recorded"), payload=payload)


def _block(*, final: bool = False) -> object:
    return _check(
        SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.NEVER_SEND_DETECTED, final=final
    )


def _edit() -> object:
    from builders.policy_cases import act

    payload = ActionRecordedPayload(act(9), ActionKind.EDIT, "x")
    return SimpleNamespace(schema=SimpleNamespace(name="action_recorded"), payload=payload)


def _evidence(provenance: EvidenceDigestProvenance | None) -> object:
    """A captured evidence row, relabelled to ``provenance`` (or unbound) past validation."""

    frozen, _captured, _scope = _captured_case_values()
    payload = copy(next(iter(frozen.projection.evidence.values())).payload)
    assert type(payload) is EvidenceRecordedPayload and payload.digest_binding is not None
    if provenance is None:
        object.__setattr__(payload, "digest_binding", None)
    else:
        binding = copy(payload.digest_binding)
        object.__setattr__(binding, "provenance", provenance)
        object.__setattr__(payload, "digest_binding", binding)
    return SimpleNamespace(schema=SimpleNamespace(name="evidence_recorded"), payload=payload)


def _standing(*records: object) -> object:
    return privacy_block_standing(cast(tuple[LedgerRecord, ...], records))


def test_an_unchanged_refusal_stands_and_a_change_ends_it() -> None:
    standing = _standing(_block())
    assert standing is not None
    assert getattr(standing, "redacted_values") == (_BLOCKED_VALUE,)
    assert getattr(standing, "final_review") is False
    # Hook-captured output leaves the refused item in place; a local-only check asks nothing.
    local = _check(SemanticStatus.NOT_REQUESTED, SemanticReason.DETERMINISTIC_MODE)
    captured = _evidence(EvidenceDigestProvenance.OBSERVATION_CAPTURED)
    assert _standing(_block(), captured, local) is not None
    # A carried refusal walks back to the refusal it carried.
    carried = _check(
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticReason.NEVER_SEND_DETECTED,
        gaps=(SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP,),
    )
    final_standing = _standing(_block(final=True), carried)
    assert final_standing is not None and getattr(final_standing, "final_review") is True
    # An edit, agent-published evidence, or a newer review outcome ends it.
    assert _standing(_block(), _edit()) is None
    assert _standing(_block(), _evidence(None)) is None
    assert _standing(_block(), _evidence(EvidenceDigestProvenance.CALLER_ASSERTED)) is None
    succeeded = _check(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
    assert _standing(_block(), succeeded) is None
    assert _standing() is None


@pytest.mark.parametrize(
    "name",
    [
        "claim_recorded",
        "decision_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "response_recorded",
    ],
)
def test_newly_published_text_ends_the_standing(name: str) -> None:
    """#966: a revision of agent-published text is composed and scanned again, never carried."""

    published = SimpleNamespace(schema=SimpleNamespace(name=name), payload=object())
    assert _standing(_block(), published) is None
    # Text published before the refusal leaves it standing.
    assert _standing(published, _block()) is not None


def test_the_skip_gap_is_a_review_only_limit() -> None:
    assert SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP in SEMANTIC_ONLY_GAPS
    assert SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP in GAP_EFFECT_TABLE


async def _review_skip_gaps(*args: Any, **kwargs: Any) -> frozenset[str]:
    """The skip gap of ``_review_skip_decision``, without the carried refusal."""

    gaps, _standing = await _review_skip_decision(*args, **kwargs)
    return gaps


def _runtime(*records: object) -> Any:
    async def load_events(session_id: object, *, through: int) -> Any:
        del session_id, through
        for record in records:
            yield record

    return SimpleNamespace(
        session_id="ses",
        task_id="tsk",
        capabilities=frozenset({RuntimeCapability.SEMANTIC}),
        ledger=SimpleNamespace(load_events=load_events),
    )


def _frozen(phase: CheckPhase = CheckPhase.LOCAL_READY) -> Any:
    return SimpleNamespace(
        case=SimpleNamespace(frontier=SimpleNamespace(sequence=10)),
        lease=SimpleNamespace(
            phase=phase,
            writer_id="wri_00000000-0000-4000-8000-000000001138",
            operation_id="req_00000000-0000-4000-8000-000000001138",
        ),
    )


def _request(mode: str = "semantic_if_configured", *, final_review: bool = False) -> Any:
    return SimpleNamespace(mode=mode, final_review=final_review, request_id="req_1138")


@pytest.mark.anyio
async def test_a_check_after_an_unchanged_refusal_skips_the_review_and_carries_it() -> None:
    runtime = _runtime(_block())
    gaps = await _review_skip_gaps(
        runtime, _request(), _frozen(), route_profile="policy", workspace_changed=True
    )
    assert gaps == frozenset({SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP})
    # Not on a local-only or strict-route check, nor for a closing review after a routine
    # refusal (it is scanned once more), nor for a check already waiting on a review.
    for request, route, frozen in (
        (_request("deterministic_only"), "policy", _frozen()),
        (_request(), "strict", _frozen()),
        (_request(final_review=True), "policy", _frozen()),
        (_request(), "policy", _frozen(CheckPhase.SEMANTIC_WAIT)),
    ):
        assert SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP not in await _review_skip_gaps(
            runtime,
            request,
            frozen,
            route_profile=cast(Literal["policy", "strict"], route),
            workspace_changed=True,
        )
    # A closing review's own refusal stands for the next closing review.
    assert await _review_skip_gaps(
        _runtime(_block(final=True)),
        _request(final_review=True),
        _frozen(),
        route_profile="policy",
        workspace_changed=True,
    ) == frozenset({SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP})
    # After an edit the review runs again.
    assert SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP not in await _review_skip_gaps(
        _runtime(_block(), _edit()),
        _request(),
        _frozen(),
        route_profile="policy",
        workspace_changed=True,
    )


@pytest.mark.anyio
async def test_the_carried_evaluation_is_the_same_block_with_nothing_composed() -> None:
    from finishup.kernel.review_round import PrivacyBlockStanding

    standing = PrivacyBlockStanding((_BLOCKED_VALUE,), False)
    evaluation = await _semantic_evaluation(
        cast(Any, None),
        _request(),
        cast(Any, None),
        cast(Any, None),
        (),
        route_profile="policy",
        privacy_block=standing,
    )
    assert (evaluation.status, evaluation.reason) == (
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticReason.NEVER_SEND_DETECTED,
    )
    assert evaluation.semantic_redacted_values == (_BLOCKED_VALUE,)
    assert evaluation.provenance is None


def test_the_final_receipt_names_a_privacy_block_as_one_on_every_rendering() -> None:
    from dataclasses import replace

    from finishup.domain.events import CheckVerdict
    from finishup.domain.receipts import (
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        ReceiptSectionKey,
        render_receipt_compact,
        render_receipt_human,
    )
    from finishup.kernel.deterministic_checks import CaseGap
    from unit.kernel.test_receipt_builder import (
        _build,  # pyright: ignore[reportPrivateUsage]
        _context,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )
    from unit.kernel.test_receipt_builder import (
        _check as _receipt_check,  # pyright: ignore[reportPrivateUsage]
    )

    gap = CaseGap(
        f"semantic_outcome:{SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP}",
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        (),
    )
    for skipped in (False, True):
        gaps = (SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,) + (
            (SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP,) if skipped else ()
        )
        coverage = _coverage(gaps=gaps)
        check = replace(
            _receipt_check(
                CheckVerdict.INSUFFICIENT_COVERAGE,
                coverage,
                semantic_redacted_values=(_BLOCKED_VALUE,),
            ),
            semantic_status=SemanticStatus.BLOCKED_FORBIDDEN_DATA,
            semantic_reason=SemanticReason.NEVER_SEND_DETECTED,
        )
        case_gaps = tuple(
            sorted(
                (gap, *(CaseGap(code, code, ()) for code in gaps[1:])),
                key=lambda item: item.marker.encode(),
            )
        )
        receipt = _build(_context(coverage=coverage, gaps=case_gaps, check=check))
        limitations = next(
            section
            for section in receipt.sections
            if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
        )
        expected = privacy_block_sentence((_BLOCKED_VALUE,), skipped=skipped)
        assert limitations.body.startswith(expected)
        assert "AI-powered relevance review was not run." not in limitations.body
        assert _EXCERPT in limitations.body
        for markdown in (True, False):
            assert expected in render_receipt_human(receipt, markdown=markdown)
        assert "blocked at the privacy boundary" in render_receipt_compact(receipt)


# -- CodeRabbit review of #1256 ------------------------------------------------------------------


def test_the_refusal_entries_survive_the_entry_bound() -> None:
    """A refusal over a full list keeps its own entries; it never sorts itself out of the bound."""

    from finishup.application.egress import (
        _blocked_redacted_values,  # pyright: ignore[reportPrivateUsage]
        _ScanBlock,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.protocol.redacted_values import MAX_SEMANTIC_REDACTED_VALUE_ITEMS

    replaced = tuple(
        SemanticRedactedValue(f"excerpt-a{index:02d}", "value_replaced", (1,))
        for index in range(MAX_SEMANTIC_REDACTED_VALUE_ITEMS)
    )
    merged = _blocked_redacted_values(
        replaced, _ScanBlock(ReceiptSecretScanStage.REVIEWER_EXCHANGE, "heuristic", ("zz-item",))
    )
    assert len(merged) == MAX_SEMANTIC_REDACTED_VALUE_ITEMS
    assert [item.item_id for item in merged] == sorted(item.item_id for item in merged)
    (blocked,) = [item for item in merged if item.disposition == "review_blocked"]
    assert (blocked.item_id, blocked.stage) == ("zz-item", "reviewer_exchange")


def test_an_exchange_whose_dispatch_failed_still_counts_as_sent() -> None:
    from finishup.application.reviewer_loop import ReviewOutcome
    from finishup.application.reviewer_run import _record  # pyright: ignore[reportPrivateUsage]

    outcome = ReviewOutcome(
        "incomplete", None, "reviewer_exchange_not_sent", (), 1, frozenset(), {}
    )
    request_id = "req_40000000-0000-4000-8000-000000001138"
    refused = SemanticEgressBlocked(
        request_id, PrivacyOutcome.BLOCKED_FORBIDDEN_DATA, PrivacyReason.NEVER_SEND_DETECTED
    )
    attempted = SemanticEgressBlocked(
        request_id,
        PrivacyOutcome.TRANSPORT_FAILED,
        PrivacyReason.OUTCOME_UNKNOWN,
        dispatch_attempted=True,
    )
    assert _record(outcome, [refused], {}, None)[0].exchanges == 0
    # The gateway was called and its outcome is unknown: the content may have been sent.
    assert _record(outcome, [attempted, refused], {}, None)[0].exchanges == 1
    with pytest.raises(ValueError):
        SemanticEgressBlocked(
            request_id,
            PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
            PrivacyReason.NEVER_SEND_DETECTED,
            dispatch_attempted=True,
        )


def test_the_replacement_line_is_only_for_replaced_or_withheld_values() -> None:
    from finishup.cli.render import (
        _semantic_redacted_value_lines,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.receipts import (
        SEMANTIC_REDACTED_VALUES_AGENT_LINE,
        SEMANTIC_REVIEW_BLOCKED_AGENT_LINE,
    )
    from finishup.mcp.summaries import (
        _semantic_redacted_values_line_part,  # pyright: ignore[reportPrivateUsage]
    )

    blocked_wire = cast(JsonValue, _BLOCKED_VALUE.as_wire())
    replaced_wire = cast(
        JsonValue, SemanticRedactedValue("excerpt-a", "value_replaced", (2,)).as_wire()
    )
    blocked_only = _semantic_redacted_value_lines((blocked_wire,))
    assert SEMANTIC_REVIEW_BLOCKED_AGENT_LINE in blocked_only
    assert SEMANTIC_REDACTED_VALUES_AGENT_LINE not in blocked_only
    mixed = _semantic_redacted_value_lines((replaced_wire, blocked_wire))
    assert SEMANTIC_REDACTED_VALUES_AGENT_LINE in mixed
    assert SEMANTIC_REVIEW_BLOCKED_AGENT_LINE in mixed
    assert SEMANTIC_REVIEW_BLOCKED_AGENT_LINE not in _semantic_redacted_value_lines(
        (replaced_wire,)
    )
    # MCP: the check lead names the refusal; the replacement line needs a replaced value.
    assert _semantic_redacted_values_line_part({"semantic_redacted_values": [blocked_wire]}) is None
    assert (
        _semantic_redacted_values_line_part(
            {"semantic_redacted_values": [blocked_wire, replaced_wire]}
        )
        is not None
    )


def test_no_rendering_claims_that_nothing_was_sent() -> None:
    """A later exchange can be refused after an earlier one was sent; only the refused is unsent."""

    sentence = privacy_block_sentence((_BLOCKED_VALUE,))
    assert "the refused content was not sent" in sentence
    assert "before anything was sent" not in sentence
    source: dict[str, JsonValue] = {
        "findings": [],
        "suppressed_count": "0",
        "semantic_redacted_values": [cast(JsonValue, _BLOCKED_VALUE.as_wire())],
        "coverage": {"known_gaps": []},
    }
    lead = _check_lead_variants(source, "insufficient_coverage", "blocked_forbidden_data", "x")[0]
    assert "the refused content was not sent" in lead
    assert "before anything was sent" not in lead


def test_the_mcp_lead_keeps_the_item_id_beside_its_ref() -> None:
    ref = "evd_10000000-0000-4000-8000-000000000001"
    blocked = SemanticRedactedValue(
        _EXCERPT, "review_blocked", (), ref, "reviewer_exchange", "heuristic"
    )
    source: dict[str, JsonValue] = {
        "findings": [],
        "suppressed_count": "0",
        "semantic_redacted_values": [cast(JsonValue, blocked.as_wire())],
        "coverage": {"known_gaps": []},
    }
    lead = _check_lead_variants(source, "insufficient_coverage", "blocked_forbidden_data", "x")[0]
    assert f"by {_EXCERPT} ({ref}, heuristic match, reviewer_exchange scan)" in lead


@pytest.mark.anyio
async def test_the_skip_and_the_carried_refusal_come_from_one_read() -> None:
    """A second read failing open would send the review the recorded gap says was skipped."""

    reads: list[int] = []
    block = _block()

    async def load_events(session_id: object, *, through: int) -> Any:
        # The round-stop read, then the privacy-block read; any further read fails open.
        del session_id, through
        reads.append(1)
        if len(reads) > 2:
            raise RuntimeError("ledger unavailable")
        yield block

    runtime = SimpleNamespace(
        session_id="ses",
        task_id="tsk",
        capabilities=frozenset({RuntimeCapability.SEMANTIC}),
        ledger=SimpleNamespace(load_events=load_events),
    )
    gaps, standing = await _review_skip_decision(
        cast(Any, runtime), _request(), _frozen(), route_profile="policy", workspace_changed=True
    )
    assert gaps == frozenset({SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP})
    assert standing is not None and standing.redacted_values == (_BLOCKED_VALUE,)
    assert len(reads) == 2
