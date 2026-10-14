"""The task statement reaches the AI-powered reviewer apart from the agent's plan (issue #908).

These tests use the termenv, superjson and koota requirements from the DeepSWE v2 post-mortem.
Each one pins what the packet carries, how it is labelled, and what the check and receipt
disclose when the statement cannot be sent.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.policy_cases import (
    clm,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
)
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.check import validate_semantic_judgment
from yoetz.application.semantic_case import (
    MAX_TASK_STATEMENT_ITEM_BYTES,
    TASK_STATEMENT_ITEM_ID,
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    review_input_manifest,
    review_packet_disclosure,
    review_packet_disclosure_result,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
)
from yoetz.domain.findings import (
    FindingKind,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ClassifiedContext,
    ClassifiedContextItem,
    DataClass,
    PrivacyDecision,
    PrivacyOutcome,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.receipts import (
    SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
)
from yoetz.domain.task_statement import (
    TASK_STATEMENT_GAPS,
    TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    TASK_STATEMENT_NOT_SUPPLIED_GAP,
    TASK_STATEMENT_UNAVAILABLE_GAP,
    RecordedTaskStatement,
)
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.semantic import ReviewerChallenge, ReviewOmission, SemanticCase, SemanticJudgment
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.models import DataCategory, SemanticReason, SemanticStatus

_TERMENV_STATEMENT = (
    "Add preserve-resets and ANSI-safe truncation to termenv. Add Style.Truncate(int, "
    "TruncateOptions) string and Output.Truncate(string, int, TruncateOptions) string. "
    "Unicode widths apply (wide runes=2, U+200B=0). Under Ascii, Style.Truncate returns plain "
    "text without tail; Output.Truncate returns text with tail; no ANSI emitted.\n"
    "Use Yoetz throughout this task."
)
_TERMENV_PLAN = (
    "Implement ANSI tokenization and width-safe truncation, integrate preserve-resets across "
    "termenv styles/output/templates, test, review, and commit on a branch from main."
)
_ASCII_RULE = "Under Ascii, Style.Truncate returns plain text without tail"
_STATEMENT_EVENT = 50
_PLAN_LABEL = "agent plan (the agent's own summary)"
_STATEMENT_LABEL = (
    "task statement: what the user asked for; the source field says who supplied the text"
)


def _statement(
    text: str = _TERMENV_STATEMENT, *, number: int = _STATEMENT_EVENT
) -> RecordedTaskStatement:
    return RecordedTaskStatement(
        text=text,
        source_event_id=evt(number),
        source_family="session_opened",
        ingestion_sequence=number,
    )


def _case(
    *,
    statement: RecordedTaskStatement | None = None,
    title: str | None = "termenv preserve resets",
    plan: PlanPublishedPayload | PlanRevisedPayload | None = None,
) -> DeterministicCase:
    plan_payload = plan or PlanPublishedPayload(1, _TERMENV_PLAN, (obl(1),))
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Ship ANSI-safe truncation", "go test ./...", ObligationStatus.OPEN
        ),
        2,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Truncation is implemented and tested.",
            (),
            obligation_refs=(obl(1),),
        ),
        3,
    )
    extra = (clm(1), obl(1)) if statement is None else (clm(1), obl(1), statement.source_event_id)
    case = make_case(
        plans={plan_payload.plan_version: plan_record(plan_payload, 1)},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        extra_refs=extra,
    )
    return replace(case, task_statement=statement, task_title=title)


def _build(
    case: DeterministicCase,
    profile: ReviewContextProfile = ReviewContextProfile.ASSISTED,
    *,
    selection: ReviewSelectionPolicy | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_90800000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection or ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_90800000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _packet(semantic: SemanticCase) -> dict[str, JsonValue]:
    payload = semantic_case_to_prepared_payload(
        semantic, frozenset(item.item_id for item in semantic.items)
    )
    return cast(dict[str, JsonValue], strict_json_parse(payload))


def _items(packet: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    return cast(list[dict[str, JsonValue]], packet["items"])


def _statement_content(semantic: SemanticCase) -> dict[str, JsonValue]:
    item = next(item for item in semantic.items if item.section == "task_statement")
    return cast(dict[str, JsonValue], strict_json_parse(item.content))


def test_agent_statement_is_its_own_labelled_section_with_the_exact_ascii_rule() -> None:
    semantic = _build(_case(statement=_statement()))

    assert semantic.packet.task_statement_item_ids == (TASK_STATEMENT_ITEM_ID,)
    item = next(item for item in semantic.items if item.item_id == TASK_STATEMENT_ITEM_ID)
    assert item.section == "task_statement"
    assert item.category is DataCategory.TASK_DESCRIPTION
    assert item.source_ref == str(evt(_STATEMENT_EVENT))
    content = _statement_content(semantic)
    assert content["source"] == "agent_transcribed"
    assert content["statement"] == _TERMENV_STATEMENT
    assert content["elided_bytes"] == 0
    # A supplied statement leaves no task-statement gap on the packet the reviewer reads.
    assert not {
        TASK_STATEMENT_UNAVAILABLE_GAP,
        TASK_STATEMENT_NOT_SUPPLIED_GAP,
        TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    } & set(semantic.packet.coverage.known_gaps)

    packet = _packet(semantic)
    statement_rows = [row for row in _items(packet) if row["section"] == "task_statement"]
    assert len(statement_rows) == 1
    assert statement_rows[0]["label"] == _STATEMENT_LABEL
    assert _ASCII_RULE in cast(str, statement_rows[0]["content"])
    review_packet = cast(dict[str, JsonValue], packet["review_packet"])
    assert review_packet["task_statement_item_ids"] == [TASK_STATEMENT_ITEM_ID]
    # The source event is citable, so a reviewer can name the requirement a plan omits.
    assert str(evt(_STATEMENT_EVENT)) in cast(list[JsonValue], packet["citable_refs"])


def test_plan_item_is_the_agent_plan_and_never_carries_the_statement() -> None:
    revised = PlanRevisedPayload(
        2,
        1,
        "The user amended the request.",
        _TERMENV_PLAN,
        (),
        task_statement=_TERMENV_STATEMENT,
    )
    semantic = _build(_case(statement=_statement(), plan=revised))
    packet = _packet(semantic)

    goal_rows = [row for row in _items(packet) if row["section"] == "goal"]
    assert len(goal_rows) == 1
    assert goal_rows[0]["label"] == _PLAN_LABEL
    plan_content = cast(str, goal_rows[0]["content"])
    assert "task_statement" not in plan_content
    assert _ASCII_RULE not in plan_content
    # No item derived from a plan is labelled as the task statement, and the plan revision's
    # statement is not repeated in any timeline row.
    for row in _items(packet):
        if row["section"] != "task_statement":
            assert row.get("label") != _STATEMENT_LABEL
            assert _ASCII_RULE not in cast(str, row["content"])
    assert [row["section"] for row in _items(packet)].count("task_statement") == 1


def test_omitted_requirement_travels_so_a_challenge_can_cite_the_statement() -> None:
    """superjson: the plan omits a stated requirement; the reviewer's challenge cites it."""

    statement = _statement(
        "`deep` keeps causes recursively up to `maxCauseDepth`; omitted defaults to `16`. "
        "If `maxCauseDepth` is present but not an integer, fall back to `includeCauses=none`."
    )
    case = _case(statement=statement)
    semantic = _build(case)
    packet = _packet(semantic)
    assert "fall back to `includeCauses=none`" in cast(
        str, next(row for row in _items(packet) if row["section"] == "task_statement")["content"]
    )

    challenge = ReviewerChallenge(
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        "Stated maxCauseDepth fallback is not implemented",
        tuple(sorted((str(clm(1)), str(statement.source_event_id)), key=str.encode)),
        "The task statement requires falling back to includeCauses=none for a non-integer "
        "maxCauseDepth; the completion claim does not cover it.",
        "The fallback may exist in code the packet does not show.",
        "Main agent: implement the stated fallback or show where it is handled.",
        "act",
        "The diff was not supplied.",
    )
    provenance = SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake-provider",
        endpoint_profile_version="1.0.0",
        model="fake/scripted-v1",
        sdk_version="0.0.0",
        prompt_digest="sha256:" + "1" * 64,
        schema_digest="sha256:" + "2" * 64,
        policy_digest="sha256:" + "3" * 64,
        privacy_policy_digest="sha256:" + "3" * 64,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_90800000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_90800000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        egress_authorization_id="aut_90800000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "4" * 64,
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (challenge,)),
        provenance,
        expected_frontier=case.frontier,
    )
    assert review.rejected_by_reason == ()
    [candidate] = review.candidates
    assert str(statement.source_event_id) in candidate.subject_refs


def test_legacy_approval_never_widens_to_the_statement() -> None:
    """An approval that predates the section sends nothing and says why (criterion 7)."""

    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.ASSISTED, preset_version="1.1.0"
    )
    assert "task_statement" not in legacy.sections
    semantic = _build(_case(statement=_statement()), selection=legacy)

    assert semantic.packet.task_statement_item_ids == ()
    assert all(item.section != "task_statement" for item in semantic.items)
    assert all(_ASCII_RULE.encode() not in item.content for item in semantic.items)
    gaps = set(semantic.packet.coverage.known_gaps)
    assert {TASK_STATEMENT_UNAVAILABLE_GAP, TASK_STATEMENT_NOT_AUTHORIZED_GAP} <= gaps
    assert TASK_STATEMENT_NOT_SUPPLIED_GAP not in gaps

    candidate = semantic_case_to_candidate_context(
        semantic,
        request_id="req_90800000-0000-4000-8000-000000000001",
        scope=AuthorizationScope(
            AuthorizationScopeKind.MACHINE, "ins_90800000-0000-4000-8000-000000000001"
        ),
        provider_binding=ProviderBinding(
            "fake", "fake-model", "fake-provider", "1.0.0", "external"
        ),
    )
    assert all(_ASCII_RULE.encode() not in item.plaintext for item in candidate.items)

    approved = _build(_case(statement=_statement()))
    assert approved.packet.task_statement_item_ids == (TASK_STATEMENT_ITEM_ID,)


def test_structural_never_sends_the_statement() -> None:
    semantic = _build(_case(statement=_statement()), ReviewContextProfile.STRUCTURAL)
    assert semantic.packet.task_statement_item_ids == ()
    assert {TASK_STATEMENT_UNAVAILABLE_GAP, TASK_STATEMENT_NOT_AUTHORIZED_GAP} <= set(
        semantic.packet.coverage.known_gaps
    )
    # A withheld section is the one reason, whether or not a statement was recorded.
    unrecorded = _build(_case(statement=None), ReviewContextProfile.STRUCTURAL)
    assert unrecorded.packet.task_statement_item_ids == ()
    assert set(unrecorded.packet.coverage.known_gaps) & TASK_STATEMENT_GAPS == {
        TASK_STATEMENT_UNAVAILABLE_GAP,
        TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    }


def test_title_is_the_labelled_fallback_and_absence_is_an_explicit_gap() -> None:
    titled = _build(_case(statement=None, title="koota entity snapshot rollback"))
    content = _statement_content(titled)
    assert content["source"] == "task_title_only"
    assert content["statement"] == "koota entity snapshot rollback"
    # The source label discloses the stand-in; no coverage gap is added for it.
    assert not set(titled.packet.coverage.known_gaps) & TASK_STATEMENT_GAPS

    bare = _build(_case(statement=None, title=None))
    assert bare.packet.task_statement_item_ids == ()
    assert set(bare.packet.coverage.known_gaps) & TASK_STATEMENT_GAPS == {
        TASK_STATEMENT_UNAVAILABLE_GAP,
        TASK_STATEMENT_NOT_SUPPLIED_GAP,
    }


@pytest.mark.parametrize("filler", ["x", "é", '"'])
def test_long_statement_keeps_head_and_tail_and_marks_the_elision(filler: str) -> None:
    head = "HEAD: the user's goal comes first. "
    tail = " TAIL: Under Ascii, Style.Truncate returns plain text without tail."
    text = head + filler * 40_000 + tail
    semantic = _build(_case(statement=_statement(text)))

    item = next(item for item in semantic.items if item.section == "task_statement")
    assert item.content_bytes <= MAX_TASK_STATEMENT_ITEM_BYTES
    content = _statement_content(semantic)
    statement = cast(str, content["statement"])
    assert statement.startswith(head)
    assert statement.endswith(tail)
    elided = cast(int, content["elided_bytes"])
    assert elided > 0
    assert f"[... {elided} bytes elided ...]" in statement
    assert content["statement_bytes"] == len(text.encode("utf-8"))
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP in semantic.packet.coverage.known_gaps
    assert semantic.packet.input_manifest is not None
    assert semantic.packet.input_manifest.specification.status == "partial"


def test_per_check_manifest_binds_specification_source_revision_and_digest() -> None:
    semantic = _build(_case(statement=_statement()))

    manifest = semantic.packet.input_manifest
    assert manifest is not None
    assert manifest.schema == "yoetz.review-input-manifest/1"
    assert manifest.specification.status == "complete"
    assert manifest.specification.source_refs == (str(evt(_STATEMENT_EVENT)),)
    assert manifest.specification.revision == _STATEMENT_EVENT
    assert manifest.specification.content_bytes == len(_TERMENV_STATEMENT.encode("utf-8"))
    assert manifest.specification.content_digest is not None
    assert manifest.specification.selected_item_ids == (TASK_STATEMENT_ITEM_ID,)
    assert manifest.selected_item_count == len(semantic.items)

    packet = _packet(semantic)
    wire = cast(dict[str, JsonValue], packet["review_packet"])["review_input_manifest"]
    assert isinstance(wire, dict)
    specification = wire["specification"]
    assert isinstance(specification, dict)
    assert specification["status"] == "complete"
    assert specification["revision"] == _STATEMENT_EVENT
    assert specification["content_digest"] == manifest.specification.content_digest
    review_packet = cast(dict[str, JsonValue], packet["review_packet"])
    provider = review_packet["provider_input_manifest"]
    assert isinstance(provider, dict)
    assert provider["phase"] == "provider_bound"
    provider_count = provider["selected_item_count"]
    assert type(provider_count) is int
    assert provider_count == len(_items(packet)) == manifest.selected_item_count


def test_input_manifest_counts_each_omission_once_across_section_projections() -> None:
    omission = ReviewOmission(
        subject_ref=str(evt(_STATEMENT_EVENT)),
        category=DataCategory.REPOSITORY_EXCERPT,
        source_kind="diff",
        reason="not_selected",
    )
    manifest = review_input_manifest(
        frozen_case=_case(statement=_statement()),
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        sections=frozenset({"task_statement", "targeted_excerpts"}),
        items=(),
        omissions=(omission,),
        task_statement_ids=(),
        task_statement_gaps=frozenset(),
        recorded_statement=None,
        pending_missing=None,
    )

    # The same diff omission is visible through the current-diff section and the top-level row;
    # it is one omitted row for accounting purposes.
    assert manifest.omitted_item_count == 1


def test_disclosure_rejects_malformed_or_count_inconsistent_provider_manifest() -> None:
    semantic = _build(_case(statement=_statement()))

    valid = _packet(semantic)
    assert review_packet_disclosure(canonical_encode(valid)) is not None
    valid_result = review_packet_disclosure_result(canonical_encode(valid))
    assert valid_result.failure is None
    assert valid_result.disclosure is not None
    assert valid_result.disclosure.provider_input_manifest is not None
    assert valid_result.disclosure.provider_input_text_by_ref
    first_item = _items(valid)[0]
    first_source = first_item["source_ref"]
    assert type(first_source) is str
    assert (
        cast(str, first_item["content"])
        in valid_result.disclosure.provider_input_text_by_ref[first_source]
    )

    malformed = _packet(semantic)
    malformed_packet = cast(dict[str, JsonValue], malformed["review_packet"])
    malformed_packet["provider_input_manifest"] = {
        "schema": "yoetz.review-input-manifest/1",
        "phase": "provider_bound",
    }
    assert review_packet_disclosure(canonical_encode(malformed)) is None

    inconsistent = _packet(semantic)
    inconsistent_packet = cast(dict[str, JsonValue], inconsistent["review_packet"])
    provider = cast(dict[str, JsonValue], inconsistent_packet["provider_input_manifest"])
    provider["selected_item_count"] = 0
    assert review_packet_disclosure(canonical_encode(inconsistent)) is None


def test_disclosure_result_keeps_provider_provenance_failures_distinct() -> None:
    semantic = _build(_case(statement=_statement()))

    missing = _packet(semantic)
    missing_packet = cast(dict[str, JsonValue], missing["review_packet"])
    del missing_packet["provider_input_manifest"]
    missing_result = review_packet_disclosure_result(canonical_encode(missing))
    assert missing_result.disclosure is not None
    assert missing_result.disclosure.provider_input_manifest is None
    assert missing_result.failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP
    # The compatibility helper retains its old fail-open behavior for a readable packet whose
    # optional provider metadata was not present in an older response.
    assert review_packet_disclosure(canonical_encode(missing)) is not None

    malformed = _packet(semantic)
    malformed_packet = cast(dict[str, JsonValue], malformed["review_packet"])
    malformed_packet["provider_input_manifest"] = {"schema": "wrong", "phase": "provider_bound"}
    malformed_result = review_packet_disclosure_result(canonical_encode(malformed))
    assert malformed_result.disclosure is not None
    assert malformed_result.failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP

    malformed_type = _packet(semantic)
    malformed_type_packet = cast(dict[str, JsonValue], malformed_type["review_packet"])
    malformed_type_packet["provider_input_manifest"] = []
    malformed_type_result = review_packet_disclosure_result(canonical_encode(malformed_type))
    assert malformed_type_result.disclosure is not None
    assert malformed_type_result.failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP

    inconsistent = _packet(semantic)
    inconsistent_packet = cast(dict[str, JsonValue], inconsistent["review_packet"])
    provider = cast(dict[str, JsonValue], inconsistent_packet["provider_input_manifest"])
    provider["selected_item_count"] = 0
    inconsistent_result = review_packet_disclosure_result(canonical_encode(inconsistent))
    assert inconsistent_result.disclosure is not None
    assert inconsistent_result.failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP

    parse_result = review_packet_disclosure_result(b"{")
    assert parse_result.disclosure is None
    assert parse_result.failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP


def test_per_check_manifest_keeps_title_only_and_policy_withheld_distinct() -> None:
    titled = _build(_case(statement=None, title="title only"))
    assert titled.packet.input_manifest is not None
    assert titled.packet.input_manifest.specification.status == "title_only"
    assert titled.packet.input_manifest.specification.source_refs == ("task-title",)

    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.ASSISTED, preset_version="1.1.0"
    )
    withheld = _build(_case(statement=_statement()), selection=legacy)
    assert withheld.packet.input_manifest is not None
    assert withheld.packet.input_manifest.specification.status == "withheld"
    assert withheld.packet.input_manifest.specification.content_digest is None


def test_provider_manifest_tracks_privacy_removal_and_rendered_statement_bytes() -> None:
    semantic = _build(_case(statement=_statement()))
    all_ids = frozenset(item.item_id for item in semantic.items)

    candidate = semantic_case_to_candidate_context(
        semantic,
        request_id="req_90800000-0000-4000-8000-000000000002",
        scope=AuthorizationScope(
            AuthorizationScopeKind.MACHINE, "ins_90800000-0000-4000-8000-000000000002"
        ),
        provider_binding=ProviderBinding(
            "fake", "fake-model", "fake-provider", "1.0.0", "external"
        ),
    )
    classified = ClassifiedContext(
        candidate,
        tuple(
            ClassifiedContextItem(
                item,
                DataClass.PUBLIC_STRUCTURAL,
                (),
                True,
                "test-manifest",
            )
            for item in candidate.items
        ),
    )
    privacy_approved = frozenset(item.item_id for item in candidate.items) - {
        TASK_STATEMENT_ITEM_ID
    }
    minimized = LocalPrivacyEnforcer().minimize_and_scan(
        classified,
        PrivacyDecision(
            tuple(sorted(privacy_approved, key=str.encode)),
            (),
            PrivacyOutcome.COMPLETED,
            None,
        ),
    )
    removed = cast(
        dict[str, JsonValue],
        strict_json_parse(minimized.prepared_bytes),
    )
    removed_result = review_packet_disclosure_result(minimized.prepared_bytes)
    assert removed_result.failure is None
    assert removed_result.disclosure is not None
    assert removed_result.disclosure.provider_input_manifest is not None
    removed_packet = cast(dict[str, JsonValue], removed["review_packet"])
    removed_manifest = cast(dict[str, JsonValue], removed_packet["provider_input_manifest"])
    removed_specification = cast(dict[str, JsonValue], removed_manifest["specification"])
    assert removed_specification["status"] == "withheld"
    assert removed_specification["content_digest"] is None
    assert removed_specification["omitted_refs"] == [str(evt(_STATEMENT_EVENT))]
    assert removed_specification["omission_reasons"] == ["withheld_by_policy"]
    # The omission is scoped to the specification; privacy removal must not make unrelated
    # verification or caller-evidence sections claim the same reason.
    assert (
        cast(dict[str, JsonValue], removed_manifest["latest_verification"])["omission_reasons"]
        == []
    )

    # Assemble a provider row whose rendered task statement was clipped after composition. The
    # provider-bound manifest reports the effective digest/bytes and makes the loss visible even
    # though the item id itself survived.
    envelope = cast(dict[str, JsonValue], strict_json_parse(bounded_case_envelope(semantic)))
    content_by_id = {item.item_id: item.content for item in semantic.items}
    rendered = cast(
        dict[str, JsonValue],
        strict_json_parse(content_by_id[TASK_STATEMENT_ITEM_ID]),
    )
    original_statement = cast(str, rendered["statement"])
    clipped_statement = original_statement[:-1]
    rendered["statement"] = clipped_statement
    rendered["statement_bytes"] = len(clipped_statement.encode("utf-8"))
    rendered["elided_bytes"] = 1
    content_by_id[TASK_STATEMENT_ITEM_ID] = canonical_encode(rendered)
    clipped = cast(
        dict[str, JsonValue],
        strict_json_parse(
            assemble_filtered_review_packet(
                envelope,
                content_by_id=content_by_id,
                included_item_ids=all_ids,
            )
        ),
    )
    clipped_result = review_packet_disclosure_result(canonical_encode(clipped))
    assert clipped_result.failure is None
    assert clipped_result.disclosure is not None
    assert clipped_result.disclosure.provider_input_manifest is not None
    clipped_packet = cast(dict[str, JsonValue], clipped["review_packet"])
    clipped_manifest = cast(dict[str, JsonValue], clipped_packet["provider_input_manifest"])
    clipped_specification = cast(dict[str, JsonValue], clipped_manifest["specification"])
    composed_specification = cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], clipped_packet["review_input_manifest"])["specification"],
    )
    assert clipped_specification["status"] == "partial"
    assert clipped_specification["content_bytes"] == len(clipped_statement.encode("utf-8"))
    assert clipped_specification["content_digest"] != composed_specification["content_digest"]
