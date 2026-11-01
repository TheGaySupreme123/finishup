"""One recorded proxy decision for a hidden-reference budget (#1246, owner decision D17).

TB4 distributed-dedup: every attempt broke a budget stated against a reference it could not see,
disclosed it as a verification limit, and never built the obvious stand-in. The disclosure stays;
the agent records one decision (`finishup-proxy:<obligation id>`: the stand-in and its measured
ratio, or why none was feasible), and the receipt says `proxy: none chosen` when it did not.
"""

from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType, SimpleNamespace
from typing import Any, cast

from builders.dialogue import limit_decision
from builders.observed_runs import ObservedLedger
from builders.policy_cases import evt, make_case, obl, obligation_record
from finishup.application.semantic_case import (
    PROXY_REVIEW_QUESTION,
    SMALL_REVIEW_CHANNEL_BYTES,
    _obligation_disclosures,  # pyright: ignore[reportPrivateUsage]
    build_semantic_case,
    review_question_set,
)
from finishup.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import (
    PolicyVersionEntry,
    ReceiptDocument,
    ReceiptRedactionProfile,
    ReceiptSectionKey,
    ReceiptVersionSlice,
    SchemaVersionEntry,
    receipt_document_to_json,
    render_receipt_human,
)
from finishup.domain.values import (
    EventId,
    Frontier,
    actor_id,
    obligation_id,
    receipt_id,
    session_id,
    task_id,
    timestamp_from_string,
)
from finishup.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    CaseGap,
    DeterministicCase,
)
from finishup.kernel.receipt_builder import (
    ReceiptBuildContext,
    ReceiptInclude,
    _proxy_sentence,  # pyright: ignore[reportPrivateUsage]
    build_receipt,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    proxy_decisions,
    proxy_line_obligations,
    verification_limits_without_proxy,
)
from finishup.mcp.summaries import (
    _receipt_proxy_clause,  # pyright: ignore[reportPrivateUsage]
)
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_LIMIT = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_UNKNOWN = obligation_id("obl_00000000-0000-4000-8000-0000000000ff")


def _ledger() -> ObservedLedger:
    ledger = ObservedLedger()
    for obligation in (_LIMIT, _OTHER):
        ledger.append(
            EventSchema("obligation_published", "1.0.0"),
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Deduplicate the corpus within twice the reference warmup",
                evidence_expectation="Observed run",
                status=ObligationStatus.OPEN,
            ),
            observed=False,
        )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_LIMIT, _OTHER)),
        observed=False,
    )
    return ledger


def _decide(
    ledger: ObservedLedger,
    statement: str,
    *,
    rationale: str = "The reference implementation is hidden.",
    supersedes: EventId | None = None,
) -> EventId:
    return ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement=statement,
            rationale=rationale,
            authority=actor_id("agt_codex"),
            supersedes_event_id=supersedes,
        ),
        observed=False,
    )


def test_only_exact_proxy_lines_with_a_well_formed_obligation_id_count() -> None:
    statement = "\n".join(
        (
            f"  finishup-proxy:{_LIMIT}  ",
            f"finishup-proxy : {_OTHER}",
            f"finishup-proxy:{_LIMIT}",
            "finishup-proxy:obl_not-an-id",
            f"I built finishup-proxy:{_OTHER}",
            f"finishup-proxy: {_OTHER} with a baseline",
        )
    )
    assert proxy_line_obligations(statement) == (_LIMIT, _OTHER)


def test_a_limit_without_a_proxy_decision_reads_none_chosen_and_one_with_it_reads_recorded() -> (
    None
):
    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}\nfinishup-verification-limit:{_OTHER}")
    projection = replay(ledger.prefix)
    assert verification_limits_without_proxy(projection) == ((_LIMIT, _OTHER), ())
    assert "proxy: none chosen" in _proxy_sentence(projection)

    decision = _decide(
        ledger,
        f"finishup-proxy:{_LIMIT}",
        rationale="A single-threaded baseline took 6.3 s; ours took 9.1 s (1.44x).",
    )
    projection = replay(ledger.prefix)
    assert [
        (item.obligation_id, item.decision_event_id) for item in proxy_decisions(projection)
    ] == [(_LIMIT, decision)]
    assert verification_limits_without_proxy(projection) == ((_OTHER,), (_LIMIT,))
    sentence = _proxy_sentence(projection)
    assert f"Disclosed verification limit {_OTHER}: proxy: none chosen" in sentence
    assert f"for disclosed verification limit {_LIMIT}." in sentence
    # Ids only: the agent's own measurement never reaches the receipt sentence.
    assert "6.3" not in sentence and "baseline" not in sentence


def test_no_disclosed_limit_adds_nothing_and_an_unknown_id_records_nothing() -> None:
    ledger = _ledger()
    _decide(ledger, f"finishup-proxy:{_UNKNOWN}")
    projection = replay(ledger.prefix)
    assert proxy_decisions(projection) == ()
    assert _proxy_sentence(projection) == ""


def test_superseding_the_proxy_decision_withdraws_it() -> None:
    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}")
    first = _decide(ledger, f"finishup-proxy:{_LIMIT}")
    _decide(ledger, "The stand-in measured the wrong workload.", supersedes=first)
    projection = replay(ledger.prefix)
    assert proxy_decisions(projection) == ()
    assert verification_limits_without_proxy(projection)[0] == (_LIMIT,)


def test_a_proxy_decision_adds_no_readiness_code_and_asks_nothing() -> None:
    """D17: no new standing question; readiness reads exactly as without the proxy line."""

    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}")
    before = ledger.prefix
    _decide(ledger, f"finishup-proxy:{_LIMIT}")
    after = ledger.prefix

    def readiness(prefix: tuple[Any, ...]) -> tuple[object, ...]:
        state = derive_closure_readiness(
            (), (), closure_readiness_facts(replay(prefix), prefix), semantic_review_required=False
        )
        return (state.state, state.agent_actionable, state.standing_limitations)

    assert readiness(after) == readiness(before)


def _coverage() -> Coverage:
    # No check recorded yet: the receipt names that gap, as every unchecked receipt does.
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.ARTIFACT_VERIFIED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=("check_not_recorded",),
    )


def _versions() -> ReceiptVersionSlice:
    return ReceiptVersionSlice(
        package_name="finishup",
        package_version="0.1.0",
        protocol_version="0.1",
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        object_format_version="yoetz-object/1",
        catalog_schema_version="1",
        bundle_schema_version="1",
        policy_versions=(
            PolicyVersionEntry("research-evidence", "0.1.0"),
            PolicyVersionEntry("work-integrity", "0.1.0"),
        ),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        resource_manifest_digest="sha256:" + "9" * 64,
    )


def _receipt(ledger: ObservedLedger) -> ReceiptDocument:
    projection = replay(ledger.prefix)
    return build_receipt(
        ReceiptBuildContext(
            projection=projection,
            subject_frontier=Frontier(projection.frontier, projection.head_digest),
            availability=CaseAvailabilityFacts(),
            coverage=_coverage(),
            gaps=(CaseGap("check_not_recorded", "check_not_recorded", ()),),
            finding_states=(),
            applicable_check=None,
            records=ledger.prefix,
        ),
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-10-30T00:00:00.000Z"),
        _versions(),
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )


def test_every_receipt_format_names_the_limit_without_a_proxy() -> None:
    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}")
    receipt = _receipt(ledger)
    limitations = next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    line = f"Disclosed verification limit {_LIMIT}: proxy: none chosen"
    assert line in limitations
    wire = cast(dict[str, Any], receipt_document_to_json(receipt))
    assert any(line in row["body"] for row in wire["sections"])
    assert line in render_receipt_human(receipt, markdown=True)
    assert line in render_receipt_human(receipt, markdown=False)
    assert _receipt_proxy_clause({"document": wire}).startswith("proxy: none chosen")


def test_the_cli_and_the_mcp_summary_name_the_proxy_line_of_every_receipt_result() -> None:
    """The CLI's human rendering of a JSON receipt names the proxy sentences once, as it names
    the review-mode and coordinator-failure sentences; markdown and text carry them in
    ``human_text``. The MCP summary points at a limit without one (#1246)."""

    from finishup.application.receipt import (
        _internal_result,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.cli.render import render_human_receipt
    from finishup.mcp.summaries import summary_for_receipt
    from finishup.protocol.models import CoverageModel, ReceiptFormat, ReceiptSuccessModel

    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}\nfinishup-verification-limit:{_OTHER}")
    _decide(ledger, f"finishup-proxy:{_OTHER}", rationale="Baseline 6.3 s; ours 9.1 s (1.44x).")
    receipt = _receipt(ledger)
    none_chosen = (
        f"Disclosed verification limit {_LIMIT}: proxy: none chosen (no finishup-proxy decision "
        "records a proxy measurement or why none was feasible)."
    )
    recorded = (
        "A finishup-proxy decision records the proxy measurement, or why none was feasible, for "
        f"disclosed verification limit {_OTHER}."
    )
    for output_format in (ReceiptFormat.JSON, ReceiptFormat.MARKDOWN, ReceiptFormat.TEXT):
        request = SimpleNamespace(
            format=output_format,
            request_id="req_00000000-0000-4000-8000-000000000001",
            redaction_profile=ReceiptRedactionProfile.FULL_LOCAL,
            include=ReceiptInclude.FULL,
            writer_id=None,
        )
        result = _internal_result(
            cast(Any, request),
            receipt,
            cast(Any, SimpleNamespace(object_id="obj_00000000-0000-4000-8000-000000000001")),
            "sha256:" + "3" * 64,
            Frontier(receipt.subject_frontier.sequence, receipt.subject_frontier.head_digest),
        )
        envelope = result.as_json()
        fields: dict[str, Any] = {
            **envelope,
            "coverage": CoverageModel.model_validate(envelope["coverage"]),
        }
        cli = render_human_receipt(ReceiptSuccessModel.model_construct(**fields))
        assert cli.count(none_chosen) == 1, output_format
        assert cli.count(recorded) == 1, output_format
        assert "6.3" not in cli and "Baseline" not in cli
        summary = summary_for_receipt(envelope)
        if output_format is ReceiptFormat.JSON:
            # Fixed wording only: the summary never carries the ids or the rationale.
            assert (
                "proxy: none chosen for a disclosed verification limit (limitations section);"
                in summary
            )
            # A review-mode tail (ADR-049) that already holds the sentences shows them once.
            document = cast(dict[str, Any], envelope["document"])
            sections = [
                {
                    **row,
                    "body": "The applicable check ran with AI-powered review requested. "
                    + row["body"],
                }
                if row["key"] == "limitations_and_coverage"
                else row
                for row in document["sections"]
            ]
            switched_fields: dict[str, Any] = {
                **fields,
                "document": {**document, "sections": sections},
            }
            switched = ReceiptSuccessModel.model_construct(**switched_fields)
            assert render_human_receipt(switched).count(none_chosen) == 1


def test_the_reviewer_question_rides_only_a_closing_review_with_an_unproxied_limit() -> None:
    assert PROXY_REVIEW_QUESTION not in review_question_set("final")
    assert PROXY_REVIEW_QUESTION not in review_question_set("routine", proxy=True)
    asked = review_question_set("final", proxy=True, linked_verification=True)
    # Before the test-quality question, which stays last.
    assert asked[-2] == PROXY_REVIEW_QUESTION
    assert "never for the hidden reference" in PROXY_REVIEW_QUESTION
    assert len(PROXY_REVIEW_QUESTION.encode()) < 400


def test_the_disclosures_row_carries_the_proxy_beside_its_limit() -> None:
    ledger = _ledger()
    _decide(ledger, f"finishup-verification-limit:{_LIMIT}")
    decision = _decide(ledger, f"finishup-proxy:{_LIMIT}\nfinishup-proxy:{_OTHER}")
    projection = replay(ledger.prefix)
    rows = _obligation_disclosures(projection, frozenset({str(decision)}))
    assert rows[str(_LIMIT)]["proxy"] == str(decision)
    # A proxy without a disclosed limit has nothing to sit beside.
    assert str(_OTHER) not in rows
    hidden = _obligation_disclosures(projection, frozenset())
    assert hidden[str(_LIMIT)]["proxy"] is True


def _closing_case(case: DeterministicCase, *, final: bool = True, ceiling: int | None = None):
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        final_review=final,
        prepared_byte_ceiling=ceiling,
    )


def test_the_built_case_asks_only_off_the_small_channel_for_a_carried_unproxied_limit() -> None:
    """The real packet gating, not only the question-set flag.

    A closing review whose packet carries an obligation row with a disclosed verification limit
    and no proxy decision asks the proxy question; a routine review or a recorded proxy does not.
    On a channel no larger than the minimal policy's the packet is planned without room for it:
    there the 359 bytes left a read no room, so a closing review whose reviewer read once ended
    ``case_capacity_exceeded`` (#1173). It never rides there, even with the obligation carried.
    """

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Deduplicate the corpus within twice the reference warmup",
            "Observed run",
            ObligationStatus.OPEN,
        ),
        2,
    )
    base = make_case(obligations={obl(1): obligation}, extra_refs=(obl(1),))
    limited = replace(
        base,
        projection=replace(
            base.projection, decisions=MappingProxyType({evt(20): limit_decision(20, obl(1))})
        ),
    )
    row = f"obligation-{obl(1)}"
    closing = _closing_case(limited)
    assert row in {item.item_id for item in closing.items}
    assert PROXY_REVIEW_QUESTION in closing.question_set
    assert PROXY_REVIEW_QUESTION not in _closing_case(limited, final=False).question_set
    small = _closing_case(limited, ceiling=SMALL_REVIEW_CHANNEL_BYTES)
    assert small.question_set[0].startswith("Review phase: final.")
    assert row in {item.item_id for item in small.items}
    assert PROXY_REVIEW_QUESTION not in small.question_set
    proxied = replace(
        limited,
        projection=replace(
            limited.projection,
            decisions=MappingProxyType(
                {
                    **limited.projection.decisions,
                    evt(21): limit_decision(21, obl(1), kind="finishup-proxy"),
                }
            ),
        ),
    )
    assert PROXY_REVIEW_QUESTION not in _closing_case(proxied).question_set
