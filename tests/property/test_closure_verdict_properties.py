"""Property checks for the one closure verdict (tb4n3 RC-3, issue #1026, ADR-046).

* The gap table is total and its judgment is a pure function of the code and the context.
* ``finding_closure`` is deterministic under replay (dictionary order is not state) and under
  ``duplicate_of`` chains (a chain counts once, under its earliest finding).
* For any short run driven through the public operations, every surface (status in every view, the
  MCP text, the CLI and terminal lines, closure_prepare and the receipt in three formats) prints
  the same predicted conclusion and the same counters, and the receipt carries the conclusion the
  status predicted.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import integration.application.test_respond_status_receipt as h
from builders.policy_cases import evd, finding_record, fnd, obl, record
from integration.closure import test_closure_shapes as shapes
from yoetz.domain.events import ResponseRecordedPayload
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    finding_policy_identity,
)
from yoetz.domain.receipts import SchemaVersionEntry
from yoetz.domain.values import FindingId, Frontier
from yoetz.kernel.closure_class import closure_counts, finding_closures
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION
from yoetz.kernel.gap_effect import GapContext, GapEffectKind, gap_effect
from yoetz.kernel.projections import (
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from yoetz.protocol.errors import PublicOperationError

_CODES = tuple(sorted(GAP_CLASSIFICATION))
_DIGEST = "sha256:" + "3" * 64


# -- gap_effect: total, pure, and the actionable rows stay actionable ---------------------------


@st.composite
def _contexts(draw: st.DrawFn) -> GapContext:
    carried = draw(st.frozensets(st.sampled_from(_CODES), max_size=6))
    historical = draw(st.frozensets(st.sampled_from(_CODES), max_size=3))
    return GapContext(
        route_requires_review=draw(st.booleans()),
        review_required=draw(st.booleans()),
        review_current=draw(st.booleans()),
        review_succeeded=draw(st.booleans()),
        reviewer_reported_insufficiency=draw(st.booleans()),
        check_carried=carried,
        commands_complete=draw(st.booleans()),
        earlier_frontier_bounds=draw(st.booleans()),
        historical=historical,
    )


@given(code=st.sampled_from(_CODES), context=_contexts())
def test_gap_effect_is_total_pure_and_closed(code: str, context: GapContext) -> None:
    effect = gap_effect(code, context)
    assert effect.code == code
    assert effect.kind in GapEffectKind
    # A pure function of the code and the context.
    assert gap_effect(code, replace(context)) == effect
    if code in context.historical:
        assert effect.kind is GapEffectKind.HISTORICAL
        assert not effect.kind.bounds
    # A wrapped marker judges by its base code and keeps the same kind.
    assert gap_effect(f"coverage:{code}", context).kind is effect.kind


@given(code=st.sampled_from(_CODES), context=_contexts())
def test_an_unclassified_marker_is_never_clean(code: str, context: GapContext) -> None:
    unknown = gap_effect(f"{code}_not_in_the_table", replace(context, historical=frozenset()))
    assert unknown.kind is GapEffectKind.ACTIONABLE
    assert unknown.kind.bounds


# -- finding_closure: deterministic under replay and under duplicate chains ---------------------


def _coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=(),
    )


def _finding(number: int) -> Finding:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    policy_id, policy_version = finding_policy_identity(kind)
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A requirement is not shown.",
        detail="Do it or state the limit.",
        subject_refs=(obl(number),),
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
    )


_ROOT_ANSWERS = (
    None,
    ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
    ResponseDisposition.REJECTED,
    ResponseDisposition.SELF_VERIFIED,
    ResponseDisposition.ACKNOWLEDGED,
)


def _answer(
    number: int, disposition: ResponseDisposition
) -> ProjectionRecord[ResponseRecordedPayload]:
    needs_reason = disposition is not ResponseDisposition.ACKNOWLEDGED
    return record(
        ResponseRecordedPayload(
            fnd(number),
            Frontier(5, _DIGEST),
            disposition,
            "A recorded reason." if needs_reason else None,
            evidence_refs=(evd(number),)
            if disposition is ResponseDisposition.SELF_VERIFIED
            else (),
        ),
        6,
    )


def _chain_state(
    length: int, root_answer: ResponseDisposition | None, *, reverse: bool
) -> ProjectionState:
    numbers = list(range(1, length + 1))
    findings: dict[FindingId, FindingProjectionRecord] = {}
    responses: dict[FindingId, ProjectionRecord[ResponseRecordedPayload]] = {}
    for number in numbers:
        findings[fnd(number)] = finding_record(_finding(number), 4 + number)
    if root_answer is not None:
        responses[fnd(1)] = _answer(1, root_answer)
    for number in numbers[1:]:
        responses[fnd(number)] = record(
            ResponseRecordedPayload(
                fnd(number),
                Frontier(5, _DIGEST),
                ResponseDisposition.DUPLICATE_OF,
                None,
                duplicate_of_finding_id=fnd(number - 1),
            ),
            20 + number,
        )
    if reverse:
        findings = dict(reversed(findings.items()))
        responses = dict(reversed(responses.items()))
    return replace(
        empty_projection_state(),
        frontier=60,
        head_digest=_DIGEST,
        findings=findings,
        responses=responses,
        freshness=LedgerFreshness.CURRENT,
    )


@given(
    length=st.integers(min_value=1, max_value=5),
    root_answer=st.sampled_from(_ROOT_ANSWERS),
)
def test_a_duplicate_chain_counts_once_and_replays_to_the_same_closures(
    length: int, root_answer: ResponseDisposition | None
) -> None:
    forward = finding_closures(_chain_state(length, root_answer, reverse=False))
    backward = finding_closures(_chain_state(length, root_answer, reverse=True))
    assert forward == backward  # insertion order is not state
    assert finding_closures(_chain_state(length, root_answer, reverse=False)) == forward
    # Every link of the chain reads under the earliest finding...
    assert {item.counts_as for item in forward.values()} == {fnd(1)}
    # ...and the chain is one count, never one per link.
    counts = closure_counts(forward.values(), ())
    assert (
        counts.findings_to_do
        + counts.findings_unmet
        + counts.findings_disclosed
        + counts.findings_to_disclose
    ) <= 1


# -- Every surface prints the same verdict for any short run ------------------------------------

_OPS = st.lists(
    st.sampled_from(("check", "answer_findings", "acknowledge_obligation", "act", "poll")),
    max_size=6,
)


async def _run_script(script: list[str]) -> None:
    run = await shapes._begin(seed=90)  # pyright: ignore[reportPrivateUsage]
    await run.publish(
        shapes._obligation(run, 1),  # pyright: ignore[reportPrivateUsage]
        shapes._obligation(run, 2),  # pyright: ignore[reportPrivateUsage]
        shapes._plan(run, 1, 2),  # pyright: ignore[reportPrivateUsage]
        shapes._action(run, 1),  # pyright: ignore[reportPrivateUsage]
    )
    last: Any = None
    acknowledged: set[int] = set()
    acted = 1
    for step in script:
        if step == "check":
            last = await run.check_in("deterministic_only")
        elif step == "answer_findings" and last is not None:
            for item in last.findings:
                try:
                    await run.respond(
                        item.finding_id,
                        last.result_frontier,
                        "acknowledged_not_done",
                        "I recorded this in my answer and cannot do it here.",
                    )
                except PublicOperationError:
                    continue  # a later publish already settled it: not every script is valid
            last = None
        elif step == "acknowledge_obligation":
            number = next((n for n in (1, 2) if n not in acknowledged), None)
            if number is not None:
                draft = shapes._obligation(  # pyright: ignore[reportPrivateUsage]
                    run,
                    number,
                    status="acknowledged_not_done",
                    acknowledged_not_done_reason="The owner decides this later.",
                )
                draft["schema"] = {"name": "obligation_published", "version": "1.1.0"}
                await run.publish(draft)
                acknowledged.add(number)
        elif step == "act" and acted < 2:
            acted += 1
            await run.publish(shapes._action(run, acted))  # pyright: ignore[reportPrivateUsage]
        # "poll" reads nothing: the surfaces below are read at the end of every script.
    gathered = await shapes._surfaces(run)  # pyright: ignore[reportPrivateUsage]
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.predicted_receipt is not None
    shapes.assert_surfaces_agree(
        gathered,
        conclusion=readiness.predicted_receipt.conclusion,
        counts=shapes._wire_counts(readiness),  # pyright: ignore[reportPrivateUsage]
    )


@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(script=_OPS)
def test_every_surface_prints_the_verdict_the_receipt_carries(script: list[str]) -> None:
    original = h._versions  # pyright: ignore[reportPrivateUsage]

    def versions() -> Any:
        return replace(
            original(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(h, "_versions", versions)
        asyncio.run(_run_script(script))
