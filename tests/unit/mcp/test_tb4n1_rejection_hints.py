"""Rejections from the tb4n1 benchmark census name the field, the admitted shape, and the repair.

Each case replays the shape an agent actually sent (attempt named in the docstring) through the
bridge's pure validation path or the shared public-error projectors; no service is contacted.
"""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from finishup.application.respond import (
    _resolution_attempt_required_message,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.events import (
    ClaimRevisionMismatch,
    ObligationResolutionMismatch,
    public_error_for_claim_revision_mismatch,
    public_error_for_obligation_resolution_mismatch,
)
from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.server import (
    _guidance_page_size_message,  # pyright: ignore[reportPrivateUsage]
    invalid_request_message,
)
from finishup.protocol.models import (
    _STATUS_FILTER_BY_VIEW,  # pyright: ignore[reportPrivateUsage]
    PublishWorkRequest,
    StatusRequest,
)

_IDENTITY: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "session_id": "ses_00000000-0000-4000-8000-000000000001",
    "writer_id": "wri_00000000-0000-4000-8000-000000000001",
    "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
    "client": {"kind": "codex_cli", "version": "1", "integration": "cooperative_mcp"},
}
_SECRET = "caller-prose-must-not-echo"
_UUID = "00000000-0000-4000-8000-00000000000"


def _publish(
    name: str,
    version: str,
    payload: dict[str, object],
    *,
    evidence_refs: list[str] | None = None,
) -> str:
    draft: dict[str, object] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000001",
        "schema": {"name": name, "version": version},
        "occurred_at": "2026-01-01T00:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [] if evidence_refs is None else evidence_refs,
    }
    request = {
        **_IDENTITY,
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "event_drafts": [draft],
    }
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequest.model_validate(request)
    message = invalid_request_message("publish_work", safe_validation_locations(caught.value))
    assert _SECRET not in message
    return message


def _status(extra: dict[str, object]) -> tuple[tuple[dict[str, str], ...], str]:
    with pytest.raises(ValidationError) as caught:
        StatusRequest.model_validate({**_IDENTITY, **extra})
    locations = safe_validation_locations(caught.value)
    return locations, invalid_request_message("status", locations)


def _claim(limitation_refs: list[str]) -> dict[str, object]:
    return {
        "claim_id": "clm_00000000-0000-4000-8000-000000000001",
        "claim_kind": "completion",
        "statement": _SECRET,
        "obligation_refs": [],
        "supporting_refs": [],
        "limitation_refs": limitation_refs,
    }


def test_evidence_id_in_limitation_refs_names_result_ids_and_where_evidence_goes() -> None:
    """formal-crypto__4QnC4wS: an evd_ id in claim limitation_refs got only the template URI."""

    sent = f"evd_{_UUID}9"
    message = _publish("claim_recorded", "1.1.0", _claim([sent]))
    assert "limitation_refs names only non-success result ids (res_)" in message
    assert "supporting_refs" in message
    assert "field `limitation_refs` expects a `res_` id; got `evd_`" in message
    assert "example: `res_00000000-0000-4000-8000-000000000001`" in message
    assert sent not in message
    assert "each limitation_refs entry admits values matching ^res_" in message


def test_result_id_in_result_evidence_refs_names_the_selected_family_shape() -> None:
    """photonic-waveguide-routing__tGLKUj6: res_ ids in result_recorded evidence_refs.

    Several families declare payload ``evidence_refs`` with different shapes, so the hint must
    follow the draft's own family rather than give up on the ambiguous union.
    """

    message = _publish(
        "result_recorded",
        "1.0.0",
        {
            "result_id": f"res_{_UUID}1",
            "action_id": f"act_{_UUID}1",
            "outcome": "success",
            "summary": _SECRET,
            "evidence_refs": [f"res_{_UUID}2"],
        },
    )
    assert "a result's evidence_refs names only evidence ids (evd_)" in message
    assert "field `evidence_refs` expects an `evd_` id; got `res_`" in message
    assert "example: `evd_00000000-0000-4000-8000-000000000001`" in message
    assert f"{_UUID}2" not in message
    assert "each evidence_refs entry admits values matching ^evd_" in message


def test_finding_id_in_disputes_refs_points_to_respond() -> None:
    """ks-solver-cpp__vFjNT8V: fnd_ ids in claim disputes_refs."""

    payload = _claim([])
    payload["disputes_refs"] = [f"fnd_{_UUID}1"]
    message = _publish("claim_recorded", "1.1.0", payload)
    assert "answer a finding (fnd_) with the respond tool" in message


def test_object_in_attempted_items_names_plain_strings() -> None:
    """html-js-filter__nyFVZUa: requested-item objects sent as action attempted_items."""

    message = _publish(
        "action_recorded",
        "1.0.0",
        {
            "action_id": f"act_{_UUID}1",
            "action_kind": "edit",
            "description": _SECRET,
            "attempted_items": [{"item_kind": "file", "value": _SECRET}],
        },
    )
    assert "each attempted_items entry admits a plain string of at most 1024 characters" in (
        message
    )


@pytest.mark.parametrize("change", ["superseded", "waived"])
def test_obligation_change_without_reason_names_the_rule(change: str) -> None:
    """formal-crypto__4QnC4wS, cargo-flight-dispatch__q5qfPQL: 19 reasonless plan changes."""

    message = _publish(
        "plan_revised",
        "1.1.0",
        {
            "plan_version": 2,
            "supersedes_plan_version": 1,
            "reason": _SECRET,
            "summary": _SECRET,
            "task_statement": _SECRET,
            "obligation_changes": [{"obligation_id": f"obl_{_UUID}1", "change": change}],
        },
    )
    assert "each obligation_changes entry with change superseded or waived requires reason" in (
        message
    )


def test_payload_missing_one_key_names_that_key() -> None:
    """formal-crypto__4QnC4wS: plan_revised 1.1.0 without task_statement."""

    message = _publish(
        "plan_revised",
        "1.1.0",
        {
            "plan_version": 2,
            "supersedes_plan_version": 1,
            "reason": _SECRET,
            "summary": _SECRET,
            "obligation_changes": [],
        },
    )
    assert "the plan_revised 1.1.0 payload is missing task_statement; it requires" in message


def test_digest_binding_subject_names_the_members_its_evidence_kind_admits() -> None:
    """music-harmony__vXXTjQJ: subject "file_bytes"; the 9-member enum was over the old bound.

    tb4n5 (#1049): the union also named subjects the draft's ``evidence_kind`` refuses, so the
    hint now names that kind's subset first and every other kind's beside it.
    """

    message = _publish(
        "evidence_recorded",
        "1.1.0",
        {
            "evidence_id": f"evd_{_UUID}1",
            "evidence_kind": "artifact",
            "strength": "content_digest",
            "observed_at": "2026-01-01T00:00:00.000Z",
            "content_digest": "sha256:" + "0" * 64,
            "digest_binding": {
                "subject": "file_bytes",
                "content_availability": "digest_only",
                "byte_count": 1,
                "provenance": "caller_asserted",
            },
        },
    )
    assert (
        "subject for evidence_kind artifact admits artifact_bytes, bounded_excerpt, source_diff"
        in (message)
    )
    assert "test_result admits approved_check_receipt, static_analysis_report" in message
    assert "file_bytes" not in message


def test_status_cursor_pattern_names_the_previous_page_and_echoes_nothing() -> None:
    """A cursor with a space fails the wire pattern before kernel decode."""

    secret = "not a cursor " + _SECRET
    locations, message = _status({"view": "results", "limit": "20", "cursor": secret})
    assert locations[0]["field"] == "/cursor"
    assert "received_prefix" not in locations[0]
    assert "field `cursor` expects the opaque next_cursor" in message
    assert "example: repeat that next_cursor unchanged" in message
    assert _SECRET not in message
    assert secret not in message


def test_status_cursor_hint_matches_the_kernel_message() -> None:
    from finishup.application.status import (
        _STATUS_CURSOR_INVALID,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.mcp.errors import (
        _CORRECTIVE_HINTS,  # pyright: ignore[reportPrivateUsage]
    )

    hint, _fields = _CORRECTIVE_HINTS[("status", "/cursor", "invalid_type_or_value")]
    assert hint == _STATUS_CURSOR_INVALID


def test_object_id_in_envelope_evidence_refs_names_evidence() -> None:
    """An envelope evidence_refs member that is another closed kind names evd_ and that kind."""

    message = _publish(
        "result_recorded",
        "1.0.0",
        {
            "result_id": f"res_{_UUID}1",
            "action_id": f"act_{_UUID}1",
            "outcome": "success",
            "summary": "checked summary",
            "evidence_refs": [],
        },
        evidence_refs=[f"obj_{_UUID}9"],
    )
    assert "field `evidence_refs` expects an `evd_` id; got `obj_`" in message
    assert "example: `evd_00000000-0000-4000-8000-000000000001`" in message
    assert f"{_UUID}9" not in message


def test_unprefixed_reference_omits_got_and_still_names_the_example() -> None:
    """A value with no closed id prefix must not be quoted back."""

    message = _publish(
        "result_recorded",
        "1.0.0",
        {
            "result_id": f"res_{_UUID}1",
            "action_id": f"act_{_UUID}1",
            "outcome": "success",
            "summary": _SECRET,
            "evidence_refs": [_SECRET],
        },
    )
    assert "field `evidence_refs` expects an `evd_` id; example:" in message
    assert "got `" not in message
    assert _SECRET not in message


def test_status_limit_over_one_hundred_says_the_range() -> None:
    """rs-archive-clone__TBksTFP and five others: status limit "200"."""

    _, message = _status({"view": "results", "limit": "200"})
    assert 'limit is a decimal string from "1" to "100"' in message


def test_status_unknown_view_lists_the_views() -> None:
    """risk-scorer-replay__2mAG7M8: view "summary"; 13 views were over the old enum bound."""

    _, message = _status({"view": "summary", "limit": "20"})
    assert "view admits advice, assignment, candidate_findings, compact" in message


def test_status_frontier_with_digest_says_sequence_only() -> None:
    """layout-config-recreation__drhGT6a: at_frontier "1697:sha256:...."."""

    _, message = _status(
        {"view": "results", "limit": "20", "at_frontier": "1697:sha256:" + "0" * 64}
    )
    assert "at_frontier is a ledger sequence alone" in message


@pytest.mark.parametrize("view", ["results", "lineage", "compact"])
def test_status_filter_beside_a_filterless_view_names_filter(view: str) -> None:
    """sglang-qwen-burst__rnWf5WV, lake-temp-glm__9kxaSRp: filter with view results."""

    locations, message = _status({"view": view, "limit": "20", "filter": {"actor_id": "codex"}})
    assert locations == ({"field": "/filter", "reason": "extra_forbidden"},)
    assert "omit filter for advice, compact, lineage, project, results, and versions" in message


def test_status_filter_sentence_matches_the_routed_views() -> None:
    from finishup.mcp.errors import (
        _STATUS_FILTER_CORRECTION,  # pyright: ignore[reportPrivateUsage]
    )

    admitted = sorted(_STATUS_FILTER_BY_VIEW)
    assert ", ".join(admitted[:-1]) + ", or " + admitted[-1] in _STATUS_FILTER_CORRECTION


def test_already_resolved_obligation_says_drop_the_draft() -> None:
    """music-harmony__mpyawbQ and seven others republished a resolved obligation."""

    error = public_error_for_obligation_resolution_mismatch(
        ObligationResolutionMismatch(
            ("status",), invariant="open_to_resolved_only", prior_status="resolved"
        ),
        event_index=3,
    )
    assert "already resolved in the ledger" in error.message
    assert "Remove this obligation_published draft" in error.message
    assert "example: omit this draft, or republish status open" in error.message
    assert cast(dict[str, str], error.safe_details)["field"] == "/event_drafts/3/payload"


def test_inadmissible_limitation_refs_are_named() -> None:
    """cargo-flight-dispatch__ZQBrmQD: the rule recital never said which ref was wrong."""

    bad = f"res_{_UUID}9"
    error = public_error_for_claim_revision_mismatch(
        ClaimRevisionMismatch(
            "limitation_refs",
            "limitation_refs_must_be_relevant_non_success_results",
            offending_refs=(bad,),  # type: ignore[arg-type]
        ),
        event_index=0,
    )
    assert f"Not admissible here: {bad}" in error.message
    assert cast(dict[str, object], error.safe_details)["count"] == 1


def test_other_claim_invariants_lead_with_their_correction() -> None:
    error = public_error_for_claim_revision_mismatch(
        ClaimRevisionMismatch("supersedes_claim_refs", "superseded_claim_must_exist")
    )
    assert "superseded_claim_must_exist at supersedes_claim_refs: name an existing claim" in (
        error.message
    )


def test_acknowledgement_without_cited_attempt_says_reason_ids_do_not_count() -> None:
    """music-harmony__mpyawbQ: the repair was described in reason, evidence_refs was empty."""

    message = _resolution_attempt_required_message(62, ())
    assert "after the finding (ledger sequence 62), cited in evidence_refs" in message
    assert "ids named only in reason do not count" in message


def test_acknowledgement_citing_only_older_evidence_names_it() -> None:
    """pretrain-shard-corruption__CGRr6L7: evidence recorded before the finding was cited."""

    early = f"evd_{_UUID}1"
    message = _resolution_attempt_required_message(631, (early,))
    assert f"recorded at or before it: {early}." in message


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("32768", "page_size exceeds the maximum of 16384 bytes"),
        ("2", "page_size is below the minimum of 4 bytes"),
        (4096, 'page_size is a decimal string such as "4096", not a JSON number'),
        ("0100", "page_size must be canonical"),
    ],
)
def test_guidance_page_size_says_which_way_it_is_wrong(raw: object, expected: str) -> None:
    """satb-audio-transcription__KpBtWht: page_size "32768" sent three times."""

    message = _guidance_page_size_message(raw)
    assert expected in message
    assert "restart at page 0 whenever page_size changes" in message
