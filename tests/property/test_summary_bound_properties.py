"""Every MCP text builder stays within its bound, ASCII and unraised (tb4n3 RC-2, #1025).

For arbitrary envelopes of every builder -- every optional field at its schema maximum, every
verdict, status, reason, readiness state, public error code, reason code and continuation token --
the rendered text is at most `MAX_SUMMARY_BYTES` (and at most 512 when the bound is tightened),
ASCII, and produced without raising. A required core is asserted where it is part of the contract.
"""

from __future__ import annotations

import string
from collections.abc import Callable
from typing import Any
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from finishup.domain.findings import CheckVerdict
from finishup.domain.receipts import (
    COORDINATOR_FAILURE_LIMITATION,
    DEFERRED_BEFORE_FIRST_EDIT_TEXT,
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
)
from finishup.mcp import summaries
from finishup.mcp.summaries import (
    MAX_SUMMARY_BYTES,
    render_safe_compact_summary,
    render_safe_compact_summary_detailed,
)
from finishup.protocol.errors import (
    PROTOCOL_REASON_CODES,
    SAFE_DETAIL_KEYS,
    PublicErrorCode,
)
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.readiness_text import READINESS_STATES
from finishup.protocol.recovery import CONTINUATION_TOKENS

_HEAD = st.one_of(
    st.just("genesis"), st.binary(min_size=32, max_size=32).map(lambda b: "sha256:" + b.hex())
)
_FRONTIER = st.fixed_dictionaries(
    {"sequence": st.integers(0, 10**12).map(str), "head_digest": _HEAD}
)


def _uuid_id(prefix: str) -> st.SearchStrategy[str]:
    return st.integers(0, 2**32 - 1).map(lambda n: f"{prefix}_{n:08x}-0000-4000-8000-{n:012x}")


_FINDING_ID = _uuid_id("fnd")
_OBLIGATION_ID = _uuid_id("obl")
_GAP = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=127).filter(
    lambda text: text[0].isalpha()
)
_TOKEN = st.text(alphabet=string.ascii_lowercase + string.digits + "_", min_size=1, max_size=60)
_COUNT = st.integers(0, 10**9).map(str)

_CHECK_REASONS = [item.value for item in SemanticReason]
_CHECK_STATUSES = [item.value for item in SemanticStatus]


@st.composite
def check_envelopes(draw: st.DrawFn) -> dict[str, Any]:
    refs = draw(st.lists(_FINDING_ID, max_size=64, unique=True))
    envelope: dict[str, Any] = {
        "verdict": draw(st.sampled_from([item.value for item in CheckVerdict])),
        "findings": [{"finding_id": ref} for ref in draw(st.lists(_FINDING_ID, max_size=100))],
        "suppressed_count": draw(_COUNT),
        "semantic_status": draw(st.sampled_from(_CHECK_STATUSES)),
        "semantic_reason": draw(st.sampled_from(_CHECK_REASONS)),
        "result_frontier": draw(_FRONTIER),
        "coverage": {"known_gaps": draw(st.lists(_GAP, max_size=64))},
    }
    action = draw(
        st.sampled_from(["supply_missing_input", "work_open_findings", "request_receipt"])
    )
    if draw(st.booleans()):
        envelope["overall_next"] = {
            "action": action,
            "status": draw(st.sampled_from(["action_required", "ready_with_limitations", "ready"])),
            "acknowledged_incomplete_endpoint": draw(st.sampled_from(["receipt", None])),
            "target_refs": refs if action != "request_receipt" else [],
        }
    if draw(st.booleans()):
        envelope["semantic_route_required"] = False
    if draw(st.booleans()):
        envelope["observations_awaited"] = draw(
            st.sampled_from(
                [
                    {"state": "complete"},
                    {"state": "unavailable"},
                    {"state": "bounded_timeout", "pending_count": "123456"},
                ]
            )
        )
    if draw(st.booleans()):
        envelope["children"] = {"label": "recorded", "items": [{}] * draw(st.integers(0, 64))}
    if draw(st.booleans()):
        envelope["advisory_notes"] = [{}] * draw(st.integers(1, 8))
    if draw(st.booleans()):
        envelope["finding_checklist"] = {
            "attempt_budget": str(draw(st.integers(1, 50))),
            "counts": {
                key: draw(_COUNT)
                for key in (
                    "open",
                    "open_at_budget",
                    "verified_resolved",
                    "acknowledged_not_done",
                    "rejection_accepted",
                    "self_verified",
                    "disputed_after_rebuttal",
                )
            },
            "next": draw(
                st.sampled_from(["decide_at_budget", "request_receipt", "work_open_findings"])
            ),
        }
    if draw(st.booleans()):
        envelope["missing_for_assessment"] = [
            {
                "kind": draw(
                    st.sampled_from(
                        ["command_identity", "current_diff_for_path", "other", "task_statement"]
                    )
                ),
                "availability": draw(
                    st.sampled_from(
                        [
                            "agent_suppliable",
                            "yoetz_limit_packet_room",
                            "yoetz_limit_unsupported_data_type",
                        ]
                    )
                ),
                "target_refs": draw(st.lists(_OBLIGATION_ID, max_size=4)),
            }
            for _ in range(draw(st.integers(1, 12)))
        ]
    if draw(st.booleans()):
        envelope["semantic_redacted_values"] = [
            {"item_id": f"item-{index}", "disposition": "value_replaced", "lines": [index + 1]}
            for index in range(draw(st.integers(1, 20)))
        ]
    if draw(st.booleans()):
        envelope["semantic_withheld_items"] = [
            {"item_id": f"item-{index}", "reason": "never_send_heuristic"}
            for index in range(draw(st.integers(1, 20)))
        ]
    return envelope


@st.composite
def status_envelopes(draw: st.DrawFn) -> dict[str, Any]:
    view = draw(
        st.sampled_from(
            [
                "compact",
                "obligations",
                "evidence",
                "findings",
                "candidate_findings",
                "results",
                "history",
                "advice",
                "versions",
                "operation",
                "lineage",
                "project",
            ]
        )
    )
    items: list[dict[str, Any]] = [
        {
            "finding_id": draw(_FINDING_ID),
            "obligation_id": draw(_OBLIGATION_ID),
            "finding_frontier": draw(_FRONTIER),
            "publication_channel": draw(st.sampled_from(["hook_observed", "local_cli", "x"])),
            "freshness": "current",
            "open_obligations": [
                {"obligation_id": ref} for ref in draw(st.lists(_OBLIGATION_ID, max_size=64))
            ],
        }
        for _ in range(draw(st.integers(0, 40)))
    ]
    envelope: dict[str, Any] = {
        "view": view,
        "head_frontier": draw(_FRONTIER),
        "gaps": draw(st.lists(_GAP, max_size=64)),
        "page": {
            "items": items,
            "next_cursor": draw(st.sampled_from([None, "cur"])),
            "attempt_budget": "5",
            "lineage": {"children": [{}] * draw(st.integers(0, 64)), "annotations": []},
            "members": [{}] * draw(st.integers(0, 64)),
        },
    }
    if draw(st.booleans()):
        envelope["closure_readiness"] = {
            "state": draw(st.sampled_from(READINESS_STATES)),
            "open_obligation_count": draw(_COUNT),
            "unanswered_finding_count": draw(_COUNT),
            "receipt_blocking_finding_count": draw(_COUNT),
            "acknowledged_obligation_count": draw(_COUNT),
            "acknowledged_not_done_count": draw(_COUNT),
            "agent_actionable": draw(st.lists(_GAP, max_size=64)),
            "standing_limitations": draw(st.lists(_GAP, max_size=64)),
            "limitation_refs_required_count": draw(st.integers(0, 70).map(str)),
            "limitation_refs_required": [
                f"res_{n:08x}-0000-4000-8000-{n:012x}" for n in range(draw(st.integers(0, 64)))
            ],
        }
    return envelope


@st.composite
def receipt_envelopes(draw: st.DrawFn) -> dict[str, Any]:
    return {
        "receipt_id": "rcp_00000000-0000-4000-8000-000000000001",
        "conclusion": draw(
            st.sampled_from(
                [
                    "unresolved_findings_remain",
                    "insufficient_coverage",
                    "no_unresolved_deterministic_findings",
                ]
            )
        ),
        "frontier": draw(_FRONTIER),
        "suppressed_finding_count": draw(_COUNT),
        "coverage": {"known_gaps": draw(st.lists(_GAP, max_size=64))},
        "obligations": [
            {"obligation_id": ref, "status": "open"}
            for ref in draw(st.lists(_OBLIGATION_ID, max_size=100, unique=True))
        ],
    }


@st.composite
def error_envelopes(draw: st.DrawFn) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if draw(st.booleans()):
        details["reason_code"] = draw(st.sampled_from(sorted(PROTOCOL_REASON_CODES)))
    if draw(st.booleans()):
        details["continuation"] = draw(st.sampled_from(sorted(CONTINUATION_TOKENS)))
    if draw(st.booleans()):
        details["field"] = "/" + "/".join(draw(st.lists(_TOKEN, min_size=1, max_size=6)))
    if draw(st.booleans()):
        count = draw(st.integers(1, 30))
        details["fields"] = [f"/event_drafts/{index}/payload/outcome" for index in range(count)]
        details["reasons"] = ["invalid_type_or_value"] * count
    if draw(st.booleans()):
        details["blocking_reasons"] = draw(st.lists(_TOKEN, min_size=1, max_size=32))
    if draw(st.booleans()):
        details["invariant"] = draw(_TOKEN)
    if draw(st.booleans()):
        details["repair_kind"] = "field_ownership"
        details["repair_field"] = draw(_TOKEN)
        details["repair_owning_family"] = draw(_TOKEN)
        details["repair_selected_family"] = draw(_TOKEN)
    for key in draw(st.lists(st.sampled_from(SAFE_DETAIL_KEYS), max_size=6)):
        details.setdefault(key, draw(_TOKEN))
    return {
        "ok": False,
        "error": {
            "code": draw(st.sampled_from([item.value for item in PublicErrorCode])),
            "retryable": draw(st.booleans()),
            "correlation_id": "err_00000000-0000-4000-8000-000000000001",
            "safe_details": details,
        },
    }


_BOUNDED = settings(
    max_examples=120,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


def _prop(envelope: dict[str, Any], limit: int) -> str:
    with mock.patch.object(summaries, "_MAX_SUMMARY_BYTES", limit):
        rendered = render_safe_compact_summary_detailed(envelope)
    assert rendered.failures == (), rendered.failures
    assert rendered.text.isascii()
    assert len(rendered.text.encode("ascii")) <= limit
    return rendered.text


@pytest.mark.parametrize("limit", [MAX_SUMMARY_BYTES, 512])
@pytest.mark.parametrize(
    "strategy",
    [check_envelopes(), status_envelopes(), receipt_envelopes(), error_envelopes()],
    ids=["check", "status", "receipt", "error"],
)
def test_every_builder_stays_in_its_bound_ascii_and_unraised(
    strategy: st.SearchStrategy[dict[str, Any]], limit: int
) -> None:
    @_BOUNDED
    @given(strategy)
    def run(envelope: dict[str, Any]) -> None:
        _prop(envelope, limit)

    run()


@_BOUNDED
@given(check_envelopes())
def test_the_check_core_survives_whatever_optional_fields_arrive(
    envelope: dict[str, Any],
) -> None:
    """The verdict, review outcome's contracted wording and frontier digest always show."""

    text = _prop(envelope, MAX_SUMMARY_BYTES)
    scoped = (
        envelope["verdict"] == "no_issue_detected"
        and envelope["semantic_status"] == "not_requested"
        and envelope["semantic_reason"] == "deterministic_mode"
    )
    assert ("No issue detected within local coverage" if scoped else envelope["verdict"]) in text
    # INTERFACES names fixed prose for pre-edit deferral and coordinator failure; those
    # outcomes deliberately replace the generic status/reason clause.
    if envelope["semantic_reason"] == "coordinator_failure":
        assert COORDINATOR_FAILURE_LIMITATION in text
    elif (
        envelope["semantic_reason"] == "deferred_before_first_edit"
        or SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP in envelope["coverage"]["known_gaps"]
    ):
        assert DEFERRED_BEFORE_FIRST_EDIT_TEXT in text
    else:
        assert (
            f"AI-powered review status/reason: {envelope['semantic_status']}/"
            f"{envelope['semantic_reason']}"
        ) in text
    frontier = envelope["result_frontier"]
    assert f"frontier: {frontier['sequence']}" in text
    if frontier["head_digest"].startswith("sha256:") or frontier["head_digest"] == "genesis":
        assert frontier["head_digest"] in text


@_BOUNDED
@given(error_envelopes())
def test_the_error_identity_and_the_reason_always_show(envelope: dict[str, Any]) -> None:
    text = _prop(envelope, 512)
    error = envelope["error"]
    assert f"Error {error['code']}; retryable: {'yes' if error['retryable'] else 'no'}" in text
    assert error["correlation_id"] in text


def test_every_reason_code_and_continuation_renders_within_the_bound() -> None:
    """Every enum value, not a sample: all reason codes and all continuation tokens."""

    for reason in sorted(PROTOCOL_REASON_CODES):
        for details in ({"reason_code": reason}, {"reason_code": reason, "field": "/uri"}):
            envelope = {
                "ok": False,
                "error": {
                    "code": "INVALID_REQUEST",
                    "retryable": False,
                    "correlation_id": "err_00000000-0000-4000-8000-000000000001",
                    "safe_details": details,
                },
            }
            for limit in (MAX_SUMMARY_BYTES, 512):
                _prop(envelope, limit)
    for token in sorted(CONTINUATION_TOKENS):
        envelope = {
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "retryable": True,
                "correlation_id": "err_00000000-0000-4000-8000-000000000001",
                "safe_details": {"continuation": token},
            },
        }
        for limit in (MAX_SUMMARY_BYTES, 512):
            _prop(envelope, limit)


def test_every_semantic_status_reason_pair_renders_within_the_bound() -> None:
    builders: list[Callable[[dict[str, Any]], str]] = [render_safe_compact_summary]
    for status in _CHECK_STATUSES:
        for reason in _CHECK_REASONS:
            for verdict in (item.value for item in CheckVerdict):
                envelope: dict[str, Any] = {
                    "verdict": verdict,
                    "findings": [],
                    "suppressed_count": "0",
                    "semantic_status": status,
                    "semantic_reason": reason,
                    "result_frontier": {"sequence": "5", "head_digest": "genesis"},
                    "overall_next": {
                        "action": "request_receipt",
                        "status": "ready_with_limitations",
                        "acknowledged_incomplete_endpoint": "receipt",
                        "target_refs": [],
                    },
                }
                for build in builders:
                    text = build(envelope)
                    assert text.isascii() and len(text) <= MAX_SUMMARY_BYTES
