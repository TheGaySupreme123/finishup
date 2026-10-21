"""Advisory identities/prose stay in the existing privacy and bounded-wire contracts."""

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.domain.correctness_advisories import validate_advisories, validate_advisory_response
from finishup.domain.events import LedgerRecord
from finishup.domain.values import JsonObject
from finishup.kernel.correctness_advisories import advisory_summary, correctness_advisories
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import DataCategory, classify_result_leaf


@pytest.mark.parametrize("field", ("summary", "detail", "reason"))
def test_advisory_history_prose_keeps_finding_summary_policy(field: str) -> None:
    from finishup.protocol.canonical import JsonValue

    body = cast(
        dict[str, JsonValue],
        {
            "ok": True,
            "view": "history",
            "page": {
                "items": [
                    {
                        "correctness_advisories": [
                            {
                                field: "Private prose",
                                "advisory_id": "evt_00000000-0000-4000-8000-000000000001:1",
                                "unregistered_text": "private",
                            }
                        ]
                    }
                ]
            },
        },
    )
    assert (
        classify_result_leaf("status", body, f"/page/items/0/correctness_advisories/0/{field}")
        is DataCategory.FINDING_SUMMARY
    )
    assert (
        classify_result_leaf("status", body, "/page/items/0/correctness_advisories/0/advisory_id")
        == "public_structural"
    )
    with pytest.raises(ProtocolValueError):
        classify_result_leaf(
            "status", body, "/page/items/0/correctness_advisories/0/unregistered_text"
        )


@pytest.mark.parametrize("refs", (("private/path.txt",), ("evt_" + "x" * 36,)))
def test_untrusted_content_cannot_become_advisory_structural_refs(refs: tuple[str, ...]) -> None:
    with pytest.raises(ProtocolValueError):
        validate_advisories(
            (JsonObject({"summary": "Concern", "detail": "Advice", "subject_refs": refs}),)
        )


def test_advisory_prose_bounds_are_utf8_bytes() -> None:
    row = JsonObject({"summary": "Concern", "detail": "界" * 3000, "subject_refs": ()})
    with pytest.raises(ProtocolValueError):
        validate_advisories((row,))
    with pytest.raises(ProtocolValueError):
        validate_advisories(tuple(row for _ in range(11)))
    with pytest.raises(ProtocolValueError):
        validate_advisory_response(
            JsonObject(
                {
                    "advisory_id": "evt_00000000-0000-4000-8000-000000000001:1",
                    "disposition": "addressed",
                    "evidence_refs": (),
                }
            )
        )


@pytest.mark.parametrize("reason", (" ", "界" * 1400))
def test_advisory_decisions_cannot_bypass_response_reason_bounds(reason: str) -> None:
    from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT
    from finishup.domain.events import DecisionRecordedPayload
    from finishup.domain.values import actor_id

    with pytest.raises(ProtocolValueError):
        DecisionRecordedPayload(
            statement=ADVISORY_RESPONSE_STATEMENT,
            rationale=reason,
            authority=actor_id("actor_agent"),
            advisory_response=JsonObject(
                {
                    "advisory_id": "evt_00000000-0000-4000-8000-000000000001:1",
                    "disposition": "declined",
                    "evidence_refs": (),
                }
            ),
        )


def test_redacted_response_is_never_inferred_to_be_no_response() -> None:
    # Indexing tests use a minimal immutable check stand-in; the event codec is covered by the
    # schema and memory/SQLite workflow tests.
    from tests.unit.kernel.test_receipt_builder import (  # pyright: ignore[reportPrivateUsage]
        _check,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.domain.events import CheckRecordedPayload
    from finishup.domain.findings import CheckVerdict

    checked = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
        correctness_advisories=(
            JsonObject({"summary": "Concern", "detail": "Advice", "subject_refs": ()}),
        ),
    )
    assert isinstance(checked, CheckRecordedPayload)
    check = SimpleNamespace(payload=checked, event_id="evt_00000000-0000-4000-8000-000000000001")
    redacted = SimpleNamespace(
        payload=None,
        schema=SimpleNamespace(name="decision_recorded"),
        causal_parents=(check.event_id,),
    )
    rows = correctness_advisories(cast(tuple[LedgerRecord, ...], (check, redacted)))
    assert rows[0].disposition == "response_unavailable"
    assert "no recorded response: 0" in advisory_summary(rows)


def test_receipt_advisory_prose_has_a_task_wide_bound_and_retrieval_marker() -> None:
    from tests.unit.kernel.test_receipt_builder import (
        _check,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.domain.findings import CheckVerdict
    from finishup.domain.receipts import ReceiptRedactionProfile
    from finishup.kernel.correctness_advisories import CorrectnessAdvisory, receipt_advisory_items

    concern = JsonObject({"summary": "Geometry concern", "detail": "x" * 8192, "subject_refs": ()})
    checked = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())
    record = cast(
        LedgerRecord,
        SimpleNamespace(payload=checked, event_id="evt_00000000-0000-4000-8000-000000000001"),
    )
    rows = tuple(
        CorrectnessAdvisory(f"{record.event_id}:{n}", record, concern) for n in range(1, 6)
    )
    items, omitted = receipt_advisory_items(rows, ReceiptRedactionProfile.FULL_LOCAL)
    assert sum(map(len, items)) <= 8192
    assert omitted == 4
    assert "advisory detail cut; retrieve history" in items[0]


@pytest.mark.parametrize("profile", ("full_local", "default_local_export", "redacted_share"))
def test_addressed_advice_keeps_evidence_links_when_export_withholds_prose(profile: str) -> None:
    from tests.unit.kernel.test_receipt_builder import (
        _check,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT
    from finishup.domain.events import DecisionRecordedPayload
    from finishup.domain.findings import CheckVerdict
    from finishup.domain.receipts import ReceiptRedactionProfile
    from finishup.domain.values import actor_id
    from finishup.kernel.correctness_advisories import CorrectnessAdvisory, advisory_item

    target = "evt_00000000-0000-4000-8000-000000000001:1"
    evidence = "res_00000000-0000-4000-8000-000000000002"
    checked = cast(
        LedgerRecord,
        SimpleNamespace(
            payload=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
            event_id=target.split(":")[0],
        ),
    )
    response = cast(
        LedgerRecord,
        SimpleNamespace(
            event_id="evt_00000000-0000-4000-8000-000000000003",
            payload=DecisionRecordedPayload(
                statement=ADVISORY_RESPONSE_STATEMENT,
                rationale="Private response prose",
                authority=actor_id("harness:test"),
                advisory_response=JsonObject(
                    {
                        "advisory_id": target,
                        "disposition": "addressed",
                        "evidence_refs": (evidence,),
                    }
                ),
            ),
        ),
    )
    row = CorrectnessAdvisory(
        target,
        checked,
        JsonObject({"summary": "Private concern prose", "detail": "Detail", "subject_refs": ()}),
        response,
    )
    text = advisory_item(row, ReceiptRedactionProfile(profile))
    assert "addressed (agent-reported, linked evidence)" in text and evidence in text
    if profile == "full_local":
        assert "Private concern prose" in text and "Private response prose" in text
    else:
        assert "Private concern prose" not in text and "Private response prose" not in text
        assert "withheld" in text
