"""Advisory identities/prose stay in the existing privacy and bounded-wire contracts."""

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.domain.correctness_advisories import validate_advisories, validate_advisory_response
from finishup.domain.events import LedgerRecord
from finishup.domain.values import JsonObject
from finishup.kernel.correctness_advisories import (
    CorrectnessAdvisoryIndex,
    advisory_summary,
    correctness_advisory_index,
)
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


_CHECK_EVENT = "evt_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000009"


def _noted_check(notes: int) -> SimpleNamespace:
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
        correctness_advisories=tuple(
            JsonObject({"summary": f"Concern {n}", "detail": "Advice", "subject_refs": ()})
            for n in range(1, notes + 1)
        ),
    )
    assert isinstance(checked, CheckRecordedPayload)
    return SimpleNamespace(payload=checked, event_id=_CHECK_EVENT, session_id=_SESSION)


def _withheld(
    seed: int, *, version: str = "1.1.0", parents: tuple[str, ...] = (_CHECK_EVENT,)
) -> SimpleNamespace:
    return SimpleNamespace(
        payload=None,
        event_id=f"evt_00000000-0000-4000-8000-{seed:012d}",
        schema=SimpleNamespace(name="decision_recorded", version=version),
        causal_parents=parents,
    )


def _answer(
    seed: int, ordinal: int, disposition: str = "declined", *, check: str = _CHECK_EVENT
) -> SimpleNamespace:
    from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT
    from finishup.domain.events import DecisionRecordedPayload
    from finishup.domain.values import actor_id

    return SimpleNamespace(
        payload=DecisionRecordedPayload(
            statement=ADVISORY_RESPONSE_STATEMENT,
            rationale=f"Readable reason {seed}",
            authority=actor_id("harness:test"),
            advisory_response=JsonObject(
                {
                    "advisory_id": f"{check}:{ordinal}",
                    "disposition": disposition,
                    "evidence_refs": (),
                }
            ),
        ),
        event_id=f"evt_00000000-0000-4000-8000-{seed:012d}",
        schema=SimpleNamespace(name="decision_recorded", version="1.1.0"),
        causal_parents=(check,),
    )


def _index(*records: SimpleNamespace) -> CorrectnessAdvisoryIndex:
    return correctness_advisory_index(cast(tuple[LedgerRecord, ...], records))


def test_a_withheld_decision_is_disclosed_as_one_that_may_answer_a_note() -> None:
    """#1162 review: a withheld payload hides whether the decision is a response at all.

    A review-mode switch whose only parent is the check has the same envelope as an advisory
    response once its payload is withheld, so it is never attached to a note (never shown as that
    note's response) and never called silence: it is counted as one that may answer a note.
    """

    from finishup.domain.correctness_advisories import validate_advisory_counts
    from finishup.kernel.correctness_advisories import advisory_closing_text, advisory_counts

    single = _index(_noted_check(1), _withheld(9))
    assert single.rows[0].response is None
    assert single.rows[0].disposition == "no recorded response"
    assert single.unmatched_withheld == 1
    assert dict(advisory_counts(single).items()) == {
        "total": "1",
        "no_recorded_response": "1",
        "withheld_may_answer": "1",
    }
    summary = advisory_summary(single.rows, unmatched_withheld=single.unmatched_withheld)
    assert "no recorded response: 1" in summary
    assert "Withheld decisions that may answer a note: 1" in summary

    index = _index(_noted_check(3), _answer(7, 1), _withheld(8))
    assert [row.disposition for row in index.rows] == [
        "declined",
        "no recorded response",
        "no recorded response",
    ]
    # The readable answer stays attached to the note it names; no note gains the withheld one.
    assert str(cast(SimpleNamespace, index.rows[0].response).event_id).endswith("000000000007")
    assert all(row.response is None for row in index.rows[1:])
    assert index.unmatched_withheld == 1
    counts = advisory_counts(index)
    validate_advisory_counts(counts)
    assert dict(counts.items()) == {
        "total": "3",
        "no_recorded_response": "2",
        "withheld_may_answer": "1",
    }
    # Readiness names only what is still open: the two unanswered notes, newest first.
    closing = advisory_closing_text(index.rows)
    assert f"no recorded response: 2, newest {_CHECK_EVENT}:3, {_CHECK_EVENT}:2." in closing
    assert f"{_CHECK_EVENT}:1" not in closing
    # More withheld decisions than unanswered notes never count past those notes.
    capped = _index(_noted_check(2), _answer(7, 1), _withheld(8), _withheld(9), _withheld(10))
    assert capped.unmatched_withheld == 1
    # Once every note has a readable answer, a withheld decision cannot answer an open note.
    answered = _index(_noted_check(2), _answer(7, 1), _answer(8, 2), _withheld(9))
    assert answered.unmatched_withheld == 0
    assert [row.disposition for row in answered.rows] == ["declined", "declined"]


def test_readiness_text_changes_exactly_when_the_unanswered_set_does() -> None:
    """#1162 review: the Stop notice is shown once per set of unanswered notes.

    The hook compares the readiness text, never parses it, so the text must be a function of
    that set alone: unchanged by answers to other notes, withheld decisions or answered additions,
    and changed by a new unanswered note or an answer to an open one.
    """

    from finishup.kernel.correctness_advisories import advisory_closing_text

    later_check = "evt_00000000-0000-4000-8000-000000000021"
    later = SimpleNamespace(
        payload=_noted_check(1).payload, event_id=later_check, session_id=_SESSION
    )

    def text(*records: SimpleNamespace) -> str:
        return advisory_closing_text(_index(*records).rows)

    open_two = text(_noted_check(2))
    # A withheld decision may answer a note but does not change which notes are unanswered.
    assert text(_noted_check(2), _withheld(9)) == open_two
    # A later check whose note was already answered adds nothing to the open set.
    assert text(_noted_check(2), later, _answer(11, 1, check=later_check)) == open_two
    # An answer to an open note, or a new open note, changes it.
    assert text(_noted_check(2), _answer(7, 1)) != open_two
    assert text(_noted_check(2), later) != open_two
    assert f"newest {later_check}:1, {_CHECK_EVENT}:2" in text(_noted_check(2), later)


def test_the_history_continuation_names_each_recording_session() -> None:
    """#1162 review: history is session-scoped, so the continuation says which session to read."""

    rows = _index(_noted_check(2)).rows
    summary = advisory_summary(rows)
    assert f"with session_id {_SESSION} (follow next_cursor)" in summary


def test_a_withheld_decision_never_replaces_a_readable_disposition() -> None:
    index = _index(_noted_check(1), _answer(7, 1, "declined"), _withheld(8))
    assert index.rows[0].disposition == "declined"
    assert str(cast(SimpleNamespace, index.rows[0].response).event_id).endswith("000000000007")
    assert index.unmatched_withheld == 0
    # A later readable answer still replaces the displayed one (the agent's latest account).
    later = _index(_noted_check(1), _withheld(8), _answer(9, 1, "declined"))
    assert str(cast(SimpleNamespace, later.rows[0].response).event_id).endswith("000000000009")


@pytest.mark.parametrize(
    "withheld",
    (
        _withheld(8, version="1.0.0"),
        _withheld(8, parents=()),
        _withheld(8, parents=(_CHECK_EVENT, "evt_00000000-0000-4000-8000-000000000002")),
        _withheld(8, parents=("evt_00000000-0000-4000-8000-000000000002",)),
    ),
)
def test_only_an_advisory_shaped_withheld_decision_can_be_a_response(
    withheld: SimpleNamespace,
) -> None:
    # Released 1.0.0 decisions cannot carry an advisory response, and every advisory response
    # names exactly its check as its only causal parent.
    index = _index(_noted_check(2), withheld)
    assert [row.disposition for row in index.rows] == ["no recorded response"] * 2
    assert index.unmatched_withheld == 0


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
        SimpleNamespace(
            payload=checked,
            event_id="evt_00000000-0000-4000-8000-000000000001",
            session_id=_SESSION,
        ),
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
            session_id=_SESSION,
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
