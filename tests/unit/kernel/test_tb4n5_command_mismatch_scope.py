"""A command mismatch refuses ``self_verified`` only on findings it is about (tb4n5, #1049).

Two tb4n5 refusals listed ``coverage:command_attempt_mismatch``:

* formal-crypto S: a ``requested_item_never_attempted`` finding about the obligation whose
  requested Sage command was linked to an observed run of another command. The mismatch is about
  that finding: the refusal stands, and the attempt cleared it by publishing the PL6-3 link.
* react-lead-form S: an ``action_without_result`` finding about an edit action that named no
  obligation and asserted no command item, while the mismatch sat on a command obligation that
  cited one observed ``npm run submit`` run for its ``npm test`` and ``npm run build`` items. The
  mismatch says nothing about that action, yet it refused ``self_verified``.

``command_attempt_mismatch`` is keyed per obligation and item (``kernel.command_attempts``), so the
scope rule of ``kernel.task_fact_scope`` now applies to it, and a refusal names the mismatched
obligation, item and linked run.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from builders.policy_cases import finding_record, fnd
from yoetz.application.respond import self_verification_refusal_message
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    finding_policy_identity,
)
from yoetz.domain.values import EventId, Frontier, ObligationId, ResultId, action_id, obligation_id
from yoetz.kernel import self_verification
from yoetz.kernel.finding_resolution import ResolutionAttempt
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_fact_scope import (
    command_mismatch_bears_on_finding,
    command_mismatches,
    command_mismatches_for_finding,
    scoped_resolution_reasons,
)
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_COMMANDS: ObligationId = obligation_id("obl_00000000-0000-4000-8000-000000000a01")
_FORM: ObligationId = obligation_id("obl_00000000-0000-4000-8000-000000000a02")
_OBLIGATION = EventSchema("obligation_published", "1.0.0")
_ACTION = EventSchema("action_recorded", "1.0.0")
_MISMATCH = "coverage:command_attempt_mismatch"
_DIGEST = "sha256:" + "e" * 64


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _commands(status: ObligationStatus, resolution: tuple[ResultId, ...] = ()) -> object:
    return ObligationPublishedPayload(
        obligation_id=_COMMANDS,
        description="The test suite and the build pass",
        evidence_expectation="Observed npm runs",
        status=status,
        requested_items=(
            RequestedItem(RequestedItemKind.COMMAND, "npm test"),
            RequestedItem(RequestedItemKind.COMMAND, "npm run build"),
        ),
        resolution_evidence_refs=resolution,
    )


def _react_s() -> tuple[ObservedLedger, dict[str, EventId]]:
    """The react-lead-form S shape at its refusal (call 48)."""

    ledger = ObservedLedger()
    ledger.append(_OBLIGATION, _commands(ObligationStatus.OPEN), observed=False)  # type: ignore[arg-type]
    ledger.append(
        _OBLIGATION,
        ObligationPublishedPayload(
            obligation_id=_FORM,
            description="The form keeps the exact labels",
            evidence_expectation="A reviewed diff",
            status=ObligationStatus.OPEN,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_COMMANDS, _FORM)),
        observed=False,
    )
    submit = ledger.passes("npm run submit")
    observed_run = ledger.records[-2].event_id
    # A global review action asserting both command items (react S act_300ac445).
    review = ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000b01"),
            ActionKind.REVIEW,
            "Reviewed the test, build and submit runs",
            attempted_items=("npm test", "npm run build"),
        ),
        observed=False,
    )
    # The edit action that named no obligation and asserted only files (act_ad8faa35).
    edit = ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000b02"),
            ActionKind.EDIT,
            "Implemented the ledger reconciliation",
            attempted_items=("/app/src/lib/submitLead.ts",),
        ),
        observed=False,
    )
    # The command obligation resolved with one observed run for both items: the mismatch.
    ledger.append(
        _OBLIGATION,
        _commands(ObligationStatus.RESOLVED, (submit,)),  # type: ignore[arg-type]
        observed=False,
    )
    return ledger, {"observed_run": observed_run, "review": review, "edit": edit}


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


def _with_finding(state: ProjectionState, kind: FindingKind, subject: str) -> ProjectionState:
    finding = Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="Synthetic finding.",
        detail="Synthetic detail.",
        subject_refs=(subject,),  # type: ignore[arg-type]
        policy_id=finding_policy_identity(kind)[0],
        policy_version=finding_policy_identity(kind)[1],
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
        provenance=None,
    )
    return replace(state, findings={fnd(1): finding_record(finding, state.frontier)})


def test_the_mismatch_rows_name_the_obligation_items_and_the_linked_run() -> None:
    ledger, events = _react_s()
    rows = command_mismatches(replay(ledger.prefix), ledger.prefix)
    assert [(row.obligation_id, row.item_index) for row in rows] == [
        (_COMMANDS, 0),
        (_COMMANDS, 1),
    ]
    for row in rows:
        assert row.observed_event_ids == (str(events["observed_run"]),)
        assert row.asserted_action_ids == ("act_00000000-0000-4000-8000-000000000b01",)


@pytest.mark.parametrize(
    ("kind", "subject", "bears"),
    [
        # react S: an edit action that named no obligation and asserted no command item.
        (FindingKind.ACTION_WITHOUT_RESULT, "edit", False),
        # An unrelated obligation.
        (FindingKind.TASK_REQUIREMENT_UNMET, str(_FORM), False),
        # formal S: the mismatched obligation itself.
        (FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED, str(_COMMANDS), True),
        # The action that asserted the mismatched item, and the linked observed run.
        (FindingKind.ACTION_WITHOUT_RESULT, "review", True),
        (FindingKind.CODE_DEFECT, "observed_run", True),
    ],
)
def test_a_mismatch_bears_only_on_findings_about_its_relation(
    kind: FindingKind, subject: str, bears: bool
) -> None:
    ledger, events = _react_s()
    state = replay(ledger.prefix)
    reference = str(events[subject]) if subject in events else subject
    state = _with_finding(state, kind, reference)
    rows = command_mismatches(state, ledger.prefix)
    assert command_mismatch_bears_on_finding(state, fnd(1), rows) is bears
    reasons = ("command_relation_independence_unproven", _MISMATCH, "coverage:truncated_payload")
    scoped = scoped_resolution_reasons(
        reasons, state=state, finding_id=fnd(1), records=ledger.prefix
    )
    assert (_MISMATCH in scoped) is bears


def test_a_mismatch_the_prefix_cannot_locate_bears() -> None:
    """Once the link is repaired the rows are gone, but the check that listed it still did."""

    ledger, events = _react_s()
    state = _with_finding(
        replay(ledger.prefix), FindingKind.ACTION_WITHOUT_RESULT, str(events["edit"])
    )
    assert command_mismatch_bears_on_finding(state, fnd(1), ())


def _attempt(reasons: tuple[str, ...]) -> ResolutionAttempt:
    return ResolutionAttempt(
        check_event_id=EventId("evt_00000000-0000-4000-8000-000000000990"),
        newest_check_event_id=EventId("evt_00000000-0000-4000-8000-000000000990"),
        could_resolve=False,
        subject_sequence=10,
        reasons=reasons,
    )


def test_react_s_is_self_verifiable_and_formal_s_is_refused_naming_the_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reasons = ("command_relation_independence_unproven", _MISMATCH, "coverage:truncated_payload")
    monkeypatch.setattr(
        self_verification,
        "finding_resolution_attempt",
        lambda *_args: _attempt(reasons),  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
    )
    ledger, events = _react_s()
    records = ledger.prefix
    state = replay(records)

    react = _with_finding(state, FindingKind.ACTION_WITHOUT_RESULT, str(events["edit"]))
    assert self_verification.self_verification_refusal(react, fnd(1), records) is None

    formal = _with_finding(state, FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED, str(_COMMANDS))
    assert (
        self_verification.self_verification_refusal(formal, fnd(1), records)
        == self_verification.FINDING_NOT_PROOF_LIMITED
    )
    blocking = self_verification.self_verification_blocking_reasons(formal, fnd(1), records)
    assert blocking == (_MISMATCH,)
    rows = command_mismatches_for_finding(formal, fnd(1), command_mismatches(formal, records))
    message = self_verification_refusal_message(blocking, command_mismatches=rows)
    assert f"{_COMMANDS} requested item 0" in message
    assert f"{_COMMANDS} requested item 1" in message
    assert str(events["observed_run"]) in message
    assert "act_00000000-0000-4000-8000-000000000b01" in message
    assert "action_kind command, attempted_items holding that item's exact value" in message
    # The command text is the agent's and is never named.
    assert "npm" not in message
    assert len(message.encode("utf-8")) <= 4096
