"""Task facts from hook observations and the ledger (issue #977)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
)
from yoetz.domain.values import EventId, ObligationId, action_id, actor_id, obligation_id
from yoetz.kernel.closure_readiness import (
    GAP_CLASSIFICATION,
    GapClass,
    closure_readiness_facts,
    derive_closure_readiness,
)
from yoetz.kernel.observed_failures import (
    observed_action_description,
    observed_action_runner_class,
    observed_action_runtime_tokens,
    observed_action_tool,
    observed_event_ids_from_records,
)
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    INSTALL_INTO_PRIVATE_ENV_GAP,
    INSTALL_INTO_YOETZ_RUNTIME_GAP,
    OBLIGATION_BLOCKED_GAP,
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
    PLANNED_VERIFICATION_AGENT_LINKED_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    REQUESTED_OUTPUT_UNVERIFIED_GAP,
    STANDING_TASK_FACT_GAPS,
    TASK_FACT_GAPS,
    VERIFICATION_ONLY_AS_ROOT_GAP,
    WRITE_OUTSIDE_WORKSPACE_GAP,
    RequestedOutputState,
    acting_started,
    blocked_obligations,
    blocker_declarations,
    confirmed_blocked_obligation_ids,
    cooperative_event_ids_from_records,
    decision_batches,
    register_command_identity_key,
    requested_output_facts,
    task_fact_signals,
)

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_OBLIGATION_SCHEMA = EventSchema("obligation_published", "1.0.0")
_PLAN_SCHEMA = EventSchema("plan_published", "1.0.0")
_DECISION_SCHEMA = EventSchema("decision_recorded", "1.0.0")
_ACTION_SCHEMA = EventSchema("action_recorded", "1.0.0")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _planned(
    ledger: ObservedLedger,
    *items: RequestedItem,
    obligation: ObligationId = _OBLIGATION,
    status: ObligationStatus = ObligationStatus.OPEN,
) -> None:
    ledger.append(
        _OBLIGATION_SCHEMA,
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Synthetic obligation",
            evidence_expectation="Observed run",
            status=status,
            requested_items=items,
        ),
        observed=False,
    )


def _plan(ledger: ObservedLedger, *obligations: ObligationId) -> None:
    ledger.append(
        _PLAN_SCHEMA,
        PlanPublishedPayload(1, "Plan", tuple(sorted(obligations))),
        observed=False,
    )


def _command(value: str) -> RequestedItem:
    return RequestedItem(RequestedItemKind.COMMAND, value)


def _codes(ledger: ObservedLedger) -> set[str]:
    prefix = ledger.prefix
    return set(task_fact_signals(replay(prefix), prefix).codes)


def _markers(ledger: ObservedLedger) -> set[tuple[str, ObligationId | None]]:
    prefix = ledger.prefix
    return set(task_fact_signals(replay(prefix), prefix).markers)


def test_every_task_fact_code_is_classified_once() -> None:
    assert AGENT_ACTIONABLE_TASK_FACT_GAPS.isdisjoint(STANDING_TASK_FACT_GAPS)
    for code in AGENT_ACTIONABLE_TASK_FACT_GAPS:
        assert GAP_CLASSIFICATION[code] is GapClass.AGENT_ACTIONABLE
    for code in STANDING_TASK_FACT_GAPS:
        assert GAP_CLASSIFICATION[code] is GapClass.STANDING_LIMITATION
    assert TASK_FACT_GAPS == AGENT_ACTIONABLE_TASK_FACT_GAPS | STANDING_TASK_FACT_GAPS


def test_planned_verification_never_observed_when_another_command_ran() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q tests/unit"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")

    assert (PLANNED_VERIFICATION_NOT_OBSERVED_GAP, _OBLIGATION) in _markers(ledger)


def test_planned_verification_matches_after_light_normalization_only() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest   -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")

    assert not {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
    } & _codes(ledger)


def test_planned_verification_failed_then_repaired_by_a_passing_rerun() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.fail("pytest -q")
    assert (PLANNED_VERIFICATION_FAILED_GAP, _OBLIGATION) in _markers(ledger)

    ledger.passes("pytest -q")
    assert PLANNED_VERIFICATION_FAILED_GAP not in _codes(ledger)


def test_planned_verification_stale_after_a_later_edit_until_rerun() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")
    ledger.edit()
    assert (PLANNED_VERIFICATION_STALE_GAP, _OBLIGATION) in _markers(ledger)

    ledger.passes("pytest -q")
    assert PLANNED_VERIFICATION_STALE_GAP not in _codes(ledger)


def test_failed_edit_does_not_make_verification_stale() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")
    ledger.edit(ResultOutcome.FAILURE)

    assert PLANNED_VERIFICATION_STALE_GAP not in _codes(ledger)


def test_unknown_outcome_is_disclosed_not_gated() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("bash run.sh"))
    _plan(ledger, _OBLIGATION)
    ledger.run("bash run.sh", ResultOutcome.UNKNOWN)

    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP in codes
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_FAILED_GAP not in codes


def test_without_the_installation_key_no_planned_fact_is_claimed() -> None:
    register_command_identity_key(None)
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -k other")

    assert not any(code.startswith("planned_verification") for code in _codes(ledger))


def test_without_keyed_observed_runs_the_match_is_unobservable() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.run(None, ResultOutcome.SUCCESS, exit_status=0)  # omitted:structural legacy row

    assert (PLANNED_VERIFICATION_UNOBSERVABLE_GAP, _OBLIGATION) in _markers(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in _codes(ledger)


def test_cooperative_runs_never_count_as_observed_verification() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("ls")  # keyed observed command, so matching is observable
    ledger.run("pytest -q", ResultOutcome.SUCCESS, exit_status=0, observed=False)

    assert (PLANNED_VERIFICATION_NOT_OBSERVED_GAP, _OBLIGATION) in _markers(ledger)


def test_edited_after_last_verification_needs_a_prior_verification_run() -> None:
    ledger = ObservedLedger()
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)

    ledger.passes("pytest -q")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    ledger.fail("pytest -q")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)


@pytest.mark.parametrize("scope", ["scratch", "yoetz_owned"])
def test_scratch_and_yoetz_owned_edits_never_make_verification_stale(scope: str) -> None:
    """ADR-042 (tb4n2 R4): pretrain D `/tmp/*.py` scratch, cad S `/app/yoetz_receipt.md`."""

    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")
    ledger.edit(write_scope=scope)
    markers = _markers(ledger)
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    assert (PLANNED_VERIFICATION_STALE_GAP, _OBLIGATION) not in markers

    # A workspace edit (no scope token) and a real outside-workspace edit still count.
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    assert (PLANNED_VERIFICATION_STALE_GAP, _OBLIGATION) in _markers(ledger)
    outside = ObservedLedger()
    outside.passes("pytest -q")
    outside.edit(write_scope="outside_workspace")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(outside)


def test_a_deliverable_the_rule_could_call_scratch_keeps_every_edit_counting() -> None:
    """Codex review round 1: a declared output under /tmp takes precedence over the exemption."""

    ledger = ObservedLedger()
    _planned(ledger, RequestedItem(RequestedItemKind.FILE, "/tmp/out/results.json"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("pytest -q")
    ledger.edit(write_scope="scratch")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_non_executing_pytest_never_clears_staleness() -> None:
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.passes("python -m pytest --version")
    ledger.passes("uv run python /app/dev/build_model.py")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_scratch_edit_alone_is_not_acting() -> None:
    ledger = ObservedLedger()
    ledger.edit(write_scope="scratch")
    prefix = ledger.prefix
    assert not acting_started(
        replay(prefix),
        observed_event_ids_from_records(prefix),
        cooperative_event_ids_from_records(prefix),
    )


def test_python_module_test_run_clears_edited_after_verification() -> None:
    """tb4n2 interleaved S (P1-2): `python -m pytest` after the last edit is a verification run.

    The fact was false in the field: `python -m pytest` classified as `other`, and an early
    `python build_model.py` classified as `build`, so the only "verification" predated the edits.
    """

    ledger = ObservedLedger()
    ledger.passes("python /app/dev/build_model.py")
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    ledger.passes("python -m pytest -q /app/dev/test_cracker.py")
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    ledger.passes("python -m pytest -q /app/dev/test_cracker.py")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)


def test_exploration_runs_are_not_verification_runs() -> None:
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.passes("ls -la")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_runtime_facts_from_observed_descriptions() -> None:
    ledger = ObservedLedger()
    ledger.run(
        "pip install numpy",
        ResultOutcome.SUCCESS,
        exit_status=0,
        install_target="yoetz_runtime",
        effective_user="root",
    )
    ledger.run(
        "pip install pandas",
        ResultOutcome.SUCCESS,
        exit_status=0,
        install_target="private_env",
    )
    ledger.edit(write_outside_workspace=True)
    codes = _codes(ledger)
    assert {
        INSTALL_INTO_YOETZ_RUNTIME_GAP,
        INSTALL_INTO_PRIVATE_ENV_GAP,
        WRITE_OUTSIDE_WORKSPACE_GAP,
    } <= codes
    assert VERIFICATION_ONLY_AS_ROOT_GAP not in codes


def test_workspace_and_system_installs_are_not_reported() -> None:
    ledger = ObservedLedger()
    for target in ("workspace_env", "system", "unresolved"):
        ledger.run("pip install x", ResultOutcome.SUCCESS, exit_status=0, install_target=target)
    assert not {INSTALL_INTO_YOETZ_RUNTIME_GAP, INSTALL_INTO_PRIVATE_ENV_GAP} & _codes(ledger)


def test_verification_only_as_root() -> None:
    ledger = ObservedLedger()
    ledger.run("pytest -q", ResultOutcome.SUCCESS, exit_status=0, effective_user="root")
    assert VERIFICATION_ONLY_AS_ROOT_GAP in _codes(ledger)
    ledger.run("pytest -q", ResultOutcome.SUCCESS, exit_status=0, effective_user="non_root")
    assert VERIFICATION_ONLY_AS_ROOT_GAP not in _codes(ledger)


def test_description_suffixes_round_trip_with_tool_and_runner() -> None:
    description = observed_action_description(
        "Observed command via Codex hook",
        "exec_command",
        "test",
        install_target="yoetz_runtime",
        write_outside_workspace=True,
        effective_user="root",
    )
    assert observed_action_tool(description) == "exec_command"
    assert observed_action_runner_class(description) == "test"
    assert observed_action_runtime_tokens(description) == frozenset(
        {"install yoetz_runtime", "write outside_workspace", "user root"}
    )
    plain = observed_action_description("Observed edit", "apply_patch", None)
    assert observed_action_runtime_tokens(plain) == frozenset()
    assert observed_action_tool(plain) == "apply_patch"


_BATCHES = [0]


def _decision(
    ledger: ObservedLedger, statement: str, *obligations: ObligationId, batch: str | None = None
) -> None:
    """Append a decision in its own publish batch unless ``batch`` names one (#985)."""

    if batch is None:
        _BATCHES[0] += 1
        batch = f"req_98500000-0000-4000-8000-{_BATCHES[0]:012d}"
    ledger.append(
        _DECISION_SCHEMA,
        DecisionRecordedPayload(
            statement=statement,
            rationale="The deployment credential is held by the operator.",
            authority=actor_id("agt_codex"),
            affected_obligation_ids=tuple(sorted(obligations)),
        ),
        observed=False,
        operation=batch,
    )


def _batches(ledger: ObservedLedger) -> Mapping[EventId, str]:
    return decision_batches(ledger.prefix)


def _confirmed(ledger: ObservedLedger) -> frozenset[ObligationId]:
    """What a deterministic case's task-fact markers say is confirmed blocked."""

    prefix = ledger.prefix
    markers = task_fact_signals(replay(prefix), prefix).markers
    return confirmed_blocked_obligation_ids(
        (code, () if obligation is None else (obligation,)) for code, obligation in markers
    )


def test_blocker_decision_is_honoured_only_for_closed_kinds() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("deploy --prod"))
    _planned(ledger, obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    _decision(ledger, "yoetz-blocker:data_not_found", _OTHER)
    _decision(ledger, "Blocked.\nyoetz-blocker:credential", _OBLIGATION)
    prefix = ledger.prefix
    projection = replay(prefix)

    # #985: the first decision only claims the blocker; it is still agent work.
    assert dict(blocked_obligations(projection, _batches(ledger))) == {}
    [declaration] = blocker_declarations(projection, _batches(ledger)).values()
    assert declaration.kind == "credential" and not declaration.confirmed
    markers = set(task_fact_signals(projection, prefix).markers)
    assert (OBLIGATION_BLOCKER_UNCONFIRMED_GAP, _OBLIGATION) in markers
    assert (OBLIGATION_BLOCKED_GAP, _OBLIGATION) not in markers
    # A claimed blocker suppresses nothing: the planned verification is still reported.
    assert any(code.startswith("planned_verification") for code, _ in markers)

    # The same line again in a later decision confirms it.
    _decision(ledger, "Still blocked.\nyoetz-blocker:credential", _OBLIGATION)
    prefix = ledger.prefix
    projection = replay(prefix)
    assert dict(blocked_obligations(projection, _batches(ledger))) == {_OBLIGATION: "credential"}
    assert blocker_declarations(projection, _batches(ledger))[_OBLIGATION].confirmed
    markers = set(task_fact_signals(projection, prefix).markers)
    assert (OBLIGATION_BLOCKED_GAP, _OBLIGATION) in markers
    assert (OBLIGATION_BLOCKER_UNCONFIRMED_GAP, _OBLIGATION) not in markers
    assert (OBLIGATION_BLOCKED_GAP, _OTHER) not in markers
    # A confirmed blocked obligation's planned verification is not reported as missing.
    assert not any(code.startswith("planned_verification") for code, _ in markers)


def test_a_kind_change_starts_a_new_claim_and_an_unrelated_obligation_confirms_nothing() -> None:
    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _planned(ledger, obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    _decision(ledger, "yoetz-blocker:authority", _OBLIGATION)
    _decision(ledger, "yoetz-blocker:authority", _OTHER)
    _decision(ledger, "yoetz-blocker:authority", _OBLIGATION)
    projection = replay(ledger.prefix)
    declarations = blocker_declarations(projection, _batches(ledger))
    assert declarations[_OBLIGATION].confirmed
    # _OTHER's own claim was never repeated; _OBLIGATION's confirmation does not reach it.
    assert not declarations[_OTHER].confirmed

    # A different kind resets the claim, even over a confirmed blocker: it must face its own
    # challenge.
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    projection = replay(ledger.prefix)
    declaration = blocker_declarations(projection, _batches(ledger))[_OBLIGATION]
    assert (declaration.kind, declaration.confirmed) == ("consent", False)
    assert dict(blocked_obligations(projection, _batches(ledger))) == {}
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    projection = replay(ledger.prefix)
    declaration = blocker_declarations(projection, _batches(ledger))[_OBLIGATION]
    assert (declaration.kind, declaration.confirmed) == ("consent", True)


def _supersede(ledger: ObservedLedger, statement: str, superseded: EventId) -> EventId:
    _BATCHES[0] += 1
    return ledger.append(
        _DECISION_SCHEMA,
        DecisionRecordedPayload(
            statement=statement,
            rationale="Revised after the challenge.",
            authority=actor_id("agt_codex"),
            affected_obligation_ids=(_OBLIGATION,),
            supersedes_event_id=superseded,
        ),
        observed=False,
        operation=f"req_98500000-0000-4000-8000-{_BATCHES[0]:012d}",
    )


def _last_event(ledger: ObservedLedger) -> EventId:
    return ledger.prefix[-1].event_id


def test_superseding_the_claim_or_the_confirmation_resets_what_counts() -> None:
    """#985: a superseded blocker decision no longer counts, whichever role it had."""

    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _plan(ledger, _OBLIGATION)
    _decision(ledger, "yoetz-blocker:credential", _OBLIGATION)
    claim = _last_event(ledger)
    # Superseding the claim with the same line makes the replacement the (unconfirmed) claim.
    replacement = _supersede(ledger, "yoetz-blocker:credential", claim)
    declaration = blocker_declarations(replay(ledger.prefix), _batches(ledger))[_OBLIGATION]
    assert (declaration.decision_event_id, declaration.confirmed) == (replacement, False)

    _decision(ledger, "yoetz-blocker:credential", _OBLIGATION)
    confirmation = _last_event(ledger)
    declaration = blocker_declarations(replay(ledger.prefix), _batches(ledger))[_OBLIGATION]
    assert declaration.confirmation_event_id == confirmation

    # Superseding the confirmation with a plain decision withdraws it: claimed again.
    _supersede(ledger, "The credential arrived; the work continues.", confirmation)
    projection = replay(ledger.prefix)
    declaration = blocker_declarations(projection, _batches(ledger))[_OBLIGATION]
    assert (declaration.decision_event_id, declaration.confirmed) == (replacement, False)
    assert dict(blocked_obligations(projection, _batches(ledger))) == {}


def test_two_back_to_back_publishes_confirm_because_the_first_result_carried_the_challenge() -> (
    None
):
    """#985 (lead decision): later-batch semantics. The claimed notice in the first publish
    result is the challenge, and no pre-claim text tells the agent how to confirm, so a second
    publish right after it is the agent's answer to that challenge."""

    from yoetz.kernel.task_facts import (
        BLOCKER_NOTICE_CLAIMED,
        BLOCKER_NOTICE_CONFIRMED,
        blocker_publication_notices,
    )

    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _plan(ledger, _OBLIGATION)
    payload = DecisionRecordedPayload(
        statement="yoetz-blocker:authority",
        rationale="Production deploy rights belong to the operator.",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(_OBLIGATION,),
    )
    first = ledger.append(
        _DECISION_SCHEMA,
        payload,
        observed=False,
        operation="req_98500000-0000-4000-8000-0000000009c1",
    )
    [notice] = blocker_publication_notices(replay(ledger.prefix), ((first, payload),))
    assert notice.notice == BLOCKER_NOTICE_CLAIMED
    second = ledger.append(
        _DECISION_SCHEMA,
        payload,
        observed=False,
        operation="req_98500000-0000-4000-8000-0000000009c2",
    )
    projection = replay(ledger.prefix)
    [notice] = blocker_publication_notices(projection, ((second, payload),))
    assert notice.notice == BLOCKER_NOTICE_CONFIRMED
    assert blocker_declarations(projection, _batches(ledger))[_OBLIGATION].confirmed


def test_a_blocker_naming_an_unknown_obligation_has_no_effect() -> None:
    from yoetz.kernel.task_facts import BLOCKER_NOTICE_WITHOUT_EFFECT, blocker_publication_notices

    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _plan(ledger, _OBLIGATION)
    unknown = obligation_id("obl_00000000-0000-4000-8000-0000000009ff")
    payload = DecisionRecordedPayload(
        statement="yoetz-blocker:consent",
        rationale="Named the wrong id.",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(unknown,),
    )
    event = ledger.append(_DECISION_SCHEMA, payload, observed=False)
    [notice] = blocker_publication_notices(replay(ledger.prefix), ((event, payload),))
    assert (notice.obligation_id, notice.notice) == (unknown, BLOCKER_NOTICE_WITHOUT_EFFECT)


def test_readiness_turns_fully_blocked_open_obligations_into_a_disclosure() -> None:
    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _planned(ledger, obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    _decision(ledger, "yoetz-blocker:authority", _OBLIGATION)
    prefix = ledger.prefix
    facts = closure_readiness_facts(replay(prefix), prefix)
    partly = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    assert "obligations_open" in partly.agent_actionable

    _decision(ledger, "yoetz-blocker:dependency_unavailable", _OTHER)
    prefix = ledger.prefix
    facts = closure_readiness_facts(replay(prefix), prefix)
    claimed = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    # #985 (C4): claimed blockers never turn readiness ready; the agent must repair or confirm.
    assert claimed.state == "action_required"
    assert "obligations_open" not in claimed.agent_actionable
    assert claimed.agent_actionable == (OBLIGATION_BLOCKER_UNCONFIRMED_GAP, "check_not_recorded")
    assert OBLIGATION_BLOCKED_GAP not in claimed.standing_limitations

    # Confirming one of the two is not enough.
    _decision(ledger, "yoetz-blocker:authority", _OBLIGATION)
    prefix = ledger.prefix
    facts = closure_readiness_facts(replay(prefix), prefix)
    assert facts.confirmed_blocked_obligation_ids == (_OBLIGATION,)
    half = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    assert OBLIGATION_BLOCKER_UNCONFIRMED_GAP in half.agent_actionable
    assert OBLIGATION_BLOCKED_GAP in half.standing_limitations

    _decision(ledger, "yoetz-blocker:dependency_unavailable", _OTHER)
    prefix = ledger.prefix
    facts = closure_readiness_facts(replay(prefix), prefix)
    blocked = derive_closure_readiness(
        ("obligations_open",),
        ("completion_plan_not_claimed",),
        facts,
        semantic_review_required=False,
    )
    assert "obligations_open" not in blocked.agent_actionable
    assert OBLIGATION_BLOCKED_GAP in blocked.standing_limitations
    # Only the missing check remains: the confirmed blocked obligations are not agent work,
    # and no completion claim can cover a plan whose every open obligation is blocked (C9).
    assert blocked.agent_actionable == ("check_not_recorded",)
    assert "completion_plan_not_claimed" in blocked.standing_limitations


def test_acting_starts_with_an_edit_a_published_action_or_a_verification_run() -> None:
    def started(ledger: ObservedLedger) -> bool:
        prefix = ledger.prefix
        return acting_started(
            replay(prefix),
            observed_event_ids_from_records(prefix),
            cooperative_event_ids_from_records(prefix),
        )

    ledger = ObservedLedger()
    _planned(ledger, RequestedItem(RequestedItemKind.FILE, "out/report.json"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("ls")
    ledger.passes("git status")
    ledger.passes("python probe.py")  # an unclassified investigation run is not acting
    assert not started(ledger)
    ledger.passes("pytest -q")
    assert started(ledger)

    # tb4n2 E4 (P1-7): a published research action only reads; it is not acting.
    researched = ObservedLedger()
    _planned(researched, RequestedItem(RequestedItemKind.FILE, "out/report.json"))
    researched.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000777"),
            ActionKind.RESEARCH,
            "Read the inputs.",
        ),
        observed=False,
    )
    assert not started(researched)

    published = ObservedLedger()
    _planned(published, RequestedItem(RequestedItemKind.FILE, "out/report.json"))
    published.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000778"),
            ActionKind.EDIT,
            "Write the report.",
        ),
        observed=False,
    )
    assert started(published)

    edited = ObservedLedger()
    edited.edit()
    assert started(edited)


def _file(value: str) -> RequestedItem:
    return RequestedItem(RequestedItemKind.FILE, value)


def _attempt(
    ledger: ObservedLedger,
    kind: ActionKind,
    *items: str,
    number: int,
    obligations: tuple[ObligationId, ...] = (),
) -> None:
    ledger.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            action_id(f"act_00000000-0000-4000-8000-{number:012d}"),
            kind,
            "Attempted requested items.",
            command="python work/make_report.py" if kind is ActionKind.COMMAND else None,
            obligation_refs=obligations,
            attempted_items=tuple(sorted(items)),
        ),
        observed=False,
    )


def test_requested_output_facts_split_absent_from_gap_markers() -> None:
    ledger = ObservedLedger()
    _planned(ledger, *(_file(f"out/{index}") for index in range(8)))
    _plan(ledger, _OBLIGATION)
    # Unchanged and outside are facts about an item the record says was written.
    _attempt(ledger, ActionKind.EDIT, "out/3", "out/4", number=901)
    projection = replay(ledger.prefix)
    states = {
        (_OBLIGATION, 0): RequestedOutputState("inside", exists=False),
        (_OBLIGATION, 1): RequestedOutputState("inside", exists=False, deleted=True),
        (_OBLIGATION, 2): RequestedOutputState(
            "inside", exists=True, ignored=True, ignored_by_task=True
        ),
        (_OBLIGATION, 7): RequestedOutputState("inside", exists=True, ignored=True),
        (_OBLIGATION, 3): RequestedOutputState("inside", exists=True, ignored=False, changed=False),
        (_OBLIGATION, 4): RequestedOutputState("outside"),
        (_OBLIGATION, 5): RequestedOutputState("unverified"),
        (_OBLIGATION, 6): RequestedOutputState("inside", exists=True, ignored=False, changed=True),
    }
    absent, markers = requested_output_facts(projection, states, blocked=_confirmed(ledger))
    assert absent == ((_OBLIGATION, 0),)
    assert {code for code, _ in markers} == {
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
        REQUESTED_OUTPUT_UNCHANGED_GAP,
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
        REQUESTED_OUTPUT_UNVERIFIED_GAP,
    }

    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    # #985: a claimed blocker suppresses nothing until a later decision confirms it.
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        absent,
        markers,
    )
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    blocked_absent, blocked_markers = requested_output_facts(
        replay(ledger.prefix), states, blocked=_confirmed(ledger)
    )
    assert blocked_absent == ()
    assert blocked_markers == ()


def test_tb4v1_atrx_read_only_inputs_are_not_unchanged_outputs() -> None:
    """tb4v1 atrx-vep-crispr: tracked /app/data inputs listed as file items, attempted by commands.

    The workspace is /app; the inputs are tracked and never change, and the requested report is a
    new untracked file. Only the report is an output: no ``requested_output_unchanged``.
    """

    inputs = (
        "/app/data/CDS-information.txt",
        "/app/data/InterPro-domain-information.tsv",
        "/app/data/ensembl-vep-release-115/",
        "/app/data/genomic-locus.fa",
        "/app/data/mutated-transcripts.txt",
    )
    ledger = ObservedLedger()
    _planned(ledger, *(_file(value) for value in inputs))
    _planned(ledger, _file("/app/output/mutation.report.json"), obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    _attempt(ledger, ActionKind.COMMAND, *inputs, "/app/output/mutation.report.json", number=902)
    states = {
        (_OBLIGATION, index): RequestedOutputState(
            "inside", exists=True, ignored=False, changed=False
        )
        for index in range(len(inputs))
    }
    states[(_OTHER, 0)] = RequestedOutputState("inside", exists=True, ignored=False, changed=True)
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        (),
        (),
    )

    # Before the report exists it is still the receipt-blocking absent output.
    states[(_OTHER, 0)] = RequestedOutputState("inside", exists=False, ignored=False)
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        ((_OTHER, 0),),
        (),
    )

    # An item the record says was edited and that is still unchanged keeps the disclosure.
    _attempt(ledger, ActionKind.EDIT, inputs[1], number=903, obligations=(_OBLIGATION,))
    _, markers = requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger))
    assert markers == ((REQUESTED_OUTPUT_UNCHANGED_GAP, _OBLIGATION),)


def test_tb4v1_heat_pump_inputs_outside_the_workspace_are_not_outputs() -> None:
    """tb4v1 heat-pump-warranty: workspace /workspace, inputs read from /app/packet.

    Read-only inputs outside the checked repository are not requested outputs, so no
    ``requested_output_outside_workspace``; an outside path the record says was edited is.
    """

    packet = (
        "/app/packet/API.md",
        "/app/packet/POLICY.md",
        "/app/packet/source_precedence.yaml",
    )
    ledger = ObservedLedger()
    _planned(ledger, *(_file(value) for value in packet))
    _planned(ledger, _file("/app/packet/claim_export.csv"), obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    _attempt(ledger, ActionKind.RESEARCH, *packet, "/app/packet/claim_export.csv", number=904)
    states = {(_OBLIGATION, index): RequestedOutputState("outside") for index in range(3)}
    states[(_OTHER, 0)] = RequestedOutputState("outside")
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        (),
        (),
    )

    # A global edit action covers every obligation that lists the value.
    _attempt(ledger, ActionKind.EDIT, "/app/packet/claim_export.csv", number=905)
    _, markers = requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger))
    assert markers == ((REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP, _OTHER),)

    # An edit scoped to another obligation does not mark this one.
    scoped = ObservedLedger()
    _planned(scoped, _file("/app/packet/API.md"))
    _planned(scoped, _file("/app/packet/API.md"), obligation=_OTHER)
    _plan(scoped, _OBLIGATION, _OTHER)
    _attempt(scoped, ActionKind.EDIT, "/app/packet/API.md", number=906, obligations=(_OTHER,))
    both = {
        (_OBLIGATION, 0): RequestedOutputState("outside"),
        (_OTHER, 0): RequestedOutputState("outside"),
    }
    _, markers = requested_output_facts(replay(scoped.prefix), both, blocked=_confirmed(scoped))
    assert markers == ((REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP, _OTHER),)


_UNCHANGED = RequestedOutputState("inside", exists=True, ignored=False, changed=False)


@pytest.mark.parametrize("kind", [kind for kind in ActionKind if kind is not ActionKind.EDIT])
def test_only_an_edit_action_marks_an_output_unchanged_or_outside(kind: ActionKind) -> None:
    ledger = ObservedLedger()
    _planned(ledger, _file("a.txt"), _file("/elsewhere/a.txt"))
    _plan(ledger, _OBLIGATION)
    _attempt(ledger, kind, "/elsewhere/a.txt", "a.txt", number=910)
    states = {(_OBLIGATION, 0): _UNCHANGED, (_OBLIGATION, 1): RequestedOutputState("outside")}
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        (),
        (),
    )


def test_ungated_output_facts_need_no_edit_and_matching_is_exact() -> None:
    ledger = ObservedLedger()
    _planned(
        ledger,
        _file("u.txt"),
        _file("ignored.txt"),
        _file("repo-ignored.txt"),
        _file("a.txt"),
        _file("/app/data/vep/"),
        _file("missing.txt"),
    )
    _plan(ledger, _OBLIGATION)
    # An edit naming other values, or the same paths spelled differently, marks nothing.
    _attempt(ledger, ActionKind.EDIT, "./a.txt", "/app/data/vep", "b.txt", number=911)
    states = {
        (_OBLIGATION, 0): RequestedOutputState("inside", exists=None),
        (_OBLIGATION, 1): RequestedOutputState(
            "inside", exists=True, ignored=True, ignored_by_task=True
        ),
        (_OBLIGATION, 2): RequestedOutputState("inside", exists=True, ignored=True),
        (_OBLIGATION, 3): _UNCHANGED,
        (_OBLIGATION, 4): _UNCHANGED,
        (_OBLIGATION, 5): RequestedOutputState("inside", exists=False, ignored=False),
    }
    absent, markers = requested_output_facts(
        replay(ledger.prefix), states, blocked=_confirmed(ledger)
    )
    assert absent == ((_OBLIGATION, 5),)
    assert {code for code, _ in markers} == {
        REQUESTED_OUTPUT_UNVERIFIED_GAP,
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    }

    _attempt(ledger, ActionKind.EDIT, "/app/data/vep/", number=912)
    _, markers = requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger))
    assert (REQUESTED_OUTPUT_UNCHANGED_GAP, _OBLIGATION) in markers

    # A confirmed blocker on the obligation still suppresses every output fact, edited or not.
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    assert requested_output_facts(replay(ledger.prefix), states, blocked=_confirmed(ledger)) == (
        (),
        (),
    )


def test_every_task_fact_code_has_one_fixed_sentence() -> None:
    from yoetz.domain.receipts import TASK_FACT_GAP_SENTENCES, check_time_change_gap_sentence

    assert set(TASK_FACT_GAP_SENTENCES) == set(TASK_FACT_GAPS)
    for code in TASK_FACT_GAPS:
        assert check_time_change_gap_sentence(code) == TASK_FACT_GAP_SENTENCES[code]


def test_a_started_run_without_a_result_is_unknown_not_unobserved() -> None:
    from builders.observed_runs import command_identity_for
    from yoetz.domain.values import action_id as make_action_id
    from yoetz.kernel.observed_failures import observed_action_description

    ledger = ObservedLedger()
    _planned(ledger, _command("pytest -q"))
    _plan(ledger, _OBLIGATION)
    ledger.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            make_action_id("act_00000000-0000-4000-8000-000000000555"),
            ActionKind.COMMAND,
            observed_action_description("Observed pending command via Codex hook", "Bash", "test"),
            command=command_identity_for("pytest -q"),
        ),
        observed=True,
    )
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP in codes


# --- Segment-aware planned-verification matching (#977 E3, tb4n1) ------------------------------

_PLANNED_GAPS = {
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
}


def _planned_codes(planned: str, *runs: tuple[str, ResultOutcome]) -> set[str]:
    ledger = ObservedLedger()
    _planned(ledger, _command(planned))
    _plan(ledger, _OBLIGATION)
    for command, outcome in runs:
        ledger.run(
            command,
            outcome,
            exit_status=0 if outcome is ResultOutcome.SUCCESS else 1,
        )
    return _codes(ledger) & _PLANNED_GAPS


@pytest.mark.parametrize(
    ("planned", "observed"),
    [
        # batched-eval det: the exact command inside a cd/&& chain.
        (
            "python evaluate.py --batch-size 8 --out /app/results.json",
            "cd /app && python evaluate.py --batch-size 8 --out /app/results.json"
            " && git diff --check",
        ),
        # react det.
        ("npm test", "npm test && npm run build"),
        # time and env-assignment prefixes.
        ("python run.py", "time python run.py"),
        ("make test", "FOO=1 make test"),
        ("pytest -q", "env PYTHONPATH=src pytest -q"),
        # A host shell wrapper around a chain.
        ("pytest -q", "/bin/bash -lc 'cd /app && pytest -q'"),
    ],
)
def test_planned_command_matches_one_segment_of_a_successful_and_chain(
    planned: str, observed: str
) -> None:
    assert _planned_codes(planned, (observed, ResultOutcome.SUCCESS)) == set()


def test_pretrain_redirected_run_matches_and_keeps_its_outcome() -> None:
    planned = "bash /app/run_pretrain.sh"
    observed = "bash /app/run_pretrain.sh > /tmp/pretrain-before.log 2>&1"
    assert _planned_codes(planned, (observed, ResultOutcome.SUCCESS)) == set()
    # A redirected single command is that command: its failure is the planned run's failure.
    assert _planned_codes(planned, (observed, ResultOutcome.FAILURE)) == {
        PLANNED_VERIFICATION_FAILED_GAP
    }
    # The planned value may carry the redirection while the run does not.
    assert _planned_codes(observed, (planned, ResultOutcome.SUCCESS)) == set()


@pytest.mark.parametrize("planned", ["! pytest -q", "pytest -q &"])
def test_a_negated_or_backgrounded_plan_does_not_take_the_runs_outcome(planned: str) -> None:
    """Adversarial review of E3: a planned `! X` or `X &` is not X's outcome."""

    unknown = {PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP}
    assert _planned_codes(planned, ("pytest -q", ResultOutcome.FAILURE)) == unknown
    assert _planned_codes(planned, ("pytest -q", ResultOutcome.SUCCESS)) == unknown
    # A redirected plan is still that command: its run's failure is the plan's failure.
    assert _planned_codes("pytest -q > log", ("pytest -q", ResultOutcome.FAILURE)) == {
        PLANNED_VERIFICATION_FAILED_GAP
    }


def test_a_failed_chain_names_no_failing_segment() -> None:
    assert _planned_codes("npm test", ("npm test && npm run build", ResultOutcome.FAILURE)) == {
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP
    }


def test_a_masking_composition_counts_the_run_but_not_its_outcome() -> None:
    assert _planned_codes("pytest -q", ("pytest -q | tee log.txt", ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP
    }


def test_cargo_layout_planned_command_on_the_last_line_of_a_shell_heredoc() -> None:
    script = "bash <<'EOF'\nset -e\ncd /app\ncargo build --release\npython check.py\nEOF"
    codes = _planned_codes("python check.py", (script, ResultOutcome.SUCCESS))
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert codes == {PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP}


def test_a_python_heredoc_body_is_data_not_commands() -> None:
    script = "python3 - <<'PY'\nimport subprocess\npython check.py\nPY"
    assert _planned_codes("python check.py", (script, ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP
    }


def test_a_different_command_in_a_chain_still_does_not_match() -> None:
    assert _planned_codes(
        "pytest -q tests/unit", ("cd /app && pytest -q && ls", ResultOutcome.SUCCESS)
    ) == {PLANNED_VERIFICATION_NOT_OBSERVED_GAP}
    # Quoted separators are text, not composition.
    assert _planned_codes("b", ("echo 'a && b'", ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP
    }


def test_a_compound_planned_command_matches_when_every_part_ran_in_one_run() -> None:
    planned = "npm test && npm run build"
    assert (
        _planned_codes(planned, ("cd /app && npm test && npm run build", ResultOutcome.SUCCESS))
        == set()
    )
    assert _planned_codes(planned, ("npm test", ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP
    }


def test_segment_matches_go_stale_after_a_later_edit() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("npm test"))
    _plan(ledger, _OBLIGATION)
    ledger.passes("npm test && npm run build")
    ledger.edit()
    assert _codes(ledger) & _PLANNED_GAPS == {PLANNED_VERIFICATION_STALE_GAP}


@pytest.mark.parametrize(
    "value",
    [
        "python cracker.py <ciphertext_file>",
        "python -m parityctl rebuild --packet <incident-packet> --out <output-dir>",
        "Broad GSEA CLI",
    ],
)
def test_placeholder_or_prose_items_are_unobservable_not_unrun(value: str) -> None:
    assert _planned_codes(value, ("python cracker.py data.bin", ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_UNOBSERVABLE_GAP
    }


def test_a_single_token_requested_command_is_still_a_command() -> None:
    assert _planned_codes("legacy-score", ("python other.py", ResultOutcome.SUCCESS)) == {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP
    }
    assert (
        _planned_codes("legacy-score", ("cd /app && legacy-score", ResultOutcome.SUCCESS)) == set()
    )


# --- Agent-linked planned verification (PL6-3, #1003) ------------------------------------------

_LINKED_GAPS = _PLANNED_GAPS | {PLANNED_VERIFICATION_AGENT_LINKED_GAP}


def _observed_run(ledger: ObservedLedger, command: str, outcome: ResultOutcome) -> EventId:
    """One hook-observed run; returns its observed action event id."""

    ledger.run(command, outcome, exit_status=0 if outcome is ResultOutcome.SUCCESS else 1)
    return ledger.records[-2].event_id


def _link(
    ledger: ObservedLedger,
    value: str,
    *parents: EventId,
    number: int,
    obligations: tuple[ObligationId, ...] = (),
    kind: ActionKind = ActionKind.COMMAND,
) -> None:
    ledger.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            action_id(f"act_00000000-0000-4000-8000-00000000a{number:03d}"),
            kind,
            "Ran the planned tests through run_tests.py",
            command="python run_tests.py" if kind is ActionKind.COMMAND else None,
            obligation_refs=obligations,
            attempted_items=(value,),
        ),
        observed=False,
        causal_parents=parents,
    )


def _formal_crypto(outcome: ResultOutcome) -> ObservedLedger:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _plan(ledger, _OBLIGATION)
    parent = _observed_run(ledger, "python run_tests.py", outcome)
    _link(ledger, "pytest tests/test_x.py", parent, number=1)
    return ledger


def test_formal_crypto_agent_link_matches_and_is_disclosed() -> None:
    assert _codes(_formal_crypto(ResultOutcome.SUCCESS)) & _LINKED_GAPS == {
        PLANNED_VERIFICATION_AGENT_LINKED_GAP
    }


def test_a_linked_run_that_failed_reports_failed_not_pass() -> None:
    assert _codes(_formal_crypto(ResultOutcome.FAILURE)) & _LINKED_GAPS == {
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_AGENT_LINKED_GAP,
    }


def test_a_linked_run_goes_stale_after_a_later_edit() -> None:
    ledger = _formal_crypto(ResultOutcome.SUCCESS)
    ledger.edit()
    assert PLANNED_VERIFICATION_STALE_GAP in _codes(ledger)


def test_an_unrelated_observed_parent_links_only_its_own_value() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _plan(ledger, _OBLIGATION)
    parent = _observed_run(ledger, "python run_tests.py", ResultOutcome.SUCCESS)
    # The link names another value, so the planned command stays unmatched.
    _link(ledger, "pytest tests/test_other.py", parent, number=1)
    assert _codes(ledger) & _LINKED_GAPS == {PLANNED_VERIFICATION_NOT_OBSERVED_GAP}


def test_a_cooperative_only_parent_never_links() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _plan(ledger, _OBLIGATION)
    _observed_run(ledger, "ls", ResultOutcome.SUCCESS)
    # A cooperative run (action and result) as the parent: never a hook observation.
    ledger.run("python run_tests.py", ResultOutcome.SUCCESS, exit_status=0, observed=False)
    cooperative_action, cooperative_result = ledger.records[-2], ledger.records[-1]
    _link(
        ledger,
        "pytest tests/test_x.py",
        cooperative_action.event_id,
        cooperative_result.event_id,
        number=1,
    )
    assert _codes(ledger) & _LINKED_GAPS == {PLANNED_VERIFICATION_NOT_OBSERVED_GAP}


def test_a_link_naming_another_obligation_does_not_count() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _planned(ledger, _command("make lint"), obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    parent = _observed_run(ledger, "python run_tests.py", ResultOutcome.SUCCESS)
    _link(ledger, "pytest tests/test_x.py", parent, number=1, obligations=(_OTHER,))
    assert (PLANNED_VERIFICATION_NOT_OBSERVED_GAP, _OBLIGATION) in _markers(ledger)


def test_a_non_command_linking_action_does_not_count() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _plan(ledger, _OBLIGATION)
    parent = _observed_run(ledger, "python run_tests.py", ResultOutcome.SUCCESS)
    _link(ledger, "pytest tests/test_x.py", parent, number=1, kind=ActionKind.OTHER)
    assert _codes(ledger) & _LINKED_GAPS == {PLANNED_VERIFICATION_NOT_OBSERVED_GAP}


def test_a_direct_match_needs_no_link_disclosure() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("pytest tests/test_x.py"))
    _plan(ledger, _OBLIGATION)
    parent = _observed_run(ledger, "pytest tests/test_x.py", ResultOutcome.SUCCESS)
    _link(ledger, "pytest tests/test_x.py", parent, number=1)
    assert _codes(ledger) & _LINKED_GAPS == set()


def test_a_placeholder_item_stays_unobservable_even_when_linked() -> None:
    ledger = ObservedLedger()
    _planned(ledger, _command("python cracker.py <ciphertext_file>"))
    _plan(ledger, _OBLIGATION)
    parent = _observed_run(ledger, "python cracker.py data.bin", ResultOutcome.SUCCESS)
    _link(ledger, "python cracker.py <ciphertext_file>", parent, number=1)
    assert _codes(ledger) & _LINKED_GAPS == {PLANNED_VERIFICATION_UNOBSERVABLE_GAP}


def test_only_a_later_publish_batch_confirms_a_blocker() -> None:
    """#985: a reflexive double publish skips the publish-time challenge, so it never confirms."""

    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _plan(ledger, _OBLIGATION)
    batch = "req_98500000-0000-4000-8000-0000000009a1"
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION, batch=batch)
    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION, batch=batch)
    # Two identical lines in one decision are one claim as well.
    _decision(ledger, "yoetz-blocker:consent\nyoetz-blocker:consent", _OBLIGATION, batch=batch)
    projection = replay(ledger.prefix)
    assert not blocker_declarations(projection, _batches(ledger))[_OBLIGATION].confirmed
    assert dict(blocked_obligations(projection, _batches(ledger))) == {}
    # Without the publish batches nothing is ever confirmed.
    assert not blocker_declarations(projection, {})[_OBLIGATION].confirmed

    _decision(ledger, "yoetz-blocker:consent", _OBLIGATION)
    projection = replay(ledger.prefix)
    declaration = blocker_declarations(projection, _batches(ledger))[_OBLIGATION]
    assert declaration.confirmed
    assert dict(blocked_obligations(projection, _batches(ledger))) == {_OBLIGATION: "consent"}


def test_publish_notices_challenge_a_first_claim_and_confirm_only_from_a_later_batch() -> None:
    from yoetz.kernel.task_facts import (
        BLOCKER_NOTICE_CLAIMED,
        BLOCKER_NOTICE_CONFIRMED,
        blocker_publication_notices,
    )

    ledger = ObservedLedger()
    _planned(ledger, obligation=_OBLIGATION)
    _planned(ledger, obligation=_OTHER)
    _plan(ledger, _OBLIGATION, _OTHER)
    payload = DecisionRecordedPayload(
        statement="yoetz-blocker:authority",
        rationale="Deploy rights are held by the operator.",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(_OBLIGATION,),
    )
    first = ledger.append(_DECISION_SCHEMA, payload, observed=False)
    second = ledger.append(_DECISION_SCHEMA, payload, observed=False)
    projection = replay(ledger.prefix)
    # One batch carrying the line twice: still only claimed.
    [notice] = blocker_publication_notices(projection, ((first, payload), (second, payload)))
    assert notice.notice == BLOCKER_NOTICE_CLAIMED
    # A later batch repeating it confirms the claim.
    third = ledger.append(
        _DECISION_SCHEMA,
        payload,
        observed=False,
        operation="req_98500000-0000-4000-8000-0000000009b1",
    )
    projection = replay(ledger.prefix)
    [notice] = blocker_publication_notices(projection, ((third, payload),))
    assert notice.notice == BLOCKER_NOTICE_CONFIRMED
