"""No AI-powered review before the first material edit (issue #1046 item 1).

tb4n4: 18 of 61 semantic-arm tasks ran a review of the plan before any work, and most routine
``insufficient_packet`` answers came from those. A routine check with no material edit recorded
and no workspace change observed runs the local plan checks only, discloses
``semantic_review_deferred_before_first_edit`` and composes or sends nothing; the closing review
is never deferred. These cases decide the deferral over hook-observed ledgers replayed through the
production case builder.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger, command_identity_for
from finishup.application.check import (
    _review_deferred_before_first_edit,  # pyright: ignore[reportPrivateUsage]
    _review_skip_gaps,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
)
from finishup.domain.receipts import (
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
    SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
)
from finishup.domain.values import action_id, claim_id, obligation_id
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.finding_resolution import SEMANTIC_ONLY_GAPS
from finishup.kernel.gap_effect import GapContext, GapEffectKind, gap_effect
from finishup.kernel.observed_failures import (
    observed_action_description,
    observed_event_ids_from_records,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    cooperative_event_ids_from_records,
    material_edit_recorded,
    register_command_identity_key,
)
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import CheckPhase

pytestmark = pytest.mark.anyio

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _planned() -> ObservedLedger:
    """Plan time: an obligation, the plan, and a read-only look around the workspace."""

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Fix the parser",
            evidence_expectation="The parser tests pass",
            status=ObligationStatus.OPEN,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    ledger.passes("ls -la")
    return ledger


_WRITER = "wri_00000000-0000-4000-8000-000000001046"
_OPERATION = "req_00000000-0000-4000-8000-000000001046"


def _frozen(ledger: ObservedLedger, phase: CheckPhase = CheckPhase.LOCAL_READY) -> Any:
    prefix = ledger.prefix
    case = build_deterministic_case(replay(prefix), prefix, CaseAvailabilityFacts())
    return SimpleNamespace(
        case=case,
        lease=SimpleNamespace(phase=phase, writer_id=_WRITER, operation_id=_OPERATION),
    )


def _request(mode: str = "semantic_required", *, final_review: bool = False) -> Any:
    return SimpleNamespace(mode=mode, final_review=final_review, request_id="req_1046")


def _runtime(*, semantic: bool = True) -> Any:
    capabilities: frozenset[RuntimeCapability] = (
        frozenset({RuntimeCapability.SEMANTIC}) if semantic else frozenset()
    )
    return SimpleNamespace(capabilities=capabilities)


def _deferred(
    ledger: ObservedLedger,
    *,
    request: Any = None,
    runtime: Any = None,
    route: str = "policy",
    workspace_changed: bool | None = None,
    phase: CheckPhase = CheckPhase.LOCAL_READY,
) -> bool:
    return _review_deferred_before_first_edit(
        _request() if request is None else request,
        _runtime() if runtime is None else runtime,
        _frozen(ledger, phase),
        route_profile=cast(Any, route),
        workspace_changed=workspace_changed,
    )


def test_a_plan_time_check_defers_the_review_for_every_reviewing_mode() -> None:
    ledger = _planned()
    for mode in ("semantic_required", "semantic_if_configured"):
        assert _deferred(ledger, request=_request(mode)) is True
    # An observed unchanged workspace agrees; an unknown one leaves the ledger to decide.
    assert _deferred(ledger, workspace_changed=False) is True
    assert _deferred(ledger, workspace_changed=None) is True


def test_the_closing_review_and_a_completion_claim_are_never_deferred() -> None:
    ledger = _planned()
    assert _deferred(ledger, request=_request(final_review=True)) is False
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id=claim_id("clm_00000000-0000-4000-8000-000000000001"),
            claim_kind=ClaimKind.COMPLETION,
            statement="Nothing needed changing.",
            supporting_refs=(),
        ),
        observed=False,
    )
    assert _deferred(ledger) is False


def test_a_check_that_would_not_dispatch_a_review_is_left_as_it_was() -> None:
    """Only a review that would be sent is deferred: the recorded status of a local-only, strict
    or unconfigured check, and a resumed check already waiting on its review, are unchanged."""

    ledger = _planned()
    assert _deferred(ledger, request=_request("deterministic_only")) is False
    assert _deferred(ledger, route="strict") is False
    assert _deferred(ledger, runtime=_runtime(semantic=False)) is False
    assert _deferred(ledger, phase=CheckPhase.SEMANTIC_WAIT) is False


@pytest.mark.parametrize(
    "work",
    [
        "observed_edit",
        "observed_shell_write",
        "pre_only_shell_patch",
        "published_edit",
        "workspace_change",
    ],
)
def test_the_first_material_edit_rearms_the_review(work: str) -> None:
    ledger = _planned()
    workspace_changed: bool | None = None
    if work == "observed_edit":
        ledger.edit()
    elif work == "pre_only_shell_patch":
        # A Codex shell ``apply_patch <<EOF``: Codex applies it itself and fires only the
        # pre-event (#1041), so the ledger holds a pending command carrying the write the hook
        # read off the patch's file headers, and no result ever. Where the check-time capture is
        # unavailable (``workspace_changed`` None), it alone must re-arm the review.
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000301"),
                ActionKind.COMMAND,
                observed_action_description(
                    "Observed pending command via Codex hook",
                    "Bash",
                    "compound",
                    write_scope="workspace",
                ),
                command=command_identity_for("apply_patch <<'EOF'"),
            ),
            observed=True,
        )
    elif work == "observed_shell_write":
        ledger.run(
            "sed -i s/a/b/ parser.py",
            ResultOutcome.SUCCESS,
            exit_status=0,
            write_scope="workspace",
        )
    elif work == "published_edit":
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000201"),
                ActionKind.EDIT,
                "Rewrote the tokenizer",
            ),
            observed=False,
        )
    else:
        # A host whose writes are opaque scripts records no edit; the check-time capture does.
        workspace_changed = True
    assert _deferred(ledger, workspace_changed=workspace_changed) is False


def test_a_pending_command_with_no_write_is_not_a_material_edit() -> None:
    """Control: a command whose result never arrived and that wrote nothing visible."""

    ledger = _planned()
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000302"),
            ActionKind.COMMAND,
            observed_action_description("Observed pending command via Codex hook", "Bash", "build"),
            command=command_identity_for("make build"),
        ),
        observed=True,
    )
    assert _deferred(ledger) is True


def test_a_scratch_write_is_not_a_material_edit() -> None:
    ledger = _planned()
    ledger.edit(write_scope="scratch")
    prefix = ledger.prefix
    assert not material_edit_recorded(
        replay(prefix),
        observed_event_ids_from_records(prefix),
        cooperative_event_ids_from_records(prefix),
    )
    assert _deferred(ledger) is True


async def test_the_skip_names_one_reason_and_the_stopped_round_wins() -> None:
    from unit.kernel.test_review_round import _check  # pyright: ignore[reportPrivateUsage]

    ledger = _planned()
    frozen = _frozen(ledger)

    async def no_events(session_id: object, *, through: int) -> Any:
        del session_id, through
        for record in ():
            yield record

    runtime = SimpleNamespace(
        session_id="ses",
        capabilities=frozenset({RuntimeCapability.SEMANTIC}),
        ledger=SimpleNamespace(load_events=no_events),
    )
    gaps = await _review_skip_gaps(
        cast(Any, runtime),
        _request("semantic_if_configured"),
        frozen,
        route_profile="policy",
        workspace_changed=None,
    )
    assert gaps == frozenset({SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP})

    stopped = (_check("insufficient_packet"), _check("insufficient_packet"))

    async def stopped_events(session_id: object, *, through: int) -> Any:
        del session_id, through
        for record in stopped:
            yield record

    runtime.ledger = SimpleNamespace(load_events=stopped_events)
    gaps = await _review_skip_gaps(
        cast(Any, runtime),
        _request("semantic_if_configured"),
        frozen,
        route_profile="policy",
        workspace_changed=None,
    )
    assert gaps == frozenset({SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP})


def _resumable_runtime(jobs: dict[tuple[str, str], object]) -> Any:
    async def no_events(session_id: object, *, through: int) -> Any:
        del session_id, through
        for record in ():
            yield record

    async def load_semantic_job(
        writer_id: str, operation_id: str, case_digest: str | None = None
    ) -> object | None:
        del case_digest
        return jobs.get((writer_id, operation_id))

    return SimpleNamespace(
        session_id="ses",
        capabilities=frozenset({RuntimeCapability.SEMANTIC}),
        ledger=SimpleNamespace(load_events=no_events, load_semantic_job=load_semantic_job),
    )


async def test_a_check_resumed_to_finalize_keeps_the_decision_its_first_attempt_made() -> None:
    """Issue #1046 (review): a retry never re-decides the deferral from a live capture.

    A check interrupted after its phase reached ``ready_to_finalize`` resumes there. Its first
    attempt already decided: if it sent a review (the operation owns a review job), a retry whose
    capture now fails is not deferred, so the paid review is kept; if it sent none, a retry whose
    capture now sees a change does not try to dispatch one in a phase that cannot send it.
    """

    ledger = _planned()
    frozen = _frozen(ledger, CheckPhase.READY_TO_FINALIZE)
    jobs: dict[tuple[str, str], object] = {(_WRITER, _OPERATION): object()}
    runtime = _resumable_runtime(jobs)
    request = _request("semantic_if_configured")
    reviewed = await _review_skip_gaps(
        runtime, request, frozen, route_profile="policy", workspace_changed=None
    )
    assert reviewed == frozenset()

    jobs.clear()
    deferred = await _review_skip_gaps(
        runtime, request, frozen, route_profile="policy", workspace_changed=True
    )
    assert deferred == frozenset({SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP})

    # Before the review phase nothing was sent, so the live capture still decides.
    ready = _frozen(ledger, CheckPhase.LOCAL_READY)
    live = await _review_skip_gaps(
        runtime, request, ready, route_profile="policy", workspace_changed=True
    )
    assert live == frozenset()


def test_the_deferral_gap_follows_the_recorded_route_and_never_vetoes_local_proof() -> None:
    """Like the missing review it rides with (#1046 review): disclosed where review is optional."""

    code = SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP
    expected = {False: GapEffectKind.DISCLOSED, True: GapEffectKind.STANDING_BOUNDING}
    for route_requires_review, kind in expected.items():
        effect = gap_effect(code, GapContext(route_requires_review=route_requires_review))
        assert effect.kind is kind
    assert code in SEMANTIC_ONLY_GAPS
