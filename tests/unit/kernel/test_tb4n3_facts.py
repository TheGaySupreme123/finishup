"""tb4n3 family C (RC-5, issue #1028): deterministic facts from history and canonical commands.

Moved from the tb4n3 verify scratch (``scratch_C_facts/test_family_c_facts.py``, build 26e9cecf,
where each failed as the defect). Provenance per test:

* ``c1`` / ``c1b`` (``declared_output_emptied``): a file created empty is not "emptied" and a new
  file cut to a stub is. ``c1b`` now supplies the earlier check's recorded reading: a 14-byte read
  alone cannot prove a 300-line file ever existed, which is exactly what ADR-045 requires.
* ``c2`` / ``c2b`` / ``c2c`` (``edited_after_last_verification`` and the runner classifier).
  ``c2c``'s "in-workspace note edit" is the hook's ``notes`` write scope (``NOTES.md``).
* ``c3`` / ``c3b`` (planned verification identity): a task-quoted flag prefix and a ``timeout``
  wrapper.
* ``c4`` (hook-observed edit after a check) belongs to lane LO (``later_material_class``) and
  ``c5`` (the A-12 acceptance re-read as its own item) to wave 2; both stay in the scratch file.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    DeliverableState,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.values import event_id, evidence_id, obligation_id
from yoetz.kernel.delivered_set import DeliverableSnapshot, emptied_declared_items
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    RequestedOutputState,
    deliverable_path_identity,
    register_command_identity_key,
    task_fact_signals,
)

_OBL = obligation_id("obl_00000000-0000-4000-8000-0000000000c1")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _ledger(*items: RequestedItem, resolved: bool = False) -> ObservedLedger:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBL,
            description="Deliver",
            evidence_expectation="files",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBL,)),
        observed=False,
    )
    if resolved:
        ledger.append(
            EventSchema("obligation_published", "1.1.0"),
            ObligationPublishedPayload(
                obligation_id=_OBL,
                description="Deliver",
                evidence_expectation="files",
                status=ObligationStatus.RESOLVED,
                requested_items=items,
                resolution_evidence_refs=(evidence_id("evd_00000000-0000-4000-8000-000000000009"),),
            ),
            observed=False,
        )
    return ledger


def _codes(ledger: ObservedLedger) -> set[str]:
    return set(task_fact_signals(replay(ledger.prefix), ledger.prefix).codes)


def _out(value: str) -> RequestedItem:
    return RequestedItem(RequestedItemKind.FILE, value, role=RequestedItemRole.OUTPUT)


def _earlier(relative: str, *, size: int, lines: int) -> DeliverableSnapshot:
    """An earlier check's recorded reading of *relative* (ADR-045)."""

    return DeliverableSnapshot(
        DeliverableState(
            obligation_id=_OBL,
            item_index=0,
            path_key=deliverable_path_identity(relative),
            size_bytes=size,
            lines=lines,
            basis="delivered",
        ),
        event_id("evt_00000000-0000-4000-8000-0000000000e1"),
        120,
    )


# --- C1 / N3-4: declared_output_emptied --------------------------------------------------------


def test_c1_file_created_empty_is_not_emptied() -> None:
    """cargo D/S: /app/apt-packages.txt created empty (untracked, never non-empty) must not fire."""

    ledger = _ledger(_out("/app/apt-packages.txt"), resolved=True)
    state = RequestedOutputState(
        "inside", exists=True, changed=True, size_bytes=0, relative="apt-packages.txt"
    )
    assert emptied_declared_items(replay(ledger.prefix), {(_OBL, 0): state}) == ()
    # Seen empty at an earlier check too: still never non-empty, still not withdrawn.
    seen_empty = DeliverableSnapshot(
        DeliverableState(
            obligation_id=_OBL,
            item_index=0,
            path_key=deliverable_path_identity("apt-packages.txt"),
            size_bytes=0,
            lines=0,
            basis="delivered",
        ),
        event_id("evt_00000000-0000-4000-8000-0000000000e2"),
        100,
    )
    assert (
        emptied_declared_items(replay(ledger.prefix), {(_OBL, 0): state}, history=(seen_empty,))
        == ()
    )


def test_c1b_new_deliverable_truncated_to_one_line_is_emptied() -> None:
    """FN: a 300-line new (untracked) solve.sage cut to one stub line keeps no base_lines, so the
    old truncation branch never ran; only exactly 0 bytes fired. The earlier check's recorded
    reading (ADR-045) is the proof the file once held 300 lines."""

    ledger = _ledger(_out("/app/solve.sage"), resolved=True)
    state = RequestedOutputState(
        "inside", exists=True, changed=True, size_bytes=14, lines=1, relative="solve.sage"
    )  # "# placeholder\n"; base_lines None because the file is untracked at task base
    history = (_earlier("solve.sage", size=9_800, lines=300),)
    assert emptied_declared_items(replay(ledger.prefix), {(_OBL, 0): state}, history=history) == (
        (_OBL, 0),
    )
    # Without that reading nothing proves the file was ever longer than one line.
    assert emptied_declared_items(replay(ledger.prefix), {(_OBL, 0): state}) == ()


# --- C4: runner classifier and edited_after_last_verification ----------------------------------


def test_c2_compound_test_rerun_clears_edited_after_verification() -> None:
    """FP: a simple `pytest -q`, an edit, then the usual `cd /app && pytest -q` re-run (runner
    class `compound`) leaves the Stop-gate token standing."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.passes("cd /app && pytest -q")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)


def test_c2b_edit_after_compound_only_verification_is_seen() -> None:
    """FN: every test run is `cd /app && pytest` / `pytest | tail`, so there is no verification
    run at all and an edit after the last test is never reported."""

    ledger = _ledger()
    ledger.passes("cd /app && python -m pytest -q 2>&1 | tail -5")
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2c_in_workspace_note_edit_does_not_stale_verification() -> None:
    """FP: apply_patch of /app/NOTES.md after the final test run counted as a workspace edit. The
    hook now names such a write ``notes`` (the agent's own working notes, ADR-045)."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.edit(write_scope="notes")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    # A real source edit still stales it.
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2d_a_run_of_the_planned_command_is_a_verification_run() -> None:
    """formal-crypto D (tb4n2): the check the task asked for (``python /app/solve.py --check``)
    ran after the last edit but classes ``other``; only the earlier pytest was a verification
    class run, so the token stood although the requested command had just run."""

    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "python /app/solve.py --check"))
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.passes("python /app/other.py")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    ledger.passes("timeout 600 python3 /app/solve.py --check")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    # A later edit stales it again.
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


# --- C3: planned verification identity ---------------------------------------------------------


def test_c3_task_quoted_flag_prefix_matches_the_real_compile() -> None:
    """ks-solver D and S (tb4n3): the task says the verifier compiles with
    `g++ -O3 -std=c++17 -DKS_SOLVER_LIBRARY -I/app`; the agent planned that value and ran it with
    the source and -o operands appended ~10 times. Capture was exact; the identity rule was not.
    The match counts as a run and is disclosed, not clean verification."""

    ledger = _ledger(
        RequestedItem(RequestedItemKind.COMMAND, "g++ -O3 -std=c++17 -DKS_SOLVER_LIBRARY -I/app")
    )
    ledger.passes(
        "g++ -O3 -std=c++17 -DKS_SOLVER_LIBRARY -I/app /app/solution.cpp /app/t.cpp -o /app/t"
    )
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP in codes


def test_c3b_timeout_wrapper_matches_planned_command() -> None:
    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "python /app/pretrain.py"))
    ledger.passes("timeout 3000 python3 /app/pretrain.py")
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_STALE_GAP not in codes
    # Wrappers and the interpreter alias are the same command: a clean match, not a disclosure.
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP not in codes
