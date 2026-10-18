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

from collections.abc import Iterator, Mapping
from dataclasses import replace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli.observe_hooks import map_hook_payload_to_envelope, workspace_relative_edit_path
from finishup.cli.runtime_facts import runtime_structural_facts
from finishup.domain.events import (
    DeliverableState,
    EventPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
)
from finishup.domain.observation import ObservationEnvelope
from finishup.domain.shell_writes import shell_write_scope
from finishup.domain.values import JsonObject, event_id, evidence_id, obligation_id
from finishup.kernel.delivered_set import DeliverableSnapshot, emptied_declared_items
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    RequestedOutputState,
    acting_started,
    cooperative_event_ids_from_records,
    deliverable_path_identity,
    material_edit_recorded,
    observed_event_ids_from_records,
    passing_verification_observed,
    register_command_identity_key,
    task_fact_signals,
)
from finishup.protocol.canonical import JsonValue

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


_WORKSPACE = "/app"
_PATCH = "*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch\n"
_EDIT_CALLS: tuple[tuple[str, str, dict[str, JsonValue]], ...] = (
    # (id, tool, tool_input): the edit-tool shapes the three hosts send.
    ("codex_apply_patch", "apply_patch", {"command": _PATCH}),
    ("claude_write", "Write", {"file_path": "{path}", "content": "x"}),
    ("claude_edit", "Edit", {"file_path": "{path}", "old_string": "a", "new_string": "b"}),
    ("cursor_write", "Write", {"path": "{path}", "contents": "x"}),
)


def _hook_edit(
    ledger: ObservedLedger,
    tool: str,
    tool_input: dict[str, JsonValue],
    path: str,
    *,
    cwd: str | None = None,
) -> str | None:
    """Record the edit a real PostToolUse hook leaves in the ledger, and return its write scope.

    The chain is the hook's own: the host payload becomes an observation envelope, the runtime
    classifier (``runtime_structural_facts``, called by ``handle_observe`` with this same ``inside``
    rule) adds the closed ``write_scope`` fact, and the materializer turns the envelope into the
    action and result the ledger holds. Nothing here names a scope by hand.
    """

    filled: dict[str, JsonValue] = {
        key: value.replace("{path}", path) if isinstance(value, str) else value
        for key, value in tool_input.items()
    }
    payload: dict[str, JsonValue] = {
        "hook_event_name": "PostToolUse",
        "session_id": "codex-c2c",
        "tool_name": tool,
        "tool_use_id": f"call-{ledger.runs + 1}",
        "tool_input": filled,
        "tool_response": "Exit code: 0\nOutput:\nSuccess.",
    }
    if cwd is not None:
        payload["cwd"] = cwd
    envelope: ObservationEnvelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment="hmac-sha256:" + "5" * 64,
        event_ordinal=ledger.runs + 1,
        key_material=INSTALLATION_KEY,
    )
    facts = runtime_structural_facts(
        payload,
        tool_name=cast(str, envelope.structural_payload["tool_name"]),
        workspace_locator=_WORKSPACE,
        inside=lambda value: workspace_relative_edit_path(value, _WORKSPACE) is not None,
    )
    envelope = replace(
        envelope, structural_payload=JsonObject({**envelope.structural_payload, **facts})
    )
    batch = materialize_observation_envelope(
        envelope, task_id="tsk_00000000-0000-4000-8000-0000000000c2"
    )
    assert batch.skip_reason is None
    for item in batch.drafts:
        ledger.append(item.draft.schema, cast(EventPayload, item.draft.payload), observed=True)
    ledger.runs += 1
    scope = cast(Mapping[str, JsonValue], envelope.structural_payload).get("write_scope")
    return scope if isinstance(scope, str) else None


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [pytest.param(tool, tool_input, id=name) for name, tool, tool_input in _EDIT_CALLS],
)
def test_c2c_the_hook_itself_names_a_notes_edit_and_it_does_not_stale_verification(
    tool: str, tool_input: dict[str, JsonValue]
) -> None:
    """tb4n3 C (c2c, issue #1028). The scope in the test above is only as good as the hook that
    produces it: for each host's edit tool, a write of /app/NOTES.md must come out of the real
    hook chain as ``notes`` and leave the verification standing, while an edit of /app/solve.py
    through the same chain carries no scope and makes it stale."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    assert _hook_edit(ledger, tool, tool_input, "/app/NOTES.md") == "notes"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)

    assert _hook_edit(ledger, tool, tool_input, "/app/solve.py") is None
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2c_a_notes_edit_that_is_a_declared_output_still_stales_verification() -> None:
    """A deliverable that happens to be named NOTES.md is not the agent's scratch notes."""

    declared = _ledger(_out("/app/NOTES.md"))
    declared.passes("pytest -q")
    assert _hook_edit(
        declared, "Write", {"file_path": "{path}", "content": "x"}, "/app/NOTES.md"
    ) == ("notes")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(declared)


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


@pytest.mark.parametrize(
    "command",
    [
        # The original repro, verbatim.
        "timeout 3000 python /app/pretrain.py",
        # ADR-045 canonical form: the wrapper and the interpreter alias are the same command.
        "timeout 3000 python3 /app/pretrain.py",
        "env PYTHONUNBUFFERED=1 nice -n 5 python3.12 /app/pretrain.py",
    ],
)
def test_c3b_timeout_wrapper_matches_planned_command(command: str) -> None:
    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "python /app/pretrain.py"))
    ledger.passes(command)
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_STALE_GAP not in codes
    # Wrappers and the interpreter alias are the same command: a clean match, not a disclosure.
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP not in codes


# --- Codex review round 1 (issue #1028): limits of the canonical rule and of shell writes ------


def test_c2e_a_failed_shell_write_still_stales_the_verification() -> None:
    """``: > solve.py; false`` empties the file whatever its exit status says."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.run(": > solve.py; false", ResultOutcome.FAILURE, exit_status=1, write_scope="workspace")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2f_a_shell_write_to_notes_counts_only_when_notes_are_declared_output() -> None:
    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.run("echo x > NOTES.md", ResultOutcome.SUCCESS, exit_status=0, write_scope="notes")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    declared = _ledger(_out("/app/NOTES.md"))
    declared.passes("pytest -q")
    declared.run("echo x > NOTES.md", ResultOutcome.SUCCESS, exit_status=0, write_scope="notes")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(declared)


def test_c2g_a_command_writing_notes_and_a_declared_receipt_keeps_counting() -> None:
    """Shell-write review (#1028): ``: > NOTES.md; : > finishup_receipt.md`` once earned only
    ``notes``, which the task's declared ``finishup_receipt.md`` could not override; the receipt
    write was exempt and the verification stayed fresh. A command that writes two non-counting
    classes now counts, as a mixed edit-tool call does."""

    command = ": > NOTES.md; : > finishup_receipt.md"
    scope = shell_write_scope(command, workspace="/app", inside=lambda p: p.startswith("/app"))
    assert scope == "workspace"
    declared = _ledger(_out("/app/finishup_receipt.md"))
    declared.passes("pytest -q")
    declared.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope=scope)
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(declared)
    # One class alone stays non-counting unless its own declared output overrides it.
    alone = shell_write_scope(
        ": > finishup_receipt.md", workspace="/app", inside=lambda p: p.startswith("/app")
    )
    assert alone == "yoetz_owned"
    plain = _ledger()
    plain.passes("pytest -q")
    plain.run(": > finishup_receipt.md", ResultOutcome.SUCCESS, exit_status=0, write_scope=alone)
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(plain)


_PATCH_THEN_TEST = (
    "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /app/solve.py\n@@\n-x = 1\n"
    "+x = 2  # don't\n*** End Patch\nPATCH\npytest -q"
)


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(_PATCH_THEN_TEST, id="apply_patch"),
        pytest.param(
            "cd /app && git apply <<'EOF'\n--- a/solve.py\n+++ b/solve.py\n@@\n-x\n+it's\nEOF\n"
            "python -m pytest -q 2>&1 | tail -5",
            id="git_apply",
        ),
    ],
)
def test_c2h_patch_then_test_with_an_apostrophe_clears_edited_after(command: str) -> None:
    """n7 RC2(a, #1106): one apostrophe in the patch body made the whole command ``compound``, so
    its test never counted and the earlier edit stayed "edited after the last verification". The
    real hook chain names the patch a workspace write and the test a verification run."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.edit()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    assert _hook_edit(ledger, "Bash", {"command": command}, "/app/solve.py") == "workspace"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    # The patch alone, after that test, is a later edit.
    assert _hook_edit(ledger, "Bash", {"command": command.rsplit("\n", 1)[0]}, "") == "workspace"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2h_a_patch_after_the_test_in_one_odd_quote_command_still_stales() -> None:
    """#1106 r1: ``pytest -q && git apply <<EOF`` with an apostrophe in the patch stays a
    ``compound`` run, so the patch it applies after its test is not covered by that test."""

    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.edit()
    command = (
        "cd /app && pytest -q && git apply <<'EOF'\n--- a/solve.py\n+++ b/solve.py\n@@\n-x\n"
        "+it's\nEOF"
    )
    assert _hook_edit(ledger, "Bash", {"command": command}, "") == "workspace"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c3c_a_bare_run_of_the_canonical_form_has_a_known_outcome() -> None:
    """Planned ``python -m pytest``, run as bare ``pytest``: one simple command, so its own
    outcome, not ``unknown`` (a bare command carries no composition suffix)."""

    planned = RequestedItem(RequestedItemKind.COMMAND, "python -m pytest")
    ledger = _ledger(planned)
    ledger.passes("pytest")
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP not in codes
    assert PLANNED_VERIFICATION_FAILED_GAP not in codes
    failing = _ledger(planned)
    failing.fail("pytest")
    assert PLANNED_VERIFICATION_FAILED_GAP in _codes(failing)


def test_c3d_a_quoted_argument_with_a_space_is_not_two_arguments() -> None:
    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, 'pytest -k "foo bar"'))
    ledger.passes("pytest -k foo bar")
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP in codes
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP not in codes


def test_c3e_an_interpreter_option_that_changes_the_outcome_is_a_disclosed_match() -> None:
    """``python -O verify.py`` disables asserts: not the planned ``python verify.py`` cleanly."""

    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "python verify.py"))
    ledger.passes("python -O verify.py")
    codes = _codes(ledger)
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP in codes
    clean = _ledger(RequestedItem(RequestedItemKind.COMMAND, "python verify.py"))
    clean.passes("python3 -u verify.py")
    assert PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP not in _codes(clean)


def test_a_masked_success_is_not_a_passing_verification() -> None:
    """``pytest -q; true`` exits 0 whatever pytest did; only a plain run or ``&&`` chain proves."""

    def passing(command: str) -> bool:
        ledger = _ledger()
        ledger.passes(command)
        records = ledger.prefix
        return passing_verification_observed(
            replay(records),
            observed_event_ids_from_records(records),
            cooperative_event_ids_from_records(records),
        )

    assert passing("pytest -q")
    assert passing("cd /app && pytest -q")
    assert not passing("pytest -q; true")
    assert not passing("pytest -q | tail -3")


# --- n7 RC2(c): a documentation edit is real work but leaves verification current (#1106) -----


def _docs_facts(ledger: ObservedLedger) -> tuple[set[str], bool, bool]:
    state = replay(ledger.prefix)
    observed = observed_event_ids_from_records(ledger.prefix)
    cooperative = cooperative_event_ids_from_records(ledger.prefix)
    return (
        _codes(ledger),
        acting_started(state, observed, cooperative),
        material_edit_recorded(state, observed, cooperative),
    )


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        *(pytest.param(tool, tool_input, id=name) for name, tool, tool_input in _EDIT_CALLS),
        pytest.param(
            "Bash", {"command": "cat > {path} <<'EOF'\n# Usage\nEOF"}, id="shell_heredoc_write"
        ),
    ],
)
def test_c2i_a_docs_edit_does_not_stale_verification_but_is_acting(
    tool: str, tool_input: dict[str, JsonValue]
) -> None:
    """n7 RC2(c): code edit, passing test, README edit gave "edited after the last verification"
    although the README changes nothing the test verified. Through each host's real hook chain
    the README write is named ``docs``: the verification stays current, the edit still counts as
    acting and as a material edit, and a planned verification is not stale."""

    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"))
    ledger.edit()
    ledger.passes("pytest -q")
    assert _hook_edit(ledger, tool, tool_input, "/app/README.md") == "docs"
    codes, acting, material = _docs_facts(ledger)
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in codes
    assert PLANNED_VERIFICATION_STALE_GAP not in codes
    assert acting and material
    # A source edit after it still stales the verification.
    assert _hook_edit(ledger, tool, tool_input, "/app/solve.py") in {None, "workspace"}
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2i_a_docs_only_edit_alone_is_still_a_material_edit() -> None:
    ledger = _ledger()
    ledger.edit(write_scope="docs")
    codes, acting, material = _docs_facts(ledger)
    assert acting and material
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in codes


@pytest.mark.parametrize(
    "declared",
    [
        pytest.param(_out("/app/README.md"), id="declared_readme"),
        pytest.param(_out("docs/guide.md"), id="declared_relative_guide"),
        pytest.param(
            RequestedItem(RequestedItemKind.DIRECTORY, "/app/docs", role=RequestedItemRole.OUTPUT),
            id="declared_directory",
        ),
    ],
)
def test_c2j_a_declared_docs_output_or_directory_still_stales(declared: RequestedItem) -> None:
    """The delivery wins: a README the task asks for is the deliverable, and any declared
    output directory may hold one, so editing it after the test makes the test stale."""

    ledger = _ledger(declared)
    ledger.passes("pytest -q")
    assert (
        _hook_edit(ledger, "Write", {"file_path": "{path}", "content": "x"}, "/app/README.md")
        == "docs"
    )
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    # An input declaration is not a delivery: the exemption stands.
    inputs = _ledger(
        RequestedItem(RequestedItemKind.FILE, "/app/README.md", role=RequestedItemRole.INPUT)
    )
    inputs.passes("pytest -q")
    inputs.edit(write_scope="docs")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(inputs)


def test_c2k_docs_and_code_in_one_shell_write_stale_verification() -> None:
    command = "cat > README.md <<'EOF'\nx\nEOF\ncat > solve.py <<'EOF'\ny\nEOF"
    assert shell_write_scope(command, workspace="/app", inside=lambda p: p.startswith("/app")) == (
        "workspace"
    )
    assert (
        shell_write_scope(
            "cat > README.md <<'EOF'\nx\nEOF",
            workspace="/app",
            inside=lambda p: p.startswith("/app"),
        )
        == "docs"
    )
    ledger = _ledger()
    ledger.passes("pytest -q")
    ledger.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


# --- #1106 r2: a fixture written after a ``cd`` is no documentation -----------------------------


@pytest.mark.parametrize(
    "command",
    [
        pytest.param("cd tests/fixtures && cat > expected.md <<'EOF'\nnew\nEOF", id="cd_heredoc"),
        pytest.param(
            "cd tests && apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: golden.md\n@@\n"
            "-a\n+b\n*** End Patch\nEOF",
            id="cd_apply_patch",
        ),
        pytest.param(
            "cd tests/data && git apply <<'EOF'\n--- a/expected.md\n+++ b/expected.md\n@@ -1 +1 @@\n"
            "-a\n+b\nEOF",
            id="cd_git_apply",
        ),
        pytest.param("cd /app/tests && printf 'x\\n' > golden.md", id="cd_absolute"),
    ],
)
def test_c2l_a_fixture_written_after_cd_stales_verification(command: str) -> None:
    """correctness-r2-2: the relative target was read against the workspace root, so a golden
    file written after ``cd tests`` was ``docs`` and the earlier passing test stayed current."""

    ledger = _ledger()
    ledger.edit()
    ledger.passes("pytest -q")
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    assert _hook_edit(ledger, "Bash", {"command": command}, "") == "workspace"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)


def test_c2l_the_hosts_cwd_places_a_relative_doc_write() -> None:
    """The host's ``cwd`` is where a relative write lands: a README written from ``tests/`` is a
    fixture, one written from the root or ``docs/`` is documentation."""

    command: dict[str, JsonValue] = {"command": "printf 'x\\n' > README.md"}
    ledger = _ledger()
    ledger.passes("pytest -q")
    assert _hook_edit(ledger, "Bash", command, "", cwd="/app") == "docs"
    assert _hook_edit(ledger, "Bash", command, "", cwd="/app/docs") == "docs"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _codes(ledger)
    assert _hook_edit(ledger, "Bash", command, "", cwd="/app/tests") == "workspace"
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
    # A cwd that cannot be placed under the root (another spelling of it) keeps it counting.
    assert _hook_edit(_ledger(), "Bash", command, "", cwd="/private/app") == "workspace"


@pytest.mark.parametrize(
    ("tool", "tool_input", "older"),
    [
        *(pytest.param(tool, tool_input, None, id=name) for name, tool, tool_input in _EDIT_CALLS),
        pytest.param(
            "Bash", {"command": "cat > {path} <<'EOF'\n# Usage\nEOF"}, "workspace", id="shell"
        ),
    ],
)
def test_c2m_without_a_service_that_reads_docs_the_older_class_is_recorded(
    tool: str,
    tool_input: dict[str, JsonValue],
    older: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """correctness-r2-1: a service that predates ``docs`` refuses a stored row naming it for the
    whole workspace. Unless the running service reads the class, the hook records what it
    recorded before the class existed, which keeps the README edit counting."""

    import finishup.service.write_scope_admission as admission

    monkeypatch.setattr(admission, "docs_write_scope_admitted", lambda: False)
    ledger = _ledger()
    ledger.passes("pytest -q")
    assert _hook_edit(ledger, tool, tool_input, "/app/README.md") == older
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _codes(ledger)
