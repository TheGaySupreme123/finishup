"""Fact lineage: the typed provenance of a derived fact, one renderer, one wire shape (ADR-045)."""

from __future__ import annotations

import typing
from types import SimpleNamespace

import pytest

from yoetz.cli.closure_gate import closure_gate_from_readiness
from yoetz.domain.values import event_id, obligation_id
from yoetz.kernel.fact_lineage import (
    FACT_LINEAGE_BASES,
    FACT_LINEAGE_PROOFS,
    FACT_LINEAGE_RULES,
    FACT_LINEAGE_STATES,
    FactLineage,
    lineage_from_wire,
    lineage_text,
    lineage_texts,
    lineage_to_wire,
)
from yoetz.protocol.models import FactLineageModel

_OBL = obligation_id("obl_00000000-0000-4000-8000-0000000000f1")
_CHECK = event_id("evt_00000000-0000-4000-8000-0000000000f2")
_PRIOR = event_id("evt_00000000-0000-4000-8000-0000000000f3")
_RUN = event_id("evt_00000000-0000-4000-8000-0000000000f4")


def _emptied() -> FactLineage:
    return FactLineage(
        code="declared_output_emptied",
        rule="deliverable_path_history",
        state="emptied",
        obligation_id=_OBL,
        item_index=0,
        check_event_id=_CHECK,
        frontier=340,
        prior_event_id=_PRIOR,
        prior_frontier=312,
        prior_size_bytes=15_975,
        prior_lines=310,
        now_size_bytes=0,
        now_lines=0,
        proof="earlier_check",
        basis="delivered",
    )


def test_the_wire_literals_match_the_kernel_sets() -> None:
    """``FactLineageModel`` repeats the closed sets (protocol cannot import the kernel)."""

    def literal(name: str) -> tuple[str, ...]:
        annotation = FactLineageModel.model_fields[name].annotation
        arguments = [
            argument
            for argument in typing.get_args(annotation)
            if typing.get_origin(argument) is typing.Literal
        ]
        values = typing.get_args(arguments[0]) if arguments else typing.get_args(annotation)
        return tuple(values)

    assert set(literal("rule")) == set(FACT_LINEAGE_RULES)
    assert set(literal("state")) == set(FACT_LINEAGE_STATES)
    assert set(literal("proof")) == set(FACT_LINEAGE_PROOFS)
    assert set(literal("basis")) == set(FACT_LINEAGE_BASES)


def test_wire_round_trip_through_the_model() -> None:
    item = _emptied()
    wire = lineage_to_wire(item)
    assert wire["frontier"] == "340" and wire["item_index"] == "0"
    model = FactLineageModel.model_validate(wire)
    assert lineage_from_wire(model) == item
    assert lineage_from_wire(wire) == item
    # Absent optionals are omitted, never null.
    bare = FactLineage(
        code="edited_after_last_verification",
        rule="edit_after_verification_run",
        state="edited_after",
    )
    assert set(lineage_to_wire(bare)) == {"code", "rule", "state"}


def test_the_sentence_names_the_subject_the_prior_state_and_the_proof() -> None:
    text = lineage_text(_emptied())
    assert text.startswith("Why: the declared output of ")
    assert f"{_OBL} requested item 0" in text
    assert "now holds 0 bytes / 0 lines at frontier 340" in text
    assert f"it held 15975 bytes / 310 lines at frontier 312, check {_PRIOR}" in text
    assert "resolved or claimed" in text and "Rule deliverable_path_history." in text
    assert text.isascii()


def test_the_sentence_is_the_same_for_a_task_base_proof() -> None:
    item = FactLineage(
        code="declared_output_emptied",
        rule="deliverable_path_history",
        state="truncated",
        obligation_id=_OBL,
        item_index=2,
        frontier=9,
        now_size_bytes=14,
        now_lines=1,
        proof="task_base",
        basis="present",
    )
    assert "it held content at the task base" in lineage_text(item)


def test_a_loose_command_match_is_disclosed_not_clean() -> None:
    item = FactLineage(
        code="planned_verification_matched_by_prefix",
        rule="planned_command_match",
        state="matched_prefix",
        obligation_id=_OBL,
        item_index=1,
        frontier=210,
        proof="observed_run",
        source_event_ids=(_RUN,),
    )
    text = lineage_text(item)
    assert "leading arguments only" in text and str(_RUN) in text
    assert "disclosed, not clean verification" in text


def test_texts_are_ordered_deduplicated_and_filtered_by_code() -> None:
    other = FactLineage(
        code="planned_verification_not_observed",
        rule="planned_command_unmatched",
        state="unmatched",
        obligation_id=_OBL,
        item_index=3,
    )
    texts = lineage_texts([other, _emptied(), _emptied()])
    assert len(texts) == 2
    assert lineage_texts([other, _emptied()], "declared_output_emptied") == (
        lineage_text(_emptied()),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule": "unknown"},
        {"state": "wat"},
        {"proof": "guess"},
        {"item_index": 64},
        {"frontier": -1},
    ],
)
def test_a_lineage_outside_the_closed_sets_is_refused(overrides: dict[str, object]) -> None:
    fields: dict[str, object] = {
        "code": "declared_output_emptied",
        "rule": "deliverable_path_history",
        "state": "emptied",
        "obligation_id": _OBL,
        "item_index": 0,
    }
    fields.update(overrides)
    with pytest.raises(ValueError):
        FactLineage(**fields)  # type: ignore[arg-type]


def test_the_gate_text_says_why_beside_the_token_it_explains() -> None:
    readiness = SimpleNamespace(
        state="action_required",
        agent_actionable=("declared_output_emptied",),
        standing_limitations=(),
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
        blocked_obligations=(),
        fact_lineage=(FactLineageModel.model_validate(lineage_to_wire(_emptied())),),
    )
    gate = closure_gate_from_readiness(
        readiness, frontier_sequence="340", frontier_digest="d", observation_pending=False
    )
    assert gate is not None
    assert lineage_text(_emptied()) in gate.text
    assert "Acknowledging or republishing the obligation does not clear this" in gate.text
    assert "yoetz-assumption:<obligation id>" in gate.text
    assert len(gate.text) <= 2_000
    # Provenance for a fact the gate is not naming is not shown.
    quiet = SimpleNamespace(
        **{
            **vars(readiness),
            "agent_actionable": ("obligations_open",),
            "open_obligation_count": "1",
        }
    )
    other = closure_gate_from_readiness(
        quiet, frontier_sequence="340", frontier_digest="d", observation_pending=False
    )
    assert other is not None and "Why:" not in other.text


def test_a_stale_or_failed_command_fact_says_what_happened_not_that_it_matched() -> None:
    """The stale and failed sentences name the run and the edit; the edit is never a "run"."""

    stale = FactLineage(
        code="planned_verification_stale",
        rule="planned_command_match",
        state="stale",
        obligation_id=obligation_id("obl_00000000-0000-4000-8000-0000000000a1"),
        item_index=0,
        frontier=40,
        prior_frontier=52,
        proof="observed_run",
        source_event_ids=(
            event_id("evt_00000000-0000-4000-8000-0000000000a1"),
            event_id("evt_00000000-0000-4000-8000-0000000000a2"),
        ),
    )
    text = lineage_text(stale)
    assert "last run at frontier 40" in text and "edit followed at frontier 52" in text
    assert "Observed run(s)" not in text and "matched by" not in text
    failed = FactLineage(
        code="planned_verification_failed",
        rule="planned_command_match",
        state="failed",
        obligation_id=obligation_id("obl_00000000-0000-4000-8000-0000000000a1"),
        item_index=0,
        frontier=40,
        proof="observed_run",
    )
    assert "failed" in lineage_text(failed) and "matched by" not in lineage_text(failed)
    edit = FactLineage(
        code="edited_after_last_verification",
        rule="edit_after_verification_run",
        state="edited_after",
        frontier=52,
        prior_frontier=40,
        proof="observed_run",
    )
    text = lineage_text(edit)
    assert "edit at frontier 52 followed the last verification run" in text
    assert "last verification run being at frontier 40" in text
